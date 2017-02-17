# Copyright (c) 2017 Pure Storage, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Volume driver for Pure Storage FlashArray storage system.

This driver requires Purity version 4.0.0 or later.
"""

import re
import uuid

from oslo.config import cfg

from cinder import exception
from cinder.i18n import _, _LE, _LI, _LW
from cinder.openstack.common import excutils
from cinder.openstack.common import log as logging
from cinder.openstack.common import units
from cinder import utils
from cinder.volume import driver
from cinder.volume.drivers.san import san
from cinder.zonemanager import utils as fczm_utils

try:
    import purestorage
except ImportError:
    purestorage = None

LOG = logging.getLogger(__name__)

PURE_OPTS = [
    cfg.StrOpt("pure_api_token",
               default=None,
               help="REST API authorization token."),
]

CONF = cfg.CONF
CONF.register_opts(PURE_OPTS)

INVALID_CHARACTERS = re.compile(r"[^-a-zA-Z0-9]")
GENERATED_NAME = re.compile(r".*-[a-f0-9]{32}-cinder$")


ERR_MSG_NOT_EXIST = "does not exist"
ERR_MSG_PENDING_ERADICATION = "has been destroyed"

CONNECT_LOCK_NAME = 'PureVolumeDriver_connect'

MANAGE_SNAP_REQUIRED_API_VERSIONS = ['1.4']


def log_debug_trace(f):
    def wrapper(*args, **kwargs):
        cls_name = args[0].__class__.__name__
        method_name = "%(cls_name)s.%(method)s" % {"cls_name": cls_name,
                                                   "method": f.func_name}
        LOG.debug("Enter " + method_name)
        result = f(*args, **kwargs)
        LOG.debug("Leave " + method_name)
        return result

    return wrapper


class PureBaseVolumeDriver(san.SanDriver):
    """Performs volume management on Pure Storage FlashArray."""

    SUPPORTED_REST_API_VERSIONS = ['1.2', '1.3', '1.4']

    def __init__(self, *args, **kwargs):
        execute = kwargs.pop("execute", utils.execute)
        super(PureBaseVolumeDriver, self).__init__(execute=execute, *args,
                                                   **kwargs)
        self.configuration.append_config_values(PURE_OPTS)
        self._array = None
        self._storage_protocol = None
        self._backend_name = (self.configuration.volume_backend_name or
                              self.__class__.__name__)

    def do_setup(self, context):
        """Performs driver initialization steps that could raise exceptions."""
        if purestorage is None:
            msg = _("Missing 'purestorage' python module, ensure the library"
                    " is installed and available.")
            raise exception.PureDriverException(msg)

        # Raises PureDriverException if unable to connect and PureHTTPError
        # if unable to authenticate.
        purestorage.FlashArray.supported_rest_versions = \
            self.SUPPORTED_REST_API_VERSIONS
        self._array = purestorage.FlashArray(
            self.configuration.san_ip,
            api_token=self.configuration.pure_api_token)

    def check_for_setup_error(self):
        # Avoid inheriting check_for_setup_error from SanDriver, which checks
        # for san_password or san_private_key, not relevant to our driver.
        pass

    @log_debug_trace
    def create_volume(self, volume):
        """Creates a volume."""
        vol_name = self._get_vol_name(volume)
        vol_size = volume["size"] * units.Gi
        self._array.create_volume(vol_name, vol_size)

    @log_debug_trace
    def create_volume_from_snapshot(self, volume, snapshot):
        """Creates a volume from a snapshot."""
        vol_name = self._get_vol_name(volume)
        snap_name = self._get_snap_name(snapshot)

        if not snap_name:
            msg = _('Unable to determine snapshot name in Purity for snapshot '
                    '%(id)s.') % {'id': snapshot['id']}
            raise exception.PureDriverException(reason=msg)

        self._array.copy_volume(snap_name, vol_name)
        self._extend_if_needed(vol_name, snapshot["volume_size"],
                               volume["size"])

    @log_debug_trace
    def create_cloned_volume(self, volume, src_vref):
        """Creates a clone of the specified volume."""
        vol_name = self._get_vol_name(volume)
        src_name = self._get_vol_name(src_vref)
        self._array.copy_volume(src_name, vol_name)
        self._extend_if_needed(vol_name, src_vref["size"], volume["size"])

    def _extend_if_needed(self, vol_name, src_size, vol_size):
        """Extend the volume from size src_size to size vol_size."""
        if vol_size > src_size:
            vol_size = vol_size * units.Gi
            self._array.extend_volume(vol_name, vol_size)

    @log_debug_trace
    def delete_volume(self, volume):
        """Disconnect all hosts and delete the volume"""
        vol_name = self._get_vol_name(volume)
        try:
            connected_hosts = \
                self._array.list_volume_private_connections(vol_name)
            for host_info in connected_hosts:
                host_name = host_info["host"]
                self._disconnect_host(host_name, vol_name)
            self._array.destroy_volume(vol_name)
        except purestorage.PureHTTPError as err:
            with excutils.save_and_reraise_exception() as ctxt:
                if err.code == 400 and \
                        ERR_MSG_NOT_EXIST in err.text:
                    # Happens if the volume does not exist.
                    ctxt.reraise = False
                    LOG.warning(_LW("Volume deletion failed with message: %s"),
                                err.text)

    @log_debug_trace
    def create_snapshot(self, snapshot):
        """Creates a snapshot."""
        vol_name, snap_suff = self._get_snap_name(snapshot).split(".")
        self._array.create_snapshot(vol_name, suffix=snap_suff)

    @log_debug_trace
    def delete_snapshot(self, snapshot):
        """Deletes a snapshot."""
        snap_name = self._get_snap_name(snapshot)
        try:
            self._array.destroy_volume(snap_name)
        except purestorage.PureHTTPError as err:
            with excutils.save_and_reraise_exception() as ctxt:
                if err.code == 400:
                    # Happens if the snapshot does not exist.
                    ctxt.reraise = False
                    LOG.error(_LE("Snapshot deletion failed with message:"
                                  " %s"), err.text)

    def ensure_export(self, context, volume):
        pass

    def create_export(self, context, volume):
        pass

    def _get_host(self, connector):
        """Get a Purity Host that corresponds to the host in the connector.

        This implementation is specific to the host type (iSCSI, FC, etc).
        """
        raise NotImplementedError

    @utils.synchronized(CONNECT_LOCK_NAME, external=True)
    def _disconnect(self, volume, connector, **kwargs):
        vol_name = self._get_vol_name(volume)
        host = self._get_host(connector)
        if host:
            host_name = host["name"]
            result = self._disconnect_host(host_name, vol_name)
        else:
            LOG.error(_LE("Unable to disconnect host from volume."))
            result = False

        return result

    @log_debug_trace
    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate connection."""
        self._disconnect(volume, connector, **kwargs)

    @log_debug_trace
    def _disconnect_host(self, host_name, vol_name):
        """Return value indicates if host was deleted on array or not"""
        try:
            self._array.disconnect_host(host_name, vol_name)
        except purestorage.PureHTTPError as err:
            with excutils.save_and_reraise_exception() as ctxt:
                if err.code == 400:
                    # Happens if the host and volume are not connected.
                    ctxt.reraise = False
                    LOG.error(_LE("Disconnection failed with message: "
                                  "%(msg)s."), {"msg": err.text})
        if (GENERATED_NAME.match(host_name) and
            not self._array.list_host_connections(host_name,
                                                  private=True)):
            LOG.info(_LI("Deleting unneeded host %(host_name)r."),
                     {"host_name": host_name})
            try:
                self._array.delete_host(host_name)
            except purestorage.PureHTTPError as err:
                with excutils.save_and_reraise_exception() as ctxt:
                    if err.code == 400 and ERR_MSG_NOT_EXIST in err.text:
                        # Happens if the host is already deleted.
                        # This is fine though, just treat it as a warning.
                        ctxt.reraise = False
                        LOG.warning(_LW("Purity host deletion failed: "
                                        "%(msg)s."), {"msg": err.text})
            return True

        return False

    @log_debug_trace
    def get_volume_stats(self, refresh=False):
        """Return the current state of the volume service.

        If 'refresh' is True, run the update first.
        """

        if refresh:
            LOG.debug("Updating volume stats.")
            self._update_stats()
        return self._stats

    def _update_stats(self):
        """Set self._stats with relevant information."""
        info = self._array.get(space=True)
        total_capacity = float(info["capacity"]) / units.Gi
        used_space = float(info["total"]) / units.Gi
        free_space = float(total_capacity - used_space)
        prov_space, total_vols = self._get_provisioned_space()
        provisioned_space = float(prov_space) / units.Gi
        # If array is empty we can not calculate a max oversubscription ratio.
        # In this case we choose 20 as a default value for the ratio.  Once
        # some volumes are actually created and some data is stored on the
        # array a much more accurate number will be presented based on current
        # usage.
        if used_space == 0 or provisioned_space == 0:
            thin_provisioning = 20
        else:
            thin_provisioning = provisioned_space / used_space
        data = {
            "volume_backend_name": self._backend_name,
            "vendor_name": "Pure Storage",
            "driver_version": self.VERSION,
            "storage_protocol": self._storage_protocol,
            "total_capacity_gb": total_capacity,
            "free_capacity_gb": free_space,
            "reserved_percentage": 0,
            "consistencygroup_support": True,
            "thin_provisioning_support": True,
            "provisioned_capacity": provisioned_space,
            "max_over_subscription_ratio": thin_provisioning,
            "total_volumes": total_vols,
            "multiattach": True,
        }
        self._stats = data

    def _get_provisioned_space(self):
        """Sum up provisioned size of all volumes on array"""
        volumes = self._array.list_volumes(pending=True)
        return sum(item["size"] for item in volumes), len(volumes)

    @log_debug_trace
    def extend_volume(self, volume, new_size):
        """Extend volume to new_size."""
        vol_name = self._get_vol_name(volume)
        new_size = new_size * units.Gi
        self._array.extend_volume(vol_name, new_size)

    @staticmethod
    def _get_vol_name(volume):
        """Return the name of the volume Purity will use."""
        return volume["name"] + "-cinder"

    @staticmethod
    def _get_snap_name(snapshot):
        """Return the name of the snapshot that Purity will use."""
        return "%s-cinder.%s" % (snapshot["volume_name"], snapshot["name"])

    @staticmethod
    def _generate_purity_host_name(name):
        """Return a valid Purity host name based on the name passed in."""
        if len(name) > 23:
            name = name[0:23]
        name = INVALID_CHARACTERS.sub("-", name)
        name = name.lstrip("-")
        return "{name}-{uuid}-cinder".format(name=name, uuid=uuid.uuid4().hex)

    def _connect_host_to_vol(self, host_name, vol_name):
        connection = None
        try:
            connection = self._array.connect_host(host_name, vol_name)
        except purestorage.PureHTTPError as err:
            with excutils.save_and_reraise_exception() as ctxt:
                if (err.code == 400 and
                        "Connection already exists" in err.text):
                    # Happens if the volume is already connected to the host.
                    # Treat this as a success.
                    ctxt.reraise = False
                    LOG.debug("Volume connection already exists for Purity "
                              "host with message: %s", err.text)

                    # Get the info for the existing connection
                    connected_hosts = \
                        self._array.list_volume_private_connections(vol_name)
                    for host_info in connected_hosts:
                        if host_info["host"] == host_name:
                            connection = host_info
                            break
        if not connection:
            raise exception.PureDriverException(
                reason=_("Unable to connect or find connection to host"))

        return connection

    def retype(self, context, volume, new_type, diff, host):
        """Retype from one volume type to another on the same backend.

        For a Pure Array there is currently no differentiation between types
        of volumes. This means that changing from one type to another on the
        same array should be a no-op.
        """
        return True, None


class PureFCDriver(PureBaseVolumeDriver, driver.FibreChannelDriver):

    VERSION = "1.0.0"

    def __init__(self, *args, **kwargs):
        execute = kwargs.pop("execute", utils.execute)
        super(PureFCDriver, self).__init__(execute=execute, *args, **kwargs)
        self._storage_protocol = "FC"
        self._lookup_service = fczm_utils.create_lookup_service()

    def do_setup(self, context):
        super(PureFCDriver, self).do_setup(context)

    def _get_host(self, connector):
        """Return dict describing existing Purity host object or None."""
        hosts = self._array.list_hosts()
        for host in hosts:
            for wwn in connector["wwpns"]:
                if wwn in str(host["wwn"]).lower():
                    return host

    def _get_array_wwns(self):
        """Return list of wwns from the array"""
        ports = self._array.list_ports()
        return [port["wwn"] for port in ports if port["wwn"]]

    @fczm_utils.AddFCZone
    @log_debug_trace
    def initialize_connection(self, volume, connector, initiator_data=None):
        """Allow connection to connector and return connection info."""

        connection = self._connect(volume, connector)
        target_wwns = self._get_array_wwns()
        init_targ_map = self._build_initiator_target_map(target_wwns,
                                                         connector)
        properties = {
            "driver_volume_type": "fibre_channel",
            "data": {
                'target_discovered': True,
                "target_lun": connection["lun"],
                "target_wwn": target_wwns,
                'access_mode': 'rw',
                'initiator_target_map': init_targ_map,
                "discard": True,
            }
        }

        return properties

    @utils.synchronized(CONNECT_LOCK_NAME, external=True)
    def _connect(self, volume, connector):
        """Connect the host and volume; return dict describing connection."""
        wwns = connector["wwpns"]

        vol_name = self._get_vol_name(volume)
        host = self._get_host(connector)

        if host:
            host_name = host["name"]
            LOG.info(_LI("Re-using existing purity host %(host_name)r"),
                     {"host_name": host_name})
        else:
            host_name = self._generate_purity_host_name(connector["host"])
            LOG.info(_LI("Creating host object %(host_name)r with WWN:"
                         " %(wwn)s."), {"host_name": host_name, "wwn": wwns})
            self._array.create_host(host_name, wwnlist=wwns)

        return self._connect_host_to_vol(host_name, vol_name)

    def _build_initiator_target_map(self, target_wwns, connector):
        """Build the target_wwns and the initiator target map."""
        init_targ_map = {}

        if self._lookup_service:
            # use FC san lookup to determine which NSPs to use
            # for the new VLUN.
            dev_map = self._lookup_service.get_device_mapping_from_network(
                connector['wwpns'],
                target_wwns)

            for fabric_name in dev_map:
                fabric = dev_map[fabric_name]
                for initiator in fabric['initiator_port_wwn_list']:
                    if initiator not in init_targ_map:
                        init_targ_map[initiator] = []
                    init_targ_map[initiator] += fabric['target_port_wwn_list']
                    init_targ_map[initiator] = list(set(
                        init_targ_map[initiator]))
        else:
            init_targ_map = dict.fromkeys(connector["wwpns"], target_wwns)

        return init_targ_map

    @fczm_utils.RemoveFCZone
    @log_debug_trace
    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate connection."""
        no_more_connections = self._disconnect(volume, connector, **kwargs)

        properties = {"driver_volume_type": "fibre_channel", "data": {}}

        if no_more_connections:
            target_wwns = self._get_array_wwns()
            init_targ_map = self._build_initiator_target_map(target_wwns,
                                                             connector)
            properties["data"] = {"target_wwn": target_wwns,
                                  "initiator_target_map": init_targ_map}

        return properties