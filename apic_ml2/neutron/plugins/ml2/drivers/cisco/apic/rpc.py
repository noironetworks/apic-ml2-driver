# Copyright (c) 2014 Cisco Systems Inc.
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

import eventlet

eventlet.monkey_patch()
from oslo_concurrency import lockutils
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_messaging import target

from neutron import context as nctx
from neutron.db import api as db_api
from neutron.extensions import providernet as api
from neutron import manager
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.plugins.ml2 import models

TOPIC_APIC_SERVICE = 'apic-service'

LOG = logging.getLogger(__name__)


class ApicTopologyRpcCallback(object):

    @lockutils.synchronized('apic_service', lock_file_prefix='apicapi-',
                            external=True)
    def update_link(self, context,
                    host, interface, mac,
                    switch, module, port):
        LOG.debug("APIC service agent: received update_link: %s",
                  ", ".join(map(str,
                                [host, interface, mac, switch, module, port])))

        nlink = (host, interface, mac, switch, module, port)
        clink = self.peers.get((host, interface), None)

        LOG.debug("current link: %s", clink)
        LOG.debug("new link: %s", nlink)

        if switch == 0:
            # this is a link delete, remove it
            if clink is not None:
                self._remove_hostlink(*clink)
                self.peers.pop((host, interface))
        else:
            if clink is not None and clink != nlink:
                # delete old link
                self._remove_hostlink(*clink)
                self.peers.pop((host, interface))
            # always try to add the new one (for sync)
            self._add_hostlink(*nlink)
            self.peers[(host, interface)] = nlink

    def delete_link(self, context, host, interface, mac, switch, module, port):
        pass

    def _remove_hostlink(self, *args):
        self.apic_manager.remove_hostlink(*args)

    def _add_hostlink(self, *args):
        self.apic_manager.add_hostlink(*args)

    def _load_peers(self):
        session = db_api.get_session()
        peers = {}
        with session.begin(subtransactions=True):
            links = session.query(apic_model.HostLink).all()
            for link in links:
                peers[(link.host, link.ifname)] = (
                    link.host, link.ifname, link.ifmac, link.swid, link.module,
                    link.port)
            return peers


class ApicTopologyRpcCallbackMechanism(ApicTopologyRpcCallback):
    """Apic Topology RPC Callback for Mechanism APIC.

    This class can be used by mechanism apic driver to take advantage of the
    Neutron environment for better host mobility in ACI. When the RPC listener
    runs within the mechanism driver, the standalone service should be
    disabled.
    """
    RPC_API_VERSION = "1.1"
    target = target.Target(version=RPC_API_VERSION)

    def __init__(self, apic_manager, driver):
        self.mech_apic = driver
        self.apic_manager = apic_manager
        self.peers = self._load_peers()
        LOG.debug("Current peers %s", self.peers)

    def _remove_hostlink(self, *args):
        LOG.debug("remove host link %s", args)
        # Remove link from the DB
        link = self.apic_manager.remove_hostlink(*args)
        context = nctx.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        host = args[0]
        LOG.debug("existing link from deletion %s", str(link))
        # Another interface could still be up for that host on that module
        # (VPC)
        if link and not self._get_hostlinks_for_host(host, link.module,
                                                     link.port):
            # REVISIT(ivar): The following could be optimized aggregating all
            # the networks by tenant
            for network in self._get_networks_from_host(context, plugin, host):
                # Delete all paths for this host
                atenant_id = self.mech_apic.name_mapper.tenant(
                    context, network['tenant_id'])
                anetwork_id = self.mech_apic.name_mapper.network(
                    context, network['id'])
                LOG.debug("deleting path %s", (
                    atenant_id, anetwork_id, link.swid, link.module,
                    link.port))
                self.apic_manager.delete_path(
                    atenant_id, anetwork_id, link.swid, link.module, link.port)

    def _add_hostlink(self, *args):
        LOG.debug("add host link %s", args)
        # Add link to the DB
        try:
            self.apic_manager.add_hostlink(*args)
        except db_exc.DBDuplicateEntry:
            LOG.info(_("Duplicate entry for link %s, topology change already "
                       "been server"), args)

        context = nctx.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        host = args[0]

        for network in self._get_networks_from_host(context, plugin, host):
            # Delete all paths for this host
            atenant_id = self.mech_apic.name_mapper.tenant(
                context, network['tenant_id'])
            anetwork_id = self.mech_apic.name_mapper.network(
                context, network['id'])
            seg = None
            if network.get(api.NETWORK_TYPE) == constants.TYPE_VLAN:
                seg = network.get(api.SEGMENTATION_ID)

            if seg:
                self.apic_manager.ensure_path_created_for_port(
                    atenant_id, anetwork_id, host, seg)
            else:
                LOG.warn("Network with empty segmentation id can't be pushed "
                         "on APIC: %s", network['id'])

    def _get_networks_from_host(self, context, plugin, host):
        # Retrieve Plugin Context and core plugin
        bindings = context.session.query(
            models.PortBinding).filter_by(host=host).all()
        port_ids = [x.port_id for x in bindings]
        networks = []
        if port_ids:
            # There are ports bound in that host
            ports = plugin.get_ports(context, {'id': port_ids})
            networks = plugin.get_networks(context, {'id': [x['network_id'] for
                                                            x in ports]})
        return networks

    def _get_hostlinks_for_host(self, host, module, port):
        session = db_api.get_session()
        return session.query(apic_model.HostLink).filter_by(
            host=host, module=module, port=port).all()


class ApicTopologyServiceNotifierApi(object):

    RPC_API_VERSION = '1.1'

    def __init__(self):
        super(ApicTopologyServiceNotifierApi, self).__init__(
            topic=TOPIC_APIC_SERVICE,
            default_version=self.RPC_API_VERSION)

    def update_link(self, context, host, interface, mac, switch, module, port):
        self.fanout_cast(
            context, self.make_msg(
                'update_link',
                host=host, interface=interface, mac=mac,
                switch=switch, module=module, port=port),
            topic=TOPIC_APIC_SERVICE)

    def delete_link(self, context, host, interface):
        self.fanout_cast(
            context, self.make_msg(
                'delete_link',
                host=host, interface=interface, mac=None,
                switch=0, module=0, port=0),
            topic=TOPIC_APIC_SERVICE)
