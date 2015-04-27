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

from apicapi import apic_manager
from keystoneclient.v2_0 import client as keyclient
import netaddr
from neutron.agent import securitygroups_rpc
from neutron.common import constants as n_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2 import models
from opflexagent import constants as ofcst
from opflexagent import rpc
from oslo.config import cfg

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import apic_sync
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import config


LOG = log.getLogger(__name__)


class APICMechanismDriver(mech_agent.AgentMechanismDriverBase):

    @staticmethod
    def get_apic_manager(client=True):
        apic_config = cfg.CONF.ml2_cisco_apic
        network_config = {
            'vlan_ranges': cfg.CONF.ml2_type_vlan.network_vlan_ranges,
            'switch_dict': config.create_switch_dictionary(),
            'vpc_dict': config.create_vpc_dictionary(),
            'external_network_dict':
            config.create_external_network_dictionary(),
        }
        apic_system_id = cfg.CONF.apic_system_id
        keyclient_param = keyclient if client else None
        keystone_authtoken = cfg.CONF.keystone_authtoken if client else None
        return apic_manager.APICManager(apic_model.ApicDbModel(), log,
                                        network_config, apic_config,
                                        keyclient_param, keystone_authtoken,
                                        apic_system_id)

    @staticmethod
    def get_base_synchronizer(inst):
        apic_config = cfg.CONF.ml2_cisco_apic
        return apic_sync.ApicBaseSynchronizer(inst,
                                              apic_config.apic_sync_interval)

    @staticmethod
    def get_router_synchronizer(inst):
        apic_config = cfg.CONF.ml2_cisco_apic
        return apic_sync.ApicRouterSynchronizer(inst,
                                                apic_config.apic_sync_interval)

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                            portbindings.OVS_HYBRID_PLUG: sg_enabled}
        self.vif_type = portbindings.VIF_TYPE_OVS
        super(APICMechanismDriver, self).__init__(
            ofcst.AGENT_TYPE_OPFLEX_OVS)

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            context.set_binding(
                segment[api.ID], self.vif_type, self.vif_details)
            return True
        else:
            return False

    def check_segment_for_agent(self, segment, agent):
        network_type = segment[api.NETWORK_TYPE]
        if network_type == ofcst.TYPE_OPFLEX:
            opflex_mappings = agent['configurations'].get('opflex_networks',
                                                          [])
            LOG.debug(_("Checking segment: %(segment)s "
                        "for physical network: %(mappings)s "),
                      {'segment': segment, 'mappings': opflex_mappings})
            return (opflex_mappings is None or
                    segment[api.PHYSICAL_NETWORK] in opflex_mappings)
        else:
            mappings = agent['configurations'].get('bridge_mappings', {})
            tunnel_types = agent['configurations'].get('tunnel_types', [])
            LOG.debug(_("Checking segment: %(segment)s "
                        "for mappings: %(mappings)s "
                        "with tunnel_types: %(tunnel_types)s"),
                      {'segment': segment, 'mappings': mappings,
                       'tunnel_types': tunnel_types})
            if network_type == 'local':
                return True
            elif network_type in tunnel_types:
                return True
            elif network_type in ['flat', 'vlan']:
                return segment[api.PHYSICAL_NETWORK] in mappings
            else:
                return False

    def initialize(self):
        # initialize apic
        self.apic_manager = APICMechanismDriver.get_apic_manager()
        self._setup_rpc_listeners()
        self._setup_rpc()
        self.name_mapper = self.apic_manager.apic_mapper
        self.synchronizer = None
        self.apic_manager.ensure_infra_created_on_apic()
        self.apic_manager.ensure_bgp_pod_policy_created_on_apic()

    def _setup_rpc_listeners(self):
        self.endpoints = [rpc.GBPServerRpcCallback(self)]
        self.topic = rpc.TOPIC_OPFLEX
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        return self.conn.consume_in_threads()

    def _setup_rpc(self):
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)

    # RPC Method
    def get_gbp_details(self, context, **kwargs):
        _core_plugin = manager.NeutronManager.get_plugin()
        port_id = _core_plugin._device_to_port_id(
            kwargs['device'])
        port_context = _core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return
        port = port_context.current

        context._plugin = _core_plugin
        context._plugin_context = context

        def is_port_promiscuous(port):
            return port['device_owner'] == n_constants.DEVICE_OWNER_DHCP

        segment = port_context.bound_segment or {}
        return {'device': kwargs.get('device'),
                'port_id': port_id,
                'mac_address': port['mac_address'],
                'segment': segment,
                'segmentation_id': segment.get('segmentation_id'),
                'network_type': segment.get('network_type'),
                'tenant_id': port['tenant_id'],
                'host': port[portbindings.HOST_ID],
                'ptg_tenant': str(self.name_mapper.tenant(
                    context, port['tenant_id'])),
                'endpoint_group_name': str(
                    self.name_mapper.network(
                        context, port['network_id'])),
                'promiscuous_mode': is_port_promiscuous(port)}

    def sync_init(f):
        def inner(inst, *args, **kwargs):
            if not inst.synchronizer:
                inst.synchronizer = (
                    APICMechanismDriver.get_base_synchronizer(inst))
                inst.synchronizer.sync_base()
            return f(inst, *args, **kwargs)
        return inner

    @lockutils.synchronized('apic-portlock')
    def _perform_path_port_operations(self, context, port):
        # Get network
        network_id = context.network.current['id']
        anetwork_id = self.name_mapper.network(context, network_id)
        # Get tenant details from port context
        tenant_id = context.current['tenant_id']
        tenant_id = self.name_mapper.tenant(context, tenant_id)

        # Get segmentation id
        if not context.bound_segment:
            LOG.debug("Port %s is not bound to a segment", port)
            return
        seg = None
        if (context.bound_segment.get(api.NETWORK_TYPE)
                in [constants.TYPE_VLAN]):
            seg = context.bound_segment.get(api.SEGMENTATION_ID)
        # hosts on which this vlan is provisioned
        host = context.host
        # Create a static path attachment for the host/epg/switchport combo
        with self.apic_manager.apic.transaction() as trs:
            self.apic_manager.ensure_path_created_for_port(
                tenant_id, anetwork_id, host, seg, transaction=trs)

    def _perform_gw_port_operations(self, context, port):
        router_id = port.get('device_id')
        network = context.network.current
        anetwork_id = self.name_mapper.network(context, network['id'])
        router_info = self.apic_manager.ext_net_dict.get(network['name'])

        if router_id and router_info:
            address = router_info['cidr_exposed']
            next_hop = router_info['gateway_ip']
            encap = router_info.get('encap')  # No encap if None
            switch = router_info['switch']
            module, sport = router_info['port'].split('/')
            with self.apic_manager.apic.transaction() as trs:
                # Get/Create contract
                arouter_id = self.name_mapper.router(context, router_id)
                cid = self.apic_manager.get_router_contract(arouter_id)
                # Ensure that the external ctx exists
                self.apic_manager.ensure_context_enforced()
                # Create External Routed Network and configure it
                self.apic_manager.ensure_external_routed_network_created(
                    anetwork_id, transaction=trs)
                self.apic_manager.ensure_logical_node_profile_created(
                    anetwork_id, switch, module, sport, encap,
                    address, transaction=trs)
                self.apic_manager.ensure_static_route_created(
                    anetwork_id, switch, next_hop, transaction=trs)
                self.apic_manager.ensure_external_epg_created(
                    anetwork_id, transaction=trs)
                self.apic_manager.ensure_external_epg_consumed_contract(
                    anetwork_id, cid, transaction=trs)
                self.apic_manager.ensure_external_epg_provided_contract(
                    anetwork_id, cid, transaction=trs)

    def _perform_port_operations(self, context):
        # Get port
        port = context.current
        # Check if a compute port
        if self._is_port_bound(port) and not self._is_apic_network_type(
                context):
            self._perform_path_port_operations(context, port)
        if port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._perform_gw_port_operations(context, port)

    def _delete_contract(self, context):
        port = context.current
        network_id = self.name_mapper.network(
            context, context.network.current['id'])
        arouter_id = self.name_mapper.router(context,
                                             port.get('device_id'))
        self.apic_manager.delete_external_epg_contract(arouter_id,
                                                       network_id)

    def _get_active_path_count(self, context):
        return context._plugin_context.session.query(
            models.PortBinding).filter_by(
                host=context.host, segment=context._binding.segment).count()

    @lockutils.synchronized('apic-portlock')
    def _delete_port_path(self, context, atenant_id, anetwork_id):
        if not self._get_active_path_count(context):
            self.apic_manager.ensure_path_deleted_for_port(
                atenant_id, anetwork_id,
                context.host)

    def _delete_path_if_last(self, context):
        if not self._get_active_path_count(context):
            tenant_id = context.current['tenant_id']
            atenant_id = self.name_mapper.tenant(context, tenant_id)
            network_id = context.network.current['id']
            anetwork_id = self.name_mapper.network(context, network_id)
            self._delete_port_path(context, atenant_id, anetwork_id)

    def _get_subnet_info(self, context, subnet):
        if subnet['gateway_ip']:
            tenant_id = subnet['tenant_id']
            network_id = subnet['network_id']
            network = context._plugin.get_network(context._plugin_context,
                                                  network_id)
            if not network.get('router:external'):
                cidr = netaddr.IPNetwork(subnet['cidr'])
                gateway_ip = '%s/%s' % (subnet['gateway_ip'],
                                        str(cidr.prefixlen))

                # Convert to APIC IDs
                tenant_id = self.name_mapper.tenant(context, tenant_id)
                network_id = self.name_mapper.network(context, network_id)
                return tenant_id, network_id, gateway_ip

    @sync_init
    def create_port_postcommit(self, context):
        self._perform_port_operations(context)

    @sync_init
    def update_port_postcommit(self, context):
        self._perform_port_operations(context)

    def delete_port_postcommit(self, context):
        port = context.current
        # Check if a compute port
        if (not self._is_apic_network_type(context) and context.host and
                context._binding.segment):
            self._delete_path_if_last(context)
        if port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._delete_contract(context)

    @sync_init
    def create_network_postcommit(self, context):
        if not context.current.get('router:external'):
            tenant_id = context.current['tenant_id']
            network_id = context.current['id']

            # Convert to APIC IDs
            tenant_id = self.name_mapper.tenant(context, tenant_id)
            network_id = self.name_mapper.network(context, network_id)

            # Create BD and EPG for this network
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.ensure_bd_created_on_apic(tenant_id,
                                                            network_id,
                                                            transaction=trs)
                self.apic_manager.ensure_epg_created(
                    tenant_id, network_id, transaction=trs)

    @sync_init
    def update_network_postcommit(self, context):
        super(APICMechanismDriver, self).update_network_postcommit(context)

    def delete_network_postcommit(self, context):
        if not context.current.get('router:external'):
            tenant_id = context.current['tenant_id']
            network_id = context.current['id']

            # Convert to APIC IDs
            tenant_id = self.name_mapper.tenant(context, tenant_id)
            network_id = self.name_mapper.network(context, network_id)

            # Delete BD and EPG for this network
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.delete_epg_for_network(tenant_id, network_id,
                                                         transaction=trs)
                self.apic_manager.delete_bd_on_apic(tenant_id, network_id,
                                                    transaction=trs)
        else:
            network_name = context.current['name']
            if self.apic_manager.ext_net_dict.get(network_name):
                network_id = self.name_mapper.network(context,
                                                      context.current['id'])
                self.apic_manager.delete_external_routed_network(network_id)

    @sync_init
    def create_subnet_postcommit(self, context):
        info = self._get_subnet_info(context, context.current)
        if info:
            tenant_id, network_id, gateway_ip = info
            # Create subnet on BD
            self.apic_manager.ensure_subnet_created_on_apic(
                tenant_id, network_id, gateway_ip)

    @sync_init
    def update_subnet_postcommit(self, context):
        if context.current['gateway_ip'] != context.original['gateway_ip']:
            with self.apic_manager.apic.transaction() as trs:
                info = self._get_subnet_info(context, context.original)
                if info:
                    tenant_id, network_id, gateway_ip = info
                    # Delete subnet
                    self.apic_manager.ensure_subnet_deleted_on_apic(
                        tenant_id, network_id, gateway_ip, transaction=trs)
                info = self._get_subnet_info(context, context.current)
                if info:
                    tenant_id, network_id, gateway_ip = info
                    # Create subnet
                    self.apic_manager.ensure_subnet_created_on_apic(
                        tenant_id, network_id, gateway_ip, transaction=trs)

    def delete_subnet_postcommit(self, context):
        info = self._get_subnet_info(context, context.current)
        if info:
            tenant_id, network_id, gateway_ip = info
            self.apic_manager.ensure_subnet_deleted_on_apic(
                tenant_id, network_id, gateway_ip)

    def _is_port_bound(self, port):
        return port[portbindings.VIF_TYPE] not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _is_apic_network_type(self, port_context):
        return (port_context.network.current['provider:network_type'] ==
                ofcst.TYPE_OPFLEX)
