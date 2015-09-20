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
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as nctx
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.plugins.ml2 import models
from opflexagent import constants as ofcst
from opflexagent import rpc as o_rpc
from oslo.config import cfg

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import apic_sync
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import config
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import rpc as t_rpc


LOG = log.getLogger(__name__)

_apic_driver_instance = None


class CidrOverlapsApicExternalSubnet(n_exc.BadRequest):
    message = _("Subnet CIDR %(subnet_cidr)s overlaps with "
                "APIC external network or host-pool subnet for %(ext_net)s.")


class APICMechanismDriver(mech_agent.AgentMechanismDriverBase):

    apic_manager = None

    @staticmethod
    def get_apic_manager(client=True):
        if APICMechanismDriver.apic_manager:
            return APICMechanismDriver.apic_manager
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
        APICMechanismDriver.apic_manager = apic_manager.APICManager(
            apic_model.ApicDbModel(), log, network_config, apic_config,
            keyclient_param, keystone_authtoken, apic_system_id)
        return APICMechanismDriver.apic_manager

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

    @staticmethod
    def get_driver_instance():
        return _apic_driver_instance

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
        APICMechanismDriver.get_apic_manager()
        self._setup_topology_rpc_listeners()
        self._setup_opflex_rpc_listeners()
        self._setup_rpc()
        self.name_mapper = self.apic_manager.apic_mapper
        self.synchronizer = None
        self.apic_manager.ensure_infra_created_on_apic()
        self.apic_manager.ensure_bgp_pod_policy_created_on_apic()
        self.nat_enabled = self.apic_manager.use_vmm
        self.per_tenant_context = cfg.CONF.ml2_cisco_apic.per_tenant_context
        self.enable_dhcp_opt = self.apic_manager.enable_optimized_dhcp
        global _apic_driver_instance
        _apic_driver_instance = self

    def _setup_opflex_rpc_listeners(self):
        self.opflex_endpoints = [o_rpc.GBPServerRpcCallback(self)]
        self.opflex_topic = o_rpc.TOPIC_OPFLEX
        self.opflex_conn = n_rpc.create_connection(new=True)
        self.opflex_conn.create_consumer(
            self.opflex_topic, self.opflex_endpoints, fanout=False)
        return self.opflex_conn.consume_in_threads()

    def _setup_topology_rpc_listeners(self):
        self.topology_endpoints = []
        if cfg.CONF.ml2_cisco_apic.integrated_topology_service:
            self.topology_endpoints.append(
                t_rpc.ApicTopologyRpcCallbackMechanism(
                    self.apic_manager, self))
        if self.topology_endpoints:
            LOG.debug("New RPC endpoints: %s", self.topology_endpoints)
            self.topology_topic = t_rpc.TOPIC_APIC_SERVICE
            self.topology_conn = n_rpc.create_connection(new=True)
            self.topology_conn.create_consumer(
                self.topology_topic, self.topology_endpoints, fanout=False)
            return self.topology_conn.consume_in_threads()

    def _setup_rpc(self):
        self.notifier = o_rpc.AgentNotifierApi(topics.AGENT)

    # RPC Method
    def get_gbp_details(self, context, **kwargs):
        core_plugin = manager.NeutronManager.get_plugin()
        port_id = core_plugin._device_to_port_id(
            kwargs['device'])
        port_context = core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return
        port = port_context.current

        context._plugin = core_plugin
        context._plugin_context = context

        network = core_plugin.get_network(context, port['network_id'])

        def is_port_promiscuous(port):
            return port['device_owner'] == n_constants.DEVICE_OWNER_DHCP

        segment = port_context.bound_segment or {}
        details = {'device': kwargs.get('device'),
                   'port_id': port_id,
                   'mac_address': port['mac_address'],
                   'app_profile_name': str(
                       self.apic_manager.app_profile_name),
                   'segment': segment,
                   'segmentation_id': segment.get('segmentation_id'),
                   'network_type': segment.get('network_type'),
                   'tenant_id': network['tenant_id'],
                   'host': port[portbindings.HOST_ID],
                   'ptg_tenant': self.apic_manager.apic.fvTenant.name(
                       str(self.name_mapper.tenant(
                           context, network['tenant_id']))),
                   'endpoint_group_name': str(
                       self.name_mapper.network(
                           context, port['network_id'])),
                   'promiscuous_mode': is_port_promiscuous(port)}
        if port['device_owner'].startswith('compute:') and port['device_id']:
            details['vm-name'] = port['device_id']
            self._add_ip_mapping_details(context, port, details)
        self._add_network_details(context, port, details)
        return details

    def _add_ip_mapping_details(self, context, port, details):
        """Add information about IP mapping for DNAT/SNAT."""
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
        core_plugin = context._plugin

        ext_nets = core_plugin.get_networks(
            context,
            filters={'name': self.apic_manager.ext_net_dict.keys()})
        ext_nets = {n['id']: n for n in ext_nets
                    if self._is_nat_enabled_on_ext_net(n)}
        fip_ext_nets = set()

        fips = l3plugin.get_floatingips(context,
                                        filters={'port_id': [port['id']]})
        for f in fips:
            net = ext_nets.get(f['floating_network_id'])
            if not net:
                continue
            l3out_name = self.name_mapper.network(context, net['id'])
            f['nat_epg_name'] = self._get_nat_epg_for_ext_net(l3out_name)
            f['nat_epg_tenant'] = apic_manager.TENANT_COMMON
            fip_ext_nets.add(net['id'])
        ipms = []
        for net_id, net in ext_nets.iteritems():
            if (net_id in fip_ext_nets or
                    not self._is_connected_to_ext_net(context, port, net)):
                continue
            l3out_name = self.name_mapper.network(context, net_id)
            ipms.append({'external_segment_name': net['name'],
                         'nat_epg_name':
                         self._get_nat_epg_for_ext_net(l3out_name),
                         'nat_epg_tenant': apic_manager.TENANT_COMMON})
        details['floating_ip'] = fips
        details['ip_mapping'] = ipms

    def _is_connected_to_ext_net(self, context, port, ext_net):
        # Return True is there a router between the external-network
        # and any subnet in which the port has an IP-address.
        core_plugin = context._plugin
        port_sn = self._get_port_subnets(port)
        router_gw_ports = core_plugin.get_ports(
            context,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_GW],
                     'network_id': [ext_net['id']]})
        router_sn = self._get_router_interface_subnets(
            context, [x['device_id'] for x in router_gw_ports])
        return bool(port_sn & router_sn)

    def _add_network_details(self, context, port, details):
        details['allowed_address_pairs'] = port['allowed_address_pairs']
        details['enable_dhcp_optimization'] = self.enable_dhcp_opt
        details['subnets'] = context._plugin.get_subnets(
            context,
            filters={'id': [ip['subnet_id'] for ip in port['fixed_ips']]})

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
        tenant_id = context.network.current['tenant_id']
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
        router_info = self.apic_manager.ext_net_dict.get(network['name'])

        if router_id and router_info:
            external_epg = apic_manager.EXT_EPG
            with self.apic_manager.apic.transaction() as trs:
                # Get/Create contract
                arouter_id = self.name_mapper.router(context, router_id)
                cid = self.apic_manager.get_router_contract(arouter_id)
                # Ensure that the external ctx exists
                self.apic_manager.ensure_context_enforced()
                # Create External Routed Network and configure it
                if not router_info.get('preexisting'):
                    address = router_info['cidr_exposed']
                    next_hop = router_info['gateway_ip']
                    encap = router_info.get('encap')  # No encap if None
                    switch = router_info['switch']
                    module, sport = router_info['port'].split('/')
                    anetwork_id = self.name_mapper.network(context,
                                                           network['id'])
                    self.apic_manager.ensure_external_routed_network_created(
                        anetwork_id, transaction=trs)
                    self.apic_manager.ensure_logical_node_profile_created(
                        anetwork_id, switch, module, sport, encap,
                        address, transaction=trs)
                    self.apic_manager.ensure_static_route_created(
                        anetwork_id, switch, next_hop, transaction=trs)
                    self.apic_manager.ensure_external_epg_created(
                        anetwork_id, external_epg=external_epg,
                        transaction=trs)
                elif 'external_epg' in router_info:
                    anetwork_id = self.name_mapper.pre_existing(
                        context, network['name'])
                    external_epg = self.name_mapper.pre_existing(
                        context, router_info['external_epg'])

            ok = False
            if self._is_nat_enabled_on_ext_net(network):
                ok = self._create_nat_epg_for_ext_net(
                    anetwork_id, external_epg, cid, router_info)
            if not ok:      # fallback to non-NAT config
                with self.apic_manager.apic.transaction() as trs:
                    self.apic_manager.ensure_external_epg_consumed_contract(
                        anetwork_id, cid, external_epg=external_epg,
                        transaction=trs)
                    self.apic_manager.ensure_external_epg_provided_contract(
                        anetwork_id, cid, external_epg=external_epg,
                        transaction=trs)

    def _perform_port_operations(self, context):
        # Get port
        port = context.current
        if port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._perform_gw_port_operations(context, port)
        elif self._is_port_bound(port) and not self._is_apic_network_type(
                context):
            self._perform_path_port_operations(context, port)
        if self._is_nat_enabled_on_ext_net(context.network.current):
            self._notify_ports_due_to_router_update(port)

    def _delete_contract(self, context):
        port = context.current
        network_id = self.name_mapper.network(
            context, context.network.current['id'])
        arouter_id = self.name_mapper.router(context,
                                             port.get('device_id'))
        router_info = self.apic_manager.ext_net_dict.get(
            context.network.current['name'], {})

        if router_info:
            if 'external_epg' not in router_info:
                self.apic_manager.delete_external_epg_contract(arouter_id,
                                                               network_id)
            else:
                anetwork_id = self.name_mapper.pre_existing(
                    context, context.network.current['name'])
                external_epg = self.name_mapper.pre_existing(
                    context, router_info['external_epg'])
                self.apic_manager.delete_external_epg_contract(
                    arouter_id, anetwork_id, external_epg=external_epg)

    def _get_active_path_count(self, context, host=None):
        return context._plugin_context.session.query(
            models.PortBinding).filter_by(
                host=host or context.host,
                segment=context._binding.segment).count()

    @lockutils.synchronized('apic-portlock')
    def _delete_port_path(self, context, atenant_id, anetwork_id, host=None):
        if not self._get_active_path_count(context):
            self.apic_manager.ensure_path_deleted_for_port(
                atenant_id, anetwork_id,
                host or context.host)

    def _delete_path_if_last(self, context, host=None):
        if not self._get_active_path_count(context):
            tenant_id = context.network.current['tenant_id']
            atenant_id = self.name_mapper.tenant(context, tenant_id)
            network_id = context.network.current['id']
            anetwork_id = self.name_mapper.network(context, network_id)
            self._delete_port_path(context, atenant_id, anetwork_id, host=host)

    def _get_subnet_info(self, context, subnet):
        if subnet['gateway_ip']:
            network_id = subnet['network_id']
            network = context._plugin.get_network(context._plugin_context,
                                                  network_id)
            tenant_id = network['tenant_id']
            cidr = netaddr.IPNetwork(subnet['cidr'])
            gateway_ip = '%s/%s' % (subnet['gateway_ip'],
                                    str(cidr.prefixlen))
            if not network.get('router:external'):
                # Convert to APIC IDs
                tenant_id = self.name_mapper.tenant(context, tenant_id)
                bd_id = self.name_mapper.network(context, network_id)
                return tenant_id, bd_id, gateway_ip
            elif self._is_nat_enabled_on_ext_net(network):
                l3out_name = self.name_mapper.network(context,
                                                      network['id'])
                tenant_id = apic_manager.TENANT_COMMON
                bd_id = self._get_nat_bd_for_ext_net(l3out_name)
                return tenant_id, bd_id, gateway_ip

    @sync_init
    def create_port_postcommit(self, context):
        self._perform_port_operations(context)

    @sync_init
    def update_port_postcommit(self, context):
        if (not self._is_apic_network_type(context) and
                context.original_host and (context.original_host !=
                                           context.host)):
            # The VM was migrated
            self._delete_path_if_last(context, host=context.original_host)
        self._perform_port_operations(context)

    def delete_port_postcommit(self, context):
        port = context.current
        # Check if a compute port
        if (not self._is_apic_network_type(context) and context.host and
                context._binding.segment):
            self._delete_path_if_last(context)
        if port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._delete_contract(context)
        if self._is_nat_enabled_on_ext_net(context.network.current):
            self._notify_ports_due_to_router_update(port)

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
                router_info = self.apic_manager.ext_net_dict.get(network_name)
                if not router_info.get('preexisting'):
                    self.apic_manager.delete_external_routed_network(
                        network_id)
                    l3out_name = network_id
                else:
                    l3out_name = self.name_mapper.pre_existing(
                        context, network_name)
                if self._is_nat_enabled_on_ext_net(context.current):
                    self._delete_nat_epg_for_ext_net(l3out_name)

    def create_subnet_precommit(self, context):
        subnet = context.current
        network = context._plugin.get_network(context._plugin_context,
                                              subnet['network_id'])
        if network.get('router:external'):
            ext_info = self.apic_manager.ext_net_dict.get(network['name'])
            if ext_info:
                cidr = netaddr.IPSet([subnet['cidr']])
                exposed = netaddr.IPSet([])
                if ext_info.get('cidr_exposed'):
                    exposed.add(ext_info['cidr_exposed'])
                if ext_info.get('host_pool_cidr'):
                    exposed.add(ext_info['host_pool_cidr'])
                # Subnet cannot overlap with APIC external network
                if exposed & cidr:
                    raise CidrOverlapsApicExternalSubnet(
                        subnet_cidr=cidr, ext_net=network['name'])

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
        # Notify ports that are in the subnet
        network = context._plugin.get_network(
            context._plugin_context,
            context.current['network_id'])
        if self._is_apic_network(network):
            ports = context._plugin.get_ports(
                context._plugin_context,
                filters={'network_id': [network['id']]})
            for p in ports:
                port_sn_ids = self._get_port_subnets(p)
                if (context.current['id'] in port_sn_ids and
                        self._is_port_bound(p)):
                    self.notifier.port_update(context._plugin_context, p)

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
        return self._is_apic_network(port_context.network.current)

    def _is_apic_network(self, network):
        return network['provider:network_type'] == ofcst.TYPE_OPFLEX

    def notify_port_update(self, port_id, context=None):
        context = context or nctx.get_admin_context()
        core_plugin = manager.NeutronManager.get_plugin()
        try:
            port = core_plugin.get_port(context, port_id)
            if self._is_port_bound(port):
                self.notifier.port_update(context, port)
        except n_exc.PortNotFound:
            # Notification not needed
            pass

    def _get_nat_epg_for_ext_net(self, l3out_name):
        return "NAT-epg-%s" % l3out_name

    def _get_nat_bd_for_ext_net(self, l3out_name):
        return "NAT-bd-%s" % l3out_name

    def _get_nat_vrf_for_ext_net(self, l3out_name):
        return "NAT-vrf-%s" % l3out_name

    def _get_shadow_name_for_nat(self, name):
        return "Shd-%s" % name

    def _create_nat_epg_for_ext_net(self, l3out_name, ext_epg_name,
                                    router_contract, ext_info):
        tenant_name = apic_manager.TENANT_COMMON
        nat_vrf_name = self._get_nat_vrf_for_ext_net(l3out_name)
        nat_bd_name = self._get_nat_bd_for_ext_net(l3out_name)
        nat_epg_name = self._get_nat_epg_for_ext_net(l3out_name)
        nat_contract = "NAT-allow-all"
        shadow_ext_epg = self._get_shadow_name_for_nat(ext_epg_name)
        shadow_l3out = self._get_shadow_name_for_nat(l3out_name)
        try:
            with self.apic_manager.apic.transaction(None) as trs:
                # create NAT EPG and allow-everything contract
                self.apic_manager.ensure_nat_epg_contract_created(
                    tenant_name, nat_epg_name, nat_bd_name,
                    nat_vrf_name, nat_contract,
                    transaction=trs)
                # make external EPG use NAT contract
                self.apic_manager.ensure_external_epg_consumed_contract(
                    l3out_name, nat_contract, external_epg=ext_epg_name,
                    transaction=trs)
                self.apic_manager.ensure_external_epg_provided_contract(
                    l3out_name, nat_contract, external_epg=ext_epg_name,
                    transaction=trs)
                # make L3-out use NAT-vrf
                self.apic_manager.ensure_external_routed_network_created(
                    l3out_name, context=nat_vrf_name,
                    transaction=trs)

                # create shadow L3-out and shadow external-epg
                self.apic_manager.ensure_external_routed_network_created(
                    shadow_l3out, transaction=trs)
                self.apic_manager.ensure_external_epg_created(
                    shadow_l3out, external_epg=shadow_ext_epg,
                    transaction=trs)
                # make them use router-contract
                self.apic_manager.ensure_external_epg_consumed_contract(
                    shadow_l3out, router_contract,
                    external_epg=shadow_ext_epg, transaction=trs)
                self.apic_manager.ensure_external_epg_provided_contract(
                    shadow_l3out, router_contract,
                    external_epg=shadow_ext_epg, transaction=trs)

                # link up shadow external-EPG to NAT EPG
                self.apic_manager.associate_external_epg_to_nat_epg(
                    tenant_name, shadow_l3out, shadow_ext_epg,
                    nat_epg_name, target_owner=tenant_name,
                    transaction=trs)

                # create any required subnets
                gw, plen = ext_info.get('host_pool_cidr', '/').split('/', 1)
                if gw and plen:
                    self.apic_manager.ensure_subnet_created_on_apic(
                        tenant_name, nat_bd_name, gw + '/' + plen,
                        transaction=trs)
            return True
        except Exception as e:
            LOG.info(_("Unable to create NAT EPG: %s"), e)
            return False

    def _delete_nat_epg_for_ext_net(self, l3out_name):
        tenant_name = apic_manager.TENANT_COMMON
        with self.apic_manager.apic.transaction(None) as trs:
            # delete shadow L3-out and shadow external-EPG
            shadow_l3out = self._get_shadow_name_for_nat(l3out_name)
            self.apic_manager.delete_external_routed_network(
                shadow_l3out, tenant_name, transaction=trs)
            # delete NAT epg
            self.apic_manager.ensure_nat_epg_deleted(
                tenant_name,
                self._get_nat_epg_for_ext_net(l3out_name),
                self._get_nat_bd_for_ext_net(l3out_name),
                self._get_nat_vrf_for_ext_net(l3out_name),
                transaction=trs)

    def _get_router_interface_subnets(self, context, router_ids):
        core_plugin = manager.NeutronManager.get_plugin()
        router_intf_ports = core_plugin.get_ports(
            context,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                     'device_id': router_ids})
        router_sn = set([y['subnet_id']
                         for x in router_intf_ports
                         for y in x.get('fixed_ips', [])])
        return router_sn

    def _get_port_subnets(self, port):
        return set([x['subnet_id']
                    for x in port.get('fixed_ips', [])])

    def _notify_ports_due_to_router_update(self, router_port):
        # Find ports whose DNAT/SNAT info may be affected due to change
        # in a router's connectivity to external/tenant network.
        if not self.nat_enabled:
            return
        dev_owner = router_port['device_owner']
        admin_ctx = nctx.get_admin_context()
        if dev_owner == n_constants.DEVICE_OWNER_ROUTER_INTF:
            subnet_ids = self._get_port_subnets(router_port)
        elif dev_owner == n_constants.DEVICE_OWNER_ROUTER_GW:
            subnet_ids = self._get_router_interface_subnets(
                admin_ctx, [router_port['device_id']])
        else:
            return
        core_plugin = manager.NeutronManager.get_plugin()
        subnets = core_plugin.get_subnets(
            admin_ctx, filters={'id': list(subnet_ids)})
        nets = set([x['network_id'] for x in subnets])
        ports = core_plugin.get_ports(
            admin_ctx, filters={'network_id': list(nets)})
        for p in ports:
            port_sn_ids = self._get_port_subnets(p)
            if (subnet_ids & port_sn_ids) and self._is_port_bound(p):
                self.notifier.port_update(admin_ctx, p)

    def _is_nat_enabled_on_ext_net(self, network):
        ext_info = self.apic_manager.ext_net_dict.get(network['name'])
        return (self.nat_enabled and ext_info and
                ext_info.get('enable_nat', True))
