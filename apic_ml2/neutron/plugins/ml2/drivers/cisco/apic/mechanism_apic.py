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

import copy

from apicapi import apic_manager
from keystoneclient.v2_0 import client as keyclient
import netaddr
from neutron.agent.linux import dhcp
from neutron.agent import securitygroups_rpc
from neutron.api.v2 import attributes
from neutron.common import constants as n_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as nctx
from neutron.db import db_base_plugin_v2 as n_db
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.plugins.ml2 import models
from opflexagent import constants as ofcst
from opflexagent import rpc as o_rpc
from oslo.config import cfg

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import apic_sync
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import attestation
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import config
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import constants as acst
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import exceptions as aexc
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import nova_client
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import rpc as t_rpc


LOG = log.getLogger(__name__)
n_db.AUTO_DELETE_PORT_OWNERS.append(acst.DEVICE_OWNER_SNAT_PORT)
_apic_driver_instance = None


# REVISIT(ivar): Since our database class is in Neutron, we need to monkey
# patch this class in order to add required features. This will have to be
# reverted in Liberty where we have control over out Database
def get_filtered_apic_names(self, neutron_id=None, neutron_type=None,
                            apic_name=None):
    query = self.session.query(apic_model.ApicName.apic_name)
    if neutron_id:
        query = query.filter_by(neutron_id=neutron_id)
    if neutron_type:
        query = query.filter_by(neutron_type=neutron_type)
    if apic_name:
        query = query.filter_by(apic_name=apic_name)
    return query.all()

apic_model.ApicDbModel.get_filtered_apic_names = get_filtered_apic_names


class CidrOverlapsApicExternalSubnet(n_exc.BadRequest):
    message = _("Subnet CIDR %(subnet_cidr)s overlaps with "
                "APIC external network or host-pool subnet for %(ext_net)s.")


class WouldRequireNAT(n_exc.BadRequest):
    message = _("Setting gateway on router would require address translation, "
                "but NAT-ing is disabled for external network %(ext_net)s.")


class NameMapper(object):
    scope_with_tenant_name = set([
        'network',
        'router'
    ])

    easy_mapping = {'bridge_domain': 'network',
                    'endpoint_group': 'network',
                    'l3_out': 'network',
                    }

    def __init__(self, aci_mapper):
        self.aci_mapper = aci_mapper
        self.single_tenant_mode = cfg.CONF.ml2_cisco_apic.single_tenant_mode

    def __getattr__(self, item):
        def name_wrapper(*args, **kwargs):
            new_item = self.easy_mapping.get(item, item)
            if self.single_tenant_mode:
                if new_item in self.scope_with_tenant_name:
                    tenant = kwargs.get('openstack_owner')
                    current_scope = kwargs.get('prefix', '')
                    current_scope = '-' + current_scope
                    if tenant:
                        tenant = self.aci_mapper.tenant(None, tenant)
                        try:
                            kwargs['prefix'] = str(tenant)[
                                :str(tenant).rindex('_')] + current_scope
                        except ValueError:
                            kwargs['prefix'] = str(tenant) + current_scope
            kwargs.pop('openstack_owner', None)
            return getattr(self.aci_mapper, new_item)(*args, **kwargs)
        return name_wrapper


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
        if cfg.CONF.ml2_cisco_apic.single_tenant_mode:
            # Force scope names to False
            apic_config.scope_names = False
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

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._l3_plugin = plugins.get('L3_ROUTER_NAT')
        return self._l3_plugin

    @property
    def db_plugin(self):
        if not self._db_plugin:
            self._db_plugin = n_db.NeutronDbPluginV2()
        return self._db_plugin

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
        self.name_mapper = NameMapper(self.apic_manager.apic_mapper)
        self.synchronizer = None
        self.apic_manager.ensure_infra_created_on_apic()
        self.apic_manager.ensure_bgp_pod_policy_created_on_apic()
        self.nat_enabled = self.apic_manager.use_vmm
        self.per_tenant_context = cfg.CONF.ml2_cisco_apic.per_tenant_context
        self.enable_dhcp_opt = self.apic_manager.enable_optimized_dhcp
        self.enable_metadata_opt = self.apic_manager.enable_optimized_metadata
        self.apic_system_id = cfg.CONF.apic_system_id
        self.single_tenant_mode = cfg.CONF.ml2_cisco_apic.single_tenant_mode
        global _apic_driver_instance
        _apic_driver_instance = self
        self._l3_plugin = None
        self._db_plugin = None
        self.attestator = attestation.EndpointAttestator(self.apic_manager)

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
    def get_vrf_details(self, context, **kwargs):
        core_plugin = manager.NeutronManager.get_plugin()
        vrf_id = kwargs['vrf_id']
        # For the APIC ML2 driver, VRF ID is a tenant_id, need to return all
        # the subnets for this tenant
        ctx = nctx.get_admin_context()
        if self.per_tenant_context:
            subnets = core_plugin.get_subnets(ctx, {'tenant_id': [vrf_id]})
        else:
            # need to retrieve the whole world
            subnets = core_plugin.get_subnets(ctx)

        # Exclude external subnets
        networks = core_plugin.get_networks(
            ctx, {'id': set([x['network_id'] for x in subnets])})
        external_networks = [x['id'] for x in networks if
                             x.get('router:external')]
        subnets = [x for x in subnets if
                   x['network_id'] not in external_networks]

        if subnets:
            subnets = netaddr.IPSet([x['cidr'] for x in subnets])
            subnets.compact()
            subnets = [str(x) for x in subnets.iter_cidrs()]

        vrf = self._get_tenant_vrf(vrf_id)
        details = {
            'l3_policy_id': vrf_id,
            'vrf_tenant': self.apic_manager.apic.fvTenant.name(
                vrf['aci_tenant']),
            'vrf_name': self.apic_manager.apic.fvCtx.name(
                str(vrf['aci_name'])),
            'vrf_subnets': subnets
        }
        return details

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
                       self._get_network_app_profile(network)),
                   'segment': segment,
                   'segmentation_id': segment.get('segmentation_id'),
                   'network_type': segment.get('network_type'),
                   'tenant_id': network['tenant_id'],
                   'l3_policy_id': network['tenant_id'],
                   'host': port[portbindings.HOST_ID],
                   'ptg_tenant': self.apic_manager.apic.fvTenant.name(
                       str(self._get_network_aci_tenant(network))),
                   'endpoint_group_name': str(
                       self.name_mapper.endpoint_group(
                           context, port['network_id'])),
                   'promiscuous_mode': is_port_promiscuous(port)}
        if port['device_owner'].startswith('compute:') and port['device_id']:
            vm = nova_client.NovaClient().get_server(port['device_id'])
            details['vm-name'] = vm.name if vm else port['device_id']
        self._add_ip_mapping_details(context, port, details)
        self._add_network_details(context, port, details)
        if self._is_nat_enabled_on_ext_net(network):
            # PTG name is different
            details['endpoint_group_name'] = self._get_ext_epg_for_ext_net(
                details['endpoint_group_name'])
        details.update(
            self.get_vrf_details(context, vrf_id=network['tenant_id']))
        try:
            details['attestation'] = self.attestator.get_endpoint_attestation(
                port_id, details['host'], details['endpoint_group_name'],
                details['ptg_tenant'])
        except AttributeError:
            pass    # EP attestation not supported by APICAPI
        return details

    def _add_port_binding(self, session, port_id, host):
        with session.begin(subtransactions=True):
            record = models.PortBinding(port_id=port_id,
                                        host=host,
                                        vif_type=portbindings.VIF_TYPE_UNBOUND)
            session.add(record)
            return record

    def _allocate_snat_ip_for_host_and_ext_net(self, context, host, network):
        """Allocate SNAT IP for a host for an external network."""
        snat_net_name = self._get_snat_db_network_name(network)
        snat_networks = self.db_plugin.get_networks(
            context, filters={'name': [snat_net_name]})
        if not snat_networks or len(snat_networks) > 1:
            LOG.info(_("Unique SNAT network not found for external network "
                       "%(net_id)s. SNAT will not function on host %(host)s "
                       "for this external network"),
                     {'net_id': network['id'], 'host': host})
            return {}

        snat_network_id = snat_networks[0]['id']
        snat_network_tenant_id = snat_networks[0]['tenant_id']
        snat_subnets = self.db_plugin.get_subnets(
            context, filters={'name': [acst.HOST_SNAT_POOL],
                              'network_id': [snat_network_id]})
        if not snat_subnets:
            LOG.info(_("Subnet for host-SNAT-pool could not be found "
                       "for SNAT network %(net_id)s. SNAT will not "
                       "function for external network %(ext_id)s"),
                     {'net_id': snat_network_id, 'ext_id': network['id']})
            return {}

        snat_ports = self.db_plugin.get_ports(
            context, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                              'network_id': [snat_network_id],
                              'device_id': [host]})
        snat_ip = None
        if not snat_ports:
            # Note that the following port is created for only getting
            # an IP assignment in the subnet used for SNAT IPs.
            # The host for which this SNAT IP is allocated is used
            # coded in the device_id.
            attrs = {'port': {'device_id': host,
                              'device_owner': acst.DEVICE_OWNER_SNAT_PORT,
                              'tenant_id': snat_network_tenant_id,
                              'name': acst.HOST_SNAT_POOL_PORT,
                              'network_id': snat_network_id,
                              'mac_address': attributes.ATTR_NOT_SPECIFIED,
                              'fixed_ips': [{'subnet_id':
                                             snat_subnets[0]['id']}],
                              'admin_state_up': False}}
            port = self.db_plugin.create_port(context, attrs)
            if port and port['fixed_ips'][0]:
                # The auto deletion of port logic looks for the port binding
                # hence we populate the port binding info here
                self._add_port_binding(context.session, port['id'], host)
                snat_ip = port['fixed_ips'][0]['ip_address']
            else:
                LOG.warning(_("SNAT-port creation failed for subnet "
                              "%(subnet_id)s on SNAT network "
                              "%(net_id)s. SNAT will not function on"
                              "host %(host)s for external network %(ext_id)s"),
                            {'subnet_id': snat_subnets[0]['id'],
                             'net_id': snat_network_id, 'host': host,
                             'ext_id': network['id']})
                return {}
        else:
            snat_ip = snat_ports[0]['fixed_ips'][0]['ip_address']

        return {'external_segment_name': network['name'],
                'host_snat_ip': snat_ip,
                'gateway_ip': snat_subnets[0]['gateway_ip'],
                'prefixlen':
                netaddr.IPNetwork(snat_subnets[0]['cidr']).prefixlen}

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
            network = core_plugin.get_network(context._plugin_context,
                                              net['id'])
            epg_tenant = self.apic_manager.apic.fvTenant.name(
                str(self._get_network_aci_tenant(network)))
            l3out_name = self.name_mapper.l3_out(
                context, net['id'], openstack_owner=net['tenant_id'])
            f['nat_epg_name'] = self._get_ext_epg_for_ext_net(l3out_name)
            f['nat_epg_app_profile'] = str(
                self._get_network_app_profile(network))
            f['nat_epg_tenant'] = epg_tenant
            fip_ext_nets.add(net['id'])
        ipms = []
        # Populate host_snat_ips in the format:
        # [ {'external_segment_name': <ext_segment_name1>,
        #    'host_snat_ip': <ip_addr>, 'gateway_ip': <gateway_ip>,
        #    'prefixlen': <prefix_length_of_host_snat_pool_subnet>},
        #    {..}, ... ]
        host_snat_ips = []
        for net_id, net in ext_nets.iteritems():
            if (net_id in fip_ext_nets or
                    not self._is_connected_to_ext_net(context, port, net)):
                continue
            network = core_plugin.get_network(context._plugin_context, net_id)
            epg_tenant = self.apic_manager.apic.fvTenant.name(
                str(self._get_network_aci_tenant(network)))
            l3out_name = self.name_mapper.l3_out(
                context, net_id, openstack_owner=network['tenant_id'])
            ipms.append({'external_segment_name': net['name'],
                         'nat_epg_name':
                         self._get_ext_epg_for_ext_net(l3out_name),
                         'nat_epg_tenant': epg_tenant,
                         'nat_epg_app_profile': str(
                             self._get_network_app_profile(network))})
            host_snat_ip_allocation = (
                self._allocate_snat_ip_for_host_and_ext_net(
                    context, details['host'], network))
            if host_snat_ip_allocation:
                host_snat_ips.append(host_snat_ip_allocation)

        details['floating_ip'] = fips
        details['host_snat_ips'] = host_snat_ips
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
        details['enable_metadata_optimization'] = self.enable_metadata_opt
        details['subnets'] = context._plugin.get_subnets(
            context,
            filters={'id': [ip['subnet_id'] for ip in port['fixed_ips']]})
        for subnet in details['subnets']:
            dhcp_ips = set()
            for port in context._plugin.get_ports(
                    context, filters={
                        'network_id': [subnet['network_id']],
                        'device_owner': [n_constants.DEVICE_OWNER_DHCP]}):
                dhcp_ips |= set([x['ip_address'] for x in port['fixed_ips']
                                 if x['subnet_id'] == subnet['id']])
            dhcp_ips = list(dhcp_ips)
            if not subnet['dns_nameservers']:
                # Use DHCP namespace port IP
                subnet['dns_nameservers'] = dhcp_ips
            # Ser Default route if needed
            metadata = default = False
            if subnet['ip_version'] == 4:
                for route in subnet['host_routes']:
                    if route['destination'] == '0.0.0.0/0':
                        default = True
                    if route['destination'] == dhcp.METADATA_DEFAULT_CIDR:
                        metadata = True
                # Set missing routes
                if not default:
                    subnet['host_routes'].append(
                        {'destination': '0.0.0.0/0',
                         'nexthop': subnet['gateway_ip']})
                if not metadata and dhcp_ips and not self.enable_metadata_opt:
                    subnet['host_routes'].append(
                        {'destination': dhcp.METADATA_DEFAULT_CIDR,
                         'nexthop': dhcp_ips[0]})
            subnet['dhcp_server_ips'] = dhcp_ips

    def sync_init(f):
        def inner(inst, *args, **kwargs):
            if not inst.synchronizer:
                inst.synchronizer = (
                    APICMechanismDriver.get_base_synchronizer(inst))
                inst.synchronizer.sync_base()
            if args and isinstance(args[0], driver_context.NetworkContext):
                if (args[0]._plugin_context.is_admin and
                        args[0].current['name'] == acst.APIC_SYNC_NETWORK):
                    inst.synchronizer._sync_base()
            return f(inst, *args, **kwargs)
        return inner

    @lockutils.synchronized('apic-portlock')
    def _perform_path_port_operations(self, context, port):
        # Get network
        network = context.network.current
        epg_name = self.name_mapper.endpoint_group(context, network['id'])
        # Get tenant details from port context
        tenant_id = self._get_network_aci_tenant(context.network.current)
        if self._is_nat_enabled_on_ext_net(context.network.current):
            # PTG name is different
            l3out_name = self.name_mapper.l3_out(
                context, network['id'], openstack_owner=network['tenant_id'])
            epg_name = self._get_ext_epg_for_ext_net(l3out_name)
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
                tenant_id, epg_name, host, seg,
                app_profile_name=self._get_network_app_profile(
                    context.network.current), transaction=trs)

    def _perform_gw_port_operations(self, context, port):
        router_id = port.get('device_id')
        network = context.network.current
        router_info = self.apic_manager.ext_net_dict.get(network['name'])
        l3out_name = self.name_mapper.l3_out(
            context, network['id'], openstack_owner=network['tenant_id'])
        network_tenant = self._get_network_aci_tenant(network)
        router = self.l3_plugin.get_router(context._plugin_context, router_id)

        vrf = self._get_tenant_vrf(router['tenant_id'])
        if router_id and router_info:
            external_epg = apic_manager.EXT_EPG
            # Get/Create contract
            arouter_id = self.name_mapper.router(
                context, router_id, openstack_owner=router['tenant_id'])
            cid = self.apic_manager.get_router_contract(
                arouter_id, owner=vrf['aci_tenant'])
            if self._is_pre_existing(router_info) and ('external_epg' in
                                                       router_info):
                l3out_name_pre = self.name_mapper.pre_existing(
                    context, network['name'])
                external_epg = self.name_mapper.pre_existing(
                    context, router_info['external_epg'])
            else:
                l3out_name_pre = None

            nat_reqd = self._is_nat_required(
                context, network, vrf, router_info)
            nat_enabled = self._is_nat_enabled_on_ext_net(network)

            if nat_reqd and not nat_enabled:
                LOG.error(_("NAT-ing needed to use External Routed network "
                            "%s, but NAT-ing is disabled") % l3out_name)
            nat_ok = False
            if nat_reqd and nat_enabled:
                nat_ok = self._create_shadow_ext_net_for_nat(
                    context, l3out_name, external_epg, cid, network, router)

            if not nat_ok:      # Use non-NAT config
                # Set contract for L3Out EPGs
                with self.apic_manager.apic.transaction() as trs:
                    self.apic_manager.ensure_external_epg_consumed_contract(
                        l3out_name_pre or l3out_name, cid,
                        external_epg=external_epg,
                        owner=network_tenant, transaction=trs)
                    self.apic_manager.ensure_external_epg_provided_contract(
                        l3out_name_pre or l3out_name, cid,
                        external_epg=external_epg,
                        owner=network_tenant, transaction=trs)
                # Set contract for EXT EPG too.
                ext_epg_name = self._get_ext_epg_for_ext_net(l3out_name)
                app_profile = self._get_network_app_profile(network)
                with self.apic_manager.apic.transaction() as trs:
                    # set the EPG to provide this contract
                    self.apic_manager.set_contract_for_epg(
                        network_tenant, ext_epg_name, cid, provider=True,
                        app_profile_name=app_profile, transaction=trs)
                    # set the EPG to consume this contract
                    self.apic_manager.set_contract_for_epg(
                        network_tenant, ext_epg_name, cid, provider=False,
                        app_profile_name=app_profile, transaction=trs)

    def _check_gw_port_operation(self, context, port):
        if port.get('device_owner') != n_constants.DEVICE_OWNER_ROUTER_GW:
            return
        router_id = port.get('device_id')
        network = context.network.current
        ext_info = self.apic_manager.ext_net_dict.get(network['name'])
        router = self.l3_plugin.get_router(context._plugin_context, router_id)
        vrf_info = self._get_tenant_vrf(router['tenant_id'])

        if router_id and ext_info:
            nat_reqd = self._is_nat_required(
                context, network, vrf_info, ext_info)
            if nat_reqd and not self._is_nat_enabled_on_ext_net(network):
                raise WouldRequireNAT(ext_net=network['name'])

    def _perform_port_operations(self, context):
        # Get port
        port = context.current
        if port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._perform_gw_port_operations(context, port)
        elif self._is_port_bound(port) and not self._is_apic_network_type(
                context):
            self._perform_path_port_operations(context, port)
        self._notify_ports_due_to_router_update(port)

    def _delete_contract(self, context):
        port = context.current
        network = context.network.current
        l3out_name = self.name_mapper.l3_out(
            context, network['id'],
            openstack_owner=network['tenant_id'])
        router = self.l3_plugin.get_router(
            context._plugin_context, port.get('device_id'))
        arouter_id = self.name_mapper.router(
            context, port.get('device_id'),
            openstack_owner=router['tenant_id'])
        router_info = self.apic_manager.ext_net_dict.get(network['name'], {})

        if router_info:
            if 'external_epg' not in router_info:
                self.apic_manager.delete_external_epg_contract(arouter_id,
                                                               l3out_name)
            else:
                l3out_name_pre = self.name_mapper.pre_existing(
                    context, network['name'])
                external_epg = self.name_mapper.pre_existing(
                    context, router_info['external_epg'])
                tenant_id = self._get_network_aci_tenant(network)
                l3out_info = self._query_l3out_info(l3out_name_pre, tenant_id)
                contract_id = 'contract-%s' % router['id']
                if l3out_info:
                    self.apic_manager.unset_contract_for_external_epg(
                        l3out_name_pre, contract_id, external_epg=external_epg,
                        owner=l3out_info['l3out_tenant'], provided=True)
                    self.apic_manager.unset_contract_for_external_epg(
                        l3out_name_pre, contract_id, external_epg=external_epg,
                        owner=l3out_info['l3out_tenant'], provided=False)

    def _get_active_path_count(self, context, host=None):
        return context._plugin_context.session.query(
            models.PortBinding).filter_by(
                host=host or context.host,
                segment=context._binding.segment).count()

    @lockutils.synchronized('apic-portlock')
    def _delete_port_path(self, context, atenant_id, anetwork_id,
                          app_profile_name, host=None):
        if not self._get_active_path_count(context):
            self.apic_manager.ensure_path_deleted_for_port(
                atenant_id, anetwork_id,
                host or context.host, app_profile_name=app_profile_name)

    def _delete_path_if_last(self, context, host=None):
        if not self._get_active_path_count(context):
            atenant_id = self._get_network_aci_tenant(context.network.current)
            network_id = context.network.current['id']
            epg_name = self.name_mapper.endpoint_group(context, network_id)
            self._delete_port_path(context, atenant_id, epg_name,
                                   self._get_network_app_profile(
                                       context.network.current), host=host)

    def _get_subnet_info(self, context, subnet):
        if subnet['gateway_ip']:
            network_id = subnet['network_id']
            network = context._plugin.get_network(context._plugin_context,
                                                  network_id)
            tenant_id = self._get_network_aci_tenant(network)
            cidr = netaddr.IPNetwork(subnet['cidr'])
            gateway_ip = '%s/%s' % (subnet['gateway_ip'], str(cidr.prefixlen))

            if not network.get('router:external'):
                # Convert to APIC IDs
                bd_id = self.name_mapper.bridge_domain(
                    context, network_id, openstack_owner=network['tenant_id'])
                return tenant_id, bd_id, gateway_ip
            elif self._is_nat_enabled_on_ext_net(network):
                l3out_name = self.name_mapper.l3_out(
                    context, network['id'],
                    openstack_owner=network['tenant_id'])
                bd_id = self._get_ext_bd_for_ext_net(l3out_name)
                return tenant_id, bd_id, gateway_ip

    def create_port_precommit(self, context):
        self._check_gw_port_operation(context, context.current)

    @sync_init
    def create_port_postcommit(self, context):
        self._perform_port_operations(context)

    def update_port_precommit(self, context):
        self._check_gw_port_operation(context, context.current)

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
        network = context.network.current
        # Check if a compute port
        if (not self._is_apic_network_type(context) and context.host and
                context._binding.segment):
            self._delete_path_if_last(context)
        if port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._delete_contract(context)
            if self._is_nat_enabled_on_ext_net(network):
                self._delete_shadow_ext_net_for_nat(context, port, network)
        self._notify_ports_due_to_router_update(port)

    @sync_init
    def create_network_postcommit(self, context):
        # The following validation is not happening in the precommit to avoid
        # database lock timeout
        if context.current['name'] == acst.APIC_SYNC_NETWORK:
            raise aexc.ReservedSynchronizationName()
        tenant_id = self._get_network_aci_tenant(context.current)
        network_id = context.current['id']
        # Convert to APIC IDs
        bd_name = self.name_mapper.bridge_domain(
            context, network_id, openstack_owner=context.current['tenant_id'])
        epg_name = self.name_mapper.endpoint_group(context, network_id)
        if not context.current.get('router:external'):
            vrf = self._get_network_vrf(context, context.current)

            # Create BD and EPG for this network
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.ensure_bd_created_on_apic(
                    tenant_id, bd_name, ctx_owner=vrf['aci_tenant'],
                    ctx_name=vrf['aci_name'], transaction=trs)
                self.apic_manager.ensure_epg_created(
                    tenant_id, epg_name,
                    app_profile_name=self._get_network_app_profile(
                        context.current), bd_name=bd_name,
                    transaction=trs)
        else:
            self._create_real_external_network(context, context.current)

    @sync_init
    def update_network_postcommit(self, context):
        super(APICMechanismDriver, self).update_network_postcommit(context)

    def delete_network_postcommit(self, context):
        if not context.current.get('router:external'):
            network_id = context.current['id']

            # Convert to APIC IDs
            tenant_id = self._get_network_aci_tenant(context.current)
            bd_name = self.name_mapper.bridge_domain(
                context, network_id,
                openstack_owner=context.current['tenant_id'])
            epg_name = self.name_mapper.endpoint_group(
                context, network_id)

            # Delete BD and EPG for this network
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.delete_epg_for_network(
                    tenant_id, epg_name,
                    app_profile_name=self._get_network_app_profile(
                        context.current), transaction=trs)
                self.apic_manager.delete_bd_on_apic(tenant_id, bd_name,
                                                    transaction=trs)
        else:
            self._delete_real_external_network(context, context.current)

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
        self.notify_subnet_update(context.current)

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
        self.notify_subnet_update(context.current)

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

    def notify_subnet_update(self, subnet, context=None):
        context = context or nctx.get_admin_context()
        self.notifier.subnet_update(context, subnet)

    def _get_ext_epg_for_ext_net(self, l3out_name):
        return "EXT-epg-%s" % l3out_name

    def _get_ext_bd_for_ext_net(self, l3out_name):
        return "EXT-bd-%s" % l3out_name

    def _get_nat_vrf_for_ext_net(self, l3out_name):
        return "NAT-vrf-%s" % l3out_name

    def _get_shadow_name_for_nat(self, name):
        return "Shd-%s" % name

    def _get_ext_allow_all_contract(self, network):
        return "EXT-%s-allow-all" % network['id']

    def _get_snat_db_network_name(self, network):
        return acst.HOST_SNAT_NETWORK_PREFIX + network['id']

    def _create_shadow_ext_net_for_nat(self, context, l3out_name, ext_epg_name,
                                       router_contract, network, router):
        no_nat_vrf = self._get_tenant_vrf(router['tenant_id'])
        nat_epg_name = self._get_ext_epg_for_ext_net(l3out_name)
        shadow_ext_epg = self._get_shadow_name_for_nat(ext_epg_name)
        shadow_l3out = self.name_mapper.l3_out(
            context, network['id'],
            openstack_owner=router['tenant_id'])
        shadow_l3out = self._get_shadow_name_for_nat(shadow_l3out)
        router_tenant = self._get_tenant(router)
        nat_epg_tenant = self._get_network_aci_tenant(network)

        try:
            with self.apic_manager.apic.transaction(None) as trs:
                # create shadow L3-out and shadow external-epg
                # This goes on the no-nat VRF (original L3 context)
                # Note: Only NAT l3Out may exist in a different tenant
                # (eg. COMMON). NO NAT L3Outs always exists in the original
                # network tenant
                self.apic_manager.ensure_external_routed_network_created(
                    shadow_l3out, owner=router_tenant,
                    context=no_nat_vrf['aci_name'], transaction=trs)
                self.apic_manager.ensure_external_epg_created(
                    shadow_l3out, external_epg=shadow_ext_epg,
                    owner=router_tenant, transaction=trs)
                # make them use router-contract
                self.apic_manager.ensure_external_epg_consumed_contract(
                    shadow_l3out, router_contract,
                    external_epg=shadow_ext_epg,
                    owner=router_tenant, transaction=trs)
                self.apic_manager.ensure_external_epg_provided_contract(
                    shadow_l3out, router_contract,
                    external_epg=shadow_ext_epg,
                    owner=router_tenant, transaction=trs)

                # link up shadow external-EPG to NAT EPG
                self.apic_manager.associate_external_epg_to_nat_epg(
                    router_tenant, shadow_l3out, shadow_ext_epg,
                    nat_epg_name, target_owner=nat_epg_tenant,
                    app_profile_name=self._get_network_app_profile(network),
                    transaction=trs)
            return True
        except Exception as e:
            LOG.info(_("Unable to create Shadow EPG: %s"), e)
            return False

    def _delete_shadow_ext_net_for_nat(self, context, port, network):
        ext_info = self.apic_manager.ext_net_dict.get(network['name'])
        if not ext_info:
            return

        router = self.l3_plugin.get_router(
            context._plugin_context, port.get('device_id'))
        shadow_l3out = self.name_mapper.l3_out(
            context, network['id'],
            openstack_owner=router['tenant_id'])
        # delete shadow L3-out and shadow external-EPG
        shadow_l3out = self._get_shadow_name_for_nat(shadow_l3out)
        self.apic_manager.delete_external_routed_network(
            shadow_l3out, owner=self._get_network_aci_tenant(network))

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
        if (self.nat_enabled and ext_info and
                network.get('router:external')):
            opt = ext_info.get('enable_nat', 'true')
            return opt.lower() in ['true', 'yes', '1']
        return False

    def _get_tenant(self, object):
        if self.single_tenant_mode:
            return self.apic_system_id
        return self.name_mapper.tenant(None, object['tenant_id'])

    def _get_network_aci_tenant(self, network):
        # When not in single_tenant_mode, BD and EPG for a specific network
        # could be in the common tenant in case of NATed shared network
        if not self.single_tenant_mode:
            if self._is_nat_enabled_on_ext_net(network) and network['shared']:
                return apic_manager.TENANT_COMMON
        return self._get_tenant(network)

    def _get_network_app_profile(self, network):
        if self.single_tenant_mode:
            return self.name_mapper.tenant(None, network['tenant_id'])
        return self.apic_system_id

    def _get_network_vrf(self, context, network):
        # Returns the VRF where a specific network should be connected.
        # Depending on the network type and the various configurations the
        # tenant and name of the VRF can change.
        vrf = {'aci_tenant': self._get_tenant(network),
               'aci_name': self.name_mapper.tenant(
                   None, network['tenant_id'])}

        # NATed networks VRFs always are nat VRFs
        if self._is_nat_enabled_on_ext_net(network):
            vrf['aci_name'] = self._get_nat_vrf_for_ext_net(
                self.name_mapper.l3_out(context, network['id'],
                                        openstack_owner=network['tenant_id']))
        elif not self.single_tenant_mode or not self.per_tenant_context:
            vrf['aci_name'] = apic_manager.CONTEXT_SHARED

        if not self.single_tenant_mode:
            # Current aci_tenant is the mapped tenant.
            # Tenant is COMMON only if per tenant context is disabled, or is a
            # shared NATed network.
            if self._is_nat_enabled_on_ext_net(network) and network['shared']:
                    vrf['aci_tenant'] = apic_manager.TENANT_COMMON
            if not self.per_tenant_context:
                vrf['aci_tenant'] = apic_manager.TENANT_COMMON

        return vrf

    def _get_tenant_vrf(self, tenant_id):
        vrf = {'aci_tenant': self.apic_system_id,
               'aci_name': self.name_mapper.tenant(None, tenant_id)}
        if not self.single_tenant_mode:
            vrf['aci_tenant'] = self.name_mapper.tenant(None, tenant_id)
            vrf['aci_name'] = apic_manager.CONTEXT_SHARED
        elif not self.per_tenant_context:
            vrf['aci_name'] = apic_manager.CONTEXT_SHARED
        return vrf

    def _get_network_no_nat_vrf(self, context, network):
        # No NAT VRF is always in the original VRF tenant.
        # To know the right tenant, pretend the network is not external
        network_copy = copy.deepcopy(network)
        network_copy['router:external'] = False
        return self._get_network_vrf(context, network_copy)

    def _get_router_aci_tenant(self, router):
        if self.single_tenant_mode:
            return self.apic_system_id
        return apic_manager.TENANT_COMMON

    def _create_snat_ip_allocation_subnet(self, context, network,
                                          host_pool_cidr, gateway):
        # A DB only shadow network is created for every external
        # network on which SNAT is enabled. A DB only subnet is
        # created on this network for the SNAT IP allocation pool
        # from which a IP will be handed to each host that needs it.
        net_name = self._get_snat_db_network_name(network)
        if context._plugin.get_networks(
                context._plugin_context.elevated(),
                {'name': [net_name]}):
            LOG.info(_("SNAT network %s already exists"), net_name)
            return
        attrs = {'network': {'name': net_name,
                             'admin_state_up': False,
                             'shared': False,
                             'status': n_constants.NET_STATUS_DOWN}}
        snat_network = self.db_plugin.create_network(
            context._plugin_context, attrs)
        if not snat_network:
            LOG.warning(_("SNAT network %(name)s creation failed for "
                          "external network %(net_id)s. SNAT "
                          "will not function for this network"),
                        {'name': net_name, 'net_id': network['id']})
            return False
        # Create a new Neutron subnet corresponding to the
        # host_pool_cidr.
        # Each host that needs to provide SNAT for this
        # external network will get port allocation and IP
        # from this subnet.
        host_cidir_ver = netaddr.IPNetwork(host_pool_cidr).version
        attrs = {'subnet': {'name': acst.HOST_SNAT_POOL,
                            'cidr': host_pool_cidr,
                            'network_id': snat_network['id'],
                            'ip_version': host_cidir_ver,
                            'enable_dhcp': False,
                            'gateway_ip': gateway,
                            'allocation_pools':
                            attributes.ATTR_NOT_SPECIFIED,
                            'dns_nameservers':
                            attributes.ATTR_NOT_SPECIFIED,
                            'host_routes':
                            attributes.ATTR_NOT_SPECIFIED}}
        subnet = self.db_plugin.create_subnet(
            context._plugin_context, attrs)
        if not subnet:
            LOG.warning(_("Subnet %(pool) creation failed for "
                          "external network %(net_id)s. SNAT "
                          "will not function for this network"),
                        {'pool': acst.HOST_SNAT_POOL, 'net_id': network['id']})
            return False

    def _create_real_external_network(self, context, network):
        # This external network is the one that offer physical ability to
        # connect to the external world. When NAT is enabled, each private
        # context will also have a shadow L3Out that will take care of address
        # translation.
        tenant_id = self._get_network_aci_tenant(network)
        l3out_name = self.name_mapper.l3_out(
            context, network['id'], openstack_owner=network['tenant_id'])
        net_info = self.apic_manager.ext_net_dict.get(network['name'])
        vrf = self._get_network_vrf(context, network)

        if not net_info:
            return

        if self._is_pre_existing(net_info):
            l3out_name_pre = self.name_mapper.pre_existing(
                context, network['name'])
            # determine l3-out tenant and private VRF by querying ACI
            l3out_info = self._query_l3out_info(l3out_name_pre, tenant_id)
            if not l3out_info:
                LOG.error(
                    _("External Routed Network %s not found") % l3out_name_pre)
                return
            if not (l3out_info.get('vrf_name') and
                    l3out_info.get('vrf_tenant')):
                LOG.error(
                    _("External Routed Network %s doesn't have private "
                      "network set") % l3out_name_pre)
                return
            l3out_tenant = l3out_info['l3out_tenant']
            external_vrf = l3out_info['vrf_name']
            external_vrf_tenant = l3out_info['vrf_tenant']
            l3out_external_epg = net_info.get('external_epg',
                                              apic_manager.EXT_EPG)
        else:
            l3out_name_pre = None
            l3out_tenant = tenant_id
            l3out_external_epg = apic_manager.EXT_EPG
            external_vrf = vrf['aci_name']
            external_vrf_tenant = vrf['aci_tenant']

        if not self._is_pre_existing(net_info):
            self.apic_manager.ensure_context_enforced(
                owner=external_vrf_tenant, ctx_id=external_vrf)
            with self.apic_manager.apic.transaction() as trs:
                # Create External Routed Network and configure it
                address = net_info['cidr_exposed']
                next_hop = net_info['gateway_ip']
                encap = net_info.get('encap')  # No encap if None
                switch = net_info['switch']
                module, sport = net_info['port'].split('/')
                self.apic_manager.ensure_external_routed_network_created(
                    l3out_name, owner=l3out_tenant,
                    context=external_vrf, transaction=trs)
                self.apic_manager.ensure_logical_node_profile_created(
                    l3out_name, switch, module, sport, encap,
                    address, transaction=trs,
                    owner=l3out_tenant)
                self.apic_manager.ensure_static_route_created(
                    l3out_name, switch, next_hop,
                    owner=l3out_tenant,
                    transaction=trs)
                self.apic_manager.ensure_external_epg_created(
                    l3out_name, external_epg=l3out_external_epg,
                    owner=l3out_tenant, transaction=trs)

        # Create contract to allow all traffic and make the L3Out's
        # external-EPG provide and consume that contract
        with self.apic_manager.apic.transaction() as trs:
            # create allow-everything contract
            contract_name = self._get_ext_allow_all_contract(network)
            self.apic_manager.create_tenant_filter(
                contract_name, owner=l3out_tenant,
                entry="allow-all", transaction=trs)
            self.apic_manager.manage_contract_subject_bi_filter(
                contract_name, contract_name, contract_name,
                owner=l3out_tenant, transaction=trs)

            # make L3out's external EPG use allow-everything contract
            self.apic_manager.set_contract_for_external_epg(
                l3out_name_pre or l3out_name, contract_name,
                external_epg=l3out_external_epg, provided=True,
                owner=l3out_tenant, transaction=trs)
            self.apic_manager.set_contract_for_external_epg(
                l3out_name_pre or l3out_name, contract_name,
                external_epg=l3out_external_epg, provided=False,
                owner=l3out_tenant, transaction=trs)

        # Create EPG and BD for external network. This EPG will hold
        # NAT-ed endpoints as well as ports of VM created in the
        # external network.
        with self.apic_manager.apic.transaction() as trs:
            # create EPG, BD for external network and connect to external VRF
            ext_bd_name = self._get_ext_bd_for_ext_net(l3out_name)
            ext_epg_name = self._get_ext_epg_for_ext_net(l3out_name)
            app_profile_name = self._get_network_app_profile(network)
            self.apic_manager.ensure_bd_created_on_apic(
                tenant_id, ext_bd_name, ctx_owner=external_vrf_tenant,
                ctx_name=external_vrf, transaction=trs)
            self.apic_manager.set_l3out_for_bd(
                tenant_id, ext_bd_name, l3out_name_pre or l3out_name,
                transaction=trs)
            self.apic_manager.ensure_epg_created(
                tenant_id, ext_epg_name, bd_name=ext_bd_name,
                app_profile_name=app_profile_name, transaction=trs)
            # create any required subnets in BD
            if self._is_nat_enabled_on_ext_net(network):
                gw, plen = net_info.get('host_pool_cidr', '/').split('/', 1)
                if gw and plen:
                    self.apic_manager.ensure_subnet_created_on_apic(
                        tenant_id, ext_bd_name, gw + '/' + plen,
                        transaction=trs)
                    self._create_snat_ip_allocation_subnet(
                        context, network, net_info.get('host_pool_cidr'), gw)

            # make EPG use allow-everything contract
            self.apic_manager.set_contract_for_epg(
                tenant_id, ext_epg_name, contract_name,
                app_profile_name=app_profile_name, transaction=trs)
            self.apic_manager.set_contract_for_epg(
                tenant_id, ext_epg_name, contract_name,
                app_profile_name=app_profile_name, provider=True,
                transaction=trs)

    def _delete_snat_ip_allocation_network(self, context, network):
        """This deletes all the SNAT pool resources we created in the DB."""
        snat_net_name = self._get_snat_db_network_name(network)
        snat_networks = self.db_plugin.get_networks(
            context, filters={'name': [snat_net_name]})

        if not snat_networks or len(snat_networks) > 1:
            LOG.info(_("Unique SNAT network not found for external network "
                       "%(net_id)s. Deletion of SNAT nework skipped."),
                     {'net_id': network['id']})
            return

        snat_network_id = snat_networks[0]['id']
        snat_ports = self.db_plugin.get_ports(
            context, filters={'network_id': [snat_network_id]})
        for snat_port in snat_ports:
            self.db_plugin.delete_port(context, snat_port['id'])

        # Only one subnet should be present on this network,
        # but we retrieve and delete all subnets that are present
        # so that we can delete the network itself. Additional
        # subnets can only be present if someone manually creates
        # them, and which is not supported in the workflow.
        snat_subnets = self.db_plugin.get_subnets(
            context, filters={'network_id': [snat_network_id]})
        if not snat_subnets:
            LOG.info(_("Subnet for host-SNAT-pool could not be found "
                       "for SNAT network %(net_id)s. Deletion of SNAT "
                       "subnet skipped."),
                     {'net_id': snat_network_id})
        else:
            for snat_subnet in snat_subnets:
                self.db_plugin.delete_subnet(context, snat_subnet['id'])

        self.db_plugin.delete_network(context, snat_network_id)

    def _delete_real_external_network(self, context, network):
        tenant_id = self._get_network_aci_tenant(network)
        l3out_name = self.name_mapper.l3_out(
            context, network['id'], openstack_owner=network['tenant_id'])
        net_info = self.apic_manager.ext_net_dict.get(network['name'])
        vrf = self._get_network_vrf(context, network)

        if not net_info:
            return

        if self._is_pre_existing(net_info):
            l3out_name_pre = self.name_mapper.pre_existing(
                context, network['name'])
            # determine l3-out tenant and private VRF by querying ACI
            l3out_info = self._query_l3out_info(l3out_name_pre, tenant_id)
            if not l3out_info:
                LOG.error(
                    _("External Routed Network %s not found") % l3out_name_pre)
                return
            l3out_tenant = l3out_info['l3out_tenant']
            l3out_external_epg = net_info.get('external_epg',
                                              apic_manager.EXT_EPG)
        else:
            l3out_name_pre = None
            l3out_tenant = tenant_id
            l3out_external_epg = apic_manager.EXT_EPG

        with self.apic_manager.apic.transaction() as trs:
            # delete EPG, BD for external network
            ext_bd_name = self._get_ext_bd_for_ext_net(l3out_name)
            ext_epg_name = self._get_ext_epg_for_ext_net(l3out_name)
            app_profile_name = self._get_network_app_profile(network)

            self.apic_manager.delete_bd_on_apic(
                tenant_id, ext_bd_name, transaction=trs)
            self.apic_manager.delete_epg_for_network(
                tenant_id, ext_epg_name,
                app_profile_name=app_profile_name, transaction=trs)

        with self.apic_manager.apic.transaction() as trs:
            # remove contract from L3Out's external EPG, then delete contract.
            # Also delete L3Out and VRF if not pre-existing
            contract_name = self._get_ext_allow_all_contract(network)

            if not self._is_pre_existing(net_info):
                # delete external VRF and L3Out+children
                self.apic_manager.delete_external_routed_network(
                    l3out_name, owner=l3out_tenant)
                self.apic_manager.ensure_context_deleted(
                    vrf['aci_tenant'], vrf['aci_name'], transaction=trs)
            else:
                self.apic_manager.unset_contract_for_external_epg(
                    l3out_name_pre, contract_name,
                    external_epg=l3out_external_epg,
                    owner=l3out_tenant, provided=True, transaction=trs)
                self.apic_manager.unset_contract_for_external_epg(
                    l3out_name_pre, contract_name,
                    external_epg=l3out_external_epg,
                    owner=l3out_tenant, provided=False, transaction=trs)
            # delete allow-everything contract
            self.apic_manager.delete_contract(
                contract_name, owner=l3out_tenant, transaction=trs)
            self.apic_manager.delete_tenant_filter(
                contract_name, owner=l3out_tenant, transaction=trs)

        self._delete_snat_ip_allocation_network(
            context._plugin_context, network)

    def _is_nat_required(self, context, network, vrf_info, ext_info):
        l3out_name = self.name_mapper.l3_out(
            context, network['id'], openstack_owner=network['tenant_id'])
        network_tenant = self._get_network_aci_tenant(network)
        if ext_info and self._is_pre_existing(ext_info):
            l3out_name_pre = self.name_mapper.pre_existing(
                context, network['name'])
            l3out_info = self._query_l3out_info(
                l3out_name_pre, network_tenant)
        else:
            network_vrf = self._get_network_vrf(context, network)
            l3out_info = {'l3out_tenant': network_tenant,
                          'vrf_name': network_vrf['aci_name'],
                          'vrf_tenant': network_vrf['aci_tenant']}

        if (l3out_info and l3out_info.get('vrf_name') and
                l3out_info.get('vrf_tenant')):
            return (l3out_info['vrf_name'] != str(vrf_info['aci_name']) or
                    l3out_info['vrf_tenant'] != vrf_info['aci_tenant'])
        else:
            LOG.error(
                _("External Routed Network %s not found, or doesn't "
                  "have private network configured") % l3out_name)
        return True

    def _query_l3out_info(self, l3out_name, tenant_id):
        info = {'l3out_tenant': tenant_id}
        l3out_children = self.apic_manager.apic.l3extOut.get_subtree(
            info['l3out_tenant'], l3out_name)
        if not l3out_children:
            info['l3out_tenant'] = apic_manager.TENANT_COMMON
            l3out_children = self.apic_manager.apic.l3extOut.get_subtree(
                info['l3out_tenant'], l3out_name)
            if not l3out_children:
                return None
        rs_ctx = [x['l3extRsEctx']
                  for x in l3out_children if x.get('l3extRsEctx')]
        if rs_ctx:
            ctx_dn = rs_ctx[0].get('attributes', {}).get('tDn')
            ctx_dn = ctx_dn.split('/') if ctx_dn else None
            if ctx_dn and len(ctx_dn) == 3:
                if ctx_dn[1].startswith('tn-'):
                    info['vrf_tenant'] = ctx_dn[1][3:]
                if ctx_dn[2].startswith('ctx-'):
                    info['vrf_name'] = ctx_dn[2][4:]
        return info

    def _is_pre_existing(self, ext_info):
        opt = ext_info.get('preexisting', 'false')
        return opt.lower() in ['true', 'yes', '1']
