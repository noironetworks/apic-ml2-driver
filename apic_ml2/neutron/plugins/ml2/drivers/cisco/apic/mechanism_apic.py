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
import re

from apicapi import apic_manager
from apicapi import apic_mapper
from keystoneclient.auth.identity.generic import password as keypassword
from keystoneclient import client as keyclient
from keystoneclient import session as keysession
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
from neutron.db.models import allowed_address_pair as n_addr_pair_db
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import rpc as neu_rpc
from opflexagent import constants as ofcst
from opflexagent import rpc as o_rpc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_utils import importutils

from apic_ml2.neutron.db import l3out_vlan_allocation as l3out_vlan_alloc
from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    network_constraints as net_cons)
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import apic_model
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import apic_sync
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import attestation
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import config  # noqa
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import constants as acst
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import exceptions as aexc
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import nova_client
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import patch  # noqa
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import rpc as t_rpc

DVS_AGENT_KLASS = 'vmware_dvs.api.dvs_agent_rpc_api.DVSClientAPI'
LOG = logging.getLogger(__name__)
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


class SubnetDisallowedByNetConstraints(n_exc.BadRequest):
    message = _("Network constraints disallow creation of subnet %(cidr)s "
                "in network %(net)s")


class OnlyOneRouterPermittedIfNatDisabled(n_exc.BadRequest):
    message = _("Cannot connect more than one router to NAT-disabled external "
                "network %(net)s")


class PreExistingL3OutNotFound(n_exc.BadRequest):
    message = _("No applicable External Routed Network named %(l3out)s was "
                "found on APIC.")


class PreExistingL3OutInIncorrectTenant(n_exc.BadRequest):
    message = _("Since NAT is disabled, VRF (%(vrf_tenant)s, %(vrf_name)s) "
                "for project %(tenant_id)s needs to be connected to existing "
                "External Routed Network (%(l3out_tenant)s, %(l3out_name)s) "
                "which is not a valid configuration. The existing External "
                "Routed Network should be in a compatible tenant.")


class VMsDisallowedOnExtNetworkIfNatDisabled(n_exc.BadRequest):
    message = _("Compute ports cannot be created on external network %(net)s "
                "because NAT is disabled")


class VMsDisallowedOnExtNetworkIfEdgeNat(n_exc.BadRequest):
    message = _("Compute ports cannot be created on external network %(net)s "
                "because edge_nat is enabled")


class EdgeNatVlanRangeNotFound(n_exc.BadRequest):
    message = _("No vlan range is specified for L3Out %(l3out)s "
                "when edge_nat is enabled.")


class EdgeNatBadVlanRange(n_exc.BadRequest):
    message = _("Bad vlan range is specified for L3Out %(l3out)s "
                "when edge_nat is enabled.")


class EdgeNatWrongL3OutIFType(n_exc.BadRequest):
    message = _("L3Out %(l3out)s can only support routed sub-interfaces and "
                "SVI in the interface profiles when edge_nat is enabled.")


class EdgeNatWrongL3OutAuthTypeForBGP(n_exc.BadRequest):
    message = _("L3Out %(l3out)s can only support no authentication "
                "for BGP interface profile when edge_nat is enabled.")


class EdgeNatWrongL3OutAuthTypeForOSPF(n_exc.BadRequest):
    message = _("L3Out %(l3out)s can only support no authentication "
                "for OSPF interface profile when edge_nat is enabled.")


class OnlyOneRouterPermittedIfVrfPerRouter(n_exc.BadRequest):
    message = _("Configuration for tenant %(tenant)s ('VRF per router') "
                "permits connecting subnets in network %(net)s to exactly "
                "one router.")


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


class KeystoneNotificationEndpoint(object):
    filter_rule = oslo_messaging.NotificationFilter(
        event_type='identity.project.update')

    def __init__(self, mechanism_driver):
        self._driver = mechanism_driver

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        LOG.debug("Keystone notification getting called!")

        tenant_id = payload.get('resource_info')
        # malformed notification?
        if not tenant_id:
            return None
        # we only update tenants which have been created in APIC. For other
        # cases, their nameAlias will be set when the first network is being
        # created under that tenant
        if not self._driver.name_mapper.is_tenant_in_apic(tenant_id):
            return None

        new_tenant_name = self._driver.name_mapper.update_tenant_name(
            tenant_id)
        if new_tenant_name:
            obj = {}
            obj['tenant_id'] = tenant_id
            apic_tenant_name = self._driver._get_tenant(obj)
            if not self._driver.single_tenant_mode:
                self._driver.apic_manager.update_name_alias(
                    self._driver.apic_manager.apic.fvTenant, apic_tenant_name,
                    nameAlias=new_tenant_name)
            else:
                apic_app_profile = self._driver._get_network_app_profile(obj)
                self._driver.apic_manager.update_name_alias(
                    self._driver.apic_manager.apic.fvAp, apic_tenant_name,
                    apic_app_profile, nameAlias=new_tenant_name)
        return oslo_messaging.NotificationResult.HANDLED


class APICMechanismDriver(api.MechanismDriver,
                          ha_ip_db.HAIPOwnerDbMixin):

    apic_manager = None

    @staticmethod
    def get_apic_manager(client=True):
        if APICMechanismDriver.apic_manager:
            return APICMechanismDriver.apic_manager
        apic_config = cfg.CONF.ml2_cisco_apic
        network_config = {
            'vlan_ranges': cfg.CONF.ml2_type_vlan.network_vlan_ranges,
        }
        apic_system_id = cfg.CONF.apic_system_id
        keyclient_param = keyclient if client else None
        keystone_authtoken = None
        session = None
        if client:
            keystone_authtoken = cfg.CONF.keystone_authtoken
            pass_params = apic_mapper.APICNameMapper.get_key_password_params(
                keystone_authtoken)
            admin_auth = keypassword.Password(
                auth_url=pass_params[0],
                username=pass_params[1], password=pass_params[2],
                tenant_name=pass_params[3],
                user_domain_id='Default', project_domain_id='Default')
            session = keysession.Session(auth=admin_auth)
        if cfg.CONF.ml2_cisco_apic.single_tenant_mode:
            # Force scope names to False
            apic_config.scope_names = False
        APICMechanismDriver.apic_manager = apic_manager.APICManager(
            apic_model.ApicDbModel(), logging, network_config, apic_config,
            keyclient_param, keystone_authtoken, apic_system_id,
            default_apic_model=('apic_ml2.neutron.plugins.ml2.drivers.'
                                'cisco.apic.apic_model'), keysession=session)
        return APICMechanismDriver.apic_manager

    @staticmethod
    def get_base_synchronizer(inst):
        return apic_sync.ApicBaseSynchronizer(inst)

    @staticmethod
    def get_router_synchronizer(inst):
        return apic_sync.ApicRouterSynchronizer(inst)

    @staticmethod
    def get_driver_instance():
        return _apic_driver_instance

    @property
    def fabric_l3(self):
        if self._fabric_l3 is None:
            self._fabric_l3 = self._cisco_l3 or hasattr(self.l3_plugin,
                                                        '_apic_driver')
        return self._fabric_l3

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._l3_plugin = plugins.get('L3_ROUTER_NAT')
        return self._l3_plugin

    @property
    def dvs_notifier(self):
        if not self._dvs_notifier:
            try:
                self._dvs_notifier = importutils.import_object(
                    DVS_AGENT_KLASS,
                    nctx.get_admin_context_without_session()
                )
            except ImportError:
                self._dvs_notifier = None
        return self._dvs_notifier

    @property
    def db_plugin(self):
        if not self._db_plugin:
            self._db_plugin = n_db.NeutronDbPluginV2()
        return self._db_plugin

    def __init__(self):
        self.sg_enabled = securitygroups_rpc.is_firewall_enabled()
        super(APICMechanismDriver, self).__init__()
        ha_ip_db.HAIPOwnerDbMixin.__init__(self)
        self._dvs_notifier = None

    def _agent_bind_port(self, context, agent_list, bind_strategy):
        """Attempt port binding per agent.

           Perform the port binding for a given agent.
           Returns True if bound successfully.
        """
        for agent in agent_list:
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if bind_strategy(context, segment, agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return True
            else:
                LOG.warning(_("Refusing to bind port %(pid)s to dead agent: "
                              "%(agent)s"),
                            {'pid': context.current['id'], 'agent': agent})
        return False

    def bind_port(self, context):
        """Get port binding per host.

           This is similar to the one defined in the
           AgentMechanismDriverBase class, but is modified
           to support multiple L2 agent types (DVS and OpFlex).
        """
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in [portbindings.VNIC_NORMAL]:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        # Attempt to bind ports for DVS agents for nova-compute daemons
        # first. This allows having network agents (dhcp, metadata)
        # that typically run on a network node using an OpFlex agent to
        # co-exist with nova-compute daemons for ESX, which host DVS agents.
        if context.current['device_owner'].startswith('compute:'):
            agent_list = context.host_agents(acst.AGENT_TYPE_DVS)
            if self._agent_bind_port(context, agent_list, self._bind_dvs_port):
                return

        # It either wasn't a DVS binding, or there wasn't a DVS
        # agent on the binding host (could be the case in a hybrid
        # environment supporting KVM and ESX compute). Go try for
        # OpFlex agents.
        agent_list = context.host_agents(ofcst.AGENT_TYPE_OPFLEX_OVS)
        if self._agent_bind_port(context, agent_list, self._bind_opflex_port):
            return

        # Try hierarchical binding for physical nodes
        self._bind_physical_node(context)

    def _bind_dvs_port(self, context, segment, agent):
        """Populate VIF type and details for DVS VIFs.

           For DVS VIFs, provide the portgroup along
           with the security groups setting
        """
        if self._check_segment_for_agent(segment, agent):
            network_id = context.current.get('network_id')
            epg = self.name_mapper.network(context, network_id)
            net = self._get_plugin().get_network(context._plugin_context,
                                                 network_id)
            # Use default security groups from MD
            vif_details = {portbindings.CAP_PORT_FILTER: self.sg_enabled}
            tenant = self._get_network_aci_tenant(net)
            aci_tenant = self.apic_manager.apic.fvTenant.name(tenant)
            app_profile = self._get_network_app_profile(net)
            vif_details['dvs_port_group_name'] = ('%s|%s|%s' %
                                                  (aci_tenant,
                                                   app_profile,
                                                   epg))
            currentcopy = copy.copy(context.current)
            currentcopy['portgroup_name'] = (
                vif_details['dvs_port_group_name'])
            booked_port_key = None
            if self.dvs_notifier:
                booked_port_key = self.dvs_notifier.bind_port_call(
                    currentcopy,
                    context.network.network_segments,
                    context.network.current,
                    context.host
                )
            if booked_port_key:
                vif_details['dvs_port_key'] = booked_port_key

            context.set_binding(segment[api.ID],
                                acst.VIF_TYPE_DVS, vif_details)
            return True
        else:
            return False

    def _bind_opflex_port(self, context, segment, agent):
        """Populate VIF type and details for OpFlex VIFs.

           For OpFlex VIFs, we just report the OVS VIF type,
           along with security groups setting, which were
           set when this mechanism driver was instantiated.
        """
        if self._check_segment_for_agent(segment, agent):
            self._complete_binding(context, segment)
            return True
        else:
            return False

    def _check_segment_for_agent(self, segment, agent):
        """Check support for OpFlex type segments.

           The agent has the ability to limit the segments in OpFlex
           networks by specifying the mappings in their config. If no
           mapping is specifified, then all OpFlex segments are
           supported.
        """
        network_type = segment[api.NETWORK_TYPE]
        if network_type == ofcst.TYPE_OPFLEX:
            opflex_mappings = agent['configurations'].get('opflex_networks')
            LOG.debug(_("Checking segment: %(segment)s "
                        "for physical network: %(mappings)s "),
                      {'segment': segment, 'mappings': opflex_mappings})
            return (opflex_mappings is None or
                    segment[api.PHYSICAL_NETWORK] in opflex_mappings)
        elif network_type == 'local':
            return True
        else:
            return False

    def _get_physical_network_for_host(self, host):
        for k, v in self.apic_manager.phy_net_dict.iteritems():
            if host in v.get('hosts', []):
                return k

    def _bind_physical_node(self, context):
        phy_seg_name = self._get_physical_network_for_host(context.host)
        if phy_seg_name:
            phy_seg = self.apic_manager.phy_net_dict[phy_seg_name]
            for segment in context.segments_to_bind:
                net_type = segment[api.NETWORK_TYPE]
                if net_type == ofcst.TYPE_OPFLEX:
                    dyn_seg = context.allocate_dynamic_segment(
                        {api.PHYSICAL_NETWORK: phy_seg_name,
                         api.NETWORK_TYPE:
                            phy_seg.get('segment_type', constants.TYPE_VLAN)})
                    LOG.info("Allocated dynamic-segment %(s)s for port %(p)s",
                             {'s': dyn_seg, 'p': context.current['id']})
                    dyn_seg['apic_ml2_created'] = True
                    context.continue_binding(segment['id'], [dyn_seg])
                    return True
                elif segment.get('apic_ml2_created'):
                    # complete binding if another driver did not bind the
                    # dynamic segment that we created
                    self._complete_binding(context, segment)
                    return True
        return False

    def _complete_binding(self, context, segment):
        context.set_binding(segment[api.ID],
                            portbindings.VIF_TYPE_OVS,
                            {portbindings.CAP_PORT_FILTER: self.sg_enabled,
                             portbindings.OVS_HYBRID_PLUG: self.sg_enabled})

    def initialize(self):
        # initialize apic
        APICMechanismDriver.get_apic_manager()
        self._setup_rpc()
        self._setup_topology_rpc_listeners()
        self._setup_opflex_rpc_listeners()
        self.keystone_notification_exchange = (self.apic_manager.
                                               keystone_notification_exchange)
        self.keystone_notification_topic = (self.apic_manager.
                                            keystone_notification_topic)
        self._setup_keystone_notification_listeners()
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
        self.single_tenant_name = cfg.CONF.ml2_cisco_apic.single_tenant_name
        global _apic_driver_instance
        _apic_driver_instance = self
        self._l3_plugin = None
        self._db_plugin = None
        self._fabric_l3 = None
        self._cisco_l3 = cfg.CONF.ml2_cisco_apic.l3_cisco_router_plugin
        self.attestator = attestation.EndpointAttestator(self.apic_manager)
        net_cons_source = cfg.CONF.ml2_cisco_apic.network_constraints_filename
        if net_cons_source is not None:
            net_cons_source = net_cons.ConfigFileSource(net_cons_source)
        self.net_cons = net_cons.NetworkConstraints(net_cons_source)
        self.l3out_vlan_alloc = l3out_vlan_alloc.L3outVlanAlloc()
        self.l3out_vlan_alloc.sync_vlan_allocations(
            self.apic_manager.ext_net_dict)
        self.advertise_mtu = cfg.CONF.advertise_mtu
        self.vrf_per_router_tenants = []
        for vpr_tenant in cfg.CONF.ml2_cisco_apic.vrf_per_router_tenants:
            vpr_tenant = vpr_tenant.strip()
            if not vpr_tenant:
                continue
            try:
                re.compile(vpr_tenant)
                self.vrf_per_router_tenants.append(vpr_tenant)
            except re.error:
                LOG.warning(_("Bad regex: %(regex)s is defined for the "
                              "vrf_per_router_tenants config parameter."),
                            {'regex': vpr_tenant})
        self.tenants_with_name_alias_set = set()
        self.apic_optimized_dhcp_lease_time = (
            self.apic_manager.apic_optimized_dhcp_lease_time)

    def _setup_opflex_rpc_listeners(self):
        self.opflex_endpoints = [o_rpc.GBPServerRpcCallback(
            self, self.notifier)]
        self.opflex_topic = o_rpc.TOPIC_OPFLEX
        self.opflex_conn = n_rpc.create_connection()
        self.opflex_conn.create_consumer(
            self.opflex_topic, self.opflex_endpoints, fanout=False)
        return self.opflex_conn.consume_in_threads()

    def _setup_keystone_notification_listeners(self):
        targets = [oslo_messaging.Target(
            exchange=self.keystone_notification_exchange,
            topic=self.keystone_notification_topic, fanout=True)]
        endpoints = [KeystoneNotificationEndpoint(self)]
        pool = "cisco_ml2_listener-workers"
        server = oslo_messaging.get_notification_listener(
            n_rpc.NOTIFICATION_TRANSPORT, targets, endpoints,
            executor='eventlet', pool=pool)
        server.start()

    def _setup_topology_rpc_listeners(self):
        self.topology_endpoints = []
        if cfg.CONF.ml2_cisco_apic.integrated_topology_service:
            self.topology_endpoints.append(
                t_rpc.ApicTopologyRpcCallbackMechanism(
                    self.apic_manager, self))
        if self.topology_endpoints:
            LOG.debug("New RPC endpoints: %s", self.topology_endpoints)
            self.topology_topic = t_rpc.TOPIC_APIC_SERVICE
            self.topology_conn = n_rpc.create_connection()
            self.topology_conn.create_consumer(
                self.topology_topic, self.topology_endpoints, fanout=False)
            return self.topology_conn.consume_in_threads()

    def _setup_rpc(self):
        self.notifier = o_rpc.AgentNotifierApi(topics.AGENT)

    # RPC Method
    def request_vrf_details(self, context, **kwargs):
        return self.get_vrf_details(context, **kwargs)

    # RPC Method
    def get_vrf_details(self, context, **kwargs):
        core_plugin = manager.NeutronManager.get_plugin()
        ctx = nctx.get_admin_context()
        vrf_id = kwargs['vrf_id']
        router = None
        if vrf_id.startswith('router:'):
            router_id = vrf_id[len('router:'):]
            router = self.l3_plugin.get_router(ctx, router_id)

        # For the APIC ML2 driver, VRF ID is a tenant_id, need to return all
        # the subnets for this tenant. If vrf-per-router is enabled for the
        # tenant, then vrf_id is ID of a router, so return subnets of
        # all connected networks
        if self.per_tenant_context:
            if router:
                intf_ports = core_plugin.get_ports(
                    ctx, filters={'device_owner':
                                  [n_constants.DEVICE_OWNER_ROUTER_INTF],
                                  'device_id': [router['id']]})
                nets = set([p['network_id'] for p in intf_ports])
            else:
                nets = core_plugin.get_networks(ctx, {'tenant_id': [vrf_id]})
                nets = [n['id'] for n in nets]
            subnets = core_plugin.get_subnets(ctx,
                                              filters={'network_id': nets})
        else:
            # need to retrieve the whole world
            subnets = core_plugin.get_subnets(ctx)

        # Exclude external subnets
        networks = core_plugin.get_networks(
            ctx, {'id': set([x['network_id'] for x in subnets])})
        external_networks = [x['id'] for x in networks if
                             x.get('router:external')]
        subnets = [x for x in subnets if
                   (x['network_id'] not in external_networks and
                    x['name'] != acst.HOST_SNAT_POOL)]

        if subnets:
            subnets = netaddr.IPSet([x['cidr'] for x in subnets])
            subnets.compact()
            subnets = [str(x) for x in subnets.iter_cidrs()]

        vrf = (self._get_router_vrf(router) if router
               else self._get_tenant_vrf(vrf_id))
        details = {
            'vrf_tenant': self.apic_manager.apic.fvTenant.name(
                vrf['aci_tenant']),
            'vrf_name': self.apic_manager.apic.fvCtx.name(vrf['aci_name']),
            'vrf_subnets': subnets
        }
        details['l3_policy_id'] = (
            self.per_tenant_context and vrf_id
            or '%s-%s' % (details['vrf_tenant'], details['vrf_name']))
        return details

    def _get_gbp_details(self, context, **kwargs):
        core_plugin = manager.NeutronManager.get_plugin()
        port_id = core_plugin._device_to_port_id(
            context, kwargs['device'])
        port_context = core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return {'device': kwargs['device']}
        port = port_context.current

        context._plugin = core_plugin
        context._plugin_context = context

        network = core_plugin.get_network(context, port['network_id'])

        def is_port_promiscuous(port):
            if port['device_owner'] == n_constants.DEVICE_OWNER_DHCP:
                return True
            if not port.get('port_security_enabled', True):
                return True
            return False

        segment = port_context.bottom_bound_segment or {}
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
        owned_addr = self.ha_ip_handler.get_ha_ipaddresses_for_port(port['id'])
        self._add_ip_mapping_details(context, port, kwargs['host'],
                                     owned_addr, details)
        self._add_network_details(context, port, owned_addr, details)
        if self._is_nat_enabled_on_ext_net(network):
            # PTG name is different
            details['endpoint_group_name'] = self._get_ext_epg_for_ext_net(
                details['endpoint_group_name'])
        router_id = None
        if self.fabric_l3 and self._is_vrf_per_router(network):
            intf_ports = core_plugin.get_ports(
                context,
                filters={'device_owner':
                         [n_constants.DEVICE_OWNER_ROUTER_INTF],
                         'network_id': [network['id']]})
            if intf_ports:
                router_id = intf_ports[0]['device_id']
        details.update(
            self.get_vrf_details(
                context, vrf_id=('router:%s' % router_id if router_id
                                 else network['tenant_id'])))
        try:
            details['attestation'] = self.attestator.get_endpoint_attestation(
                port_id, details['host'],
                details['app_profile_name'] + "|" +
                details['endpoint_group_name'], details['ptg_tenant'])
        except AttributeError:
            pass  # EP attestation not supported by APICAPI

        if self.advertise_mtu and network.get('mtu'):
            details['interface_mtu'] = network['mtu']

        if self.apic_optimized_dhcp_lease_time > 0:
            details['dhcp_lease_time'] = self.apic_optimized_dhcp_lease_time

        return details

    # RPC Method
    def get_gbp_details(self, context, **kwargs):
        try:
            return self._get_gbp_details(context, **kwargs)
        except Exception as e:
            LOG.error(_(
                "An exception has occurred while retrieving device "
                "gbp details for %s"), kwargs.get('device'))
            LOG.exception(e)
            details = {'device': kwargs.get('device')}
        return details

    # RPC Method
    def request_endpoint_details(self, context, **kwargs):
        try:
            LOG.debug("Request GBP details: %s", kwargs)
            kwargs.update(kwargs['request'])
            result = {'device': kwargs['device'],
                      'timestamp': kwargs['timestamp'],
                      'request_id': kwargs['request_id'],
                      'gbp_details': None,
                      'neutron_details': None}
            result['gbp_details'] = self._get_gbp_details(context, **kwargs)
            result['neutron_details'] = neu_rpc.RpcCallbacks(
                None, None).get_device_details(context, **kwargs)
            return result
        except Exception as e:
            LOG.error(_("An exception has occurred while requesting device "
                        "gbp details for %s"), kwargs.get('device'))
            LOG.exception(e)
            return None

    def _add_port_binding(self, session, port_id, host):
        with session.begin(subtransactions=True):
            record = models.PortBinding(port_id=port_id,
                                        host=host,
                                        vif_type=portbindings.VIF_TYPE_UNBOUND)
            session.add(record)
            return record

    def get_snat_ip_for_vrf(self, context, vrf_id, network):
        return self._allocate_snat_ip(context, vrf_id, network)

    def _allocate_snat_ip(self, context, host_or_vrf, network):
        """Allocate SNAT IP for a host or vrf for an external network."""
        snat_net_name = self._get_snat_db_network_name(network)
        snat_networks = self.db_plugin.get_networks(
            context, filters={'name': [snat_net_name]})
        if not snat_networks or len(snat_networks) > 1:
            LOG.info(_("Unique SNAT network not found for external network "
                       "%(net_id)s. SNAT will not function with host or vrf "
                       "%(host_or_vrf)s for this external network"),
                     {'net_id': network['id'], 'host_or_vrf': host_or_vrf})
            return {}

        snat_network_id = snat_networks[0]['id']
        snat_network_tenant_id = snat_networks[0]['tenant_id']
        snat_subnets = self.db_plugin.get_subnets(
            context, filters={'name': [acst.HOST_SNAT_POOL],
                              'network_id': [snat_network_id]})
        if not snat_subnets:
            LOG.info(_("Subnet for SNAT-pool could not be found "
                       "for SNAT network %(net_id)s. SNAT will not "
                       "function for external network %(ext_id)s"),
                     {'net_id': snat_network_id, 'ext_id': network['id']})
            return {}

        snat_ports = self.db_plugin.get_ports(
            context, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                              'network_id': [snat_network_id],
                              'device_id': [host_or_vrf]})
        snat_ip = None
        if not snat_ports or not snat_ports[0]['fixed_ips']:
            if snat_ports:
                # Fixed IP disappeared
                self.db_plugin.delete_port(context, snat_ports[0]['id'])
            # Note that the following port is created for only getting
            # an IP assignment in the subnet used for SNAT IPs.
            # The host or VRF for which this SNAT IP is allocated is
            # coded in the device_id.
            attrs = {'port': {'device_id': host_or_vrf,
                              'device_owner': acst.DEVICE_OWNER_SNAT_PORT,
                              'tenant_id': snat_network_tenant_id,
                              'name': acst.HOST_SNAT_POOL_PORT,
                              'network_id': snat_network_id,
                              'mac_address': attributes.ATTR_NOT_SPECIFIED,
                              'fixed_ips': [{'subnet_id':
                                             snat_subnets[0]['id']}],
                              'admin_state_up': False}}
            port = self.db_plugin.create_port(context, attrs)
            if port and port['fixed_ips']:
                # The auto deletion of port logic looks for the port binding
                # hence we populate the port binding info here
                self._add_port_binding(context.session,
                                       port['id'], host_or_vrf)
                snat_ip = port['fixed_ips'][0]['ip_address']
            else:
                LOG.warning(_("SNAT-port creation failed for subnet "
                              "%(subnet_id)s on SNAT network "
                              "%(net_id)s. SNAT will not function on"
                              "host or vrf %(host_or_vrf)s for external "
                              "network %(ext_id)s"),
                            {'subnet_id': snat_subnets[0]['id'],
                             'net_id': snat_network_id,
                             'host_or_vrf': host_or_vrf,
                             'ext_id': network['id']})
                return {}
        elif snat_ports[0]['fixed_ips']:
            snat_ip = snat_ports[0]['fixed_ips'][0]['ip_address']

        return {'external_segment_name': network['name'],
                'host_snat_ip': snat_ip,
                'gateway_ip': snat_subnets[0]['gateway_ip'],
                'prefixlen':
                netaddr.IPNetwork(snat_subnets[0]['cidr']).prefixlen}

    def _add_ip_mapping_details(self, context, port, host, owned_addr,
                                details):
        """Add information about IP mapping for DNAT/SNAT."""
        if not self.fabric_l3:
            return
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
        core_plugin = context._plugin

        fips_filter = [port['id']]
        if owned_addr:
            # If another port has a fixed IP that is same as an owned address,
            # then steal that port's floating IP
            other_ports = core_plugin.get_ports(
                context,
                filters={
                    'network_id': [port['network_id']],
                    'fixed_ips': {'ip_address': owned_addr}})
            fips_filter.extend([p['id'] for p in other_ports])
        fips = l3plugin.get_floatingips(
            context,
            filters={'port_id': fips_filter})

        ext_nets = core_plugin.get_networks(
            context,
            filters={'name': self.apic_manager.ext_net_dict.keys()})
        ext_nets = {n['id']: n for n in ext_nets
                    if self._is_nat_enabled_on_ext_net(n) and
                    not self._is_edge_nat(
                        self.apic_manager.ext_net_dict[n['name']])}
        fip_ext_nets = set()

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
                self._allocate_snat_ip(
                    context, host, network))
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

    def _add_network_details(self, context, port, owned_addr, details):
        details['allowed_address_pairs'] = port['allowed_address_pairs']
        details['enable_dhcp_optimization'] = self.enable_dhcp_opt
        details['enable_metadata_optimization'] = self.enable_metadata_opt
        # mark owned addresses from allowed-address pairs as 'active'
        owned_addr = set(owned_addr)
        for allowed in details['allowed_address_pairs']:
            if allowed['ip_address'] in owned_addr:
                allowed['active'] = True
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

    # RPC Method
    def ip_address_owner_update(self, context, **kwargs):
        if not kwargs.get('ip_owner_info'):
            return
        ports_to_update = self.update_ip_owner(kwargs['ip_owner_info'])
        for p in ports_to_update:
            LOG.debug("Ownership update for port %s", p)
            self.notify_port_update(p)

    def sync_init(f):
        def inner(inst, *args, **kwargs):
            if not inst.synchronizer:
                inst.synchronizer = (
                    APICMechanismDriver.get_base_synchronizer(inst))
                inst.router_synchronizer = (
                    APICMechanismDriver.get_router_synchronizer(
                        inst.l3_plugin))
                inst.synchronizer.sync_base()
                inst.router_synchronizer.sync_router()
            if args and isinstance(args[0], driver_context.NetworkContext):
                if (args[0]._plugin_context.is_admin and
                        args[0].current['name'] == acst.APIC_SYNC_NETWORK):
                    inst.synchronizer._sync_base()
                    inst.router_synchronizer._sync_router()
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
        if not context.bottom_bound_segment:
            LOG.debug("Port %s is not bound to a segment", port)
            return
        seg = None
        if (context.bottom_bound_segment.get(api.NETWORK_TYPE)
                in [constants.TYPE_VLAN]):
            seg = context.bottom_bound_segment.get(api.SEGMENTATION_ID)
        # hosts on which this vlan is provisioned
        host = context.host
        # Create a static path attachment for the host/epg/switchport combo
        with self.apic_manager.apic.transaction() as trs:
            self.apic_manager.ensure_path_created_for_port(
                tenant_id, epg_name, host, seg,
                app_profile_name=self._get_network_app_profile(
                    context.network.current), transaction=trs)

    def _perform_interface_port_operations(self, context, port, network,
                                           is_delete=False):
        router_id = port.get('device_id')
        if not router_id:
            return
        router = self.l3_plugin.get_router(context._plugin_context, router_id)

        # Other L3 plugins (e.g. ASR) create db-only routers, which
        # are indicated by an empty string tenant. Don't do anything
        # for these devices
        if router['tenant_id'] == '':
            return

        bd_name = self.name_mapper.bridge_domain(
            context, network['id'],
            openstack_owner=network['tenant_id'])
        bd_tenant = self._get_network_aci_tenant(network)

        is_vrf_per_router = self._is_vrf_per_router(router)
        with self.apic_manager.apic.transaction() as trs:
            if is_vrf_per_router:
                vrf_info = self._get_router_vrf(router)
                if is_delete:
                    # point BD back to the default VRF for this tenant
                    # if router is not connected to any subnet anymore
                    intf_ports = context._plugin.get_ports(
                        context._plugin_context,
                        filters={'device_owner':
                                 [n_constants.DEVICE_OWNER_ROUTER_INTF],
                                 'device_id': [router['id']],
                                 'network_id': [network['id']]})
                    if not [p for p in intf_ports if p['id'] != port['id']]:
                        vrf_default = self._get_network_vrf(context, network)
                        self.apic_manager.set_context_for_bd(
                            bd_tenant, bd_name, vrf_default['aci_name'],
                            transaction=trs)
                else:
                    self.apic_manager.set_context_for_bd(
                        bd_tenant, bd_name, vrf_info['aci_name'],
                        transaction=trs)

            if not router.get('external_gateway_info'):
                return

            ext_net_id = router['external_gateway_info'].get('network_id')
            ext_net = context._plugin.get_network(context._plugin_context,
                                                  ext_net_id)
            net_info = self.apic_manager.ext_net_dict.get(ext_net['name'])
            if not net_info:
                return

            nat_enabled = self._is_nat_enabled_on_ext_net(ext_net)
            is_edge_nat = nat_enabled and self._is_edge_nat(net_info)
            if not nat_enabled or is_edge_nat:
                if self.per_tenant_context:
                    os_owner = (router['tenant_id'] if is_edge_nat
                                else ext_net['tenant_id'])
                    l3out = self.name_mapper.l3_out(
                        context, ext_net_id, openstack_owner=os_owner,
                        prefix='%s-' % router['id'] if (is_vrf_per_router and
                                                        is_edge_nat) else '')
                else:
                    # There is exactly one shadow L3Out for all tenants since
                    # there is exactly one VRF for all tenants
                    l3out = self.name_mapper.l3_out(context, ext_net_id)

                if is_edge_nat:
                    l3out = self._get_shadow_name_for_nat(l3out,
                                                          is_edge_nat=True)
                elif self._is_pre_existing(net_info):
                    l3out = self.name_mapper.pre_existing(context,
                                                          ext_net['name'])

                if is_delete:
                    self.apic_manager.unset_l3out_for_bd(
                        bd_tenant, bd_name, l3out, transaction=trs)
                else:
                    self.apic_manager.set_l3out_for_bd(
                        bd_tenant, bd_name, l3out, transaction=trs)

    def _perform_gw_port_operations(self, context, port):
        router_id = port.get('device_id')
        network = context.network.current
        router_info = self.apic_manager.ext_net_dict.get(network['name'])
        l3out_name = self.name_mapper.l3_out(
            context, network['id'], openstack_owner=network['tenant_id'])
        network_tenant = self._get_network_aci_tenant(network)
        router = self.l3_plugin.get_router(context._plugin_context, router_id)

        # Other L3 plugins (e.g. ASR) create db-only routers, which
        # are indicated by an empty string tenant. Don't do anything
        # for these devices
        if router['tenant_id'] == '':
            return
        vrf = self.get_router_vrf_and_tenant(router)
        if router_id and router_info:
            external_epg = apic_manager.EXT_EPG
            # Get/Create contract
            arouter_id = self.name_mapper.router(
                context, router_id, openstack_owner=router['tenant_id'])
            cid = self.apic_manager.get_router_contract(
                arouter_id, owner=self._get_router_aci_tenant(router))
            if self._is_pre_existing(router_info) and ('external_epg' in
                                                       router_info):
                l3out_name_pre = self.name_mapper.pre_existing(
                    context, network['name'])
                external_epg = self.name_mapper.pre_existing(
                    context, router_info['external_epg'])
            else:
                l3out_name_pre = None

            nat_enabled = self._is_nat_enabled_on_ext_net(network)
            l3out_tenant = network_tenant
            if not nat_enabled and self._is_pre_existing(router_info):
                l3out_info = self._query_l3out_info(
                    l3out_name_pre, l3out_tenant)
                if not l3out_info:
                    raise PreExistingL3OutNotFound(l3out=l3out_name_pre)
                l3out_tenant = l3out_info['l3out_tenant']

            if nat_enabled:
                self._create_shadow_ext_net_for_nat(
                    context, l3out_name, external_epg, cid, network, router)
            else:
                with self.apic_manager.apic.transaction() as trs:
                    # Connect L3-out to tenant's VRF
                    self.apic_manager.set_context_for_external_routed_network(
                        l3out_tenant, l3out_name_pre or l3out_name,
                        vrf['aci_name'], transaction=trs)
                    # Set contract for L3Out EPGs
                    self.apic_manager.ensure_external_epg_consumed_contract(
                        l3out_name_pre or l3out_name, cid,
                        external_epg=external_epg,
                        owner=l3out_tenant, transaction=trs)
                    self.apic_manager.ensure_external_epg_provided_contract(
                        l3out_name_pre or l3out_name, cid,
                        external_epg=external_epg,
                        owner=l3out_tenant, transaction=trs)
                self._manage_bd_to_l3out_link(
                    context, router, l3out_name_pre or l3out_name)

    def _check_gw_port_operation(self, context, port):
        if port.get('device_owner') != n_constants.DEVICE_OWNER_ROUTER_GW:
            return
        router_id = port.get('device_id')
        network = context.network.current
        if not router_id or not network.get('router:external'):
            return

        router = self.l3_plugin.get_router(context._plugin_context, router_id)
        if router['tenant_id'] == '':
            return
        nat_disabled = not self._is_nat_enabled_on_ext_net(network)
        ext_info = self.apic_manager.ext_net_dict.get(network['name'], {})

        # If NAT is disabled on L3-out, then we can connect exactly one VRF
        # to the L3-out because shadow L3-outs are not created.
        # If each OS tenant has its own VRF, it means at any time only
        # one tenant can connect to the NAT-disabled L3-out.
        if self.per_tenant_context and nat_disabled:
            # get routers on this network belonging to other tenants
            router_gw_ports = context._plugin.get_ports(
                context._plugin_context.elevated(),
                filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_GW],
                         'network_id': [network['id']]})
            routers = self.l3_plugin.get_routers(
                context._plugin_context,
                filters={'id': [p['device_id'] for p in router_gw_ports]})
            routers = [r for r in routers
                       if r['tenant_id'] and
                       r['tenant_id'] != router['tenant_id']]
            if routers:
                raise OnlyOneRouterPermittedIfNatDisabled(net=network['name'])

        is_edge_nat = self._is_edge_nat(ext_info)
        if is_edge_nat:
            vlan_range = ext_info.get('vlan_range')
            if not vlan_range:
                raise EdgeNatVlanRangeNotFound(l3out=network['name'])
            elif not self.l3out_vlan_alloc.l3out_vlan_ranges.get(
                network['name']):
                raise EdgeNatBadVlanRange(l3out=network['name'])

        if self._is_pre_existing(ext_info):
            l3out_name_pre = self.name_mapper.pre_existing(
                context, network['name'])
            ext_net_tenant = self._get_network_aci_tenant(network)
            l3out_info = self._query_l3out_info(l3out_name_pre, ext_net_tenant,
                                                return_full=is_edge_nat)
            if not l3out_info:
                raise PreExistingL3OutNotFound(l3out=l3out_name_pre)

            # A NAT-disabled, pre-existing L3-out is directly connected to the
            # OS tenant's VRF. So the OS tenant's VRF must be visible to the
            # L3-out in ACI, i.e. the tenant's VRF must be in 'common' in ACI,
            # or the L3-out and the tenant's VRF must in the same ACI tenant.
            if nat_disabled:
                vrf_info = self._get_tenant_vrf(router['tenant_id'])
                vrf_aci_tenant = str(vrf_info['aci_tenant'])
                l3out_tenant = str(l3out_info['l3out_tenant'])
                if (vrf_aci_tenant != str(apic_manager.TENANT_COMMON) and
                        vrf_aci_tenant != l3out_tenant):
                    ac = self.apic_manager.apic
                    raise PreExistingL3OutInIncorrectTenant(
                        l3out_name=l3out_name_pre,
                        l3out_tenant=ac.fvTenant.name(
                            l3out_info['l3out_tenant']),
                        vrf_name=ac.fvCtx.name(vrf_info['aci_name']),
                        vrf_tenant=ac.fvTenant.name(vrf_info['aci_tenant']),
                        tenant_id=router['tenant_id'])
            elif is_edge_nat:
                l3out_str = str(l3out_info['l3out'])
                for match in re.finditer("u'ifInstT': u'([^']+)'",
                                         l3out_str):
                    if (match.group(1) != 'sub-interface' and
                            match.group(1) != 'ext-svi'):
                        raise EdgeNatWrongL3OutIFType(l3out=network['name'])
                for match in re.finditer("u'authType': u'([^']+)'",
                                         l3out_str):
                    if match.group(1) != 'none':
                        raise EdgeNatWrongL3OutAuthTypeForOSPF(
                            l3out=network['name'])
                for match in re.finditer(
                    "u'bfdIfP': {u'attributes': {((?!u'attributes': {).)*u"
                        "'type': u'([^']+)'", l3out_str):
                    if match.group(2) != 'none':
                        raise EdgeNatWrongL3OutAuthTypeForBGP(
                            l3out=network['name'])

    def _check_interface_port_operation(self, context, port):
        if port.get('device_owner') != n_constants.DEVICE_OWNER_ROUTER_INTF:
            return
        router_id = port.get('device_id')
        if not router_id:
            return
        router = self.l3_plugin.get_router(context._plugin_context, router_id)
        if router['tenant_id'] == '':
            return
        if self._is_vrf_per_router(router):
            network = context.network.current
            other_ports = context._plugin.get_ports(
                context._plugin_context,
                filters={
                    'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                    'network_id': [network['id']]})
            if [p for p in other_ports if p['device_id'] != router_id]:
                raise OnlyOneRouterPermittedIfVrfPerRouter(
                    tenant=network['tenant_id'], net=network['name'])

    def _perform_port_operations(self, context):
        # Get port
        port = context.current
        if not self.fabric_l3:
            if (self._is_port_bound(port) and
                    self._port_needs_static_path_binding(context)):
                self._perform_path_port_operations(context, port)
        elif port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_GW:
            self._perform_gw_port_operations(context, port)
        elif port.get('device_owner') == n_constants.DEVICE_OWNER_ROUTER_INTF:
            self._perform_interface_port_operations(context, port,
                                                    context.network.current)
        elif (self._is_port_bound(port) and
              self._port_needs_static_path_binding(context)):
            self._perform_path_port_operations(context, port)
        self._notify_ports_due_to_router_update(port)

    def _delete_gw_port_nat_disabled(self, context):
        port = context.current
        network = context.network.current
        router_info = self.apic_manager.ext_net_dict.get(network['name'], {})
        if not router_info:
            return

        network_tenant = self._get_network_aci_tenant(network)
        l3out_name = self.name_mapper.l3_out(
            context, network['id'],
            openstack_owner=network['tenant_id'])
        l3out_name_pre = (
            self.name_mapper.pre_existing(context, network['name'])
            if self._is_pre_existing(router_info) else None)
        router = self.l3_plugin.get_router(
            context._plugin_context, port.get('device_id'))

        # Other L3 plugins (e.g. ASR) create db-only routers, which
        # are indicated by an empty string tenant. Don't do anything
        # for these devices
        if router['tenant_id'] == '':
            return
        arouter_id = self.name_mapper.router(
            context, port.get('device_id'),
            openstack_owner=router['tenant_id'])

        self._manage_bd_to_l3out_link(
            context, router, l3out_name_pre or l3out_name, unlink=True)

        # check if there are other routers
        is_last_gw_port = self._is_last_gw_port(context, port, router)

        with self.apic_manager.apic.transaction() as trs:
            if not self._is_pre_existing(router_info):
                self.apic_manager.delete_external_epg_contract(
                    arouter_id, l3out_name, transaction=trs)
            else:
                external_epg = self.name_mapper.pre_existing(
                    context,
                    router_info.get('external_epg', apic_manager.EXT_EPG))
                l3out_info = self._query_l3out_info(l3out_name_pre,
                                                    network_tenant)
                contract_id = 'contract-%s' % router['id']
                if not l3out_info:
                    return
                network_tenant = l3out_info['l3out_tenant']
                self.apic_manager.unset_contract_for_external_epg(
                    l3out_name_pre, contract_id, external_epg=external_epg,
                    owner=network_tenant, provided=True,
                    transaction=trs)
                self.apic_manager.unset_contract_for_external_epg(
                    l3out_name_pre, contract_id, external_epg=external_epg,
                    owner=network_tenant, provided=False,
                    transaction=trs)

            # detach VRF from L3-out if last router
            if is_last_gw_port:
                self.apic_manager.set_context_for_external_routed_network(
                    network_tenant, l3out_name_pre or l3out_name, None,
                    transaction=trs)

    def _get_active_path_count(self, context, host, segment):
        return context._plugin_context.session.query(
            models.PortBindingLevel).filter_by(
                host=host, segment_id=segment['id']).count()

    @lockutils.synchronized('apic-portlock')
    def _delete_port_path(self, context, atenant_id, anetwork_id,
                          app_profile_name, host, segment):
        if not self._get_active_path_count(context, host, segment):
            self.apic_manager.ensure_path_deleted_for_port(
                atenant_id, anetwork_id, host,
                app_profile_name=app_profile_name)

    def _delete_path_if_last(self, context, host=None, segment=None):
        host = host or context.host
        segment = segment or context.bottom_bound_segment
        if not self._get_active_path_count(context, host, segment):
            atenant_id = self._get_network_aci_tenant(context.network.current)
            network_id = context.network.current['id']
            epg_name = self.name_mapper.endpoint_group(context, network_id)
            self._delete_port_path(
                context, atenant_id, epg_name,
                self._get_network_app_profile(context.network.current),
                host, segment)

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
            elif (self._is_nat_enabled_on_ext_net(network) and
                    not self._is_edge_nat(
                        self.apic_manager.ext_net_dict[network['name']])):
                l3out_name = self.name_mapper.l3_out(
                    context, network['id'],
                    openstack_owner=network['tenant_id'])
                bd_id = self._get_ext_bd_for_ext_net(l3out_name)
                return tenant_id, bd_id, gateway_ip

    def _notify_ports_on_subnets(self, context, network_id, subnets=None):
        if not subnets:
            return
        context._plugin_context.session.expunge_all()
        ports = context._plugin.get_ports(
            context._plugin_context.elevated(), {'network_id': [network_id]})
        for port in ports:
            if set([x['subnet_id'] for x in port['fixed_ips']]) & set(subnets):
                if (self._is_port_bound(port) and
                        port['id'] != context.current['id']):
                    self.notifier.port_update(context._plugin_context, port)

    def create_port_precommit(self, context):
        if not self.fabric_l3:
            return
        port = context.current
        network = context.network.current
        self._check_gw_port_operation(context, port)
        self._check_interface_port_operation(context, port)
        if (network.get('router:external') and
                port.get('device_owner').startswith('compute:')):
            if not self._is_nat_enabled_on_ext_net(network):
                raise VMsDisallowedOnExtNetworkIfNatDisabled(
                    net=network['name'])
            elif self._is_edge_nat(
                self.apic_manager.ext_net_dict.get(network['name'])):
                raise VMsDisallowedOnExtNetworkIfEdgeNat(net=network['name'])

    def create_port_postcommit(self, context):
        self._perform_port_operations(context)
        if context.current['device_owner'] == n_constants.DEVICE_OWNER_DHCP:
            # Notify ports in the DHCP subnet
            subs = [x['subnet_id'] for x in context.current['fixed_ips']]
            self._notify_ports_on_subnets(
                context, context.current['network_id'], subs)

    def update_port_precommit(self, context):
        if not self.fabric_l3:
            return
        self._check_gw_port_operation(context, context.current)
        self._check_interface_port_operation(context, context.current)

    def update_port_postcommit(self, context):
        if (self._port_needs_static_path_binding(context, use_original=True)
            and context.original_host and (context.original_host !=
                                           context.host)):
            # The VM was migrated
            self._delete_path_if_last(
                context, host=context.original_host,
                segment=context.original_bottom_bound_segment)
            self._release_dynamic_segment(context, use_original=True)
        self._perform_port_operations(context)
        port = context.current
        if (port.get('binding:vif_details') and
                port['binding:vif_details'].get('dvs_port_group_name')) and (
                self.dvs_notifier):
            self.dvs_notifier.update_postcommit_port_call(
                context.current,
                context.original,
                context.network.network_segments[0],
                context.host
            )
        if context.current['device_owner'] == n_constants.DEVICE_OWNER_DHCP:
            if context.current['fixed_ips'] != context.original['fixed_ips']:
                # Notify on modified subnets
                curr_subs = set([x['subnet_id'] for x in
                                 context.current['fixed_ips']])
                old_subs = set([x['subnet_id'] for x in
                                context.original['fixed_ips']])
                diff_subs = curr_subs ^ old_subs
                self._notify_ports_on_subnets(
                    context, context.current['network_id'], diff_subs)

    def delete_port_postcommit(self, context):
        port = context.current
        network = context.network.current
        if (self._port_needs_static_path_binding(context) and
                self._is_port_bound(port) and context.bottom_bound_segment):
            self._delete_path_if_last(context)
            self._release_dynamic_segment(context)
        if self.fabric_l3:
            owner = port.get('device_owner')
            if owner == n_constants.DEVICE_OWNER_ROUTER_GW:
                if self._is_nat_enabled_on_ext_net(network):
                    self._delete_shadow_ext_net_for_nat(context, port, network)
                else:
                    self._delete_gw_port_nat_disabled(context)
            elif owner == n_constants.DEVICE_OWNER_ROUTER_INTF:
                self._perform_interface_port_operations(context, port, network,
                                                        is_delete=True)

        self._notify_ports_due_to_router_update(port)
        if (port.get('binding:vif_details') and
                port['binding:vif_details'].get('dvs_port_group_name')) and (
                self.dvs_notifier):
            self.dvs_notifier.delete_port_call(
                context.current,
                context.original,
                context.network.network_segments[0],
                context.host
            )

    def update_network_precommit(self, context):
        if context.current['name'] == acst.APIC_SYNC_NETWORK:
            raise aexc.ReservedSynchronizationName()
        super(APICMechanismDriver, self).update_network_precommit(context)

    @sync_init
    def create_network_postcommit(self, context):
        # The following validation is not happening in the precommit to avoid
        # database lock timeout
        if context.current['name'] == acst.APIC_SYNC_NETWORK:
            raise aexc.ReservedSynchronizationName()
        tenant_id = self._get_network_aci_tenant(context.current)
        network_id = context.current['id']
        network_name = context.current['name']
        # Convert to APIC IDs
        bd_name = self.name_mapper.bridge_domain(
            context, network_id, openstack_owner=context.current['tenant_id'])
        epg_name = self.name_mapper.endpoint_group(context, network_id)
        if not context.current.get('router:external'):
            vrf = self._get_network_vrf(context, context.current)

            # Create BD and EPG for this network
            app_profile_name = self._get_network_app_profile(context.current)
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.ensure_bd_created_on_apic(
                    tenant_id, bd_name, ctx_owner=vrf['aci_tenant'],
                    ctx_name=vrf['aci_name'], transaction=trs,
                    unicast_route=self.fabric_l3)
                self.apic_manager.ensure_epg_created(
                    tenant_id, epg_name,
                    app_profile_name=app_profile_name, bd_name=bd_name,
                    transaction=trs)
            self.apic_manager.update_name_alias(
                self.apic_manager.apic.fvBD, tenant_id, bd_name,
                nameAlias=network_name)
            self.apic_manager.update_name_alias(
                self.apic_manager.apic.fvAEPg, tenant_id, app_profile_name,
                epg_name, nameAlias=network_name)
            # set the tenant or application profile nameAlias if this is the
            # first network being created under this tenant
            if (context.current['tenant_id'] in
                    self.tenants_with_name_alias_set):
                return
            tenant_name_alias = self.name_mapper.get_tenant_name(
                context.current['tenant_id'], require_keystone_session=True)
            if not tenant_name_alias:
                return
            if self.single_tenant_mode:
                self.apic_manager.update_name_alias(
                    self.apic_manager.apic.fvAp, tenant_id,
                    app_profile_name, nameAlias=tenant_name_alias)
                self.tenants_with_name_alias_set.add(
                    context.current['tenant_id'])
            elif tenant_id != apic_manager.TENANT_COMMON:
                self.apic_manager.update_name_alias(
                    self.apic_manager.apic.fvTenant, tenant_id,
                    nameAlias=tenant_name_alias)
                self.tenants_with_name_alias_set.add(
                    context.current['tenant_id'])
        elif self.fabric_l3:
            self._create_real_external_network(context, context.current)

    def update_network_postcommit(self, context):
        super(APICMechanismDriver, self).update_network_postcommit(context)
        if (not context.current.get('router:external') and
                context.original['name'] != context.current['name']):
            tenant_id = self._get_network_aci_tenant(context.current)
            app_profile_name = self._get_network_app_profile(context.current)
            network_id = context.current['id']
            network_name = context.current['name']
            bd_name = self.name_mapper.bridge_domain(
                context, network_id,
                openstack_owner=context.current['tenant_id'])
            epg_name = self.name_mapper.endpoint_group(context,
                                                       network_id)
            self.apic_manager.update_name_alias(
                self.apic_manager.apic.fvBD, tenant_id, bd_name,
                nameAlias=network_name)
            self.apic_manager.update_name_alias(
                self.apic_manager.apic.fvAEPg, tenant_id, app_profile_name,
                epg_name, nameAlias=network_name)

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
        context.subnet_scope = self.net_cons.get_subnet_scope(
            str(self.name_mapper.tenant(context, network['tenant_id'])),
            network['name'],
            subnet['cidr'])
        if context.subnet_scope == net_cons.SCOPE_DENY:
            raise SubnetDisallowedByNetConstraints(cidr=subnet['cidr'],
                                                   net=network['name'])
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

    def create_subnet_postcommit(self, context):
        if not self.fabric_l3:
            return
        info = self._get_subnet_info(context, context.current)
        if info:
            tenant_id, network_id, gateway_ip = info
            # Create subnet on BD
            self.apic_manager.ensure_subnet_created_on_apic(
                tenant_id, network_id, gateway_ip,
                scope=getattr(context, 'subnet_scope', None))
        self.notify_subnet_update(context.current)

    def update_subnet_postcommit(self, context):
        if self.fabric_l3 and (context.current['gateway_ip'] !=
                               context.original['gateway_ip']):
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
        if self.fabric_l3 and info:
            tenant_id, network_id, gateway_ip = info
            self.apic_manager.ensure_subnet_deleted_on_apic(
                tenant_id, network_id, gateway_ip)
        self.notify_subnet_update(context.current)

    def _is_port_bound(self, port):
        return port[portbindings.VIF_TYPE] not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _is_opflex_type(self, net_type):
        return net_type == ofcst.TYPE_OPFLEX

    def _is_supported_non_opflex_type(self, net_type):
        return net_type in [constants.TYPE_VLAN]

    def _is_apic_network(self, network):
        return self._is_opflex_type(network['provider:network_type'])

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

    def notify_port_update_for_fip(self, port_id, context=None):
        context = context or nctx.get_admin_context()
        core_plugin = manager.NeutronManager.get_plugin()
        try:
            port = core_plugin.get_port(context, port_id)
        except n_exc.PortNotFound:
            return
        ports_to_notify = [port_id]
        fixed_ips = [x['ip_address'] for x in port['fixed_ips']]
        if fixed_ips:
            addr_pair = (
                context.session.query(n_addr_pair_db.AllowedAddressPair)
                .join(models_v2.Port)
                .filter(models_v2.Port.network_id == port['network_id'])
                .filter(n_addr_pair_db.AllowedAddressPair.ip_address.in_(
                    fixed_ips)).all())
            ports_to_notify.extend([x['port_id'] for x in addr_pair])
        for p in sorted(ports_to_notify):
            self.notify_port_update(p, context)

    def notify_subnet_update(self, subnet, context=None):
        context = context or nctx.get_admin_context()
        self.notifier.subnet_update(context, subnet)

    def _get_ext_epg_for_ext_net(self, l3out_name):
        return "EXT-epg-%s" % l3out_name

    def _get_ext_bd_for_ext_net(self, l3out_name):
        return "EXT-bd-%s" % l3out_name

    def _get_nat_vrf_for_ext_net(self, l3out_name):
        return "NAT-vrf-%s" % l3out_name

    def _get_shadow_name_for_nat(self, name, is_edge_nat=False):
        if is_edge_nat:
            return "Auto-%s" % name
        else:
            return "Shd-%s" % name

    def _get_ext_allow_all_contract(self, network):
        return "EXT-%s-allow-all" % network['id']

    def _get_snat_db_network_name(self, network):
        return acst.HOST_SNAT_NETWORK_PREFIX + network['id']

    # return True if key exists in req_dict
    def _trim_tDn_from_dict(self, req_dict, key):
        try:
            if req_dict.get(key) is not None:
                del req_dict['tDn']
                return True
            else:
                return False
        except KeyError:
            return True

    def _trim_keys_from_dict(self, req_dict, keys, encap, l3p_name):
        for key in keys:
            try:
                del req_dict[key]
            except KeyError:
                pass

        # remove the default value parameter and replace encap
        if (req_dict.get('targetDscp') and
                req_dict['targetDscp'] == 'unspecified'):
            del req_dict['targetDscp']
        if req_dict.get('addr') and req_dict['addr'] == '0.0.0.0':
            del req_dict['addr']
        if req_dict.get('encap'):
            if req_dict['encap'] == 'unknown':
                del req_dict['encap']
            elif req_dict['encap'].startswith('vlan-'):
                req_dict['encap'] = encap

        # this is for l3extRsEctx case that it
        # doesn't allow tDn being present
        if self._trim_tDn_from_dict(req_dict, 'tnFvCtxName'):
            req_dict['tnFvCtxName'] = l3p_name
        # this is for l3extRsNdIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnNdIfPolName')
        # this is for l3extRsDampeningPol/l3extRsInterleakPol case
        self._trim_tDn_from_dict(req_dict, 'tnRtctrlProfileName')
        # this is for ospfRsIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnOspfIfPolName')
        # this is for l3extRs[I|E]ngressQosDppPol case
        self._trim_tDn_from_dict(req_dict, 'tnQosDppPolName')
        # this is for bfdRsIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnBfdIfPolName')
        # this is for bgpRsPeerPfxPol case
        self._trim_tDn_from_dict(req_dict, 'tnBgpPeerPfxPolName')
        # this is for eigrpRsIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnEigrpIfPolName')

        for value in req_dict.values():
            if isinstance(value, dict):
                self._trim_keys_from_dict(value, keys, encap, l3p_name)
            elif isinstance(value, list):
                for element in value:
                    if isinstance(element, dict):
                        self._trim_keys_from_dict(element, keys,
                                                  encap, l3p_name)
        return req_dict

    def _clone_l3out(self, context, network_tenant, router_tenant, vrf, es,
                     es_name, encap):
        pre_es_name = self.name_mapper.pre_existing(context, es['name'])
        l3out_info = self._query_l3out_info(pre_es_name, network_tenant,
                                            return_full=True)

        old_tenant = self.apic_manager.apic.fvTenant.rn(
            l3out_info['l3out_tenant'])
        new_tenant = self.apic_manager.apic.fvTenant.rn(router_tenant)
        old_l3_out = self.apic_manager.apic.l3extOut.rn(pre_es_name)
        new_l3_out = self.apic_manager.apic.l3extOut.rn(es_name)

        request = {}
        request['children'] = l3out_info['l3out']
        request['attributes'] = {"rn": new_l3_out}

        # trim the request
        keys = (['l3extInstP', 'l3extRtBDToOut',
                 'l3extExtEncapAllocator',
                 'l3extRsOutToBDPublicSubnetHolder', 'modTs',
                 'uid', 'lcOwn', 'monPolDn', 'forceResolve',
                 'rType', 'state', 'stateQual', 'tCl', 'tType',
                 'type', 'tContextDn', 'tRn', 'tag', 'name',
                 'configIssues'])
        request = self._trim_keys_from_dict(request, keys, encap, vrf)
        final_req = {}
        final_req['l3extOut'] = request
        request_json = jsonutils.dumps(final_req)
        if old_tenant != new_tenant:
            request_json = re.sub(old_tenant, new_tenant, request_json)
        request_json = re.sub(old_l3_out, new_l3_out, request_json)
        request_json = re.sub('{},*', '', request_json)

        self.apic_manager.apic.post_body(
            self.apic_manager.apic.l3extOut.mo,
            request_json,
            router_tenant,
            es_name)

    def get_router_vrf_and_tenant(self, router):
        return (self._get_router_vrf(router) if self._is_vrf_per_router(router)
                else self._get_tenant_vrf(router['tenant_id']))

    def _create_shadow_ext_net_for_nat(self, context, l3out_name, ext_epg_name,
                                       router_contract, network, router):
        vrf_info = self.get_router_vrf_and_tenant(router)
        nat_epg_name = self._get_ext_epg_for_ext_net(l3out_name)

        net_info = self.apic_manager.ext_net_dict.get(network['name'])
        is_edge_nat = self._is_edge_nat(net_info)
        shadow_ext_epg = self._get_shadow_name_for_nat(ext_epg_name,
                                                       is_edge_nat)

        is_vrf_per_router = self._is_vrf_per_router(router)
        if self.per_tenant_context:
            shadow_l3out = self.name_mapper.l3_out(
                context, network['id'],
                openstack_owner=router['tenant_id'],
                prefix='%s-' % router['id'] if is_vrf_per_router else '')
        else:
            # There is exactly one shadow L3Out for all tenants since there
            # is exactly one VRF for all tenants
            shadow_l3out = self.name_mapper.l3_out(context, network['id'])

        shadow_l3out = self._get_shadow_name_for_nat(
            shadow_l3out, is_edge_nat)
        nat_epg_tenant = self._get_network_aci_tenant(network)

        with self.apic_manager.apic.transaction(None) as trs:
            # create shadow L3-out and shadow external-epg
            # This goes on the no-nat VRF (original L3 context)
            # Note: Only NAT l3Out may exist in a different tenant
            # (eg. COMMON). NO NAT L3Outs always exists in the original
            # network tenant

            # don't need to explicitly create the shadow l3out in this case
            # because we are going to query APIC then use the pre-existing
            # l3out as a template then clone it accordingly
            if is_edge_nat and self._is_pre_existing(net_info):
                pass
            else:
                self.apic_manager.ensure_external_routed_network_created(
                    shadow_l3out, owner=vrf_info['aci_tenant'],
                    context=vrf_info['aci_name'], transaction=trs)

            # if its edge nat then we have to flesh
            # out this shadow L3 out in APIC
            if is_edge_nat:
                vlan_id = self.l3out_vlan_alloc.reserve_vlan(
                    network['name'], vrf_info['aci_name'],
                    vrf_info['aci_tenant'])
                encap = 'vlan-' + str(vlan_id)
                if not self._is_pre_existing(net_info):
                    address = net_info['cidr_exposed']
                    next_hop = net_info['gateway_ip']
                    switch = net_info['switch']
                    module, sport = net_info['port'].split('/', 1)

                    (self.apic_manager.
                        set_domain_for_external_routed_network(
                            shadow_l3out, owner=vrf_info['aci_tenant'],
                            transaction=trs))
                    self.apic_manager.ensure_logical_node_profile_created(
                        shadow_l3out, switch, module, sport,
                        encap, address, transaction=trs,
                        owner=vrf_info['aci_tenant'])
                    self.apic_manager.ensure_static_route_created(
                        shadow_l3out, switch, next_hop,
                        owner=vrf_info['aci_tenant'],
                        transaction=trs)
                else:
                    vrf = self.apic_manager.apic.fvCtx.name(
                        vrf_info['aci_name'])
                    self._clone_l3out(context, nat_epg_tenant,
                                      vrf_info['aci_tenant'],
                                      vrf, network,
                                      shadow_l3out, encap)

                self._manage_bd_to_l3out_link(
                    context, router, shadow_l3out)

            self.apic_manager.ensure_external_epg_created(
                shadow_l3out, external_epg=shadow_ext_epg,
                owner=vrf_info['aci_tenant'], transaction=trs)

            # make them use router-contract
            self.apic_manager.ensure_external_epg_consumed_contract(
                shadow_l3out, router_contract,
                external_epg=shadow_ext_epg,
                owner=vrf_info['aci_tenant'], transaction=trs)
            self.apic_manager.ensure_external_epg_provided_contract(
                shadow_l3out, router_contract,
                external_epg=shadow_ext_epg,
                owner=vrf_info['aci_tenant'], transaction=trs)

            # link up shadow external-EPG to NAT EPG
            if not is_edge_nat:
                self.apic_manager.associate_external_epg_to_nat_epg(
                    vrf_info['aci_tenant'], shadow_l3out, shadow_ext_epg,
                    nat_epg_name, target_owner=nat_epg_tenant,
                    app_profile_name=self. _get_network_app_profile(
                        network),
                    transaction=trs)

    def _delete_shadow_ext_net_for_nat(self, context, port, network):
        ext_info = self.apic_manager.ext_net_dict.get(network['name'])
        if not ext_info:
            return

        router = self.l3_plugin.get_router(
            context._plugin_context, port.get('device_id'))
        vrf_info = self.get_router_vrf_and_tenant(router)
        is_vrf_per_router = self._is_vrf_per_router(router)
        remove_contracts_only = False

        # Other L3 plugins (e.g. ASR) create db-only routers, which
        # are indicated by an empty string tenant. Don't do anything
        # for these devices
        if router['tenant_id'] == '':
            return
        if self.per_tenant_context:
            shadow_l3out = self.name_mapper.l3_out(
                context, network['id'],
                openstack_owner=router['tenant_id'],
                prefix='%s-' % router['id'] if is_vrf_per_router else '')
        else:
            shadow_l3out = self.name_mapper.l3_out(context, network['id'])

        remove_contracts_only = (
            not is_vrf_per_router and
            not self._is_last_gw_port(context, port, router))

        is_edge_nat = self._is_edge_nat(ext_info)
        shadow_l3out = self._get_shadow_name_for_nat(
            shadow_l3out, is_edge_nat)

        if remove_contracts_only:
            external_epg = apic_manager.EXT_EPG
            contract = 'contract-%s' % router['id']
            if self._is_pre_existing(ext_info) and 'external_epg' in ext_info:
                external_epg = self.name_mapper.pre_existing(
                    context, ext_info['external_epg'])
            shadow_ext_epg = self._get_shadow_name_for_nat(external_epg,
                                                           is_edge_nat)
            self.apic_manager.unset_contract_for_external_epg(
                shadow_l3out, contract, external_epg=shadow_ext_epg,
                owner=vrf_info['aci_tenant'], provided=True)
            self.apic_manager.unset_contract_for_external_epg(
                shadow_l3out, contract, external_epg=shadow_ext_epg,
                owner=vrf_info['aci_tenant'], provided=False)
        else:
            # delete shadow L3-out and shadow external-EPG
            self.apic_manager.delete_external_routed_network(
                shadow_l3out, owner=vrf_info['aci_tenant'])
            # if its edge nat then we have to release
            # the vlan associated with this shadow L3out
            if is_edge_nat:
                self.l3out_vlan_alloc.release_vlan(
                    network['name'], vrf_info['aci_name'],
                    vrf_info['aci_tenant'])

                self._manage_bd_to_l3out_link(
                    context, router, shadow_l3out, unlink=True)

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
        core_plugin = manager.NeutronManager.get_plugin()
        admin_ctx = nctx.get_admin_context()
        dev_owner = router_port['device_owner']
        skip = [n_constants.DEVICE_OWNER_ROUTER_INTF,
                n_constants.DEVICE_OWNER_ROUTER_GW]

        # With VRF-per-router, update all ports in the network when
        # there is an update to the router interface port
        if (dev_owner == n_constants.DEVICE_OWNER_ROUTER_INTF and
                self._is_vrf_per_router(router_port)):
            ports = core_plugin.get_ports(
                admin_ctx,
                filters={'network_id': [router_port['network_id']]})
            for p in ports:
                if p['device_owner'] not in skip and self._is_port_bound(p):
                    self.notifier.port_update(admin_ctx, p)
            return

        # Find ports whose DNAT/SNAT info may be affected due to change
        # in a router's connectivity to external/tenant network.
        if not self.nat_enabled:
            return
        if dev_owner == n_constants.DEVICE_OWNER_ROUTER_INTF:
            subnet_ids = self._get_port_subnets(router_port)
        elif dev_owner == n_constants.DEVICE_OWNER_ROUTER_GW:
            subnet_ids = self._get_router_interface_subnets(
                admin_ctx, [router_port['device_id']])
        else:
            return

        subnets = core_plugin.get_subnets(
            admin_ctx, filters={'id': list(subnet_ids)})
        nets = set([x['network_id'] for x in subnets])
        ports = core_plugin.get_ports(
            admin_ctx, filters={'network_id': list(nets)})
        for p in ports:
            if p['device_owner'] not in skip:
                port_sn_ids = self._get_port_subnets(p)
                if (subnet_ids & port_sn_ids) and self._is_port_bound(p):
                    self.notifier.port_update(admin_ctx, p)

    def _is_nat_enabled_on_ext_net(self, network):
        if not self.fabric_l3:
            return False
        ext_info = self.apic_manager.ext_net_dict.get(network['name'])
        if (self.nat_enabled and ext_info and
                network.get('router:external')):
            opt = ext_info.get('enable_nat', 'true')
            return opt.lower() in ['true', 'yes', '1']
        return False

    def _get_tenant(self, object):
        if self.single_tenant_mode:
            return self.single_tenant_name
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
        # NOTE This method does not account for VRFs created per router,
        #      use _get_router_vrf() for that case.
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
        vrf = {'aci_tenant': self.single_tenant_name,
               'aci_name': self.name_mapper.tenant(None, tenant_id)}
        if not self.single_tenant_mode:
            vrf['aci_tenant'] = (self.per_tenant_context and
                                 self.name_mapper.tenant(None, tenant_id) or
                                 apic_manager.TENANT_COMMON)
            vrf['aci_name'] = apic_manager.CONTEXT_SHARED
        elif not self.per_tenant_context:
            vrf['aci_name'] = apic_manager.CONTEXT_SHARED
        return vrf

    def _get_router_aci_tenant(self, router):
        if self.single_tenant_mode:
            return self.single_tenant_name
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
                             'tenant_id': network['tenant_id'],
                             'status': n_constants.NET_STATUS_DOWN}}
        snat_network = self.db_plugin.create_network(
            context._plugin_context, attrs)
        segment = {api.NETWORK_TYPE: constants.TYPE_LOCAL}
        ml2_db.add_network_segment(context._plugin_context,
                                   snat_network['id'], segment)

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
                            'tenant_id': snat_network['tenant_id'],
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
                raise PreExistingL3OutNotFound(l3out=l3out_name_pre)
            if not (l3out_info.get('vrf_name') and
                    l3out_info.get('vrf_tenant')):
                LOG.error(
                    _("External Routed Network %s doesn't have private "
                      "network set") % l3out_name_pre)
                return
            l3out_tenant = l3out_info['l3out_tenant']
            external_vrf = self.name_mapper.pre_existing(
                context, l3out_info['vrf_name'])
            external_vrf_tenant = self.name_mapper.pre_existing(
                context, l3out_info['vrf_tenant'])
            l3out_external_epg = self.name_mapper.pre_existing(
                context, net_info.get('external_epg', apic_manager.EXT_EPG))
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
                module, sport = net_info['port'].split('/', 1)
                self.apic_manager.ensure_external_routed_network_created(
                    l3out_name, owner=l3out_tenant,
                    context=external_vrf, transaction=trs)
                self.apic_manager.set_domain_for_external_routed_network(
                    l3out_name, owner=l3out_tenant, transaction=trs)
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

        # If NAT is enabled, create EPG and BD for external network. This EPG
        # will hold NAT-ed endpoints as well as ports of VM created in the
        # external network.
        if self._is_nat_enabled_on_ext_net(network):
            with self.apic_manager.apic.transaction() as trs:
                # create EPG, BD for external network and
                # connect to external VRF
                if not self._is_edge_nat(net_info):
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
                gw, plen = net_info.get('host_pool_cidr', '/').split('/', 1)
                if gw and plen:
                    if not self._is_edge_nat(net_info):
                        self.apic_manager.ensure_subnet_created_on_apic(
                            tenant_id, ext_bd_name, gw + '/' + plen,
                            transaction=trs)
                    # we still need this even in edge_nat mode
                    self._create_snat_ip_allocation_subnet(
                        context, network, net_info.get('host_pool_cidr'), gw)

                # make EPG use allow-everything contract
                if not self._is_edge_nat(net_info):
                    self.apic_manager.set_contract_for_epg(
                        tenant_id, ext_epg_name, contract_name,
                        app_profile_name=app_profile_name, transaction=trs)
                    self.apic_manager.set_contract_for_epg(
                        tenant_id, ext_epg_name, contract_name,
                        app_profile_name=app_profile_name, provider=True,
                        transaction=trs)

    def _delete_snat_ip_allocation_network(self, context, network):
        """This deletes all the SNAT pool resources we created in the DB """
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
            l3out_external_epg = self.name_mapper.pre_existing(
                context, net_info.get('external_epg', apic_manager.EXT_EPG))
        else:
            l3out_name_pre = None
            l3out_tenant = tenant_id
            l3out_external_epg = apic_manager.EXT_EPG

        # If NAT is enabled, delete EPG, BD for external network
        if (self._is_nat_enabled_on_ext_net(network) and
                not self._is_edge_nat(net_info)):
            with self.apic_manager.apic.transaction() as trs:
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

    def _query_l3out_info(self, l3out_name, tenant_id, return_full=False):
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
        if return_full:
            info['l3out'] = l3out_children
        return info

    def _is_pre_existing(self, ext_info):
        opt = ext_info.get('preexisting', 'false')
        return opt.lower() in ['true', 'yes', '1']

    def _is_edge_nat(self, ext_info):
        opt = ext_info.get('edge_nat', 'false')
        return opt.lower() in ['true', 'yes', '1']

    def _is_last_gw_port(self, context, gw_port, router):
        gw_port_filter = {
            'device_owner': [n_constants.DEVICE_OWNER_ROUTER_GW],
            'network_id': [gw_port['network_id']]}
        if self.per_tenant_context:
            # Narrow down the gateway-ports to the routers in this tenant
            tenant_routers = self.l3_plugin.get_routers(
                context._plugin_context.elevated(),
                filters={'tenant_id': [router['tenant_id']]})
            gw_port_filter['device_id'] = [r['id'] for r in tenant_routers]

        # Return false if there are other routers still connected
        router_gw_ports = context._plugin.get_ports(
            context._plugin_context.elevated(), filters=gw_port_filter)
        return (not [p for p in router_gw_ports if p['id'] != gw_port['id']])

    def _port_needs_static_path_binding(self, port_context,
                                        use_original=False):
        bound_seg = (port_context.original_bottom_bound_segment if use_original
                     else port_context.bottom_bound_segment)
        return (not self._is_apic_network(port_context.network.current) or
                (bound_seg and self._is_supported_non_opflex_type(
                    bound_seg[api.NETWORK_TYPE])))

    def _release_dynamic_segment(self, port_context, use_original=False):
        top = (port_context.original_top_bound_segment if use_original
               else port_context.top_bound_segment)
        btm = (port_context.original_bottom_bound_segment if use_original
               else port_context.bottom_bound_segment)
        if (top and btm and
                self._is_opflex_type(top[api.NETWORK_TYPE]) and
                self._is_supported_non_opflex_type(btm[api.NETWORK_TYPE])):
            # if there are no other ports bound to segment, release it
            num_binds = port_context._plugin_context.session.query(
                models.PortBindingLevel).filter_by(
                    segment_id=btm[api.ID]).filter(
                        models.PortBindingLevel.port_id !=
                        port_context.current['id']).count()
            if not num_binds:
                LOG.info("Releasing dynamic-segment %(s)s for port %(p)s",
                         {'s': btm, 'p': port_context.current['id']})
                port_context.release_dynamic_segment(btm[api.ID])

    def _manage_bd_to_l3out_link(self, context, router, l3out, unlink=False,
                                 transaction=None):
        # Find networks connected to this router, set/unset the link from
        # corresponding BDs to specified L3Out
        core_plugin = manager.NeutronManager.get_plugin()
        admin_ctx = nctx.get_admin_context()
        router_intf_ports = core_plugin.get_ports(
            admin_ctx,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                     'device_id': [router['id']]})
        networks = core_plugin.get_networks(
            admin_ctx,
            filters={'id': [p['network_id'] for p in router_intf_ports]})
        func = (self.apic_manager.unset_l3out_for_bd if unlink else
                self.apic_manager.set_l3out_for_bd)
        for net in networks:
            bd_tenant_name = self._get_network_aci_tenant(net)
            bd_name = self.name_mapper.bridge_domain(
                context, net['id'], openstack_owner=net['tenant_id'])
            func(bd_tenant_name, bd_name, l3out, transaction=transaction)

    def _is_vrf_per_router(self, object):
        if self.per_tenant_context and object.get('tenant_id'):
            tenant = str(self.name_mapper.tenant(None, object['tenant_id']))
            for vpr_tenant in self.vrf_per_router_tenants:
                if re.search(vpr_tenant, tenant):
                    return True
        return False

    def _get_router_vrf(self, router):
        tenant = self.name_mapper.tenant(None, router['tenant_id'])
        vrf_name = ('%s-%s' % (tenant, router['id'])
                    if self.single_tenant_mode else router['id'])
        return {'aci_name': vrf_name, 'aci_tenant': self._get_tenant(router)}

    def create_vrf_per_router(self, router, transaction=None):
        if self._is_vrf_per_router(router):
            vrf_info = self._get_router_vrf(router)
            self.apic_manager.ensure_context_enforced(
                owner=vrf_info['aci_tenant'], ctx_id=vrf_info['aci_name'],
                transaction=transaction)

    def delete_vrf_per_router(self, router, transaction=None):
        if self._is_vrf_per_router(router):
            vrf_info = self._get_router_vrf(router)
            self.apic_manager.ensure_context_deleted(
                owner=vrf_info['aci_tenant'], ctx_id=vrf_info['aci_name'],
                transaction=transaction)
