# Copyright (c) 2014 Cisco Systems
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

import base64
import hashlib
import hmac
import re
import sys
import tempfile

from apicapi import apic_client
from apicapi import apic_manager
from apicapi import apic_mapper
import mock
import netaddr
from neutron.api import extensions
from neutron.common import constants as n_constants
from neutron import context
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2  # noqa
from neutron.db import model_base
from neutron.db import models_v2  # noqa
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.tests import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from opflexagent import constants as ofcst
from oslo_serialization import jsonutils as json
# Mock the opflex agent type driver, and its constants,
# so that we can test port binding to opflex networks
T_DRV = "opflexagent.type_opflex"
sys.modules["opflexagent"] = mock.Mock()
sys.modules["opflexagent"].constants.TYPE_OPFLEX = 'opflex'
sys.modules["opflexagent"].constants.AGENT_TYPE_OPFLEX_OVS = (
    'OpFlex Open vSwitch agent')
sys.modules[T_DRV] = mock.Mock()
sys.modules[T_DRV].OpflexTypeDriver().get_type.return_value = 'opflex'
sys.modules[T_DRV].OpflexTypeDriver().allocate_tenant_segment.return_value = (
    {api.NETWORK_TYPE: ofcst.TYPE_OPFLEX,
     api.PHYSICAL_NETWORK: 'physnet1'})

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    mechanism_apic as md)
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    rpc as mech_rpc)
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import constants as acst
from apic_ml2.neutron.services.l3_router import apic_driver as driver
from apic_ml2.neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)

sys.modules["apicapi"].apic_manager.EXT_EPG = mocked.APIC_EXT_EPG


HOST_ID1 = 'ubuntu'
HOST_ID2 = 'rhel'
ENCAP = '101'

SUBNET_GATEWAY = '10.3.2.1'
SUBNET_CIDR = '10.3.1.0/24'
SUBNET_NETMASK = '24'

TEST_SEGMENT1 = 'test-segment1'
TEST_SEGMENT2 = 'test-segment2'

BOOKED_PORT_VALUE = 'myBookedPort'

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'
AGENT_TYPE = n_constants.AGENT_TYPE_OVS
AGENT_CONF = {'alive': True, 'binary': 'somebinary',
              'topic': 'sometopic', 'agent_type': AGENT_TYPE,
              'configurations': {'opflex_networks': None,
                                 'bridge_mappings': {'physnet1': 'br-eth1'}}}
AGENT_TYPE_DVS = acst.AGENT_TYPE_DVS
AGENT_CONF_DVS = {'alive': True, 'binary': 'anotherbinary',
                  'topic': 'anothertopic', 'agent_type': AGENT_TYPE_DVS,
                  'configurations': {'opflex_networks': None}}
AGENT_CONF_OPFLEX = {'alive': True, 'binary': 'somebinary',
                     'topic': 'sometopic',
                     'agent_type': ofcst.AGENT_TYPE_OPFLEX_OVS,
                     'configurations': {
                         'opflex_networks': None,
                         'bridge_mappings': {'physnet1': 'br-eth1'}}}
APIC_EXTERNAL_RID = '1.0.0.1'


def echo(context, id, prefix=''):
    return id if not prefix else (prefix + id)


def name(name):
    return name


def equal(x, y):
    return str(x) == str(y)


class ApicML2IntegratedTestBase(test_plugin.NeutronDbPluginV2TestCase,
                                mocked.ControllerMixin, mocked.ConfigMixin,
                                mocked.ApicDBTestBase):

    def setUp(self, service_plugins=None, ml2_opts=None):
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self, ml2_opts=ml2_opts)
        self.override_conf('integrated_topology_service', True,
                           'ml2_cisco_apic')
        self.override_conf('per_tenant_context', False,
                           'ml2_cisco_apic')
        self.override_conf('path_mtu', 1000, group='ml2')
        self.override_conf('global_physnet_mtu', 1000)
        self.override_conf('advertise_mtu', True, None)
        service_plugins = (
            service_plugins or
            {'L3_ROUTER_NAT': 'apic_ml2.neutron.services.l3_router.'
                              'l3_apic.ApicL3ServicePlugin'})
        mock.patch('apic_ml2.neutron.plugins.ml2.drivers.'
                   'cisco.apic.nova_client.NovaClient').start()
        apic_client.RestClient = mock.Mock()
        apic_manager.APICManager.ensure_infra_created_on_apic = mock.Mock()
        apic_manager.APICManager.ensure_bgp_pod_policy_created_on_apic = (
            mock.Mock())
        apic_mapper.ApicName.__eq__ = equal
        super(ApicML2IntegratedTestBase, self).setUp(
            PLUGIN_NAME, service_plugins=service_plugins)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.plugin.remove_networks_from_down_agents = mock.Mock()
        self.plugin.is_agent_down = mock.Mock(return_value=False)
        self.driver = self.plugin.mechanism_manager.mech_drivers[
            'cisco_apic_ml2'].obj
        self.synchronizer = mock.Mock()
        md.importutils = mock.Mock()
        md.APICMechanismDriver.get_base_synchronizer = mock.Mock(
            return_value=self.synchronizer)
        self.driver.name_mapper.aci_mapper.tenant = echo
        self.driver.apic_manager.apic = mock.Mock()
        self.driver.apic_manager.apic.transaction = self.fake_transaction
        self.rpc = self.driver.topology_endpoints[0]
        self.db = self.driver.apic_manager.db

        for switch in self.switch_dict:
            for module_port in self.switch_dict[switch]:
                module, port = module_port.split('/', 1)
                hosts = self.switch_dict[switch][module_port]
                for host in hosts:
                    self.driver.apic_manager.add_hostlink(
                        host, 'static', None, switch, module, port)

        self.mgr = self.driver.apic_manager
        self.mgr.apic.fvTenant.name = name
        self.mgr.apic.fvCtx.name = name
        self.l3_plugin = manager.NeutronManager.get_service_plugins()[
            'L3_ROUTER_NAT']
        self.driver.apic_manager.vmm_shared_secret = base64.b64encode(
            'dirtylittlesecret')
        self.driver.notifier = mock.Mock()

    def _mock_external_dict(self, data, is_edge_nat=False):
        self.driver.apic_manager.ext_net_dict = {}
        for x in data:
            self.driver.apic_manager.ext_net_dict.update(
                self._build_external_dict(x[0], x[1], is_edge_nat=is_edge_nat))

    def _build_external_dict(self, name, cidr_exposed, nat_enabled=True,
                             is_edge_nat=False):
        ext_info = {
            'enable_nat': 'True' if nat_enabled else 'False'
        }
        ext_info.update({
            'switch': mocked.APIC_EXT_SWITCH,
            'port': mocked.APIC_EXT_MODULE + '/' + mocked.APIC_EXT_PORT,
            'encap': mocked.APIC_EXT_ENCAP,
            'router_id': APIC_EXTERNAL_RID,
            'gateway_ip': str(netaddr.IPNetwork(cidr_exposed)[1]),
            'cidr_exposed': cidr_exposed})

        if is_edge_nat:
            ext_info['edge_nat'] = 'true'
            ext_info['vlan_range'] = '2000:2010'

        return {name: ext_info}

    def _register_agent(self, host, agent_cfg=AGENT_CONF):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.get_admin_context()
        agent = {'host': host}
        agent.update(agent_cfg)
        plugin.create_or_update_agent(ctx, agent)

    def _bind_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'compute:',
                         'device_id': 'someid'}}
        # Create EP with bound port
        req = self.new_update_request('ports', data, port_id,
                                      self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def _bind_dhcp_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'network:dhcp',
                         'device_id': 'someid'}}
        # Create EP with bound port
        req = self.new_update_request('ports', data, port_id,
                                      self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def _check_call_list(self, expected, observed):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        self.assertFalse(
            len(observed),
            msg='There are more calls than expected: %s' % str(observed))

    def _add_hosts_to_apic(self, num, vpc=False):
        for x in range(1, num + 1):
            self.db.add_hostlink(
                'h%s' % x, 'eth0' if vpc else 'static', None, str(x),
                '1', str(x))
            if vpc:
                self.db.add_hostlink(
                    'h%s' % x, 'eth1', None, str(x + 1), '1', str(x))
        self.rpc.peers = self.rpc._load_peers()

    def _get_gbp_details(self, port_id, host):
        return self.driver.get_gbp_details(
            context.get_admin_context(),
            device='tap%s' % port_id, host=host)

    def _request_endpoint_details(self, port_id, host, timestamp=None,
                                  request_id=None):
        return self.driver.request_endpoint_details(
            context.get_admin_context(),
            request={'device': 'tap%s' % port_id, 'timestamp': 0,
                     'request_id': 'request_id'}, host=host)


class ApicML2IntegratedTestCase(ApicML2IntegratedTestBase):

    def test_network_visibility(self):
        net = self.create_network(tenant_id='onetenant',
                                  expected_res_status=201)['network']

        # Visible by onetenant
        self.show_network(net['id'], tenant_id='onetenant',
                          expected_res_status=200)
        # Not visible by anothertenant
        self.show_network(net['id'], tenant_id='anothertenant',
                          expected_res_status=404)
        # Visible by admintenant
        self.show_network(net['id'], tenant_id='admintenant',
                          is_admin_context=True, expected_res_status=200)

    def test_shared_network_visibility(self):
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']

        # Visible by onetenant
        self.show_network(net['id'], tenant_id='onetenant',
                          expected_res_status=200)
        # Visible by anothertenant
        self.show_network(net['id'], tenant_id='anothertenant',
                          expected_res_status=200)
        # Visible by admintenant
        self.show_network(net['id'], tenant_id='admintenant',
                          is_admin_context=True, expected_res_status=200)

    def test_port_on_shared_non_opflex_network(self):
        self._register_agent('h1')
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub, tenant_id='anothertenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            self._bind_port_to_host(p1['id'], 'h1')
            # Called on the network's tenant
            self.mgr.ensure_path_created_for_port.assert_called_once_with(
                self._tenant(neutron_tenant='onetenant'),
                net['id'], 'h1', mock.ANY, transaction=mock.ANY,
                app_profile_name=self._app_profile(
                    neutron_tenant='onetenant'))

    def test_port_on_shared_opflex_network(self):
        self._register_agent('h1')
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub, tenant_id='anothertenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            # Bind port to trigger path binding
            self._bind_port_to_host(p1['id'], 'h1')
            self.driver._add_ip_mapping_details = mock.Mock()
            details = self._get_gbp_details(p1['id'], 'h1')
            self.assertEqual(self._tenant(neutron_tenant='onetenant'),
                             details['ptg_tenant'])
            self.assertEqual(self._app_profile(neutron_tenant='onetenant'),
                             details['app_profile_name'])
            self.assertEqual('onetenant',
                             details['tenant_id'])
            self.assertTrue(details['enable_dhcp_optimization'])
            self.assertEqual(1, len(details['subnets']))
            self.assertEqual(sub['subnet']['id'], details['subnets'][0]['id'])
            # Verify Interface MTU correctly set
            self.assertEqual(1000, details['interface_mtu'])

    def test_enhanced_subnet_options(self):
        self._register_agent('h1')
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            with self.port(subnet=sub, device_owner='network:dhcp',
                           tenant_id='onetenant') as dhcp:
                p1 = p1['port']
                dhcp = dhcp['port']
                self.assertEqual(net['id'], p1['network_id'])
                # Bind port to trigger path binding
                self._bind_port_to_host(p1['id'], 'h1')
                self.driver._add_ip_mapping_details = mock.Mock()
                self.driver.enable_metadata_opt = False
                details = self._get_gbp_details(p1['id'], 'h1')

                self.assertEqual(1, len(details['subnets']))
                # Verify that DNS nameservers are correctly set
                self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                                 details['subnets'][0]['dns_nameservers'])
                # Verify Default route via GW
                self.assertTrue({'destination': '0.0.0.0/0',
                                 'nexthop': '192.168.0.1'} in
                                details['subnets'][0]['host_routes'])

                # Verify Metadata route via DHCP
                self.assertTrue(
                    {'destination': '169.254.169.254/16',
                     'nexthop': dhcp['fixed_ips'][0]['ip_address']} in
                    details['subnets'][0]['host_routes'])

                # Verify no extra routes are leaking inside
                self.assertEqual(2, len(details['subnets'][0]['host_routes']))

                self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                                 details['subnets'][0]['dhcp_server_ips'])

    def _test_vrf_details(self, vrf_per_router=False):
        self._register_agent('h1')
        net = self.create_network(
            tenant_id=mocked.APIC_TENANT, is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        self.create_subnet(
            network_id=net['id'], cidr='192.168.2.0/24',
            ip_version=4, is_admin_context=True)
        net1 = self.create_network(
            tenant_id=mocked.APIC_TENANT, is_admin_context=True)['network']
        sub2 = self.create_subnet(
            network_id=net1['id'], cidr='192.168.4.0/24',
            ip_version=4, is_admin_context=True)
        router = self.create_router(api=self.ext_api,
                                    tenant_id=mocked.APIC_TENANT)['router']
        self.l3_plugin.add_router_interface(
            context.get_admin_context(), router['id'],
            {'subnet_id': sub['subnet']['id']})
        self.driver._add_ip_mapping_details = mock.Mock()
        with self.port(subnet=sub, tenant_id=mocked.APIC_TENANT) as p1:
            p1 = p1['port']
            self._bind_port_to_host(p1['id'], 'h1')
            details = self._get_gbp_details(p1['id'], 'h1')
            if self.driver.per_tenant_context and vrf_per_router:
                self.assertEqual('router:%s' % router['id'],
                                 details['l3_policy_id'])
                self.assertEqual(self._tenant(vrf=True),
                                 details['vrf_tenant'])
                self.assertEqual(
                    self._routed_network_vrf_name(router=router['id']),
                    details['vrf_name'])
                self.assertEqual(['192.168.0.0/24', '192.168.2.0/24'],
                                 details['vrf_subnets'])
            else:
                if self.driver.per_tenant_context:
                    self.assertEqual(mocked.APIC_TENANT,
                                     details['l3_policy_id'])
                else:
                    self.assertEqual('%s-shared' % self._tenant(vrf=True),
                                     details['l3_policy_id'])
                self.assertEqual(self._tenant(vrf=True),
                                 details['vrf_tenant'])
                self.assertEqual(self._network_vrf_name(),
                                 details['vrf_name'])
                self.assertEqual(['192.168.0.0/24', '192.168.2.0/24',
                                  '192.168.4.0/24'],
                                 details['vrf_subnets'])

        with self.port(subnet=sub2, tenant_id=mocked.APIC_TENANT) as p2:
            p2 = p2['port']
            self._bind_port_to_host(p2['id'], 'h1')
            details = self._get_gbp_details(p2['id'], 'h1')
            if self.driver.per_tenant_context:
                self.assertEqual(mocked.APIC_TENANT,
                                 details['l3_policy_id'])
            else:
                self.assertEqual('%s-shared' % self._tenant(vrf=True),
                                 details['l3_policy_id'])
            self.assertEqual(self._tenant(vrf=True),
                             details['vrf_tenant'])
            self.assertEqual(self._network_vrf_name(),
                             details['vrf_name'])
            self.assertEqual(['192.168.0.0/24', '192.168.2.0/24',
                              '192.168.4.0/24'],
                             details['vrf_subnets'])

    def test_vrf_details(self):
        self._test_vrf_details()

    def test_vrf_details_vrf_per_router(self):
        self.driver.vrf_per_router_tenants.append(mocked.APIC_TENANT)
        self._test_vrf_details(vrf_per_router=True)

    def test_add_router_interface_on_shared_net_by_port(self):
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        router = self.create_router(api=self.ext_api,
                                    expected_res_status=201)['router']
        with self.port(subnet=sub, tenant_id='anothertenant') as p1:
            self.mgr.add_router_interface = mock.Mock()
            self.l3_plugin.add_router_interface(
                context.get_admin_context(), router['id'],
                {'port_id': p1['port']['id']})
            self.mgr.add_router_interface.assert_called_once_with(
                self._tenant(neutron_tenant='onetenant'),
                self._scoped_name(router['id'], tenant='test-tenant'),
                net['id'],
                app_profile_name=self._app_profile(neutron_tenant='onetenant'))

            self.mgr.remove_router_interface = mock.Mock()
            # Test removal
            self.l3_plugin.remove_router_interface(
                context.get_admin_context(), router['id'],
                {'port_id': p1['port']['id']})
            self.mgr.remove_router_interface.assert_called_once_with(
                self._tenant(neutron_tenant='onetenant'),
                self._scoped_name(router['id'], tenant='test-tenant'),
                net['id'],
                app_profile_name=self._app_profile(neutron_tenant='onetenant'))

    def test_add_router_interface_on_shared_net_by_subnet(self):
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True,
            tenant_id='anothertenant')['subnet']
        router = self.create_router(api=self.ext_api,
                                    expected_res_status=201)['router']

        self.mgr.add_router_interface = mock.Mock()

        self.l3_plugin.add_router_interface(
            context.get_admin_context(), router['id'],
            {'subnet_id': sub['id']})
        self.mgr.add_router_interface.assert_called_once_with(
            self._tenant(neutron_tenant='onetenant'),
            self._scoped_name(router['id'], tenant='test-tenant'),
            net['id'],
            app_profile_name=self._app_profile(neutron_tenant='onetenant'))

        self.mgr.remove_router_interface = mock.Mock()
        # Test removal
        self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router['id'],
            {'subnet_id': sub['id']})
        self.mgr.remove_router_interface.assert_called_once_with(
            self._tenant(neutron_tenant='onetenant'),
            self._scoped_name(router['id'], tenant='test-tenant'),
            net['id'],
            app_profile_name=self._app_profile(neutron_tenant='onetenant'))

    def test_sync_on_demand(self):
        self.synchronizer.reset_mock()
        self.create_network(name=acst.APIC_SYNC_NETWORK, is_admin_context=True)
        self.assertTrue(self.synchronizer._sync_base.called)

    def test_sync_on_demand_no_admin(self):
        self.synchronizer.reset_mock()
        self.create_network(name=acst.APIC_SYNC_NETWORK)
        self.assertFalse(self.synchronizer._sync_base.called)

    def test_sync_on_demand_not(self):
        self.synchronizer.reset_mock()
        self.create_network(name='some_name', is_admin_context=True,
                            expected_res_status=201)
        self.assertFalse(self.synchronizer._sync_base.called)

    def test_attestation(self):
        self._register_agent('h1')
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201)['network']
        expected_attestation = {'ports': [{'switch': '102',
                                           'port': 'eth4/23'}],
                                'policy-space-name': self._tenant(
                                    neutron_tenant='onetenant'),
                                'endpoint-group-name': (
                                    self._app_profile(
                                        neutron_tenant='onetenant') + '|' +
                                    net['id'])}
        sub = self.create_subnet(
            tenant_id='onetenant', network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        self.driver.apic_manager.get_switch_and_port_for_host = mock.Mock(
            return_value=[('102', 'eth4/23')])
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            p1 = p1['port']
            self._bind_port_to_host(p1['id'], 'h1')
            self.driver._add_ip_mapping_details = mock.Mock()
            # Mock switch, module and port for host
            details = self._get_gbp_details(p1['id'], 'h1')
            # Test attestation exists
            self.assertTrue('attestation' in details)
            self.assertEqual(1, len(details['attestation']))
            observed_attestation = base64.b64decode(
                details['attestation'][0]['validator'])
            # It's a json string
            observed_attestation_copy = observed_attestation
            # Unmarshal
            observed_attestation = json.loads(observed_attestation)
            del observed_attestation['timestamp']
            del observed_attestation['validity']
            self.assertEqual(expected_attestation, observed_attestation)
            self.assertEqual(details['attestation'][0]['name'], p1['id'])

            # Validate decrypting
            observed_mac = base64.b64decode(
                details['attestation'][0]['validator-mac'])
            expected_mac = hmac.new(
                'dirtylittlesecret', msg=observed_attestation_copy,
                digestmod=hashlib.sha256).digest()
            # Validation succeeded
            self.assertEqual(expected_mac, observed_mac)

    def test_dhcp_notifications_on_create(self):
        self._register_agent('h1')
        net = self.create_network(
            expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub) as p1:
            self._bind_port_to_host(p1['port']['id'], 'h1')
            with self.port(subnet=sub) as p2:
                self._bind_port_to_host(p2['port']['id'], 'h1')
                self.driver.notifier.reset_mock()
                with self.port(subnet=sub, device_owner="network:dhcp"):
                    self.assertEqual(
                        2, self.driver.notifier.port_update.call_count)
                    p1 = self.show_port(p1['port']['id'],
                                        is_admin_context=True)['port']
                    p2 = self.show_port(p2['port']['id'],
                                        is_admin_context=True)['port']
                    p1['dns_name'] = None
                    p2['dns_name'] = None
                    expected_calls = [
                        mock.call(mock.ANY, p1),
                        mock.call(mock.ANY, p2)]
                    self._check_call_list(
                        expected_calls,
                        self.driver.notifier.port_update.call_args_list)

    def test_dhcp_notifications_on_update(self):
        self._register_agent('h1')
        net = self.create_network(
            expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        sub2 = self.create_subnet(
            network_id=net['id'], cidr='192.168.1.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub) as p1:
            # Force port on a specific subnet
            self.update_port(
                p1['port']['id'],
                fixed_ips=[{'subnet_id': sub['subnet']['id']}],
                is_admin_context=True)
            self._bind_port_to_host(p1['port']['id'], 'h1')
            with self.port(subnet=sub2) as p2:
                # Force port on a specific subnet
                self.update_port(
                    p2['port']['id'],
                    fixed_ips=[{'subnet_id': sub2['subnet']['id']}],
                    is_admin_context=True)
                self._bind_port_to_host(p2['port']['id'], 'h1')
                self.driver.notifier.port_update.reset_mock()
                with self.port(subnet=sub, device_owner="network:dhcp") as p3:
                    # Only sub 1 notifies
                    self.assertEqual(
                        1, self.driver.notifier.port_update.call_count)
                    # Force port on a specific subnet
                    self.update_port(
                        p3['port']['id'],
                        fixed_ips=[{'subnet_id': sub['subnet']['id']}],
                        is_admin_context=True)
                    self.driver.notifier.port_update.reset_mock()
                    # Switch DHCP port to sub2
                    self.update_port(
                        p3['port']['id'],
                        fixed_ips=[{'subnet_id': sub2['subnet']['id']}],
                        is_admin_context=True)
                    self.assertEqual(
                        2, self.driver.notifier.port_update.call_count)
                    p1 = self.show_port(p1['port']['id'],
                                        is_admin_context=True)['port']
                    p2 = self.show_port(p2['port']['id'],
                                        is_admin_context=True)['port']
                    p1['dns_name'] = None
                    p2['dns_name'] = None
                    expected_calls = [
                        mock.call(mock.ANY, p1),
                        mock.call(mock.ANY, p2)]
                    self._check_call_list(
                        expected_calls,
                        self.driver.notifier.port_update.call_args_list)

    def test_overlapping_ip_ownership(self):
        ha_handler = ha.HAIPOwnerDbMixin()
        net1 = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub1 = self.create_subnet(
            network_id=net1['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)

        # Create another network with the same subnet
        net2 = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub2 = self.create_subnet(
            network_id=net2['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)

        # Create 2 ports in each subnet, with the same IP address
        with self.port(subnet=sub1, fixed_ips=[{'ip_address':
                                                '192.168.0.4'}]) as p1:
            with self.port(subnet=sub2, fixed_ips=[{'ip_address':
                                                    '192.168.0.4'}]) as p2:
                p1 = p1['port']
                p2 = p2['port']
                # Verify the two IPs are the same
                self.assertEqual([x['ip_address'] for x in p1['fixed_ips']],
                                 [x['ip_address'] for x in p2['fixed_ips']])
                # Set P1 as owner
                ha_handler.update_ip_owner(
                    {'port': p1['id'], 'ip_address_v4': '192.168.0.4'})
                # Ownership is set in the DB for P1
                own_p1 = ha_handler.ha_ip_handler.get_ha_ipaddresses_for_port(
                    p1['id'])
                self.assertEqual(['192.168.0.4'], own_p1)

                # Set P2 as owner
                ha_handler.update_ip_owner(
                    {'port': p2['id'], 'ip_address_v4': '192.168.0.4'})
                # Ownership is set in the DB for P2
                own_p2 = ha_handler.ha_ip_handler.get_ha_ipaddresses_for_port(
                    p2['id'])
                self.assertEqual(['192.168.0.4'], own_p2)

                # P1 is still there
                own_p1 = ha_handler.ha_ip_handler.get_ha_ipaddresses_for_port(
                    p1['id'])
                self.assertEqual(['192.168.0.4'], own_p1)

                # Verify number of entries is exactly 2
                entries = ha_handler.ha_ip_handler.session.query(
                    ha.HAIPAddressToPortAssocation).all()
                self.assertEqual(2, len(entries))

    def test_ip_address_owner_update(self):
        net = self.create_network(
            tenant_id=mocked.APIC_TENANT, expected_res_status=201)['network']
        self.create_subnet(
            tenant_id=mocked.APIC_TENANT,
            network_id=net['id'], cidr='10.0.0.0/24', ip_version=4)['subnet']
        p1 = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            device_owner='compute:', device_id='someid')['port']
        p2 = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            device_owner='compute:', device_id='someid')['port']

        ip_owner_info = {'port': p1['id'], 'ip_address_v4': '1.2.3.4'}
        self.driver.notify_port_update = mock.Mock()

        # set new owner
        self.driver.ip_address_owner_update(
            context.get_admin_context(),
            ip_owner_info=ip_owner_info, host='h1')
        obj = self.driver.ha_ip_handler.get_port_for_ha_ipaddress(
            '1.2.3.4', net['id'])
        self.assertEqual(p1['id'], obj['port_id'])
        self.driver.notify_port_update.assert_called_with(p1['id'])

        # update existing owner
        self.driver.notify_port_update.reset_mock()
        ip_owner_info['port'] = p2['id']
        self.driver.ip_address_owner_update(
            context.get_admin_context(),
            ip_owner_info=ip_owner_info, host='h2')
        obj = self.driver.ha_ip_handler.get_port_for_ha_ipaddress(
            '1.2.3.4', net['id'])
        self.assertEqual(p2['id'], obj['port_id'])
        exp_calls = [
            mock.call(p1['id']),
            mock.call(p2['id'])]
        self._check_call_list(
            exp_calls, self.driver.notify_port_update.call_args_list)

    def test_gbp_details_for_allowed_address_pair(self):
        self._register_agent('h1')
        self._register_agent('h2')
        net = self.create_network(
            tenant_id=mocked.APIC_TENANT, expected_res_status=201)['network']
        sub1 = self.create_subnet(
            tenant_id=mocked.APIC_TENANT,
            network_id=net['id'], cidr='10.0.0.0/24', ip_version=4)['subnet']
        sub2 = self.create_subnet(
            tenant_id=mocked.APIC_TENANT,
            network_id=net['id'], cidr='1.2.3.0/24', ip_version=4)['subnet']
        allow_addr = [{'ip_address': '1.2.3.250',
                       'mac_address': '00:00:00:AA:AA:AA'},
                      {'ip_address': '1.2.3.251',
                       'mac_address': '00:00:00:BB:BB:BB'}]
        # create 2 ports with same allowed-addresses
        p1 = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            device_owner='compute:', device_id='someid',
            fixed_ips=[{'subnet_id': sub1['id']}],
            allowed_address_pairs=allow_addr)['port']
        p2 = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            device_owner='compute:', device_id='someid',
            fixed_ips=[{'subnet_id': sub1['id']}],
            allowed_address_pairs=allow_addr)['port']

        self._bind_port_to_host(p1['id'], 'h1')
        self._bind_port_to_host(p2['id'], 'h2')
        self.driver.ha_ip_handler.set_port_id_for_ha_ipaddress(
            p1['id'], '1.2.3.250')
        self.driver.ha_ip_handler.set_port_id_for_ha_ipaddress(
            p2['id'], '1.2.3.251')
        allow_addr[0]['active'] = True
        details = self._get_gbp_details(p1['id'], 'h1')
        self.assertEqual(allow_addr, details['allowed_address_pairs'])
        del allow_addr[0]['active']
        allow_addr[1]['active'] = True
        details = self._get_gbp_details(p2['id'], 'h2')
        self.assertEqual(allow_addr, details['allowed_address_pairs'])

        # set allowed-address as fixed-IP of ports p3 and p4, which also have
        # floating-IPs. Verify that FIP is "stolen" by p1 and p2
        net_ext = self.create_network(
            is_admin_context=True, tenant_id=mocked.APIC_TENANT,
            **{'router:external': 'True'})['network']
        self.create_subnet(
            is_admin_context=True, tenant_id=mocked.APIC_TENANT,
            network_id=net_ext['id'], cidr='8.8.8.0/24',
            ip_version=4)['subnet']
        p3 = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            fixed_ips=[{'subnet_id': sub2['id'],
                        'ip_address': '1.2.3.250'}])['port']
        p4 = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            fixed_ips=[{'subnet_id': sub2['id'],
                        'ip_address': '1.2.3.251'}])['port']
        rtr = self.create_router(
            api=self.ext_api, tenant_id=mocked.APIC_TENANT,
            external_gateway_info={'network_id': net_ext['id']})['router']
        self.l3_plugin.add_router_interface(
            context.get_admin_context(), rtr['id'], {'subnet_id': sub2['id']})
        fip1 = self.create_floatingip(
            tenant_id=mocked.APIC_TENANT, port_id=p3['id'],
            floating_network_id=net_ext['id'],
            api=self.ext_api)['floatingip']
        fip2 = self.create_floatingip(
            tenant_id=mocked.APIC_TENANT, port_id=p4['id'],
            floating_network_id=net_ext['id'],
            api=self.ext_api)['floatingip']
        details = self._get_gbp_details(p1['id'], 'h1')
        self.assertEqual(1, len(details['floating_ip']))
        self.assertEqual(
            fip1['floating_ip_address'],
            details['floating_ip'][0]['floating_ip_address'])
        details = self._get_gbp_details(p2['id'], 'h2')
        self.assertEqual(1, len(details['floating_ip']))
        self.assertEqual(
            fip2['floating_ip_address'],
            details['floating_ip'][0]['floating_ip_address'])

        # verify FIP updates: update to p3, p4 should also update p1 and p2
        self.driver.notify_port_update = mock.Mock()
        self.driver.notify_port_update_for_fip(p3['id'])
        expected_calls = [
            mock.call(p, mock.ANY)
            for p in sorted([p1['id'], p2['id'], p3['id']])]
        self._check_call_list(
            expected_calls, self.driver.notify_port_update.call_args_list)

        self.driver.notify_port_update.reset_mock()
        self.driver.notify_port_update_for_fip(p4['id'])
        expected_calls = [
            mock.call(p, mock.ANY)
            for p in sorted([p1['id'], p2['id'], p4['id']])]
        self._check_call_list(
            expected_calls, self.driver.notify_port_update.call_args_list)

    def test_notify_router_interface_update(self):
        exc = driver.InterTenantRouterInterfaceNotAllowedOnPerTenantContext
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        router = self.create_router(api=self.ext_api,
                                    expected_res_status=201)['router']
        self._register_agent('h1')
        with self.port(subnet=sub, tenant_id='anothertenant',
                       device_owner='network:router_interface') as p1:
            with self.port(subnet=sub, tenant_id='anothertenant') as p2:
                self._bind_port_to_host(p2['port']['id'], 'h1')
                self.mgr.add_router_interface = mock.Mock()
                if self.driver.per_tenant_context:
                    self.assertRaises(
                        exc,
                        self.l3_plugin.add_router_interface,
                        context.get_admin_context(),
                        router['id'], {'port_id': p1['port']['id']}
                    )
                else:
                    self.l3_plugin.add_router_interface(
                        context.get_admin_context(), router['id'],
                        {'port_id': p1['port']['id']})
                    self.assertEqual(n_constants.DEVICE_OWNER_ROUTER_INTF,
                                     p1['port']['device_owner'])
                    self.driver.notifier.port_update = mock.Mock()
                    self.driver._notify_ports_due_to_router_update(p1['port'])
                    self.assertEqual(
                        1, self.driver.notifier.port_update.call_count)
                    self.assertEqual(
                        p2['port']['id'],
                        self.driver.notifier.port_update.call_args_list[
                            0][0][1]['id'])

    def test_create_reserved_name(self):
        net = self.create_network(
            tenant_id='onetenant', name=acst.APIC_SYNC_NETWORK,
            expected_res_status=201)
        self.assertEqual({}, net['network'])
        # Net shouldn't exist
        nets = self.driver.db_plugin.get_networks(
            context.get_admin_context(),
            filters={'name': [acst.APIC_SYNC_NETWORK]})
        self.assertEqual(0, len(nets))

    def test_request_endpoint_details(self):
        net = self.create_network(expected_res_status=201)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        self._register_agent('h1')
        with self.port(subnet=sub) as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            # Bind port to trigger path binding
            self._bind_port_to_host(p1['id'], 'h1')
            self.driver._add_ip_mapping_details = mock.Mock()
            details = self._get_gbp_details(p1['id'], 'h1')
            request = self._request_endpoint_details(p1['id'], 'h1')
            details.pop('attestation', None)
            request['gbp_details'].pop('attestation', None)
            self.assertEqual(details, request['gbp_details'])
            self.assertEqual(p1['id'], request['neutron_details']['port_id'])

    def test_request_endpoint_details_not_found(self):
        self.driver._add_ip_mapping_details = mock.Mock()
        request = self._request_endpoint_details('randomid', 'h1')
        # Port not found
        self.assertEqual({'device': 'tap%s' % 'randomid'},
                         request['gbp_details'])
        self.assertTrue('port_id' not in request['neutron_details'])

    def test_request_endpoint_details_exception(self):
        net = self.create_network(expected_res_status=201)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        self._register_agent('h1')
        with self.port(subnet=sub) as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            # Bind port to trigger path binding
            self._bind_port_to_host(p1['id'], 'h1')
            self.driver._add_ip_mapping_details = mock.Mock(
                side_effect=Exception)
            request = self._request_endpoint_details(p1['id'], 'h1')
            self.assertIsNone(request)

    def test_snat_port_ip_loss(self):
        self._register_agent('h1')
        admin_ctx = context.get_admin_context()

        self._mock_external_dict([('supported', '192.168.0.2/24')])
        self.driver.apic_manager.ext_net_dict[
            'supported']['host_pool_cidr'] = '192.168.200.1/24'
        # Create external network
        net_ext = self.create_network(
            is_admin_context=True, tenant_id=mocked.APIC_TENANT,
            name='supported',
            **{'router:external': 'True'})['network']
        self.create_subnet(
            is_admin_context=True, tenant_id=mocked.APIC_TENANT,
            network_id=net_ext['id'], cidr='8.8.8.0/24',
            ip_version=4)
        # Create internal network
        net = self.create_network(
            tenant_id=mocked.APIC_TENANT, expected_res_status=201)['network']
        sub = self.create_subnet(
            tenant_id=mocked.APIC_TENANT,
            network_id=net['id'], cidr='10.0.0.0/24', ip_version=4)['subnet']
        # Attach router to them
        rtr = self.create_router(
            api=self.ext_api, tenant_id=mocked.APIC_TENANT,
            external_gateway_info={'network_id': net_ext['id']})['router']
        self.l3_plugin.add_router_interface(
            context.get_admin_context(), rtr['id'], {'subnet_id': sub['id']})
        # Create port on internal subnet
        p = self.create_port(
            network_id=net['id'], tenant_id=mocked.APIC_TENANT,
            device_owner='compute:', device_id='someid',
            fixed_ips=[{'subnet_id': sub['id']}])['port']
        self._bind_port_to_host(p['id'], 'h1')

        # Request gbp details
        mapping = self._get_gbp_details(p['id'], 'h1')
        self.assertEqual(1, len(mapping['host_snat_ips']))

        snat_ports = self.driver.db_plugin.get_ports(
            admin_ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                'device_id': ['h1']})
        # Delete Fixed IPs
        self.driver.db_plugin.update_port(
            admin_ctx, snat_ports[0]['id'], {'port': {'fixed_ips': []}})
        # Re run
        mapping = self._get_gbp_details(p['id'], 'h1')
        self.assertEqual(1, len(mapping['host_snat_ips']))

        snat_ports_2 = self.driver.db_plugin.get_ports(
            admin_ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                'device_id': ['h1']})

        self.assertEqual(1, len(snat_ports))
        self.assertEqual(1, len(snat_ports_2))
        self.assertNotEqual(snat_ports[0]['id'], snat_ports_2[0]['id'])


class TestCiscoApicML2SubnetScope(ApicML2IntegratedTestCase):
    def setUp(self, service_plugins=None):
        with tempfile.NamedTemporaryFile(delete=False) as fd:
            self.cons_file_name = fd.name
        self.override_conf('network_constraints_filename',
                           self.cons_file_name,
                           'ml2_cisco_apic')
        super(TestCiscoApicML2SubnetScope, self).setUp(service_plugins)

    def test_subnet_scope(self):
        cons_data = """
[DEFAULT]
subnet_scope = deny

[%s/net1]
public = 10.10.10.1/24,10.10.20.1/24
private = 20.10.10.0/28,20.10.20.0/24
deny = 30.10.10.0/24
default = private
            """ % (mocked.APIC_TENANT)
        self.driver.net_cons.source.last_refresh_time = 0
        with open(self.cons_file_name, 'w') as fd:
            fd.write(cons_data)

        self.mgr.ensure_subnet_created_on_apic = mock.Mock()
        self.driver.name_mapper.aci_mapper.min_suffix = 0
        net1 = self.create_network(
            name='net1', tenant_id=mocked.APIC_TENANT,
            expected_res_status=201)['network']
        net2 = self.create_network(
            name='net2', tenant_id=mocked.APIC_TENANT,
            expected_res_status=201)['network']

        for cidr in ['10.10.10.0/28', '20.10.10.0/26', '40.10.10.0/30']:
            self.create_subnet(
                tenant_id=mocked.APIC_TENANT,
                network_id=net1['id'], cidr=cidr, ip_version=4)
        exp_calls = [
            mock.call(
                self._tenant(), self._scoped_name('net1'),
                '10.10.10.1/28', scope='public'),
            mock.call(
                self._tenant(), self._scoped_name('net1'),
                '20.10.10.1/26', scope='private'),
            mock.call(
                self._tenant(), self._scoped_name('net1'),
                '40.10.10.1/30', scope='private')]
        self._check_call_list(
            exp_calls, self.mgr.ensure_subnet_created_on_apic.call_args_list)

        res = self.create_subnet(
            tenant_id=mocked.APIC_TENANT,
            network_id=net1['id'], cidr='30.10.10.0/24', ip_version=4,
            expected_res_status=500)
        self.assertEqual('MechanismDriverError', res['NeutronError']['type'])
        res = self.create_subnet(
            tenant_id=mocked.APIC_TENANT,
            network_id=net2['id'], cidr='10.10.10.0/24', ip_version=4,
            expected_res_status=500)
        self.assertEqual('MechanismDriverError', res['NeutronError']['type'])


class MechanismRpcTestCase(ApicML2IntegratedTestBase):

    def test_rpc_endpoint_set(self):
        self.assertEqual(1, len(self.driver.topology_endpoints))
        rpc = self.driver.topology_endpoints[0]
        self.assertIsInstance(rpc, mech_rpc.ApicTopologyRpcCallbackMechanism)

    def test_peers_loaded(self):
        # Verify static configured hosts in rpc peers
        self._add_hosts_to_apic(2)

        peers = self.rpc._load_peers()
        self.assertIn(('h1', 'static'), peers)
        self.assertIn(('h2', 'static'), peers)

    def test_remove_hostlink(self):
        self._register_agent('h1')
        self._register_agent('h2')
        # Test removal of one link
        self._add_hosts_to_apic(3)
        self.driver.apic_manager.delete_path = mock.Mock()
        net = self.create_network()['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        # Create two ports
        with self.port(subnet=sub) as p1:
            with self.port(subnet=sub) as p2:
                self._bind_port_to_host(p1['port']['id'], 'h1')
                self._bind_port_to_host(p2['port']['id'], 'h2')

                # Remove H1 interface from ACI
                self.rpc.update_link(mock.Mock(), 'h1', 'static', None, 0, '1',
                                     '1')
                # Assert H1 on net vlan static paths deleted
                (self.driver.apic_manager.delete_path.
                    assert_called_once_with(self._tenant_id, net['id'], '1',
                                            '1', '1'))

                self.driver.apic_manager.delete_path.reset_mock()
                # Unbound
                self.rpc.update_link(mock.Mock(), 'h3', 'static', None, 0, '1',
                                     '3')
                self.assertEqual(
                    0, self.driver.apic_manager.delete_path.call_count)

    def test_remove_hostlink_vpc(self):
        self._register_agent('h1')
        self._add_hosts_to_apic(3, vpc=True)
        self.driver.apic_manager.delete_path = mock.Mock()
        net = self.create_network()['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        # Create two ports
        with self.port(subnet=sub) as p1:
            self._bind_port_to_host(p1['port']['id'], 'h1')

            # Remove H1 interface from ACI
            self.rpc.update_link(mock.Mock(), 'h1', 'eth0', None, 0, '1',
                                 '1')
            # Another link still exists
            self.assertEqual(
                0, self.driver.apic_manager.delete_path.call_count)

            self.driver.apic_manager.delete_path.reset_mock()
            self.rpc.update_link(mock.Mock(), 'h1', 'eth1', None, 0, '2',
                                 '1')

            (self.driver.apic_manager.delete_path.
             assert_called_once_with(self._tenant_id, net['id'], '2', '1',
                                     '1'))

    def test_add_hostlink(self):
        self._register_agent('h1')
        self._register_agent('h2')
        self._register_agent('rhel03')
        # Test removal of one link
        self._add_hosts_to_apic(2)
        net = self.create_network()['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        # Create two ports
        with self.port(subnet=sub) as p1:
            with self.port(subnet=sub) as p2:
                with self.port(subnet=sub) as p3:
                    self._bind_port_to_host(p1['port']['id'], 'h1')
                    self._bind_port_to_host(p2['port']['id'], 'h2')
                    self._bind_port_to_host(p3['port']['id'], 'rhel03')
                    self.driver.apic_manager.ensure_path_created_for_port = (
                        mock.Mock())
                    # Add H3 interface from ACI
                    self.rpc.update_link(
                        mock.Mock(), 'h3', 'static', None, '3', '1', '3')
                    # No path created since no port is bound on H3
                    self.assertEqual(
                        0,
                        self.driver.apic_manager.ensure_path_created_for_port.
                        call_count)
                    (self.driver.apic_manager.ensure_path_created_for_port.
                     reset_mock())
                    # Add H4 interface from ACI
                    self.rpc.update_link(
                        mock.Mock(), 'rhel03', 'static', None, '4', '1', '4')

                    # P3 was bound in H4
                    net = self.show_network(net['id'],
                                            is_admin_context=True)['network']
                    (self.driver.apic_manager.ensure_path_created_for_port.
                        assert_called_once_with(
                            self._tenant_id, net['id'], 'rhel03',
                            net['provider:segmentation_id']))

    def test_update_hostlink(self):
        self._register_agent('h1')
        self._add_hosts_to_apic(1)

        net1 = self.create_network()['network']
        sub1 = self.create_subnet(
            network_id=net1['id'], cidr='192.168.0.0/24',
            ip_version=4)

        net2 = self.create_network()['network']
        sub2 = self.create_subnet(
            network_id=net2['id'], cidr='192.168.1.0/24',
            ip_version=4)
        # Create two ports
        with self.port(subnet=sub1) as p1:
            with self.port(subnet=sub1) as p2:
                with self.port(subnet=sub2) as p3:
                    # Bind all on H1
                    self._bind_port_to_host(p1['port']['id'], 'h1')
                    self._bind_port_to_host(p2['port']['id'], 'h1')
                    self._bind_port_to_host(p3['port']['id'], 'h1')
                    mgr = self.driver.apic_manager
                    mgr.delete_path = mock.Mock()
                    mgr.ensure_path_created_for_port = mock.Mock()
                    # Change host interface
                    self.rpc.update_link(
                        mock.Mock(), 'h1', 'static', None, '1', '1', '24')

                    # Ports' path have been deleted and reissued two times (one
                    # for network)
                    expected_calls_remove = [
                        mock.call(self._tenant_id, net1['id'], '1', '1', '1'),
                        mock.call(self._tenant_id, net2['id'], '1', '1', '1')]

                    # Create path expected calls
                    net1 = self.show_network(
                        net1['id'], is_admin_context=True)['network']
                    net2 = self.show_network(
                        net2['id'], is_admin_context=True)['network']
                    expected_calls_add = [
                        mock.call(self._tenant_id, net1['id'], 'h1',
                                  net1['provider:segmentation_id']),
                        mock.call(self._tenant_id, net2['id'], 'h1',
                                  net2['provider:segmentation_id'])]
                    self._check_call_list(
                        expected_calls_remove,
                        mgr.delete_path.call_args_list)
                    self._check_call_list(
                        expected_calls_add,
                        mgr.ensure_path_created_for_port.call_args_list)

    def test_duplicate_hostlink(self):
        self.driver.apic_manager.add_hostlink(
            'h1', 'static', None, '1', '1', '1')
        # The below doesn't rise
        self.rpc.update_link(
            mock.Mock(), 'h1', 'static', None, '1', '1', '1')


class TestCiscoApicMechDriver(base.BaseTestCase,
                              mocked.ControllerMixin,
                              mocked.ConfigMixin):
    def setUp(self):
        model_base.BASEV2.metadata.create_all(db_api.get_engine())

        super(TestCiscoApicMechDriver, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.mock_apic_manager_login_responses()
        self.driver = md.APICMechanismDriver()
        self.driver.synchronizer = None
        self.synchronizer = mock.Mock()
        md.APICMechanismDriver.get_base_synchronizer = mock.Mock(
            return_value=self.synchronizer)
        apic_mapper.ApicName.__eq__ = equal
        self.driver.apic_manager = mock.Mock(
            name_mapper=mock.Mock(), ext_net_dict=self.external_network_dict)
        self.driver.initialize()
        self.driver.vif_type = 'test-vif_type'
        self.driver.cap_port_filter = 'test-cap_port_filter'
        self.driver.name_mapper.aci_mapper.tenant = echo
        self.driver.name_mapper.aci_mapper.network = echo
        self.driver.name_mapper.aci_mapper.subnet = echo
        self.driver.name_mapper.aci_mapper.port = echo
        self.driver.name_mapper.aci_mapper.router = echo
        self.driver.name_mapper.aci_mapper.pre_existing = echo
        self.driver.name_mapper.aci_mapper.echo = echo
        self.driver.name_mapper.aci_mapper.app_profile.return_value = (
            mocked.APIC_AP)

        self.driver.apic_manager.apic.transaction = self.fake_transaction
        self.agent = {'configurations': {
            'opflex_networks': None,
            'bridge_mappings': {'physnet1': 'br-eth1'}}}
        mock.patch('neutron.manager.NeutronManager').start()
        self.driver._l3_plugin = mock.Mock()
        self.driver._allocate_snat_ip = echo
        self.driver._create_snat_ip_allocation_subnet = echo
        self.driver._delete_snat_ip_allocation_network = echo

        def get_resource(context, resource_id):
            return {'id': resource_id, 'tenant_id': mocked.APIC_TENANT}
        self.driver._l3_plugin.get_router = get_resource
        self.driver._l3_plugin.get_routers = mock.Mock(return_value=[
            {'id': mocked.APIC_ROUTER, 'tenant_id': mocked.APIC_TENANT}])

        self.trimmed_l3out = u'{"l3extOut": {"attributes": {"rn": "Auto-Sub\
"}, "children": [    {"l3extRsNdIfPol": {"tnNdIfPolName": ""}}, \
{"l3extRsDampeningPol": {"tnRtctrlProfileName": ""}}, {"ospfRsIfPol": \
{"tnOspfIfPolName": ""}}, {"l3extRsEngressQosDppPol": {"tnQosDppPolName": ""}}\
, {"bfdRsIfPol": {"tnBfdIfPolName": ""}}, {"bgpRsPeerPfxPol": \
{"tnBgpPeerPfxPolName": ""}}, {"eigrpRsIfPol": {"tnEigrpIfPolName": ""}}, \
{"l3extLNodeP": {"attributes": {"dn": "uni/tn-Sub/out-Auto-Sub/\
lnodep-Leaf3-4_NP"}, "children": [{"l3extLIfP": {"children": [{"\
l3extRsPathL3OutAtt": {"attributes": {"ifInstT": "sub-interface", "encap": \
"vlan-999"}}}]}}]}}, {"l3extRsEctx": {"attributes": {"dn": "uni/tn-Sub\
/out-Auto-Sub/rsectx", "tnFvCtxName": "ctx-Sub"}}}]}}'

    def _check_call_list(self, expected, observed):
        exp_bkp = expected[:]
        obs_bkp = observed[:]
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(exp_bkp), str(obs_bkp)))
            observed.remove(call)
        self.assertFalse(
            len(observed),
            msg='There are more calls than expected: %s' % str(observed))

    def test_initialize(self):
        mgr = self.driver.apic_manager
        self.assertEqual(1, mgr.ensure_infra_created_on_apic.call_count)
        self.assertEqual(
            1, mgr.ensure_bgp_pod_policy_created_on_apic.call_count)

    def test_update_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        mgr = self.driver.apic_manager
        self.driver.update_port_postcommit(port_ctx)
        mgr.ensure_path_created_for_port.assert_called_once_with(
            self._tenant(), mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, transaction='transaction',
            app_profile_name=self._app_profile())

    def test_update_host(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        port_ctx.original_host = HOST_ID2
        self.driver.update_port_postcommit(port_ctx)

    def test_create_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1,
                                            seg_type=ofcst.TYPE_OPFLEX)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        mgr = self.driver.apic_manager
        self.assertTrue(self.driver._check_segment_for_agent(
            port_ctx._bound_segment, self.agent))
        self.driver.create_port_postcommit(port_ctx)
        mgr.ensure_path_created_for_port.assert_not_called()

    def test_update_port_precommit_empty_tenant_1(self):
        self.driver._is_nat_enabled_on_ext_net = mock.Mock()
        self.driver._l3_plugin.get_router = mock.Mock(
            return_value={'id': mocked.APIC_ROUTER, 'tenant_id': ''})
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1,
                                            seg_type=ofcst.TYPE_OPFLEX,
                                            external=True)
        r_cnst = n_constants.DEVICE_OWNER_ROUTER_GW
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          mocked.APIC_ROUTER,
                                          net_ctx, HOST_ID1,
                                          device_owner=r_cnst)
        self.assertTrue(self.driver._check_segment_for_agent(
            port_ctx._bound_segment, self.agent))
        self.driver.update_port_precommit(port_ctx)
        self.driver._is_nat_enabled_on_ext_net.assert_not_called()

    def test_update_port_precommit_empty_tenant_2(self):
        self.driver._is_nat_enabled_on_ext_net = mock.Mock(return_value=False)
        self.driver.per_tenant_context = True
        self.driver._is_edge_nat = mock.Mock(return_value=False)
        self.driver._is_pre_existing = mock.Mock(return_value=False)
        self.driver._l3_plugin.get_router = mock.Mock(
            return_value={'id': mocked.APIC_ROUTER, 'tenant_id': 'foo'})
        self.driver._l3_plugin.get_routers = mock.Mock(
            return_value=[{'id': mocked.APIC_ROUTER, 'tenant_id': ''}])
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1,
                                            seg_type=ofcst.TYPE_OPFLEX,
                                            external=True)
        r_cnst = n_constants.DEVICE_OWNER_ROUTER_GW
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          mocked.APIC_ROUTER,
                                          net_ctx, HOST_ID1,
                                          device_owner=r_cnst)
        self.assertTrue(self.driver._check_segment_for_agent(
            port_ctx._bound_segment, self.agent))
        self.driver.update_port_precommit(port_ctx)
        self.driver._l3_plugin.get_routers.assert_called_once_with(
            mock.ANY, filters=mock.ANY)
        self.driver._is_pre_existing.assert_called_once_with(mock.ANY)

    def test_create_port_postcommit_empty_tenant(self):
        self.driver._create_shadow_ext_net_for_nat = mock.Mock()
        self.driver._is_nat_enabled_on_ext_net = mock.Mock(return_value=True)
        self.driver._l3_plugin.get_router = mock.Mock(
            return_value={'id': mocked.APIC_ROUTER, 'tenant_id': ''})
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1,
                                            seg_type=ofcst.TYPE_OPFLEX)
        r_cnst = n_constants.DEVICE_OWNER_ROUTER_GW
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          mocked.APIC_ROUTER,
                                          net_ctx, HOST_ID1,
                                          device_owner=r_cnst)
        self.assertTrue(self.driver._check_segment_for_agent(
            port_ctx._bound_segment, self.agent))
        self.driver.create_port_postcommit(port_ctx)
        self.driver._create_shadow_ext_net_for_nat.assert_not_called()

    def test_create_port_postcommit_opflex(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, seg_type='opflex')
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        self.assertTrue(self.driver._check_segment_for_agent(
            port_ctx._bound_segment, self.agent))
        mgr = self.driver.apic_manager
        self.driver.create_port_postcommit(port_ctx)
        self.assertFalse(mgr.ensure_path_created_for_port.called)

    def test_create_port_cross_tenant(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context('some-admin',
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        mgr = self.driver.apic_manager
        self.driver.create_port_postcommit(port_ctx)
        self.assertEqual(port_ctx.current['tenant_id'], 'some-admin')
        # Path creation gets called with the network tenant id
        mgr.ensure_path_created_for_port.assert_called_once_with(
            self._tenant(), mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, transaction='transaction',
            app_profile_name=self._app_profile())

    def test_update_port_nobound_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, None,
                                          device_owner='any')
        self.driver.update_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        self.assertFalse(mgr.ensure_path_created_for_port.called)

    def test_create_port_nobound_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, None,
                                          device_owner='any')
        self.driver.create_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        self.assertFalse(mgr.ensure_path_created_for_port.called)

    def _test_update_gw_port_postcommit(self, net_tenant=mocked.APIC_TENANT):
        net_ctx = self._get_network_context(net_tenant,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._router_tenant())

        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        shd_l3out = (self.driver.per_tenant_context and
                     self._scoped_name(vrf_pfx + mocked.APIC_NETWORK) or
                     mocked.APIC_NETWORK)
        expected_calls = [
            mock.call("Shd-%s" % shd_l3out,
                      owner=self._tenant(ext_nat=True), transaction=mock.ANY,
                      context=self._routed_network_vrf_name())]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        expected_calls = [
            mock.call("Shd-%s" % shd_l3out,
                      external_epg="Shd-%s" % mocked.APIC_EXT_EPG,
                      owner=self._tenant(ext_nat=True), transaction=mock.ANY)]

        self._check_call_list(
            expected_calls, mgr.ensure_external_epg_created.call_args_list)

        expected_calls = [
            mock.call(
                "Shd-%s" % shd_l3out,
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % mocked.APIC_EXT_EPG,
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                "Shd-%s" % shd_l3out,
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % mocked.APIC_EXT_EPG,
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

    def test_update_gw_port_postcommit(self):
        self._test_update_gw_port_postcommit()

    def test_update_cross_tenant_gw_port_postcommit(self):
        self._test_update_gw_port_postcommit('admin_tenant')

    def _test_update_edge_nat_gw_port_postcommit(
        self, net_tenant=mocked.APIC_TENANT):
        net_ctx = self._get_network_context(net_tenant,
                                            mocked.APIC_NETWORK_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver.l3out_vlan_alloc.reserve_vlan = mock.Mock()

        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = [
            {'tenant_id': mocked.APIC_TENANT,
             'name': mocked.APIC_NETWORK,
             'id': u'net_id'}]
        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._router_tenant())

        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        l3out_name = (self.driver.per_tenant_context and
                      self._scoped_name(vrf_pfx + mocked.APIC_NETWORK_EDGE_NAT)
                      or mocked.APIC_NETWORK_EDGE_NAT)
        l3out_name = "Auto-%s" % l3out_name
        expected_calls = [
            mock.call(l3out_name,
                      owner=self._tenant(ext_nat=True), transaction=mock.ANY,
                      context=self._routed_network_vrf_name())]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        expected_calls = [
            mock.call(l3out_name,
                      external_epg="Auto-%s" % mocked.APIC_EXT_EPG,
                      owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.ensure_external_epg_created.call_args_list)

        self.driver.l3out_vlan_alloc.reserve_vlan.assert_called_once_with(
            mocked.APIC_NETWORK_EDGE_NAT + '-name',
            self._routed_network_vrf_name(),
            self._tenant(ext_nat=True))
        self.assertTrue(mgr.set_domain_for_external_routed_network.called)
        self.assertTrue(mgr.ensure_logical_node_profile_created.called)
        self.assertTrue(mgr.ensure_static_route_created.called)

        bd_name = self._scoped_name('net_id')
        mgr.set_l3out_for_bd.assert_called_once_with(
            self._tenant(), bd_name, l3out_name, transaction=mock.ANY)

        expected_calls = [
            mock.call(
                l3out_name,
                mgr.get_router_contract.return_value,
                external_epg="Auto-%s" % mocked.APIC_EXT_EPG,
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                l3out_name,
                mgr.get_router_contract.return_value,
                external_epg="Auto-%s" % mocked.APIC_EXT_EPG,
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

    def test_update_edge_nat_gw_port_postcommit(self):
        self._test_update_edge_nat_gw_port_postcommit()

    def test_update_cross_tenant_edge_nat_gw_port_postcommit(self):
        self._test_update_edge_nat_gw_port_postcommit('admin_tenant')

    def _test_update_interface_port_postcommit(self, no_nat=False, pre=False,
                                               net_tenant=None):
        net_tenant = net_tenant or mocked.APIC_TENANT
        if self.driver.vrf_per_router_tenants:
            self.driver.vrf_per_router_tenants.append(net_tenant)
        if no_nat:
            ext_net = mocked.APIC_NETWORK_NO_NAT
            if pre:
                self.external_network_dict[ext_net + '-name'][
                    'preexisting'] = 'True'
                self.driver._query_l3out_info = mock.Mock()
                self.driver._query_l3out_info.return_value = {
                    'l3out_tenant': self._tenant(),
                    'vrf_name': self._network_vrf_name(),
                    'vrf_tenant': self._tenant(vrf=True)}
        else:
            ext_net = mocked.APIC_NETWORK_EDGE_NAT
        net_ctx = self._get_network_context(net_tenant,
                                            'net_id',
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(net_tenant,
                                          'net_id',
                                          'vm1', net_ctx, HOST_ID1,
                                          interface=True)
        self.driver._l3_plugin.get_router = mock.Mock(
            return_value={'id': mocked.APIC_ROUTER,
                          'tenant_id': net_tenant,
                          'external_gateway_info':
                              {'network_id': ext_net,
                               'external_fixed_ips': []}})
        port_ctx._plugin.get_network = mock.Mock(
            return_value={'name': ext_net + '-name',
                          'tenant_id': mocked.APIC_TENANT,
                          'router:external': True})

        self.driver.update_port_postcommit(port_ctx)

        prefix = ('%s-' % mocked.APIC_ROUTER
                  if self.driver.vrf_per_router_tenants and not no_nat else '')
        l3out_name = (self.driver.per_tenant_context and
                      self._scoped_name(prefix + ext_net) or ext_net)
        if not no_nat:
            l3out_name = "Auto-%s" % l3out_name
        elif pre:
            l3out_name = self._scoped_name(ext_net + '-name', preexisting=True)
        bd_tenant = self._tenant(neutron_tenant=net_tenant)
        bd_name = self._scoped_name('net_id', tenant=net_tenant)
        mgr = self.driver.apic_manager
        if self.driver.vrf_per_router_tenants:
            mgr.set_context_for_bd.assert_called_once_with(
                bd_tenant, bd_name,
                self._routed_network_vrf_name(tenant=net_tenant),
                transaction=mock.ANY)
        mgr.set_l3out_for_bd.assert_called_once_with(
            bd_tenant, bd_name, l3out_name,
            transaction=mock.ANY)

    def test_update_edge_nat_interface_port_postcommit(self):
        self._test_update_interface_port_postcommit()

    def test_update_cross_tenant_edge_nat_interface_port_postcommit(self):
        self._test_update_interface_port_postcommit('another')

    def test_update_no_nat_interface_port_postcommit(self):
        self._test_update_interface_port_postcommit(no_nat=True)

    def test_update_cross_tenant_no_nat_interface_port_postcommit(self):
        self._test_update_interface_port_postcommit(no_nat=True,
                                                    net_tenant='another')

    def test_update_pre_no_nat_interface_port_postcommit(self):
        self._test_update_interface_port_postcommit(no_nat=True, pre=True)

    def test_update_cross_tenant_pre_no_nat_interface_port_postcommit(self):
        self._test_update_interface_port_postcommit(
            no_nat=True, pre=True, net_tenant='another')

    def _test_update_pre_edge_nat_gw_port_postcommit(
        self, net_tenant=mocked.APIC_TENANT):
        net_ctx = self._get_network_context(net_tenant,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver.l3out_vlan_alloc.reserve_vlan = mock.Mock()
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant',

            # fake l3out response from APIC for testing purpose only
            'l3out': ([{u'l3extExtEncapAllocator': {}},
                       {u'l3extInstP': {}},
                       {u'l3extRtBDToOut': {}},
                       {u'l3extRsOutToBDPublicSubnetHolder': {}},
                       {u'l3extRsNdIfPol': {u'tDn': u'',
                                            u'tnNdIfPolName': u''}},
                       {u'l3extRsDampeningPol':
                           {u'tDn': u'', u'tnRtctrlProfileName': u''}},
                       {u'ospfRsIfPol': {u'tDn': u'',
                                         u'tnOspfIfPolName': u''}},
                       {u'l3extRsEngressQosDppPol':
                           {u'tDn': u'', u'tnQosDppPolName': u''}},
                       {u'bfdRsIfPol': {u'tDn': u'',
                                        u'tnBfdIfPolName': u''}},
                       {u'bgpRsPeerPfxPol': {u'tDn': u'',
                                             u'tnBgpPeerPfxPolName': u''}},
                       {u'eigrpRsIfPol': {u'tDn': u'',
                                          u'tnEigrpIfPolName': u''}},
                       {u'l3extLNodeP': {u'attributes':
                                         {u'dn': u'uni/tn-bar_tenant/out-netwo\
rk_pre_edge_nat-name/lnodep-Leaf3-4_NP',
                                          u'lcOwn': u'local',
                                          u'name': u'Leaf3-4_NP',
                                          u'targetDscp': u'unspecified',
                                          u'configIssues': u'',
                                          u'stateQual': u'', u'tCl': u'',
                                          u'tContextDn': u'', u'tRn': u'',
                                          u'type': u'', u'rType': u'',
                                          u'state': u'', u'forceResolve': u'',
                                          u'tag': u'yellow-green',
                                          u'monPolDn': u'', u'modTs': u'',
                                          u'uid': u'15374',
                                          u'encap': u'unknown',
                                          u'addr': u'0.0.0.0'},
                                         u'children': [{u'l3extLIfP':
                                                        {u'children':
                                                         [{u'l3extRsPathL3OutA\
tt':
                                                           {u'attributes':
                                                            {u'encap':
                                                             u'vlan-3101',
                                                             u'ifInstT':
                                                             u'sub-interface'
                                                             }}}]}}
                                                       ]}},
                       {u'l3extRsEctx':
                        {u'attributes':
                         {u'dn':
                          u'uni/tn-bar_tenant/out-network_pre_edge_nat-name\
/rsectx',
                          u'tDn': u'', u'tnFvCtxName': u'default'}}}])}

        def echo1(obj):
            return str(obj)
        self.driver.apic_manager.apic.fvTenant.rn = echo1
        self.driver.apic_manager.apic.l3extOut.rn = echo1
        self.driver.apic_manager.apic.fvCtx.name = echo1
        self.driver.l3out_vlan_alloc.reserve_vlan.return_value = 999

        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = [
            {'tenant_id': mocked.APIC_TENANT,
             'name': mocked.APIC_NETWORK,
             'id': u'net_id'}]

        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._router_tenant())

        self.driver.l3out_vlan_alloc.reserve_vlan.assert_called_once_with(
            mocked.APIC_NETWORK_PRE_EDGE_NAT + '-name',
            self._routed_network_vrf_name(), self._tenant(ext_nat=True))
        self.assertFalse(mgr.mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)

        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        l3out_name = (self.driver.per_tenant_context and
                      self._scoped_name(vrf_pfx +
                                        mocked.APIC_NETWORK_PRE_EDGE_NAT) or
                      mocked.APIC_NETWORK_PRE_EDGE_NAT)
        l3out_name = "Auto-%s" % l3out_name

        final_req = re.sub('Auto-Sub',
                           l3out_name, self.trimmed_l3out)
        final_req = re.sub('tn-Sub',
                           "tn-%s" % self._tenant(ext_nat=True), final_req)
        final_req = re.sub('ctx-Sub',
                           "%s" % self._routed_network_vrf_name(), final_req)
        mgr.apic.post_body.assert_called_once_with(
            mgr.apic.l3extOut.mo, final_req, self._tenant(ext_nat=True),
            l3out_name)

        mgr.ensure_external_epg_created.assert_called_once_with(
            l3out_name,
            external_epg="Auto-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                       preexisting=True),
            owner=self._tenant(ext_nat=True), transaction=mock.ANY)

        mgr.set_l3out_for_bd.assert_called_once_with(
            self._tenant(), self._scoped_name('net_id'), l3out_name,
            transaction=mock.ANY)

        expected_calls = [
            mock.call(
                l3out_name,
                mgr.get_router_contract.return_value,
                external_epg="Auto-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                           preexisting=True),
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                l3out_name,
                mgr.get_router_contract.return_value,
                external_epg="Auto-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                           preexisting=True),
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

    def test_update_pre_edge_nat_gw_port_postcommit(self):
        self._test_update_pre_edge_nat_gw_port_postcommit()

    def test_update_cross_tenant_pre_edge_nat_gw_port_postcommit(self):
        self._test_update_pre_edge_nat_gw_port_postcommit('admin_tenant')

    def _test_update_pre_gw_port_postcommit(self,
                                            net_tenant=mocked.APIC_TENANT):
        net_ctx = self._get_network_context(net_tenant,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._router_tenant())

        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        shd_l3out = (self.driver.per_tenant_context and
                     self._scoped_name(vrf_pfx + mocked.APIC_NETWORK_PRE) or
                     mocked.APIC_NETWORK_PRE)
        expected_calls = [
            mock.call("Shd-%s" % shd_l3out,
                      owner=self._tenant(ext_nat=True), transaction=mock.ANY,
                      context=self._routed_network_vrf_name())]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)

        mgr.ensure_external_epg_created.assert_called_once_with(
            "Shd-%s" % shd_l3out,
            external_epg="Shd-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                      preexisting=True),
            owner=self._tenant(ext_nat=True), transaction=mock.ANY)

        expected_calls = [
            mock.call(
                "Shd-%s" % shd_l3out,
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                          preexisting=True),
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                "Shd-%s" % shd_l3out,
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                          preexisting=True),
                owner=self._tenant(ext_nat=True), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

    def test_update_pre_gw_port_postcommit(self):
        self._test_update_pre_gw_port_postcommit()

    def test_update_cross_tenant_pre_gw_port_postcommit(self):
        self._test_update_pre_gw_port_postcommit('admin_tenant')

    def _test_update_pre_no_nat_gw_port_postcommit(self, l3out_tenant):
        self.external_network_dict[mocked.APIC_NETWORK_PRE + '-name'][
            'enable_nat'] = 'False'
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        ctx_name = self._network_vrf_name(
            nat_vrf=False, net_name=self._scoped_name(net_ctx.current['id']))
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': l3out_tenant,
            'vrf_name': ctx_name,
            'vrf_tenant': self._tenant(vrf=True)}
        nets = [
            {'tenant_id': mocked.APIC_TENANT + '1',
             'name': mocked.APIC_NETWORK,
             'id': 'net_id1'},
            {'tenant_id': mocked.APIC_TENANT + '2',
             'name': mocked.APIC_NETWORK,
             'id': 'net_id2'}]
        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = nets

        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._router_tenant())

        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)

        l3out_name = self._scoped_name(net_ctx.current['name'],
                                       preexisting=True)
        mgr.set_context_for_external_routed_network.assert_called_once_with(
            l3out_tenant, l3out_name, self._routed_network_vrf_name(),
            transaction=mock.ANY)

        expected_calls = [
            mock.call(
                l3out_name,
                mgr.get_router_contract.return_value,
                external_epg=self._scoped_name(mocked.APIC_EXT_EPG,
                                               preexisting=True),
                owner=l3out_tenant, transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                l3out_name, mgr.get_router_contract.return_value,
                external_epg=self._scoped_name(mocked.APIC_EXT_EPG,
                                               preexisting=True),
                owner=l3out_tenant, transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)
        self.assertFalse(mgr.set_contract_for_epg.called)

        expected_l3out_bd_calls = [
            mock.call(self._tenant(neutron_tenant=n['tenant_id']),
                      self._scoped_name(n['id'], tenant=n['tenant_id']),
                      l3out_name,
                      transaction=mock.ANY)
            for n in nets]
        self._check_call_list(expected_l3out_bd_calls,
                              mgr.set_l3out_for_bd.call_args_list)

    def test_update_pre_no_nat_gw_port_postcommit_tenant(self):
        self._test_update_pre_no_nat_gw_port_postcommit(self._tenant())

    def test_update_pre_no_nat_gw_port_postcommit_common(self):
        self._test_update_pre_no_nat_gw_port_postcommit('common')

    def test_delete_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        self.driver._delete_path_if_last = mock.Mock()
        self.driver.delete_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        mgr.delete_external_routed_network.assert_called_once_with(
            "Shd-%s" % (self.driver.per_tenant_context and
                        self._scoped_name(vrf_pfx + mocked.APIC_NETWORK) or
                        mocked.APIC_NETWORK),
            owner=self._tenant(ext_nat=True))

    def test_delete_gw_port_postcommit_empty_tenant(self):
        self.driver._l3_plugin.get_router = mock.Mock(
            return_value={'id': mocked.APIC_ROUTER, 'tenant_id': ''})
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, external=True)
        r_cnst = n_constants.DEVICE_OWNER_ROUTER_GW
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          mocked.APIC_ROUTER,
                                          net_ctx, HOST_ID1, gw=True,
                                          device_owner=r_cnst)
        self.driver.delete_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        mgr.delete_external_routed_network.assert_not_called()

    def test_delete_edge_nat_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        self.driver._delete_path_if_last = mock.Mock()
        self.driver.l3out_vlan_alloc.release_vlan = mock.Mock()
        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = [
            {'tenant_id': mocked.APIC_TENANT,
             'name': mocked.APIC_NETWORK,
             'id': 'net_id'}]
        self.driver.delete_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        l3out_name = (self.driver.per_tenant_context and
                      self._scoped_name(vrf_pfx + mocked.APIC_NETWORK_EDGE_NAT)
                      or mocked.APIC_NETWORK_EDGE_NAT)
        l3out_name = "Auto-%s" % l3out_name
        mgr.delete_external_routed_network.assert_called_once_with(
            l3out_name, owner=self._tenant(ext_nat=True))
        self.driver.l3out_vlan_alloc.release_vlan.assert_called_once_with(
            mocked.APIC_NETWORK_EDGE_NAT + '-name',
            self._routed_network_vrf_name(),
            self._tenant(ext_nat=True))

        bd_name = self._scoped_name('net_id')
        mgr.unset_l3out_for_bd.assert_called_once_with(
            self._tenant(), bd_name, l3out_name, transaction=mock.ANY)

    def test_delete_pre_edge_nat_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        self.driver._delete_path_if_last = mock.Mock()
        self.driver.l3out_vlan_alloc.release_vlan = mock.Mock()
        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = [
            {'tenant_id': mocked.APIC_TENANT,
             'name': mocked.APIC_NETWORK,
             'id': 'net_id'}]
        self.driver.delete_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        l3out_name = (self.driver.per_tenant_context and
                      self._scoped_name(vrf_pfx +
                                        mocked.APIC_NETWORK_PRE_EDGE_NAT) or
                      mocked.APIC_NETWORK_PRE_EDGE_NAT)
        l3out_name = "Auto-%s" % l3out_name
        mgr.delete_external_routed_network.assert_called_once_with(
            l3out_name, owner=self._tenant(ext_nat=True))
        self.driver.l3out_vlan_alloc.release_vlan.assert_called_once_with(
            mocked.APIC_NETWORK_PRE_EDGE_NAT + '-name',
            self._routed_network_vrf_name(), self._tenant(ext_nat=True))

        bd_name = self._scoped_name('net_id')
        mgr.unset_l3out_for_bd.assert_called_once_with(
            self._tenant(), bd_name, l3out_name, transaction=mock.ANY)

    def test_delete_edge_nat_interface_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            'net_id',
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          'net_id',
                                          'vm1', net_ctx, HOST_ID1,
                                          interface=True)
        self.driver._l3_plugin.get_router = mock.Mock(
            return_value={'id': mocked.APIC_ROUTER,
                          'tenant_id': mocked.APIC_TENANT,
                          'external_gateway_info':
                              {'network_id': mocked.APIC_NETWORK_EDGE_NAT,
                               'external_fixed_ips': []}})
        port_ctx._plugin.get_network = mock.Mock(
            return_value={'name': mocked.APIC_NETWORK_EDGE_NAT + '-name',
                          'router:external': True})

        self.driver.delete_port_postcommit(port_ctx)

        prefix = ('%s-' % mocked.APIC_ROUTER
                  if self.driver.vrf_per_router_tenants else '')
        l3out_name = (self.driver.per_tenant_context and
                      self._scoped_name(prefix + mocked.APIC_NETWORK_EDGE_NAT)
                      or mocked.APIC_NETWORK_EDGE_NAT)
        l3out_name = "Auto-%s" % l3out_name
        bd_name = self._scoped_name('net_id')
        mgr = self.driver.apic_manager
        mgr.unset_l3out_for_bd.assert_called_once_with(
            self._tenant(), bd_name, l3out_name, transaction=mock.ANY)
        if self.driver.vrf_per_router_tenants:
            mgr.ensure_context_deleted(
                owner=self._tenant(), ctx_id=self._routed_network_vrf_name(),
                transaction=mock.ANY)
            mgr.set_context_for_bd.assert_called_once_with(
                self._tenant(), bd_name, self._network_vrf_name(),
                transaction=mock.ANY)

    def test_update_no_nat_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_NO_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_NO_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        nets = [
            {'tenant_id': mocked.APIC_TENANT + '1',
             'name': mocked.APIC_NETWORK,
             'id': 'net_id1'},
            {'tenant_id': mocked.APIC_TENANT + '2',
             'name': mocked.APIC_NETWORK,
             'id': 'net_id2'}]
        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = nets

        self.driver.update_port_postcommit(port_ctx)
        l3out_name = self._scoped_name(mocked.APIC_NETWORK_NO_NAT)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._router_tenant())

        mgr.set_context_for_external_routed_network.assert_called_once_with(
            self._tenant(), l3out_name,
            self._routed_network_vrf_name(),
            transaction=mock.ANY)

        mgr.ensure_external_epg_consumed_contract.assert_called_once_with(
            l3out_name,
            mgr.get_router_contract.return_value,
            external_epg=mocked.APIC_EXT_EPG, transaction=mock.ANY,
            owner=self._tenant())

        mgr.ensure_external_epg_provided_contract.assert_called_once_with(
            l3out_name,
            mgr.get_router_contract.return_value,
            external_epg=mocked.APIC_EXT_EPG, transaction=mock.ANY,
            owner=self._tenant())

        self.assertFalse(mgr.set_contract_for_epg.called)
        expected_l3out_bd_calls = [
            mock.call(self._tenant(neutron_tenant=n['tenant_id']),
                      self._scoped_name(n['id'], tenant=n['tenant_id']),
                      l3out_name,
                      transaction=mock.ANY)
            for n in nets]
        self._check_call_list(expected_l3out_bd_calls,
                              mgr.set_l3out_for_bd.call_args_list)

    def test_delete_unrelated_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            'unrelated',
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          'unrelated',
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        self.driver._delete_path_if_last = mock.Mock()
        self.driver.delete_port_postcommit(port_ctx)
        mgr = self.driver.apic_manager
        self.assertFalse(mgr.delete_external_epg_contract.called)

    def test_delete_pre_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        self.driver._delete_path_if_last = mock.Mock()
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant'}
        self.driver.delete_port_postcommit(port_ctx)
        vrf_pfx = ('%s-' % mocked.APIC_ROUTER
                   if self.driver.vrf_per_router_tenants else '')
        mgr.delete_external_routed_network.assert_called_once_with(
            "Shd-%s" % (self.driver.per_tenant_context and
                        self._scoped_name(vrf_pfx + mocked.APIC_NETWORK_PRE) or
                        mocked.APIC_NETWORK_PRE),
            owner=self._tenant(ext_nat=True))

    def _test_delete_no_nat_gw_port_postcommit(self, pre):
        if pre:
            self.external_network_dict[mocked.APIC_NETWORK_NO_NAT + '-name'][
                'preexisting'] = 'True'
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_NO_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_NO_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        self.driver._delete_path_if_last = mock.Mock()
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        if pre:
            self.driver._query_l3out_info = mock.Mock()
            self.driver._query_l3out_info.return_value = {
                'l3out_tenant': self._tenant(),
                'vrf_name': self._network_vrf_name(),
                'vrf_tenant': self._tenant(vrf=True)}
        nets = [
            {'tenant_id': mocked.APIC_TENANT + '1',
             'name': mocked.APIC_NETWORK,
             'id': 'net_id1'},
            {'tenant_id': mocked.APIC_TENANT + '2',
             'name': mocked.APIC_NETWORK,
             'id': 'net_id2'}]
        manager.NeutronManager = mock.MagicMock()
        manager.NeutronManager.get_plugin().get_networks.return_value = nets

        self.driver.delete_port_postcommit(port_ctx)

        if pre:
            l3out_name = self._scoped_name(net_ctx.current['name'],
                                           preexisting=True)
        else:
            l3out_name = self._scoped_name(mocked.APIC_NETWORK_NO_NAT)

        mgr.set_context_for_external_routed_network.assert_called_once_with(
            self._tenant(), l3out_name, None, transaction=mock.ANY)
        if pre:
            expected_calls = [
                mock.call(
                    l3out_name,
                    'contract-%s' % mocked.APIC_ROUTER,
                    external_epg=mocked.APIC_EXT_EPG, owner=self._tenant(),
                    provided=True, transaction=mock.ANY),
                mock.call(
                    l3out_name,
                    'contract-%s' % mocked.APIC_ROUTER,
                    external_epg=mocked.APIC_EXT_EPG, owner=self._tenant(),
                    provided=False, transaction=mock.ANY)]
            self._check_call_list(
                expected_calls,
                mgr.unset_contract_for_external_epg.call_args_list)
        else:
            mgr.delete_external_epg_contract.assert_called_once_with(
                self._scoped_name(mocked.APIC_ROUTER),
                l3out_name,
                transaction=mock.ANY)

        self.assertFalse(mgr.delete_external_routed_network.called)
        expected_l3out_bd_calls = [
            mock.call(self._tenant(neutron_tenant=n['tenant_id']),
                      self._scoped_name(n['id'], tenant=n['tenant_id']),
                      l3out_name,
                      transaction=mock.ANY)
            for n in nets]
        self._check_call_list(expected_l3out_bd_calls,
                              mgr.unset_l3out_for_bd.call_args_list)

    def test_delete_no_nat_gw_port_postcommit(self):
        self._test_delete_no_nat_gw_port_postcommit(False)

    def test_delete_no_nat_pre_gw_port_postcommit(self):
        self._test_delete_no_nat_gw_port_postcommit(True)

    def test_create_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1)
        mgr = self.driver.apic_manager
        self.driver.create_network_postcommit(ctx)
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            self._tenant(), self._scoped_name(mocked.APIC_NETWORK),
            ctx_owner=self._tenant(vrf=True),
            ctx_name=self._network_vrf_name(net_name=ctx.current['id']),
            transaction='transaction')
        mgr.ensure_epg_created.assert_called_once_with(
            self._tenant(), mocked.APIC_NETWORK, transaction='transaction',
            app_profile_name=self._app_profile(),
            bd_name=self._scoped_name(mocked.APIC_NETWORK))

    def test_create_external_network_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver.create_network_postcommit(net_ctx)

        ctx_name = self._network_vrf_name(
            nat_vrf=True, net_name=self._scoped_name(net_ctx.current['id']))
        mgr.ensure_context_enforced.assert_called_once_with(
            owner=self._tenant(vrf=True), ctx_id=ctx_name)

        bd_name = "EXT-bd-%s" % self._scoped_name(mocked.APIC_NETWORK)
        mgr.ensure_epg_created.assert_called_once_with(
            self._tenant(),
            "EXT-epg-%s" % self._scoped_name(mocked.APIC_NETWORK),
            bd_name=bd_name, app_profile_name=self._app_profile(),
            transaction=mock.ANY)
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            self._tenant(), bd_name,
            ctx_name=ctx_name, ctx_owner=self._tenant(vrf=True),
            transaction=mock.ANY)
        mgr.set_l3out_for_bd.assert_called_once_with(
            self._tenant(), bd_name, self._scoped_name(mocked.APIC_NETWORK),
            transaction=mock.ANY)

        expected_calls = [
            mock.call(self._scoped_name(mocked.APIC_NETWORK),
                      owner=self._tenant(),
                      context=self._network_vrf_name(
                          nat_vrf=True,
                          net_name=self._scoped_name(net_ctx.current['id'])),
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        mgr.set_domain_for_external_routed_network.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK),
            owner=self._tenant(), transaction='transaction')
        mgr.ensure_logical_node_profile_created.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK), mocked.APIC_EXT_SWITCH,
            mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT,
            mocked.APIC_EXT_ENCAP, mocked.APIC_EXT_CIDR_EXPOSED,
            owner=self._tenant(), transaction='transaction')
        mgr.ensure_static_route_created.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK), mocked.APIC_EXT_SWITCH,
            mocked.APIC_EXT_GATEWAY_IP, transaction='transaction',
            owner=self._tenant())

        contract_name = "EXT-%s-allow-all" % mocked.APIC_NETWORK
        mgr.create_tenant_filter.assert_called_once_with(
            contract_name, owner=self._tenant(), entry="allow-all",
            transaction=mock.ANY)
        mgr.manage_contract_subject_bi_filter.assert_called_once_with(
            contract_name, contract_name, contract_name,
            owner=self._tenant(),
            transaction=mock.ANY)

        expected_calls = [
            mock.call(self._scoped_name(mocked.APIC_NETWORK),
                      external_epg=mocked.APIC_EXT_EPG,
                      owner=self._tenant(),
                      transaction=mock.ANY)]

        self._check_call_list(
            expected_calls, mgr.ensure_external_epg_created.call_args_list)

        expected_calls = [
            mock.call(self._scoped_name(mocked.APIC_NETWORK), contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=True,
                      owner=self._tenant(), transaction=mock.ANY),
            mock.call(self._scoped_name(mocked.APIC_NETWORK), contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=False,
                      owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.set_contract_for_external_epg.call_args_list)

    def test_create_pre_external_network_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        self.driver.create_network_postcommit(net_ctx)

        self.assertFalse(mgr.ensure_context_enforced.called)
        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)

        bd_name = "EXT-bd-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE)
        l3out = self._scoped_name(net_ctx.current['name'], preexisting=True)
        mgr.ensure_epg_created.assert_called_once_with(
            self._tenant(),
            "EXT-epg-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE),
            bd_name=bd_name, app_profile_name=self._app_profile(),
            transaction=mock.ANY)
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            self._tenant(), bd_name,
            ctx_name='bar_ctx', ctx_owner='bar_tenant',
            transaction=mock.ANY)
        mgr.set_l3out_for_bd.assert_called_once_with(
            self._tenant(), bd_name, l3out,
            transaction=mock.ANY)

        contract_name = "EXT-%s-allow-all" % mocked.APIC_NETWORK_PRE
        mgr.create_tenant_filter.assert_called_once_with(
            contract_name, owner='bar_tenant', entry="allow-all",
            transaction=mock.ANY)
        mgr.manage_contract_subject_bi_filter.assert_called_once_with(
            contract_name, contract_name, contract_name,
            owner='bar_tenant', transaction=mock.ANY)

        expected_calls = [
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=True,
                      owner='bar_tenant', transaction=mock.ANY),
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=False,
                      owner='bar_tenant', transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.set_contract_for_external_epg.call_args_list)

    def test_create_pre_edge_nat_external_network_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        self.driver.create_network_postcommit(net_ctx)

        self.assertFalse(mgr.ensure_context_enforced.called)
        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)

        self.assertFalse(mgr.ensure_epg_created.called)
        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.set_l3out_for_bd.called)
        self.assertFalse(mgr.set_contract_for_epg.called)
        self.assertFalse(mgr.ensure_subnet_created_on_apic.called)

    def test_create_unknown_pre_external_network_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = None
        self.assertRaises(
            md.PreExistingL3OutNotFound,
            self.driver.create_network_postcommit, net_ctx)

        self.assertFalse(mgr.ensure_context_enforced.called)
        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)
        self.assertFalse(mgr.ensure_epg_created.called)
        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.create_tenant_filter.called)
        self.assertFalse(mgr.manage_contract_subject_bi_filter.called)
        self.assertFalse(mgr.set_contract_for_external_epg.called)
        self.assertFalse(mgr.set_l3out_for_bd.called)

    def test_delete_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1)
        mgr = self.driver.apic_manager
        self.driver.delete_network_postcommit(ctx)
        mgr.delete_bd_on_apic.assert_called_once_with(
            self._tenant(), self._scoped_name(mocked.APIC_NETWORK),
            transaction='transaction')
        mgr.delete_epg_for_network.assert_called_once_with(
            self._tenant(), mocked.APIC_NETWORK, transaction='transaction',
            app_profile_name=self._app_profile())

    def test_delete_external_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver.delete_network_postcommit(ctx)

        self.assertEqual(1, mgr.delete_bd_on_apic.call_count)
        self.assertEqual(1, mgr.delete_epg_for_network.call_count)

        mgr.delete_external_routed_network.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK), owner=self._tenant())
        ctx_name = self._network_vrf_name(
            nat_vrf=True, net_name=self._scoped_name(ctx.current['id']))
        mgr.ensure_context_deleted.assert_called_once_with(
            self._tenant(vrf=True), ctx_name, transaction=mock.ANY)

        contract_name = "EXT-%s-allow-all" % mocked.APIC_NETWORK
        mgr.delete_tenant_filter.assert_called_once_with(
            contract_name, owner=self._tenant(), transaction=mock.ANY)
        mgr.delete_contract.assert_called_once_with(
            contract_name, owner=self._tenant(), transaction=mock.ANY)

    def test_delete_pre_external_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK_PRE,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        self.driver.delete_network_postcommit(ctx)

        self.assertEqual(1, mgr.delete_bd_on_apic.call_count)
        self.assertEqual(1, mgr.delete_epg_for_network.call_count)

        self.assertFalse(mgr.delete_external_routed_network.called)

        contract_name = "EXT-%s-allow-all" % mocked.APIC_NETWORK_PRE
        l3out = self._scoped_name(ctx.current['name'], preexisting=True)
        expected_calls = [
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=True,
                      owner='bar_tenant', transaction=mock.ANY),
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=False,
                      owner='bar_tenant', transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.unset_contract_for_external_epg.call_args_list)

        mgr.delete_tenant_filter.assert_called_once_with(
            contract_name, owner='bar_tenant', transaction=mock.ANY)
        mgr.delete_contract.assert_called_once_with(
            contract_name, owner='bar_tenant', transaction=mock.ANY)

    def test_delete_pre_edge_nat_external_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        self.driver.delete_network_postcommit(ctx)

        self.assertFalse(mgr.delete_bd_on_apic.called)
        self.assertFalse(mgr.delete_epg_for_network.called)
        self.assertFalse(mgr.delete_external_routed_network.called)

        contract_name = "EXT-%s-allow-all" % mocked.APIC_NETWORK_PRE_EDGE_NAT
        l3out = self._scoped_name(ctx.current['name'], preexisting=True)
        expected_calls = [
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=True,
                      owner='bar_tenant', transaction=mock.ANY),
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=False,
                      owner='bar_tenant', transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.unset_contract_for_external_epg.call_args_list)

        mgr.delete_tenant_filter.assert_called_once_with(
            contract_name, owner='bar_tenant', transaction=mock.ANY)
        mgr.delete_contract.assert_called_once_with(
            contract_name, owner='bar_tenant', transaction=mock.ANY)

    def test_delete_external_no_nat_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK_NO_NAT,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver.delete_network_postcommit(ctx)
        mgr.delete_external_routed_network.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK_NO_NAT),
            owner=self._tenant())

    def test_create_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        subnet_ctx = self._get_subnet_context(SUBNET_GATEWAY,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager
        self.driver.create_subnet_postcommit(subnet_ctx)
        mgr.ensure_subnet_created_on_apic.assert_called_once_with(
            self._tenant(), self._scoped_name(mocked.APIC_NETWORK),
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK),
            scope=None)

    def test_create_subnet_nogw_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        subnet_ctx = self._get_subnet_context(None,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager
        self.driver.create_subnet_postcommit(subnet_ctx)
        self.assertFalse(mgr.ensure_subnet_created_on_apic.called)

    def test_create_external_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            external=True)
        subnet_ctx = self._get_subnet_context(SUBNET_GATEWAY,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager
        self.driver.create_subnet_postcommit(subnet_ctx)
        mgr.ensure_subnet_created_on_apic.assert_called_once_with(
            self._tenant(),
            "EXT-bd-%s" % self._scoped_name(mocked.APIC_NETWORK),
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK),
            scope=None)

    def test_create_edge_nat_external_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            external=True)
        subnet_ctx = self._get_subnet_context(SUBNET_GATEWAY,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager
        self.driver.create_subnet_postcommit(subnet_ctx)
        self.assertFalse(mgr.ensure_subnet_created_on_apic.called)

    def test_delete_external_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            external=True)
        subnet_ctx = self._get_subnet_context(SUBNET_GATEWAY,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager
        self.driver.delete_subnet_postcommit(subnet_ctx)
        mgr.ensure_subnet_deleted_on_apic.assert_called_once_with(
            self._tenant(),
            "EXT-bd-%s" % self._scoped_name(mocked.APIC_NETWORK),
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK))

    def test_delete_edge_nat_external_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            external=True)
        subnet_ctx = self._get_subnet_context(SUBNET_GATEWAY,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager
        self.driver.delete_subnet_postcommit(subnet_ctx)
        self.assertFalse(mgr.ensure_subnet_deleted_on_apic.called)

    def test_update_external_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            external=True)
        subnet_ctx1 = self._get_subnet_context(SUBNET_GATEWAY,
                                               SUBNET_CIDR,
                                               net_ctx)
        subnet_ctx2 = self._get_subnet_context('10.3.1.1',
                                               SUBNET_CIDR,
                                               net_ctx)
        subnet_ctx2.original = subnet_ctx1.current
        mgr = self.driver.apic_manager
        self.driver.update_subnet_postcommit(subnet_ctx2)
        mgr.ensure_subnet_deleted_on_apic.assert_called_once_with(
            self._tenant(),
            "EXT-bd-%s" % self._scoped_name(mocked.APIC_NETWORK),
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK),
            transaction=mock.ANY)
        mgr.ensure_subnet_created_on_apic.assert_called_once_with(
            self._tenant(),
            "EXT-bd-%s" % self._scoped_name(mocked.APIC_NETWORK),
            '%s/%s' % ('10.3.1.1', SUBNET_NETMASK),
            transaction=mock.ANY)

    def test_update_edge_nat_external_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            external=True)
        subnet_ctx1 = self._get_subnet_context(SUBNET_GATEWAY,
                                               SUBNET_CIDR,
                                               net_ctx)
        subnet_ctx2 = self._get_subnet_context('10.3.1.1',
                                               SUBNET_CIDR,
                                               net_ctx)
        subnet_ctx2.original = subnet_ctx1.current
        mgr = self.driver.apic_manager
        self.driver.update_subnet_postcommit(subnet_ctx2)
        self.assertFalse(mgr.ensure_subnet_deleted_on_apic.called)
        self.assertFalse(mgr.ensure_subnet_created_on_apic.called)

    def test_create_external_subnet_overlap(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            external=True)
        subnet_ctx = self._get_subnet_context(mocked.APIC_EXT_GATEWAY_IP,
                                              mocked.APIC_EXT_CIDR_EXPOSED,
                                              net_ctx)
        raised = False
        try:
            self.driver.create_subnet_precommit(subnet_ctx)
        except md.CidrOverlapsApicExternalSubnet:
            raised = True
        self.assertTrue(raised)

    def test_port_notify_on_subnet_update(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            seg_type='opflex')
        subnet_ctx1 = self._get_subnet_context(SUBNET_GATEWAY,
                                               SUBNET_CIDR,
                                               net_ctx)
        subnet_ctx2 = self._get_subnet_context('10.3.1.1',
                                               SUBNET_CIDR,
                                               net_ctx)
        subnet_ctx2.original = subnet_ctx1.current
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1)
        port_ctx.current['fixed_ips'] = [
            {'subnet_id': subnet_ctx2.current['id'],
             'ip_address': '10.3.1.42'}]
        subnet_ctx2._plugin.get_ports.return_value = [port_ctx.current]
        self.driver.update_subnet_postcommit(subnet_ctx2)
        self.assertTrue(self.driver.notifier.port_update.called)

    def test_query_l3out_info(self):
        ctx1 = [{
            'l3extRsEctx': {'attributes': {'tDn': 'uni/tn-foo/ctx-foobar'}}}]
        mgr = self.driver.apic_manager
        mgr.apic.l3extOut.get_subtree.return_value = ctx1
        info = self.driver._query_l3out_info('l3out', 'bar_tenant')
        self.assertEqual('bar_tenant', info['l3out_tenant'])
        self.assertEqual('foobar', info['vrf_name'])
        self.assertEqual('foo', info['vrf_tenant'])

        mgr.apic.l3extOut.get_subtree.reset_mock()
        mgr.apic.l3extOut.get_subtree.return_value = []
        info = self.driver._query_l3out_info('l3out', 'bar_tenant')
        self.assertEqual(None, info)
        expected_calls = [
            mock.call('bar_tenant', 'l3out'),
            mock.call('common', 'l3out')]
        self._check_call_list(
            expected_calls, mgr.apic.l3extOut.get_subtree.call_args_list)

    def test_nat_gw_port_precommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver.update_port_precommit(port_ctx)

    def _test_no_nat_multiple_gw_port_precommit_exception(self, pre):
        if pre:
            self.external_network_dict[mocked.APIC_NETWORK_NO_NAT + '-name'][
                'preexisting'] = 'True'
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_NO_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_NO_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True,
                                          router_owner='r2')
        self.driver._l3_plugin.get_routers.return_value = [
            {'id': 'r1', 'tenant_id': 't1'},
            {'id': 'r2', 'tenant_id': mocked.APIC_TENANT},
            {'id': 'r3', 'tenant_id': mocked.APIC_TENANT}]
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)

        if pre:
            self.driver._query_l3out_info = mock.Mock()
            self.driver._query_l3out_info.return_value = {
                'l3out_tenant': self._tenant(),
                'vrf_name': self._network_vrf_name(),
                'vrf_tenant': self._tenant(vrf=True)}

        if self.driver.per_tenant_context:
            self.assertRaises(md.OnlyOneRouterPermittedIfNatDisabled,
                              self.driver.update_port_precommit,
                              port_ctx)
        else:
            self.driver.update_port_precommit(port_ctx)

        del self.driver._l3_plugin.get_routers.return_value[0]
        self.driver.update_port_precommit(port_ctx)

    def test_no_nat_multiple_gw_port_precommit_exception(self):
        self._test_no_nat_multiple_gw_port_precommit_exception(False)

    def test_no_nat_multiple_pre_gw_port_precommit_exception(self):
        self._test_no_nat_multiple_gw_port_precommit_exception(True)

    def test_no_nat_pre_gw_port_precommit_l3out_wrong_tenant(self):
        self.external_network_dict[mocked.APIC_NETWORK_NO_NAT + '-name'][
            'preexisting'] = 'True'
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_NO_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_NO_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        if self.driver.per_tenant_context or self.driver.single_tenant_mode:
            self.assertRaises(md.PreExistingL3OutInIncorrectTenant,
                              self.driver.update_port_precommit,
                              port_ctx)
        else:
            self.driver.update_port_precommit(port_ctx)

    def test_pre_gw_port_precommit_l3out_not_exist(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = None
        self.assertRaises(md.PreExistingL3OutNotFound,
                          self.driver.update_port_precommit,
                          port_ctx)

    def test_gw_port_precommit_l3out_edge_nat_invalid_vlan_range(self):
        self.driver.l3out_vlan_alloc.l3out_vlan_ranges = {}
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.assertRaises(md.EdgeNatBadVlanRange,
                          self.driver.update_port_precommit,
                          port_ctx)

        del (self.external_network_dict[mocked.APIC_NETWORK_EDGE_NAT + '-name']
             ['vlan_range'])
        self.assertRaises(md.EdgeNatVlanRangeNotFound,
                          self.driver.update_port_precommit,
                          port_ctx)

    def test_pre_gw_port_precommit_l3out_edge_nat_wrong_IF_type(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant',
            'l3out': [{u'l3extLNodeP':
                       {u'attributes':
                        {u'dn':
                         u'uni/tn-common/out-supported/lnodep-Leaf3-4_NP'},
                        u'children': [{u'l3extLIfP':
                                       {u'children': [{u'l3extRsPathL3OutAtt':
                                                       {u'attributes':
                                                        {u'ifInstT': u'l3-port'
                                                         }}}]}}]}}]}
        self.assertRaises(md.EdgeNatWrongL3OutIFType,
                          self.driver.update_port_precommit,
                          port_ctx)

    def test_pre_gw_port_precommit_l3out_edge_nat_wrong_OSPF_auth(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant',
            'l3out': [{u'l3extLNodeP':
                       {u'attributes':
                        {u'dn':
                         u'uni/tn-common/out-supported/lnodep-Leaf3-4_NP'},
                        u'children': [{u'l3extLIfP':
                                       {u'children': [{u'ospfIfP':
                                                       {u'attributes':
                                                        {u'authType': u'simple'
                                                         }}}]}}]}}]}
        self.assertRaises(md.EdgeNatWrongL3OutAuthTypeForOSPF,
                          self.driver.update_port_precommit,
                          port_ctx)

    def test_pre_gw_port_precommit_l3out_edge_nat_wrong_BGP_auth(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant',
            'l3out': [{u'l3extLNodeP':
                       {u'attributes':
                        {u'dn':
                         u'uni/tn-common/out-supported/lnodep-Leaf3-4_NP'},
                        u'children': [{u'l3extLIfP':
                                       {u'children': [{u'l3extRsNodeL3OutAtt':
                                                       {u'attributes':
                                                        {u'type': u'sha1'}}},
                                                      {u'bfdIfP':
                                                       {u'attributes':
                                                        {u'type': u'sha1'}}},
                                                      {u'l3extRsNodeL3OutAtt':
                                                       {u'attributes':
                                                        {u'type': u'sha1'}}}]}}
                                      ]}}]}
        self.assertRaises(md.EdgeNatWrongL3OutAuthTypeForBGP,
                          self.driver.update_port_precommit,
                          port_ctx)

        # try again with a good input
        self.driver._query_l3out_info.return_value['l3out'] = (
            [{u'l3extLNodeP':
              {u'attributes':
               {u'dn': u'uni/tn-common/out-supported/lnodep-Leaf3-4_NP'},
               u'children': [{u'l3extLIfP':
                              {u'children': [{u'l3extRsNodeL3OutAtt':
                                              {u'attributes':
                                               {u'type': u'sha1'}}},
                                             {u'bfdIfP':
                                              {u'attributes':
                                               {u'type': u'none'}}},
                                             {u'l3extRsNodeL3OutAtt':
                                              {u'attributes':
                                               {u'type': u'sha1'}}}]}}]}}])
        self.driver.update_port_precommit(port_ctx)

    def _setup_multiple_routers(self, ext_net_name, net_ctx):
        routers = [{'id': 'r1', 'tenant_id': 't1'},
                   {'id': 'r2', 'tenant_id': 't1'},
                   {'id': 'r3', 'tenant_id': 't2'}]

        def get_router(ctx, id):
            for r in routers:
                if r['id'] == id:
                    return r

        def get_routers(ctx, filters):
            tenants = filters.get('tenant_id', [])
            return [r for r in routers
                    if (not tenants or r['tenant_id'] in tenants)]

        self.driver._l3_plugin.get_router = get_router
        self.driver._l3_plugin.get_routers = get_routers

        gw_ports = [
            self._get_port_context(mocked.APIC_TENANT,
                                   ext_net_name,
                                   'gw', net_ctx, HOST_ID1, gw=True,
                                   router_owner=r['id'])
            for r in routers]

        def get_ports(ctx, filters):
            devices = filters.get('device_id', [])
            return [p.current for p in gw_ports
                    if (not devices or p.current['device_id'] in devices)]
        for i in xrange(len(gw_ports)):
            gw_ports[i].current['id'] += i
            gw_ports[i]._plugin.get_ports = get_ports

        if self.driver.vrf_per_router_tenants:
            self.driver.vrf_per_router_tenants.extend(['t1', 't2'])
        return gw_ports

    def _test_delete_gw_port_multiple_postcommit(self, pre):
        if pre:
            ext_net_name = mocked.APIC_NETWORK_PRE
            ext_epg = self._scoped_name(mocked.APIC_EXT_EPG,
                                        preexisting=True)
        else:
            ext_net_name = mocked.APIC_NETWORK
            ext_epg = mocked.APIC_EXT_EPG

        shadow_ext_epg = "Shd-%s" % ext_epg

        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            ext_net_name,
                                            TEST_SEGMENT1, external=True)
        gw_ports = self._setup_multiple_routers(ext_net_name, net_ctx)

        self.driver._delete_path_if_last = mock.Mock()
        mgr = self.driver.apic_manager

        # Delete first GW port
        self.driver.delete_port_postcommit(gw_ports[0])
        vrf_pfx = ('%s-' % gw_ports[0]._port['device_id']
                   if self.driver.vrf_per_router_tenants else '')
        if self.driver.single_tenant_mode and self.driver.per_tenant_context:
            shadow_l3out = (
                "Shd-%s" % self._scoped_name(vrf_pfx + ext_net_name,
                                             tenant='t1'))
        else:
            shadow_l3out = "Shd-%s" % (vrf_pfx + ext_net_name)

        if self.driver.vrf_per_router_tenants:
            mgr.delete_external_routed_network.assert_called_once_with(
                shadow_l3out, owner=self._tenant(ext_nat=True,
                                                 neutron_tenant='t1'))
        else:
            self.assertFalse(mgr.delete_external_routed_network.called)
            exp_calls = [
                mock.call(shadow_l3out,
                          'contract-r1',
                          external_epg=shadow_ext_epg,
                          owner=self._tenant(ext_nat=True,
                                             neutron_tenant='t1'),
                          provided=True),
                mock.call(shadow_l3out,
                          'contract-r1',
                          external_epg=shadow_ext_epg,
                          owner=self._tenant(ext_nat=True,
                                             neutron_tenant='t1'),
                          provided=False)
            ]
            self._check_call_list(
                exp_calls, mgr.unset_contract_for_external_epg.call_args_list)
        del gw_ports[0]

        # Delete second GW port
        mgr.delete_external_routed_network.reset_mock()
        mgr.unset_contract_for_external_epg.reset_mock()
        self.driver.delete_port_postcommit(gw_ports[0])
        vrf_pfx = ('%s-' % gw_ports[0]._port['device_id']
                   if self.driver.vrf_per_router_tenants else '')

        if self.driver.per_tenant_context:
            if self.driver.single_tenant_mode:
                shadow_l3out = (
                    "Shd-%s" % self._scoped_name(vrf_pfx + ext_net_name,
                                                 tenant='t1'))
            else:
                shadow_l3out = "Shd-%s" % (vrf_pfx + ext_net_name)
            mgr.delete_external_routed_network.assert_called_once_with(
                shadow_l3out,
                owner=self._tenant(ext_nat=True, neutron_tenant='t1'))
        else:
            self.assertFalse(mgr.delete_external_routed_network.called)

            exp_calls = [
                mock.call(shadow_l3out,
                          'contract-r2',
                          external_epg=shadow_ext_epg,
                          owner=self._tenant(ext_nat=True), provided=True),
                mock.call(shadow_l3out,
                          'contract-r2',
                          external_epg=shadow_ext_epg,
                          owner=self._tenant(ext_nat=True), provided=False)
            ]
            self._check_call_list(
                exp_calls, mgr.unset_contract_for_external_epg.call_args_list)
        del gw_ports[0]

        # Delete third GW port
        mgr.unset_contract_for_external_epg.reset_mock()
        mgr.delete_external_routed_network.reset_mock()
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT + 'r3')
        self.driver.delete_port_postcommit(gw_ports[0])
        vrf_pfx = ('%s-' % gw_ports[0]._port['device_id']
                   if self.driver.vrf_per_router_tenants else '')
        if self.driver.single_tenant_mode and self.driver.per_tenant_context:
            shadow_l3out = (
                "Shd-%s" % self._scoped_name(vrf_pfx + ext_net_name,
                                             tenant='t2'))
        else:
            shadow_l3out = "Shd-%s" % (vrf_pfx + ext_net_name)
        mgr.delete_external_routed_network.assert_called_once_with(
            shadow_l3out, owner=self._tenant(ext_nat=True,
                                             neutron_tenant='t2'))

    def test_delete_gw_port_multiple_postcommit(self):
        self._test_delete_gw_port_multiple_postcommit(pre=False)

    def test_delete_pre_gw_port_multiple_postcommit(self):
        self._test_delete_gw_port_multiple_postcommit(pre=True)

    def _test_delete_no_nat_gw_port_multiple_postcommit(self, pre):
        ext_net_name = mocked.APIC_NETWORK_NO_NAT
        if pre:
            self.external_network_dict[mocked.APIC_NETWORK_NO_NAT + '-name'][
                'preexisting'] = 'True'

        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            ext_net_name,
                                            TEST_SEGMENT1, external=True)
        gw_ports = self._setup_multiple_routers(ext_net_name, net_ctx)
        mgr = self.driver.apic_manager
        l3out = net_ctx.current['name'] if pre else ext_net_name
        if pre:
            self.driver._query_l3out_info = mock.Mock()
            self.driver._query_l3out_info.return_value = {
                'l3out_tenant': self._tenant()}

        # Delete first GW port
        self.driver.delete_port_postcommit(gw_ports[0])
        self.assertFalse(mgr.set_context_for_external_routed_network.called)
        del gw_ports[0]

        # delete second GW port
        self.driver.delete_port_postcommit(gw_ports[0])
        if self.driver.single_tenant_mode:
            l3out = self._scoped_name(
                net_ctx.current['name'] if pre else ext_net_name,
                preexisting=pre)

        if self.driver.per_tenant_context:
            mgr.set_context_for_external_routed_network.assert_called_with(
                self._tenant(), l3out, None, transaction=mock.ANY)
        else:
            self.assertFalse(
                mgr.set_context_for_external_routed_network.called)
        del gw_ports[0]

        # delete third GW port
        mgr.set_context_for_external_routed_network.reset_mock()
        self.driver.delete_port_postcommit(gw_ports[0])
        mgr.set_context_for_external_routed_network.assert_called_with(
            self._tenant(), l3out, None, transaction=mock.ANY)

    def test_delete_no_nat_gw_port_multiple_postcommit(self):
        self._test_delete_no_nat_gw_port_multiple_postcommit(False)

    def test_delete_no_nat_pre_gw_port_multiple_postcommit(self):
        self._test_delete_no_nat_gw_port_multiple_postcommit(True)

    def test_no_nat_compute_port_precommit_exception(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_NO_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_NO_NAT,
                                          'vm1', net_ctx, HOST_ID1)
        self.assertRaises(md.VMsDisallowedOnExtNetworkIfNatDisabled,
                          self.driver.create_port_precommit,
                          port_ctx)

    def test_edge_nat_compute_port_precommit_exception(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_EDGE_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_EDGE_NAT,
                                          'vm1', net_ctx, HOST_ID1)
        self.assertRaises(md.VMsDisallowedOnExtNetworkIfEdgeNat,
                          self.driver.create_port_precommit,
                          port_ctx)

    def _get_network_context(self, tenant_id, net_id, seg_id=None,
                             seg_type='vlan', external=False, shared=False):
        network = {'id': net_id,
                   'name': net_id + '-name',
                   'tenant_id': tenant_id,
                   'provider:segmentation_id': seg_id,
                   'provider:network_type': seg_type,
                   'shared': shared}
        if external:
            network['router:external'] = True
        if seg_id:
            network_segments = [{'id': seg_id,
                                 'segmentation_id': ENCAP,
                                 'network_type': seg_type,
                                 'physical_network': 'physnet1'}]
        else:
            network_segments = []
        return FakeNetworkContext(network, network_segments)

    def _get_subnet_context(self, gateway_ip, cidr, network):
        subnet = {'tenant_id': network.current['tenant_id'],
                  'network_id': network.current['id'],
                  'id': '[%s/%s]' % (gateway_ip, cidr),
                  'gateway_ip': gateway_ip,
                  'cidr': cidr}
        return FakeSubnetContext(subnet, network)

    def _get_port_context(self, tenant_id, net_id, vm_id, network_ctx, host,
                          gw=False, device_owner='compute:nova',
                          router_owner=None, interface=False):
        port = {'device_id': vm_id,
                'device_owner': device_owner,
                'binding:host_id': host,
                'binding:vif_type': 'unbound' if not host else 'ovs',
                'tenant_id': tenant_id,
                'id': mocked.APIC_PORT,
                'name': mocked.APIC_PORT,
                'network_id': net_id}
        if gw:
            port['device_owner'] = n_constants.DEVICE_OWNER_ROUTER_GW
            port['device_id'] = router_owner or mocked.APIC_ROUTER
        if interface:
            port['device_owner'] = n_constants.DEVICE_OWNER_ROUTER_INTF
            port['device_id'] = router_owner or mocked.APIC_ROUTER

        return FakePortContext(port, network_ctx)


class ApicML2IntegratedTestCaseDvs(ApicML2IntegratedTestBase):

    def setUp(self, service_plugins=None):
        ml2_opts = {
            'mechanism_drivers': ['openvswitch', 'cisco_apic_ml2'],
            'tenant_network_types': ['opflex'],
            'type_drivers': ['opflex'],
        }
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseDvs, self).setUp(
            service_plugins, ml2_opts=ml2_opts)
        # This is required for the test. Without it,
        # the ML2 driver's agent_type ends up being a
        # mocked type, which fails when passed to the
        # hast_agents() method for the PortContext
        # (but only for types not defined by the
        # mechanism driver class itself).
        self.driver.agent_type = ofcst.AGENT_TYPE_OPFLEX_OVS
        self.driver._dvs_notifier = mock.MagicMock()
        self.driver.dvs_notifier.bind_port_call = mock.Mock(
            return_value=BOOKED_PORT_VALUE)

    def _verify_dvs_notifier(self, notifier, port, host):
            # can't use getattr() with mock, so use eval instead
            try:
                dvs_mock = eval('self.driver.dvs_notifier.' + notifier)
            except Exception:
                self.assertTrue(False,
                                "The method " + notifier + " was not called")
                return

            self.assertTrue(dvs_mock.called)
            a1, a2, a3, a4 = dvs_mock.call_args[0]
            self.assertEqual(a1['id'], port['id'])
            self.assertEqual(a2['id'], port['id'])
            self.assertEqual(a4, host)

    def _get_expected_pg(self, net):
        if self.driver.single_tenant_mode:
            return (self.driver.single_tenant_name + '|' +
                    net['tenant_id'] + '|' + net['id'])
        else:
            return (net['tenant_id'] + '|' +
                    mocked.APIC_SYSTEM_ID + '|' + net['id'])

    def test_bind_port_dvs(self):
        # Register a DVS agent
        self._register_agent('h1', agent_cfg=AGENT_CONF_DVS)
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=False,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp1 = self._bind_port_to_host(p1['id'], 'h1')
            # Called on the network's tenant
            expected_pg = self._get_expected_pg(net)
            pg = newp1['port']['binding:vif_details']['dvs_port_group_name']
            self.assertEqual(pg, expected_pg)
            port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNotNone(port_key)
            self.assertEqual(port_key, BOOKED_PORT_VALUE)
            self._verify_dvs_notifier('update_postcommit_port_call', p1, 'h1')
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp1['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            self._verify_dvs_notifier('delete_port_call', p1, 'h1')

    def test_bind_port_dvs_with_opflex_diff_hosts(self):
        # Register an OpFlex agent and DVS agent
        self._register_agent('h1')
        self._register_agent('h2', agent_cfg=AGENT_CONF_DVS)
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=False,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        # Bind a VLAN port after registering a DVS agent
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp1 = self._bind_port_to_host(p1['id'], 'h2')
            # Called on the network's tenant
            expected_pg = self._get_expected_pg(net)
            vif_det = newp1['port']['binding:vif_details']
            self.assertIsNotNone(vif_det.get('dvs_port_group_name', None))
            self.assertEqual(expected_pg, vif_det.get('dvs_port_group_name'))
            port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNotNone(port_key)
            self.assertEqual(port_key, BOOKED_PORT_VALUE)
            self._verify_dvs_notifier('update_postcommit_port_call', p1, 'h2')
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp1['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            self._verify_dvs_notifier('delete_port_call', p1, 'h2')

    def test_bind_ports_opflex_same_host(self):
        # Register an OpFlex agent and DVS agent
        self._register_agent('h1')
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=False,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        # Bind a VLAN port after registering a DVS agent
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp1 = self._bind_port_to_host(p1['id'], 'h1')
            # Called on the network's tenant
            vif_det = newp1['port']['binding:vif_details']
            self.assertIsNone(vif_det.get('dvs_port_group_name', None))
            port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNone(port_key)
            dvs_mock = self.driver.dvs_notifier.update_postcommit_port_call
            dvs_mock.assert_not_called()
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp1['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            dvs_mock = self.driver.dvs_notifier.delete_port_call
            dvs_mock.assert_not_called()
        self.driver.dvs_notifier.reset_mock()
        with self.port(subnet=sub, tenant_id='onetenant') as p2:
            p2 = p2['port']
            self.assertEqual(net['id'], p2['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp2 = self._bind_dhcp_port_to_host(p2['id'], 'h1')
            # Called on the network's tenant
            vif_det = newp2['port']['binding:vif_details']
            self.assertIsNone(vif_det.get('dvs_port_group_name', None))
            port_key = newp2['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNone(port_key)
            dvs_mock.assert_not_called()
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp2['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            dvs_mock = self.driver.dvs_notifier.delete_port_call
            dvs_mock.assert_not_called()

    def test_bind_ports_dvs_with_opflex_same_host(self):
        # Register an OpFlex agent and DVS agent
        self._register_agent('h1', agent_cfg=AGENT_CONF_DVS)
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=False,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        # Bind a VLAN port after registering a DVS agent
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp1 = self._bind_port_to_host(p1['id'], 'h1')
            # Called on the network's tenant
            expected_pg = self._get_expected_pg(net)
            vif_det = newp1['port']['binding:vif_details']
            self.assertIsNotNone(vif_det.get('dvs_port_group_name', None))
            self.assertEqual(expected_pg, vif_det.get('dvs_port_group_name'))
            port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNotNone(port_key)
            self.assertEqual(port_key, BOOKED_PORT_VALUE)
            self._verify_dvs_notifier('update_postcommit_port_call', p1, 'h1')
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp1['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            self._verify_dvs_notifier('delete_port_call', p1, 'h1')
        self.driver.dvs_notifier.reset_mock()
        with self.port(subnet=sub, tenant_id='onetenant') as p2:
            p2 = p2['port']
            self.assertEqual(net['id'], p2['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp2 = self._bind_dhcp_port_to_host(p2['id'], 'h1')
            # Called on the network's tenant
            vif_det = newp2['port']['binding:vif_details']
            self.assertIsNone(vif_det.get('dvs_port_group_name', None))
            port_key = newp2['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNone(port_key)
            dvs_mock = self.driver.dvs_notifier.update_postcommit_port_call
            dvs_mock.assert_not_called()
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp2['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            dvs_mock = self.driver.dvs_notifier.delete_port_call
            dvs_mock.assert_not_called()

    def test_bind_port_dvs_shared(self):
        # Register a DVS agent
        self._register_agent('h1', agent_cfg=AGENT_CONF_DVS)
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True)
        with self.port(subnet=sub, tenant_id='onetenant') as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            self.mgr.ensure_path_created_for_port = mock.Mock()
            # Bind port to trigger path binding
            newp1 = self._bind_port_to_host(p1['id'], 'h1')
            # Called on the network's tenant
            expected_pg = self._get_expected_pg(net)
            pg = newp1['port']['binding:vif_details']['dvs_port_group_name']
            self.assertEqual(pg, expected_pg)
            port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
            self.assertIsNotNone(port_key)
            self.assertEqual(port_key, BOOKED_PORT_VALUE)
            self._verify_dvs_notifier('update_postcommit_port_call', p1, 'h1')
            net_ctx = FakeNetworkContext(net, [{'network_type': 'opflex'}])
            port_ctx = FakePortContext(newp1['port'], net_ctx)
            self.driver.delete_port_postcommit(port_ctx)
            self._verify_dvs_notifier('delete_port_call', p1, 'h1')


class ApicML2IntegratedTestCaseDvsSingleTenantMode(
    ApicML2IntegratedTestCaseDvs):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseDvsSingleTenantMode, self).setUp()


class ApicML2IntegratedTestCaseDvsSingleTenantModeWithName(
    ApicML2IntegratedTestCaseDvs):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        self.override_conf('single_tenant_name', "singleTenantName",
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseDvsSingleTenantModeWithName,
              self).setUp()


class ApicML2IntegratedTestCaseSingleVRF(ApicML2IntegratedTestCase):

    def setUp(self, service_plugins=None):
        super(ApicML2IntegratedTestCaseSingleVRF, self).setUp(service_plugins)
        self.driver.per_tenant_context = True

    def test_add_router_interface_on_shared_net_by_subnet(self):
        pass

    def test_add_router_interface_on_shared_net_by_port(self):
        pass

    def test_inter_tenant_router_interface_disallowed(self):
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4, is_admin_context=True,
            tenant_id='anothertenant')
        router = self.create_router(api=self.ext_api,
                                    expected_res_status=201)['router']
        self.l3_plugin.per_tenant_context = True

        # Per subnet
        self.assertRaises(
            driver.InterTenantRouterInterfaceNotAllowedOnPerTenantContext,
            self.l3_plugin.add_router_interface, context.get_admin_context(),
            router['id'], {'subnet_id': sub['subnet']['id']})

        # Per port
        with self.port(subnet=sub, tenant_id='anothertenant') as p1:
            self.assertRaises(
                driver.InterTenantRouterInterfaceNotAllowedOnPerTenantContext,
                self.l3_plugin.add_router_interface,
                context.get_admin_context(), router['id'],
                {'port_id': p1['port']['id']})

    def test_vrf_per_router_intf_update(self):
        self.driver.vrf_per_router_tenants.append(mocked.APIC_TENANT)
        net = self.create_network(tenant_id=mocked.APIC_TENANT)['network']
        sub1 = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            tenant_id=mocked.APIC_TENANT, ip_version=4)
        sub2 = self.create_subnet(
            network_id=net['id'], cidr='192.168.1.0/24',
            tenant_id=mocked.APIC_TENANT, ip_version=4)
        router = self.create_router(api=self.ext_api,
                                    tenant_id=mocked.APIC_TENANT)['router']
        with self.port(subnet=sub1,
                       fixed_ips=[{'subnet_id': sub1['subnet']['id']}],
                       tenant_id=mocked.APIC_TENANT) as p:
            p1 = p['port']
        with self.port(subnet=sub2,
                       fixed_ips=[{'subnet_id': sub2['subnet']['id']}],
                       tenant_id=mocked.APIC_TENANT) as p:
            p2 = p['port']

        self.mgr.add_router_interface = mock.Mock()
        self.driver.notifier.port_update = mock.Mock()

        self._register_agent('h1')
        self._bind_port_to_host(p1['id'], 'h1')
        self._bind_port_to_host(p2['id'], 'h1')

        ctx = context.Context(user_id=None, tenant_id=mocked.APIC_TENANT)

        self.driver.notifier.port_update.reset_mock()
        self.l3_plugin.add_router_interface(
            ctx, router['id'], {'subnet_id': sub1['subnet']['id']})
        updates = sorted(set(
            [pt[0][1]['id']
             for pt in self.driver.notifier.port_update.call_args_list]))
        self.assertEqual(sorted([p1['id'], p2['id']]), updates)

        self.driver.notifier.port_update.reset_mock()
        self.l3_plugin.remove_router_interface(
            ctx, router['id'], {'subnet_id': sub1['subnet']['id']})
        updates = sorted(set(
            [pt[0][1]['id']
             for pt in self.driver.notifier.port_update.call_args_list]))
        self.assertEqual(sorted([p1['id'], p2['id']]), updates)


class ApicML2IntegratedTestCaseSingleTenant(ApicML2IntegratedTestCase):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseSingleTenant, self).setUp(
            service_plugins)


class ApicML2IntegratedTestCaseSingleTenantWithName(ApicML2IntegratedTestCase):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        self.override_conf('single_tenant_name', "singleTenantName",
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseSingleTenantWithName, self).setUp(
            service_plugins)


class ApicML2IntegratedTestCaseSingleTenantSingleContext(
        ApicML2IntegratedTestCaseSingleVRF):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseSingleTenantSingleContext,
              self).setUp(service_plugins)


class ApicML2IntegratedTestCaseSingleTenantWithNameSingleContext(
        ApicML2IntegratedTestCaseSingleVRF):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        self.override_conf('single_tenant_name', "singleTenantName",
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseSingleTenantWithNameSingleContext,
              self).setUp(service_plugins)


class TestApicML2IntegratedPhysicalNode(ApicML2IntegratedTestBase):

    def setUp(self, mech_drivers=None, service_plugins=None):
        ml2_opts = {
            'mechanism_drivers': mech_drivers or ['cisco_apic_ml2'],
            'tenant_network_types': ['opflex'],
            'type_drivers': ['opflex', 'vlan'],
        }
        super(TestApicML2IntegratedPhysicalNode, self).setUp(
            service_plugins=service_plugins, ml2_opts=ml2_opts)
        self.driver.agent_type = ofcst.AGENT_TYPE_OPFLEX_OVS
        self.driver.apic_manager.phy_net_dict = {
            'physnet1': {'hosts': set(['fw-app-01', 'lb-app-01'])}}
        self.mgr.ensure_path_created_for_port = mock.Mock()
        self.mgr.ensure_path_deleted_for_port = mock.Mock()
        self._register_agent('fw-app-01')
        self._register_agent('lb-app-01')
        self.expected_bound_driver = 'cisco_apic_ml2'

    def _get_bound_seg(self, port_id):
        port_context = self.plugin.get_bound_port_context(
            context.get_admin_context(), port_id)
        if port_context:
            driver = (port_context.binding_levels[-1]['bound_driver']
                      if port_context.binding_levels else None)
            return port_context.bottom_bound_segment, driver

    def _query_dynamic_seg(self, network_id):
        return ml2_db.get_network_segments(
            context.get_admin_context().session, network_id,
            filter_dynamic=True)

    def test_physical_bind(self):
        tenant1 = self._tenant(neutron_tenant='onetenant')
        app_prof1 = self._app_profile(neutron_tenant='onetenant')

        self._register_agent('h1', agent_cfg=AGENT_CONF_OPFLEX)

        net1 = self.create_network(tenant_id='onetenant',
                                   expected_res_status=201)['network']
        sub1 = self.create_subnet(
            network_id=net1['id'], cidr='192.168.0.0/24',
            is_admin_context=True, ip_version=4)
        with self.port(subnet=sub1, tenant_id='onetenant') as p:
            p1 = p['port']

        # bind to VM-host
        self._bind_port_to_host(p1['id'], 'h1')
        bseg_p1, bdriver = self._get_bound_seg(p1['id'])
        self.assertEqual(bseg_p1['network_type'], 'opflex')
        self.assertEqual('cisco_apic_ml2', bdriver)
        self.mgr.ensure_path_created_for_port.assert_not_called()

        # bind to one physical node
        self._bind_port_to_host(p1['id'], 'fw-app-01')
        bseg_p1, bdriver = self._get_bound_seg(p1['id'])
        self.assertEqual(bseg_p1['network_type'], 'vlan')
        self.assertEqual(self.expected_bound_driver, bdriver)
        self.assertEqual(1, len(self._query_dynamic_seg(net1['id'])))
        self.mgr.ensure_path_created_for_port.assert_called_once_with(
            tenant1, net1['id'], 'fw-app-01', bseg_p1['segmentation_id'],
            app_profile_name=app_prof1, transaction=mock.ANY)
        self.mgr.ensure_path_created_for_port.reset_mock()

        # bind another physical node to same network, then delete that port
        with self.port(subnet=sub1, tenant_id='onetenant') as p1_1:
            p1_1 = p1_1['port']
            self._bind_port_to_host(p1_1['id'], 'lb-app-01')
            self.assertEqual(bseg_p1, self._get_bound_seg(p1_1['id'])[0])
            self.assertEqual(1, len(self._query_dynamic_seg(net1['id'])))
            self.mgr.ensure_path_created_for_port.assert_called_once_with(
                tenant1, net1['id'], 'lb-app-01', bseg_p1['segmentation_id'],
                app_profile_name=app_prof1, transaction=mock.ANY)

            self.delete_port(p1_1['id'], tenant_id=p1_1['tenant_id'])
            self.assertEqual(1, len(self._query_dynamic_seg(net1['id'])))
            self.mgr.ensure_path_deleted_for_port.assert_called_once_with(
                tenant1, net1['id'], 'lb-app-01', app_profile_name=app_prof1)
        self.mgr.ensure_path_created_for_port.reset_mock()
        self.mgr.ensure_path_deleted_for_port.reset_mock()

        # bind p1 back to VM-host
        self._bind_port_to_host(p1['id'], 'h1')
        bseg_p1, bdriver = self._get_bound_seg(p1['id'])
        self.assertEqual('cisco_apic_ml2', bdriver)
        self.assertEqual(bseg_p1['network_type'], 'opflex')
        self.assertEqual(0, len(self._query_dynamic_seg(net1['id'])))
        self.mgr.ensure_path_deleted_for_port.assert_called_once_with(
            tenant1, net1['id'], 'fw-app-01', app_profile_name=app_prof1)
        self.mgr.ensure_path_deleted_for_port.reset_mock()

    def test_physical_bind_multiple_network(self):
        tenant1 = self._tenant(neutron_tenant='onetenant')
        app_prof1 = self._app_profile(neutron_tenant='onetenant')

        net1 = self.create_network(tenant_id='onetenant',
                                   expected_res_status=201)['network']
        sub1 = self.create_subnet(
            network_id=net1['id'], cidr='192.168.0.0/24',
            is_admin_context=True, ip_version=4)
        net2 = self.create_network(tenant_id='onetenant',
                                   expected_res_status=201)['network']
        sub2 = self.create_subnet(
            network_id=net2['id'], cidr='192.168.0.0/24',
            is_admin_context=True, ip_version=4)
        with self.port(subnet=sub1, tenant_id='onetenant') as p:
            p1 = p['port']
        with self.port(subnet=sub2, tenant_id='onetenant') as p:
            p2 = p['port']

        self._bind_port_to_host(p1['id'], 'fw-app-01')
        bseg_p1, bdriver = self._get_bound_seg(p1['id'])
        self.assertEqual(self.expected_bound_driver, bdriver)
        self.mgr.ensure_path_created_for_port.assert_called_once_with(
            tenant1, net1['id'], 'fw-app-01', bseg_p1['segmentation_id'],
            app_profile_name=app_prof1, transaction=mock.ANY)
        self.mgr.ensure_path_created_for_port.reset_mock()

        # bind port from another network to first physical node
        self._bind_port_to_host(p2['id'], 'fw-app-01')
        bseg_p2, bdriver = self._get_bound_seg(p2['id'])
        self.assertEqual(self.expected_bound_driver, bdriver)
        self.assertEqual(bseg_p2['network_type'], 'vlan')
        self.assertNotEqual(bseg_p1['segmentation_id'],
                            bseg_p2['segmentation_id'])
        self.assertEqual(1, len(self._query_dynamic_seg(net2['id'])))
        self.mgr.ensure_path_created_for_port.assert_called_once_with(
            tenant1, net2['id'], 'fw-app-01', bseg_p2['segmentation_id'],
            app_profile_name=app_prof1, transaction=mock.ANY)

        # delete the ports
        self.delete_port(p1['id'], tenant_id=p1['tenant_id'])
        self.assertEqual(0, len(self._query_dynamic_seg(net1['id'])))
        self.mgr.ensure_path_deleted_for_port.assert_called_once_with(
            tenant1, net1['id'], 'fw-app-01', app_profile_name=app_prof1)
        self.mgr.ensure_path_deleted_for_port.reset_mock()

        self.delete_port(p2['id'], tenant_id=p2['tenant_id'])
        self.assertEqual(0, len(self._query_dynamic_seg(net2['id'])))
        self.mgr.ensure_path_deleted_for_port.assert_called_once_with(
            tenant1, net2['id'], 'fw-app-01', app_profile_name=app_prof1)
        self.mgr.ensure_path_deleted_for_port.reset_mock()


class TestApicML2IntegratedPhysicalNodeMultiDriver(
    TestApicML2IntegratedPhysicalNode):

    def setUp(self, service_plugins=None):
        super(TestApicML2IntegratedPhysicalNodeMultiDriver, self).setUp(
            mech_drivers=['openvswitch', 'cisco_apic_ml2'],
            service_plugins=service_plugins)
        self.expected_bound_driver = 'openvswitch'


class TestCiscoApicMechDriverSingleVRF(TestCiscoApicMechDriver):

    def setUp(self):
        self.override_conf('per_tenant_context', False,
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverSingleVRF, self).setUp()


class TestCiscoApicMechDriverSingleTenant(TestCiscoApicMechDriver):

    def setUp(self):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverSingleTenant, self).setUp()


class TestCiscoApicMechDriverSingleTenantWithName(TestCiscoApicMechDriver):

    def setUp(self):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        self.override_conf('single_tenant_name', "singleTenantName",
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverSingleTenantWithName, self).setUp()


class TestCiscoApicMechDriverSingleTenantSingleVRF(
        TestCiscoApicMechDriverSingleVRF):

    def setUp(self):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverSingleTenantSingleVRF, self).setUp()


class TestCiscoApicMechDriverSingleTenantWithNameSingleVRF(
        TestCiscoApicMechDriverSingleVRF):

    def setUp(self):
        self.override_conf('single_tenant_mode', True,
                           'ml2_cisco_apic')
        self.override_conf('single_tenant_name', "singleTenantName",
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverSingleTenantWithNameSingleVRF,
              self).setUp()


class VrfPerRouterBase(object):
    def doSetup(self):
        self.override_conf('vrf_per_router_tenants',
                           [' coke ', '', ' ', mocked.APIC_TENANT],
                           'ml2_cisco_apic')

    def test_config_option(self):
        self.assertEqual(['coke', mocked.APIC_TENANT],
                         self.driver.vrf_per_router_tenants)

    def test_create_delete_router_vrf(self):
        routers = [{'id': 'r1', 'tenant_id': mocked.APIC_TENANT},
                   {'id': 'r2', 'tenant_id': 'another'}]

        for rtr in routers:
            is_vrf_per_router = (rtr['tenant_id'] == mocked.APIC_TENANT)
            mgr = self.driver.apic_manager
            vrf_tenant = self._tenant(neutron_tenant=rtr['tenant_id'])
            vrf_name = self._routed_network_vrf_name(router=rtr['id'],
                                                     tenant=rtr['tenant_id'])

            mgr.ensure_context_enforced.reset_mock()
            self.driver.create_vrf_per_router(rtr, 'txn')
            if is_vrf_per_router:
                mgr.ensure_context_enforced.assert_called_once_with(
                    owner=vrf_tenant, ctx_id=vrf_name, transaction='txn')
            else:
                mgr.ensure_context_enforced.assert_not_called()

            mgr.ensure_context_deleted.reset_mock()
            self.driver.delete_vrf_per_router(rtr, 'txn')
            if is_vrf_per_router:
                mgr.ensure_context_deleted.assert_called_once_with(
                    owner=vrf_tenant, ctx_id=vrf_name, transaction='txn')
            else:
                mgr.ensure_context_deleted.assert_not_called()

    def test_multiple_routers_precommit_exception(self):
        intf_ports = []

        def get_ports(ctx, filters):
            return [p.current for p in intf_ports]

        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK, TEST_SEGMENT1)
        for x in range(0, 3):
            rtr = '%s-%d' % (mocked.APIC_ROUTER, x / 2)
            port = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'intf', net_ctx, HOST_ID1,
                                          router_owner=rtr,
                                          interface=True)
            port.current['id'] += x
            port._plugin.get_ports = get_ports
            intf_ports.append(port)

            if x < 2:
                # no exception expected
                self.driver.create_port_precommit(port)
                self.driver.update_port_precommit(port)
            else:
                self.assertRaises(md.OnlyOneRouterPermittedIfVrfPerRouter,
                                  self.driver.create_port_precommit, port)
                self.assertRaises(md.OnlyOneRouterPermittedIfVrfPerRouter,
                                  self.driver.update_port_precommit, port)

    def test_multiple_intf_ports_delete(self):
        intf_ports = []

        def get_ports(ctx, filters):
            return [p.current for p in intf_ports]

        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK, TEST_SEGMENT1)
        mgr = self.driver.apic_manager
        for x in range(0, 3):
            port = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'intf', net_ctx, HOST_ID1,
                                          router_owner=mocked.APIC_ROUTER,
                                          interface=True)
            port.current['id'] += x
            port._plugin.get_ports = get_ports
            intf_ports.append(port)

        while intf_ports:
            port = intf_ports[0]
            del intf_ports[0]
            self.driver.delete_port_postcommit(port)
            if intf_ports:
                mgr.set_context_for_bd.assert_not_called()
            else:
                mgr.set_context_for_bd.assert_called_once_with(
                    self._tenant(), self._scoped_name(mocked.APIC_NETWORK),
                    self._network_vrf_name(), transaction=mock.ANY)


class TestCiscoApicMechDriverVrfPerRouter(TestCiscoApicMechDriver,
                                          VrfPerRouterBase):

    def setUp(self):
        self.doSetup()
        super(TestCiscoApicMechDriverVrfPerRouter, self).setUp()


class TestCiscoApicMechDriverVrfPerRouterSingleTenant(
    TestCiscoApicMechDriverSingleTenant, VrfPerRouterBase):

    def setUp(self):
        self.doSetup()
        super(TestCiscoApicMechDriverVrfPerRouterSingleTenant, self).setUp()


class TestCiscoApicMechDriverHostSNAT(ApicML2IntegratedTestBase):

    def setUp(self):
        super(TestCiscoApicMechDriverHostSNAT, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.mock_apic_manager_login_responses()
        self.driver = md.APICMechanismDriver()
        self.driver.synchronizer = None
        self.synchronizer = mock.Mock()
        md.APICMechanismDriver.get_base_synchronizer = mock.Mock(
            return_value=self.synchronizer)
        self.driver.initialize()
        self.driver.apic_manager = mock.Mock(
            name_mapper=mock.Mock(), ext_net_dict=self.external_network_dict)

        self.driver.apic_manager.apic.transaction = self.fake_transaction
        self.agent = {'configurations': {
            'opflex_networks': None,
            'bridge_mappings': {'physnet1': 'br-eth1'}}}
        self.actual_core_plugin = manager.NeutronManager.get_plugin()
        self.mgr_patch = mock.patch('neutron.manager.NeutronManager')
        self.mgr_patch.start()
        self.driver._l3_plugin = mock.Mock()

        def get_resource(context, resource_id):
            return {'id': resource_id, 'tenant_id': mocked.APIC_TENANT}

        self.driver._l3_plugin.get_router = get_resource

    def tearDown(self):
        self.mgr_patch.stop()
        super(TestCiscoApicMechDriverHostSNAT, self).tearDown()

    def _get_network_context(self, plugin, tenant_id, net_id, seg_id=None,
                             seg_type='vlan', external=False, shared=False):
        ctx = context.get_admin_context()
        network = {'id': net_id,
                   'name': mocked.APIC_NETWORK_HOST_SNAT + '-name',
                   'tenant_id': tenant_id,
                   'provider:segmentation_id': seg_id,
                   'provider:network_type': seg_type,
                   'shared': shared}
        if external:
            network['router:external'] = True
        return driver_context.NetworkContext(plugin, ctx, network)

    def test_1_port_created_for_host(self):
        # This test case is more of a functional test and should be revisited.
        ctx = context.get_admin_context()
        agent = {'host': 'h1'}
        agent.update(AGENT_CONF)
        self.actual_core_plugin.create_or_update_agent(ctx, agent)
        args = {'network': {'name': mocked.APIC_NETWORK_HOST_SNAT + '-name',
                            'admin_state_up': True, 'shared': True,
                            'status': n_constants.NET_STATUS_ACTIVE,
                            'tenant_id': 'onetenant',
                            'router:external': True}}
        db_net = self.driver.db_plugin.create_network(ctx, args)
        net_ctx = self._get_network_context(self.actual_core_plugin,
                                            ctx.tenant_id,
                                            db_net['id'],
                                            TEST_SEGMENT1, external=True)
        self.driver.create_network_postcommit(net_ctx)
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        snat_network_id = snat_networks[0]['id']
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='10.0.0.0/24',
            ip_version=4, is_admin_context=True)
        host_arg = {'binding:host_id': 'h2'}
        with self.port(subnet=sub, tenant_id='anothertenant',
                       device_owner='compute:', device_id='someid',
                       arg_list=(portbindings.HOST_ID,), **host_arg) as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            # We need the db_plugin to get invoked from the code being
            # tested. However, this was earlier mocked out in the setup,
            # hence we reset it here.
            manager.NeutronManager.get_plugin.return_value = (
                self.driver.db_plugin)
            self.driver.db_plugin._device_to_port_id = (
                self.actual_core_plugin._device_to_port_id)
            self.driver.db_plugin.get_bound_port_context = (
                self.actual_core_plugin.get_bound_port_context)
            self.driver.db_plugin.get_agents = (
                self.actual_core_plugin.get_agents)
            self.driver.db_plugin.create_or_update_agent = (
                self.actual_core_plugin.create_or_update_agent)
            self.driver.db_plugin._create_or_update_agent = (
                self.actual_core_plugin._create_or_update_agent)
            self.driver._is_nat_enabled_on_ext_net = mock.Mock()
            self.driver._is_connected_to_ext_net = mock.Mock()
            self.driver.agent_type = 'Open vSwitch agent'
            details = self.driver.get_gbp_details(
                ctx, device='tap%s' % p1['id'], host='h1')
            host_snat_ips = details['host_snat_ips']
            self.assertEqual(1, len(host_snat_ips))
            self.assertEqual(db_net['name'],
                             host_snat_ips[0]['external_segment_name'])
            self.assertEqual('192.168.0.2',
                             host_snat_ips[0]['host_snat_ip'])
            self.assertEqual('192.168.0.1',
                             host_snat_ips[0]['gateway_ip'])
            self.assertEqual(
                netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                host_snat_ips[0]['prefixlen'])
            snat_ports = self.driver.db_plugin.get_ports(
                ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                              'network_id': [snat_network_id],
                              'device_id': ['h1']})
            self.assertEqual(1, len(snat_ports))
            # Simulate a second event on the same host for the same external
            # network to check if the earlier allocated SNAT IP is returned
            with self.port(subnet=sub, tenant_id='anothertenant',
                           device_owner='compute:', device_id='someid',
                           arg_list=(portbindings.HOST_ID,), **host_arg) as p2:
                p2 = p2['port']
                self.assertEqual(net['id'], p2['network_id'])
                details = self.driver.get_gbp_details(
                    ctx, device='tap%s' % p2['id'], host='h1')
                host_snat_ips = details['host_snat_ips']
                self.assertEqual(1, len(host_snat_ips))
                self.assertEqual(db_net['name'],
                                 host_snat_ips[0]['external_segment_name'])
                self.assertEqual('192.168.0.2',
                                 host_snat_ips[0]['host_snat_ip'])
                self.assertEqual('192.168.0.1',
                                 host_snat_ips[0]['gateway_ip'])
                self.assertEqual(
                    netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                    host_snat_ips[0]['prefixlen'])
                snat_ports = self.driver.db_plugin.get_ports(
                    ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                  'network_id': [snat_network_id],
                                  'device_id': ['h1']})
                self.assertEqual(1, len(snat_ports))
            # Now simulate event of a second host
            host_arg = {'binding:host_id': 'h2'}
            with self.port(subnet=sub, tenant_id='anothertenant',
                           device_owner='compute:', device_id='someid',
                           arg_list=(portbindings.HOST_ID,), **host_arg) as p3:
                p3 = p3['port']
                self.assertEqual(net['id'], p3['network_id'])
                details = self.driver.get_gbp_details(
                    ctx, device='tap%s' % p3['id'], host='h2')
                host_snat_ips = details['host_snat_ips']
                self.assertEqual(1, len(host_snat_ips))
                self.assertEqual(db_net['name'],
                                 host_snat_ips[0]['external_segment_name'])
                self.assertEqual('192.168.0.3',
                                 host_snat_ips[0]['host_snat_ip'])
                self.assertEqual('192.168.0.1',
                                 host_snat_ips[0]['gateway_ip'])
                self.assertEqual(
                    netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                    host_snat_ips[0]['prefixlen'])
                snat_ports = self.driver.db_plugin.get_ports(
                    ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                  'network_id': [snat_network_id],
                                  'device_id': ['h2']})
                self.assertEqual(1, len(snat_ports))
        snat_ports = self.driver.db_plugin.get_ports(
            ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                          'network_id': [snat_network_id]})
        self.assertEqual(2, len(snat_ports))
        self.driver.delete_network_postcommit(net_ctx)
        snat_ports = self.driver.db_plugin.get_ports(
            ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                          'network_id': [snat_network_id]})
        self.assertEqual(0, len(snat_ports))
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        self.assertEqual(0, len(snat_networks))
        subnets = self.driver.db_plugin.get_subnets(
            ctx, filters={'name': [acst.HOST_SNAT_POOL]})
        self.assertEqual(0, len(subnets))

    def test_1_port_created_for_host_edge_nat(self):
        # This test case is more of a functional test and should be revisited.
        ctx = context.get_admin_context()
        agent = {'host': 'h1'}
        agent.update(AGENT_CONF)
        self.actual_core_plugin.create_or_update_agent(ctx, agent)
        args = {'network': {'name': mocked.APIC_NETWORK_EDGE_NAT + '-name',
                            'admin_state_up': True, 'shared': True,
                            'status': n_constants.NET_STATUS_ACTIVE,
                            'tenant_id': 'onetenant',
                            'router:external': True}}
        db_net = self.driver.db_plugin.create_network(ctx, args)
        net_ctx = self._get_network_context(self.actual_core_plugin,
                                            ctx.tenant_id,
                                            db_net['id'],
                                            TEST_SEGMENT1, external=True)
        self.driver.create_network_postcommit(net_ctx)
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        snat_network_id = snat_networks[0]['id']
        net = self.create_network(
            tenant_id='onetenant', expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='10.0.0.0/24',
            ip_version=4, is_admin_context=True)
        host_arg = {'binding:host_id': 'h2'}
        with self.port(subnet=sub, tenant_id='anothertenant',
                       device_owner='compute:', device_id='someid',
                       arg_list=(portbindings.HOST_ID,), **host_arg) as p1:
            p1 = p1['port']
            self.assertEqual(net['id'], p1['network_id'])
            # We need the db_plugin to get invoked from the code being
            # tested. However, this was earlier mocked out in the setup,
            # hence we reset it here.
            manager.NeutronManager.get_plugin.return_value = (
                self.driver.db_plugin)
            self.driver.db_plugin._device_to_port_id = (
                self.actual_core_plugin._device_to_port_id)
            self.driver.db_plugin.get_bound_port_context = (
                self.actual_core_plugin.get_bound_port_context)
            self.driver.db_plugin.get_agents = (
                self.actual_core_plugin.get_agents)
            self.driver.db_plugin.create_or_update_agent = (
                self.actual_core_plugin.create_or_update_agent)
            self.driver.db_plugin._create_or_update_agent = (
                self.actual_core_plugin._create_or_update_agent)
            self.driver._is_nat_enabled_on_ext_net = mock.Mock()
            self.driver._is_connected_to_ext_net = mock.Mock()
            self.driver.agent_type = 'Open vSwitch agent'
            details = self.driver.get_gbp_details(
                ctx, device='tap%s' % p1['id'], host='h1')
            host_snat_ips = details['host_snat_ips']
            self.assertEqual(0, len(host_snat_ips))
            snat_ports = self.driver.db_plugin.get_ports(
                ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                              'network_id': [snat_network_id],
                              'device_id': ['h1']})
            self.assertEqual(0, len(snat_ports))
            ipms = details['ip_mapping']
            self.assertEqual(0, len(ipms))

    def _create_snat_network(self, ctx, tenant_id):
        args = {'network': {'name': mocked.APIC_NETWORK_HOST_SNAT + '-name',
                            'admin_state_up': True, 'shared': True,
                            'status': n_constants.NET_STATUS_ACTIVE,
                            'tenant_id': tenant_id,
                            'router:external': True}}
        db_net = self.driver.db_plugin.create_network(ctx, args)
        net_ctx = self._get_network_context(self.actual_core_plugin,
                                            ctx.tenant_id,
                                            db_net['id'],
                                            TEST_SEGMENT1, external=True)
        self.driver.create_network_postcommit(net_ctx)
        return db_net, net_ctx

    def _snat_mock_setup(self, tenant_id):
        self.driver._is_edge_nat = mock.Mock(return_value=True)
        self.driver._is_pre_existing = mock.Mock(return_value=False)
        self.driver.apic_manager.apic.fvTenant.name = mock.Mock(
            return_value=tenant_id)
        # We need the db_plugin to get invoked from the code being
        # tested. However, this was earlier mocked out in the setup,
        # hence we reset it here.
        manager.NeutronManager.get_plugin.return_value = (
            self.driver.db_plugin)
        self.driver.db_plugin._device_to_port_id = (
            self.actual_core_plugin._device_to_port_id)
        self.driver.db_plugin.get_bound_port_context = (
            self.actual_core_plugin.get_bound_port_context)
        self.driver.db_plugin.get_agents = (
            self.actual_core_plugin.get_agents)
        self.driver.db_plugin.create_or_update_agent = (
            self.actual_core_plugin.create_or_update_agent)
        self.driver.db_plugin._create_or_update_agent = (
            self.actual_core_plugin._create_or_update_agent)
        self.driver._is_nat_enabled_on_ext_net = mock.Mock()
        self.driver._is_connected_to_ext_net = mock.Mock()
        self.driver.agent_type = 'Open vSwitch agent'

    def test_1_snat_ip_created_for_vrf_edge_nat(self):
        # This test case is more of a functional test and should be revisited.
        TEST_TENANT_ID1 = 'onetenant'
        TEST_TENANT_ID2 = 'anothertenant'
        self._snat_mock_setup(TEST_TENANT_ID1)
        ctx = context.get_admin_context()
        agent = {'host': 'h1'}
        agent.update(AGENT_CONF)
        self.actual_core_plugin.create_or_update_agent(ctx, agent)
        db_net, net_ctx = self._create_snat_network(ctx, TEST_TENANT_ID1)
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        snat_network_id = snat_networks[0]['id']
        net = self.create_network(
            tenant_id=TEST_TENANT_ID1, expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='10.0.0.0/24',
            ip_version=4, is_admin_context=True)
        host_arg = {'binding:host_id': 'h2'}
        # Create port with a different tenant
        with self.port(subnet=sub, tenant_id=TEST_TENANT_ID2,
                       device_owner='compute:', device_id='someid',
                       arg_list=(portbindings.HOST_ID,), **host_arg) as p1:
            port1 = p1['port']
            self.assertEqual(net['id'], port1['network_id'])
            details = self.driver.get_snat_ip_for_vrf(ctx,
                                                      TEST_TENANT_ID1, db_net)
            # Verify that the port has an SNAT IP, which is
            # allocated in the SNAT network tenant ID
            self.assertEqual(db_net['name'],
                             details['external_segment_name'])
            self.assertEqual('192.168.0.2', details['host_snat_ip'])
            self.assertEqual('192.168.0.1', details['gateway_ip'])
            self.assertEqual(
                netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                details['prefixlen'])
            snat_ports = self.driver.db_plugin.get_ports(
                ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                              'network_id': [snat_network_id],
                              'device_id': [TEST_TENANT_ID1]})
            self.assertEqual(1, len(snat_ports))
            # Simulate a second event on the same host with the same VRF for
            # the same external network to check if the earlier allocated SNAT
            # IP is returned
            with self.port(subnet=sub, tenant_id=TEST_TENANT_ID2,
                           device_owner='compute:', device_id='someid',
                           arg_list=(portbindings.HOST_ID,), **host_arg) as p2:
                port2 = p2['port']
                self.assertEqual(net['id'], port2['network_id'])
                details = self.driver.get_snat_ip_for_vrf(ctx,
                                                          TEST_TENANT_ID1,
                                                          db_net)
                self.assertEqual(db_net['name'],
                                 details['external_segment_name'])
                self.assertEqual('192.168.0.2', details['host_snat_ip'])
                self.assertEqual('192.168.0.1', details['gateway_ip'])
                self.assertEqual(
                    netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                    details['prefixlen'])
                snat_ports = self.driver.db_plugin.get_ports(
                    ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                  'network_id': [snat_network_id],
                                  'device_id': [TEST_TENANT_ID1]})
                self.assertEqual(1, len(snat_ports))
            # Now simulate event of a second host with same VRF
            host_arg = {'binding:host_id': 'h2'}
            with self.port(subnet=sub, tenant_id=TEST_TENANT_ID2,
                           device_owner='compute:', device_id='someid',
                           arg_list=(portbindings.HOST_ID,), **host_arg) as p3:
                port3 = p3['port']
                self.assertEqual(net['id'], port3['network_id'])
                details = self.driver.get_snat_ip_for_vrf(ctx,
                                                          TEST_TENANT_ID1,
                                                          db_net)
                self.assertEqual(db_net['name'],
                                 details['external_segment_name'])
                self.assertEqual('192.168.0.2',
                                 details['host_snat_ip'])
                self.assertEqual('192.168.0.1',
                                 details['gateway_ip'])
                self.assertEqual(
                    netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                    details['prefixlen'])
                snat_ports = self.driver.db_plugin.get_ports(
                    ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                  'network_id': [snat_network_id],
                                  'device_id': [TEST_TENANT_ID1]})
                self.assertEqual(1, len(snat_ports))
        snat_ports = self.driver.db_plugin.get_ports(
            ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                          'network_id': [snat_network_id]})
        self.assertEqual(1, len(snat_ports))
        self.driver.delete_network_postcommit(net_ctx)
        snat_ports = self.driver.db_plugin.get_ports(
            ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                          'network_id': [snat_network_id]})
        self.assertEqual(0, len(snat_ports))
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        self.assertEqual(0, len(snat_networks))
        subnets = self.driver.db_plugin.get_subnets(
            ctx, filters={'name': [acst.HOST_SNAT_POOL]})
        self.assertEqual(0, len(subnets))

    def test_2_snat_ips_created_for_2_vrfs_edge_nat(self):
        # This test case is more of a functional test and should be revisited.
        TEST_TENANT_ID1 = 'onetenant'
        TEST_TENANT_ID2 = 'anothertenant'
        self._snat_mock_setup(TEST_TENANT_ID1)
        ctx = context.get_admin_context()
        agent = {'host': 'h1'}
        agent.update(AGENT_CONF)
        self.actual_core_plugin.create_or_update_agent(ctx, agent)
        db_net, net_ctx = self._create_snat_network(ctx, TEST_TENANT_ID1)
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        snat_network_id = snat_networks[0]['id']
        net = self.create_network(
            tenant_id=TEST_TENANT_ID1, expected_res_status=201, shared=True,
            is_admin_context=True)['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='10.0.0.0/24',
            ip_version=4, is_admin_context=True)
        host_arg = {'binding:host_id': 'h2'}
        # Create port with a different tenant
        with self.port(subnet=sub, tenant_id=TEST_TENANT_ID2,
                       device_owner='compute:', device_id='someid',
                       arg_list=(portbindings.HOST_ID,), **host_arg) as p1:
            port1 = p1['port']
            self.assertEqual(net['id'], port1['network_id'])
            self.driver.apic_manager.apic.fvTenant.name = mock.Mock(
                return_value=TEST_TENANT_ID2)
            details = self.driver.get_snat_ip_for_vrf(ctx,
                                                      TEST_TENANT_ID2, db_net)
            # Verify that the port has an SNAT IP, which is
            # allocated in the SNAT network tenant ID
            self.assertEqual(db_net['name'],
                             details['external_segment_name'])
            self.assertEqual('192.168.0.2',
                             details['host_snat_ip'])
            self.assertEqual('192.168.0.1',
                             details['gateway_ip'])
            self.assertEqual(
                netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                details['prefixlen'])
            snat_ports = self.driver.db_plugin.get_ports(
                ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                              'network_id': [snat_network_id],
                              'device_id': [TEST_TENANT_ID2]})
            self.assertEqual(1, len(snat_ports))
            # Simulate a second event on the same host with the a different VRF
            # for the same external network to check if the earlier allocated
            # SNAT IP is returned
            with self.port(subnet=sub, tenant_id=TEST_TENANT_ID1,
                           device_owner='compute:', device_id='someid',
                           arg_list=(portbindings.HOST_ID,), **host_arg) as p2:
                port2 = p2['port']
                self.assertEqual(net['id'], port2['network_id'])
                self.driver.apic_manager.apic.fvTenant.name = mock.Mock(
                    return_value=TEST_TENANT_ID1)
                details = self.driver.get_snat_ip_for_vrf(ctx,
                                                          TEST_TENANT_ID1,
                                                          db_net)
                self.assertEqual(db_net['name'],
                                 details['external_segment_name'])
                self.assertEqual('192.168.0.3',
                                 details['host_snat_ip'])
                self.assertEqual('192.168.0.1',
                                 details['gateway_ip'])
                self.assertEqual(
                    netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                    details['prefixlen'])
                snat_ports = self.driver.db_plugin.get_ports(
                    ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                  'network_id': [snat_network_id],
                                  'device_id': [TEST_TENANT_ID1]})
                self.assertEqual(1, len(snat_ports))
            # Now simulate event of a second host with same VRF
            host_arg = {'binding:host_id': 'h2'}
            with self.port(subnet=sub, tenant_id=TEST_TENANT_ID2,
                           device_owner='compute:', device_id='someid',
                           arg_list=(portbindings.HOST_ID,), **host_arg) as p3:
                port3 = p3['port']
                self.assertEqual(net['id'], port3['network_id'])
                self.driver.apic_manager.apic.fvTenant.name = mock.Mock(
                    return_value=TEST_TENANT_ID2)
                details = self.driver.get_snat_ip_for_vrf(ctx,
                                                          TEST_TENANT_ID2,
                                                          db_net)
                self.assertEqual(db_net['name'],
                                 details['external_segment_name'])
                self.assertEqual('192.168.0.2',
                                 details['host_snat_ip'])
                self.assertEqual('192.168.0.1',
                                 details['gateway_ip'])
                self.assertEqual(
                    netaddr.IPNetwork(mocked.HOST_POOL_CIDR).prefixlen,
                    details['prefixlen'])
                snat_ports = self.driver.db_plugin.get_ports(
                    ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                                  'network_id': [snat_network_id],
                                  'device_id': [TEST_TENANT_ID2]})
                self.assertEqual(1, len(snat_ports))
        snat_ports = self.driver.db_plugin.get_ports(
            ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                          'network_id': [snat_network_id]})
        self.assertEqual(2, len(snat_ports))
        self.driver.delete_network_postcommit(net_ctx)
        snat_ports = self.driver.db_plugin.get_ports(
            ctx, filters={'name': [acst.HOST_SNAT_POOL_PORT],
                          'network_id': [snat_network_id]})
        self.assertEqual(0, len(snat_ports))
        snat_networks = self.driver.db_plugin.get_networks(
            ctx, filters={'name': [self.driver._get_snat_db_network_name(
                db_net)]})
        self.assertEqual(0, len(snat_networks))
        subnets = self.driver.db_plugin.get_subnets(
            ctx, filters={'name': [acst.HOST_SNAT_POOL]})
        self.assertEqual(0, len(subnets))

    def test_create_external_network_postcommit(self):
        ctx = context.get_admin_context()
        args = {'network': {'name': mocked.APIC_NETWORK_HOST_SNAT + '-name',
                            'admin_state_up': True, 'shared': True,
                            'tenant_id': 'onetenant',
                            'status': n_constants.NET_STATUS_ACTIVE}}
        db_net = self.driver.db_plugin.create_network(ctx, args)
        net_ctx = self._get_network_context(self.actual_core_plugin,
                                            ctx.tenant_id,
                                            db_net['id'],
                                            TEST_SEGMENT1, external=True)
        self.driver.create_network_postcommit(net_ctx)
        snat_networks = self.driver.db_plugin.get_networks(
            ctx,
            filters={'name': [self.driver._get_snat_db_network_name(db_net)]})
        snat_net_id = snat_networks[0]['id']
        self.assertEqual(1, len(snat_networks))
        seg = ml2_db.get_network_segments(ctx.session, snat_net_id)
        self.assertEqual(1, len(seg))
        subnets = self.driver.db_plugin.get_subnets(
            ctx, filters={'name': [acst.HOST_SNAT_POOL]})
        self.assertEqual(1, len(subnets))
        self.driver.delete_network_postcommit(net_ctx)
        snat_networks = self.driver.db_plugin.get_networks(
            ctx,
            filters={'name': [self.driver._get_snat_db_network_name(db_net)]})
        self.assertEqual(0, len(snat_networks))
        seg = ml2_db.get_network_segments(ctx.session, snat_net_id)
        self.assertEqual(0, len(seg))
        subnets = self.driver.db_plugin.get_subnets(
            ctx, filters={'name': [acst.HOST_SNAT_POOL]})
        self.assertEqual(0, len(subnets))


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, network, segments):
        self._network = network
        self._segments = segments
        self._plugin_context = mock.Mock()

    @property
    def current(self):
        return self._network

    @property
    def network_segments(self):
        return self._segments


class FakeSubnetContext(object):
    """To generate subnet context for testing purposes only."""

    def __init__(self, subnet, network):
        self._subnet = subnet
        self._network = network
        self._plugin = mock.Mock()
        self._plugin_context = mock.Mock()
        self._plugin.get_network.return_value = network.current

    @property
    def current(self):
        return self._subnet

    @property
    def network(self):
        return self._network


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, network):
        self._port = port
        self._network = network
        self._plugin = mock.Mock()
        self._plugin_context = mock.Mock()
        self._plugin.get_ports.return_value = []
        if network.network_segments:
            self._bound_segment = network.network_segments[0]
        else:
            self._bound_segment = None

        self.current = self._port
        self.original = self._port
        self.network = self._network
        self.top_bound_segment = self._bound_segment
        self.bottom_bound_segment = self._bound_segment
        self.host = self._port.get(portbindings.HOST_ID)
        self.original_host = None
        self.original_top_bound_segment = None
        self.original_bottom_bound_segment = None
        self._binding = mock.Mock()
        self._binding.segment = self._bound_segment

    def set_binding(self, segment_id, vif_type, cap_port_filter):
        pass
