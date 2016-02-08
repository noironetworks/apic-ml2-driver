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
import sys

from apicapi import apic_client
from apicapi import apic_manager
from apicapi import apic_mapper
import mock
sys.modules["opflexagent"] = mock.Mock()
sys.modules["opflexagent"].constants.TYPE_OPFLEX = 'opflex'
import netaddr
from neutron.api import extensions
from neutron.common import constants as n_constants
from neutron import context
from neutron.db import db_base_plugin_v2  # noqa
from neutron.db import models_v2  # noqa
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.tests import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from oslo_serialization import jsonutils as json

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    mechanism_apic as md)
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    rpc as mech_rpc)
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import constants as acst
from apic_ml2.neutron.services.l3_router import l3_apic
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

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'
AGENT_TYPE = n_constants.AGENT_TYPE_OVS
AGENT_CONF = {'alive': True, 'binary': 'somebinary',
              'topic': 'sometopic', 'agent_type': AGENT_TYPE,
              'configurations': {'opflex_networks': None,
                                 'bridge_mappings': {'physnet1': 'br-eth1'}}}


def echo(context, id, prefix=''):
    return id if not prefix else (prefix + id)


def name(name):
    return name


def equal(x, y):
    return str(x) == str(y)


class ApicML2IntegratedTestBase(test_plugin.NeutronDbPluginV2TestCase,
                                mocked.ControllerMixin, mocked.ConfigMixin,
                                mocked.ApicDBTestBase):

    def setUp(self, service_plugins=None):
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.override_conf('integrated_topology_service', True,
                           'ml2_cisco_apic')
        self.override_conf('per_tenant_context', False,
                           'ml2_cisco_apic')
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
        md.APICMechanismDriver.get_base_synchronizer = mock.Mock(
            return_value=self.synchronizer)
        self.driver.name_mapper.aci_mapper.tenant = echo
        self.driver.apic_manager.apic.transaction = self.fake_transaction
        self.rpc = self.driver.topology_endpoints[0]
        self.db = self.driver.apic_manager.db

        for switch in self.switch_dict:
            for module_port in self.switch_dict[switch]:
                module, port = module_port.split('/')
                hosts = self.switch_dict[switch][module_port]
                for host in hosts:
                    self.driver.apic_manager.add_hostlink(
                        host, 'static', None, switch, module, port)

        self.mgr = self.driver.apic_manager
        self.mgr.apic.fvTenant.name = name
        self.l3_plugin = manager.NeutronManager.get_service_plugins()[
            'L3_ROUTER_NAT']
        l3_apic.apic_mapper.mapper_context = self.fake_transaction
        self.driver.apic_manager.vmm_shared_secret = base64.b64encode(
            'dirtylittlesecret')
        self.driver.notifier = mock.Mock()

    def _bind_port_to_host(self, port_id, host):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.get_admin_context()
        agent = {'host': host}
        agent.update(AGENT_CONF)
        plugin.create_or_update_agent(ctx, agent)
        data = {'port': {'binding:host_id': host, 'device_owner': 'compute:',
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

    def test_enhanced_subnet_options(self):
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
        self.create_network(name=acst.APIC_SYNC_NETWORK, is_admin_context=True,
                            expected_res_status=500)
        self.assertTrue(self.synchronizer._sync_base.called)

    def test_sync_on_demand_no_admin(self):
        self.synchronizer.reset_mock()
        self.create_network(name=acst.APIC_SYNC_NETWORK,
                            expected_res_status=500)
        self.assertFalse(self.synchronizer._sync_base.called)

    def test_sync_on_demand_not(self):
        self.synchronizer.reset_mock()
        self.create_network(name='some_name', is_admin_context=True,
                            expected_res_status=201)
        self.assertFalse(self.synchronizer._sync_base.called)

    def test_attestation(self):
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
                    expected_calls = [
                        mock.call(mock.ANY, p1),
                        mock.call(mock.ANY, p2)]
                    self._check_call_list(
                        expected_calls,
                        self.driver.notifier.port_update.call_args_list)

    def test_dhcp_notifications_on_update(self):
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
        super(TestCiscoApicMechDriver, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.mock_apic_manager_login_responses()
        self.driver = md.APICMechanismDriver()
        self.driver.synchronizer = None
        self.synchronizer = mock.Mock()
        md.APICMechanismDriver.get_base_synchronizer = mock.Mock(
            return_value=self.synchronizer)
        md.APICMechanismDriver.get_apic_manager = mock.Mock()
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
        self.driver._allocate_snat_ip_for_host_and_ext_net = echo
        self.driver._create_snat_ip_allocation_subnet = echo
        self.driver._delete_snat_ip_allocation_network = echo

        def get_resource(context, resource_id):
            return {'id': resource_id, 'tenant_id': mocked.APIC_TENANT}

        self.driver._l3_plugin.get_router = get_resource

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
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        mgr = self.driver.apic_manager
        self.assertTrue(self.driver.check_segment_for_agent(
            port_ctx._bound_segment, self.agent))
        self.driver.create_port_postcommit(port_ctx)
        mgr.ensure_path_created_for_port.assert_called_once_with(
            self._tenant(), mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, transaction='transaction',
            app_profile_name=self._app_profile())

    def test_create_port_postcommit_opflex(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, seg_type='opflex')
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        self.assertTrue(self.driver.check_segment_for_agent(
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
            owner=self._tenant(vrf=True))

        expected_calls = [
            mock.call("Shd-%s" % self._scoped_name(mocked.APIC_NETWORK),
                      owner=self._tenant(), transaction=mock.ANY,
                      context=self._network_vrf_name())]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        expected_calls = [
            mock.call("Shd-%s" % self._scoped_name(mocked.APIC_NETWORK),
                      external_epg="Shd-%s" % mocked.APIC_EXT_EPG,
                      owner=self._tenant(), transaction=mock.ANY)]

        self._check_call_list(
            expected_calls, mgr.ensure_external_epg_created.call_args_list)

        expected_calls = [
            mock.call(
                "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK),
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % mocked.APIC_EXT_EPG,
                owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK),
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % mocked.APIC_EXT_EPG,
                owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

    def test_update_gw_port_postcommit(self):
        self._test_update_gw_port_postcommit()

    def test_update_cross_tenant_gw_port_postcommit(self):
        self._test_update_gw_port_postcommit('admin_tenant')

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
            owner=self._tenant(vrf=True))

        expected_calls = [
            mock.call("Shd-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE),
                      owner=self._tenant(), transaction=mock.ANY,
                      context=self._network_vrf_name())]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)

        mgr.ensure_external_epg_created.assert_called_once_with(
            "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE),
            external_epg="Shd-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                      preexisting=True),
            owner=self._tenant(), transaction=mock.ANY)

        expected_calls = [
            mock.call(
                "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE),
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                          preexisting=True),
                owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE),
                mgr.get_router_contract.return_value,
                external_epg="Shd-%s" % self._scoped_name(mocked.APIC_EXT_EPG,
                                                          preexisting=True),
                owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

    def test_update_pre_gw_port_postcommit(self):
        self._test_update_pre_gw_port_postcommit()

    def test_update_cross_tenant_pre_gw_port_postcommit(self):
        self._test_update_pre_gw_port_postcommit('admin_tenant')

    def test_update_pre_no_nat_gw_port_postcommit(self):
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
            'l3out_tenant': self._tenant(),
            'vrf_name': ctx_name,
            'vrf_tenant': self._tenant(vrf=True)}
        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._tenant(vrf=True))

        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)

        expected_calls = [
            mock.call(
                self._scoped_name(net_ctx.current['name'], preexisting=True),
                mgr.get_router_contract.return_value,
                external_epg=self._scoped_name(mocked.APIC_EXT_EPG,
                                               preexisting=True),
                owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_consumed_contract.call_args_list)

        expected_calls = [
            mock.call(
                self._scoped_name(net_ctx.current['name'], preexisting=True),
                mgr.get_router_contract.return_value,
                external_epg=self._scoped_name(mocked.APIC_EXT_EPG,
                                               preexisting=True),
                owner=self._tenant(), transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.ensure_external_epg_provided_contract.call_args_list)

        epg_name = "EXT-epg-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE)
        expected_calls = [
            mock.call(self._tenant(), epg_name,
                      mgr.get_router_contract.return_value, provider=True,
                      app_profile_name=self._app_profile(),
                      transaction=mock.ANY),
            mock.call(self._tenant(), epg_name,
                      mgr.get_router_contract.return_value, provider=False,
                      app_profile_name=self._app_profile(),
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls,
            mgr.set_contract_for_epg.call_args_list)

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
        mgr.delete_external_epg_contract.assert_called_once_with(
            self._scoped_name(mocked.APIC_ROUTER),
            self._scoped_name(mocked.APIC_NETWORK))
        mgr.delete_external_routed_network.assert_called_once_with(
            "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK),
            owner=self._tenant())

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

        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            self._scoped_name(port_ctx.current['device_id']),
            owner=self._tenant(vrf=True))

        mgr.ensure_external_epg_consumed_contract.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK_NO_NAT),
            mgr.get_router_contract.return_value,
            external_epg=mocked.APIC_EXT_EPG, transaction=mock.ANY,
            owner=self._tenant())

        mgr.ensure_external_epg_provided_contract.assert_called_once_with(
            self._scoped_name(mocked.APIC_NETWORK_NO_NAT),
            mgr.get_router_contract.return_value,
            external_epg=mocked.APIC_EXT_EPG, transaction=mock.ANY,
            owner=self._tenant())

        expected_calls = [
            mock.call(self._tenant(),
                      "EXT-epg-%s" % self._scoped_name(
                          mocked.APIC_NETWORK_NO_NAT),
                      mgr.get_router_contract.return_value,
                      provider=True,
                      app_profile_name=self._app_profile(mocked.APIC_TENANT),
                      transaction=mock.ANY),
            mock.call(self._tenant(),
                      "EXT-epg-%s" % self._scoped_name(
                          mocked.APIC_NETWORK_NO_NAT),
                      mgr.get_router_contract.return_value,
                      provider=False,
                      app_profile_name=self._app_profile(mocked.APIC_TENANT),
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.set_contract_for_epg.call_args_list)

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
        contract_name = "contract-%s" % mocked.APIC_ROUTER
        l3out = self._scoped_name(net_ctx.current['name'], preexisting=True)
        expected_calls = [
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=True,
                      owner='bar_tenant'),
            mock.call(l3out, contract_name,
                      external_epg=mocked.APIC_EXT_EPG, provided=False,
                      owner='bar_tenant')]
        self._check_call_list(
            expected_calls,
            mgr.unset_contract_for_external_epg.call_args_list)
        mgr.delete_external_routed_network.assert_called_once_with(
            "Shd-%s" % self._scoped_name(mocked.APIC_NETWORK_PRE),
            owner=self._tenant())

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
        mgr.set_l3out_for_bd(
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

    def test_create_unknown_pre_external_network_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = None
        self.driver.create_network_postcommit(net_ctx)

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
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK))

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
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK))

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
        raised = False
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        try:
            self.driver.update_port_precommit(port_ctx)
        except md.WouldRequireNAT:
            raised = True
        self.assertFalse(raised)

    def test_no_nat_gw_port_precommit(self):
        self.external_network_dict[mocked.APIC_NETWORK_NO_NAT + '-name'][
            'preexisting'] = 'True'
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_NO_NAT,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_NO_NAT,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        raised = False
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver._query_l3out_info = mock.Mock()
        self.driver._query_l3out_info.return_value = {
            'l3out_tenant': 'bar_tenant',
            'vrf_name': 'bar_ctx',
            'vrf_tenant': 'bar_tenant'}
        try:
            self.driver.update_port_precommit(port_ctx)
        except md.WouldRequireNAT:
            raised = True
        self.assertTrue(raised)

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
                          gw=False, device_owner='compute'):
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
            port['device_id'] = mocked.APIC_ROUTER
        return FakePortContext(port, network_ctx)


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
            l3_apic.InterTenantRouterInterfaceNotAllowedOnPerTenantContext,
            self.l3_plugin.add_router_interface, context.get_admin_context(),
            router['id'], {'subnet_id': sub['subnet']['id']})

        # Per port
        with self.port(subnet=sub, tenant_id='anothertenant') as p1:
            self.assertRaises(
                l3_apic.InterTenantRouterInterfaceNotAllowedOnPerTenantContext,
                self.l3_plugin.add_router_interface,
                context.get_admin_context(), router['id'],
                {'port_id': p1['port']['id']})


class ApicML2IntegratedTestCaseNoSingleTenant(ApicML2IntegratedTestCase):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', False,
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseNoSingleTenant, self).setUp(
            service_plugins)


class ApicML2IntegratedTestCaseNoSingleTenantSingleContext(
        ApicML2IntegratedTestCaseSingleVRF):

    def setUp(self, service_plugins=None):
        self.override_conf('single_tenant_mode', False,
                           'ml2_cisco_apic')
        super(ApicML2IntegratedTestCaseNoSingleTenantSingleContext,
              self).setUp(service_plugins)


class TestCiscoApicMechDriverPerTenantVRF(TestCiscoApicMechDriver):

    def setUp(self):
        self.override_conf('per_tenant_context', True,
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverPerTenantVRF, self).setUp()


class TestCiscoApicMechDriverMultiTenant(TestCiscoApicMechDriver):

    def setUp(self):
        self.override_conf('single_tenant_mode', False,
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverMultiTenant, self).setUp()


class TestCiscoApicMechDriverMultiTenantPerTenantVRF(
        TestCiscoApicMechDriverPerTenantVRF):

    def setUp(self):
        self.override_conf('single_tenant_mode', False,
                           'ml2_cisco_apic')
        super(TestCiscoApicMechDriverMultiTenantPerTenantVRF, self).setUp()


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
        mock.patch('neutron.manager.NeutronManager').start()
        self.driver._l3_plugin = mock.Mock()

        def get_resource(context, resource_id):
            return {'id': resource_id, 'tenant_id': mocked.APIC_TENANT}

        self.driver._l3_plugin.get_router = get_resource

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

    def test_create_external_network_postcommit(self):
        ctx = context.get_admin_context()
        args = {'network': {'name': mocked.APIC_NETWORK_HOST_SNAT + '-name',
                            'admin_state_up': True, 'shared': True,
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
        self.network = self._network
        self.top_bound_segment = self._bound_segment
        self.host = self._port.get(portbindings.HOST_ID)
        self.original_host = None
        self._binding = mock.Mock()
        self._binding.segment = self._bound_segment

    def set_binding(self, segment_id, vif_type, cap_port_filter):
        pass
