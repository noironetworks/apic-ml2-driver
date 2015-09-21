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

import sys

import mock
from neutron.common import exceptions as n_exc
from neutron import context

sys.modules["apicapi"] = mock.Mock()

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    mechanism_apic as md)
from apic_ml2.neutron.services.l3_router import l3_apic
from apic_ml2.neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)
from neutron.tests.unit import testlib_api


TENANT = 'tenant1'
TENANT_CONTRACT = 'abcd'
ROUTER = 'router1'
SUBNET = 'subnet1'
NETWORK = 'network1'
PORT = 'port1'
NETWORK_NAME = 'one_network'
NETWORK_EPG = 'one_network-epg'
TEST_SEGMENT1 = 'test-segment1'
SUBNET_GATEWAY = '10.3.2.1'
SUBNET_CIDR = '10.3.1.0/24'
SUBNET_NETMASK = '24'


class FakeContract(object):
    def __init__(self):
        self.contract_id = '123'


class FakeEpg(object):
    def __init__(self):
        self.epg_id = 'abcd_epg'


class FakePort(object):
    def __init__(self):
        self.id = 'Fake_port_id'
        self.network_id = NETWORK
        self.subnet_id = SUBNET


class TestCiscoApicL3Plugin(testlib_api.SqlTestCase,
                            mocked.ControllerMixin,
                            mocked.ConfigMixin):
    def setUp(self):
        super(TestCiscoApicL3Plugin, self).setUp()
        mock.patch('neutron.plugins.ml2.drivers.cisco.apic.'
                   'apic_model.ApicDbModel').start()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.plugin = l3_apic.ApicL3ServicePlugin()
        md.APICMechanismDriver.get_router_synchronizer = mock.Mock()
        self.context = context.get_admin_context()
        self.context.tenant_id = TENANT
        self.interface_info = {'subnet': {'subnet_id': SUBNET},
                               'port': {'port_id': PORT}}
        self.subnet = {'network_id': NETWORK, 'tenant_id': TENANT}
        self.port = {'tenant_id': TENANT,
                     'network_id': NETWORK,
                     'fixed_ips': [{'subnet_id': SUBNET}]}
        self.network = {'tenant_id': TENANT}
        self.plugin.name_mapper = mock.Mock()
        l3_apic.apic_mapper.mapper_context = self.fake_transaction
        self.plugin.name_mapper.tenant.return_value = mocked.APIC_TENANT
        self.plugin.name_mapper.network.return_value = mocked.APIC_NETWORK
        self.plugin.name_mapper.subnet.return_value = mocked.APIC_SUBNET
        self.plugin.name_mapper.port.return_value = mocked.APIC_PORT
        self.plugin.name_mapper.router.return_value = mocked.APIC_ROUTER
        self.plugin.name_mapper.app_profile.return_value = mocked.APIC_AP

        self.contract = FakeContract()
        self.plugin.get_router = mock.Mock(
            return_value={'id': ROUTER, 'admin_state_up': True,
                          'tenant_id': TENANT})
        self.plugin.manager.apic.transaction = self.fake_transaction

        self.plugin.get_subnet = mock.Mock(return_value=self.subnet)
        self.plugin.get_network = mock.Mock(return_value=self.network)
        self.plugin.get_port = mock.Mock(return_value=self.port)
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   '_core_plugin').start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'add_router_interface').start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'remove_router_interface').start()
        mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins').start()
        self.addCleanup(self.plugin.manager.reset_mock)

    def _tenant(self):
        return ('common' if not self.plugin.per_tenant_context else
                mocked.APIC_TENANT)

    def _test_add_router_interface(self, interface_info):
        mgr = self.plugin.manager
        mgr.reset_mock()
        self.plugin.add_router_interface(self.context, ROUTER, interface_info)
        mgr.create_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                  owner=self._tenant(),
                                                  transaction='transaction')
        mgr.add_router_interface.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_ROUTER, mocked.APIC_NETWORK)

    def _test_remove_router_interface(self, interface_info):
        mgr = self.plugin.manager
        self.plugin.remove_router_interface(self.context, ROUTER,
                                            interface_info)
        mgr.delete_contract_for_epg.assert_called_once()

    def test_add_router_interface_subnet(self):
        self._test_add_router_interface(self.interface_info['subnet'])

    def test_add_router_interface_port(self):
        self._test_add_router_interface(self.interface_info['port'])

    def test_remove_router_interface_subnet(self):
        self._test_remove_router_interface(self.interface_info['subnet'])

    def test_remove_router_interface_port(self):
        self._test_remove_router_interface(self.interface_info['port'])

    def test_create_router_gateway_fails(self):
        # Force _update_router_gw_info failure
        self.plugin._update_router_gw_info = mock.Mock(
            side_effect=n_exc.NeutronException)
        data = {'router': {
            'name': 'router1', 'admin_state_up': True,
            'external_gateway_info': {'network_id': 'some_uuid'}}}

        # Verify router doesn't persist on failure
        self.assertRaises(n_exc.NeutronException,
                          self.plugin.create_router, self.context, data)
        routers = self.plugin.get_routers(self.context)
        self.assertEqual(0, len(routers))

    def test_singleton_manager(self):
        self.assertIs(md.APICMechanismDriver.apic_manager, self.plugin.manager)


class TestCiscoApicL3PluginPerTenantVRF(TestCiscoApicL3Plugin):

    def setUp(self):
        self.override_conf('per_tenant_context', True,
                           'ml2_cisco_apic')
        super(TestCiscoApicL3PluginPerTenantVRF, self).setUp()
