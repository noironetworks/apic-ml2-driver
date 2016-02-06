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
from neutron.common import constants as q_const
from neutron.common import exceptions as n_exc
from neutron import context

import apicapi.apic_mapper  # noqa
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
FLOATINGIP = 'fip1'


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
        mock.patch('apic_ml2.neutron.plugins.ml2.drivers.cisco.apic.'
                   'apic_model.ApicDbModel').start()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.plugin = l3_apic.ApicL3ServicePlugin()
        md.APICMechanismDriver.get_router_synchronizer = mock.Mock()
        self.ml2_driver = mock.Mock()
        md.APICMechanismDriver.get_driver_instance = mock.Mock(
            return_value=self.ml2_driver)
        md.APICMechanismDriver.notify_port_update_for_fip = mock.Mock()
        self.context = context.get_admin_context()
        self.context.tenant_id = TENANT
        self.interface_info = {'subnet': {'subnet_id': SUBNET},
                               'port': {'port_id': PORT}}
        self.subnet = {'network_id': NETWORK, 'tenant_id': TENANT}
        self.port = {'tenant_id': TENANT,
                     'network_id': NETWORK,
                     'fixed_ips': [{'subnet_id': SUBNET}],
                     'id': 'port_id'}
        self.network = {'tenant_id': TENANT,
                        'id': 'network_id'}
        self.floatingip = {'id': FLOATINGIP,
                           'floating_network_id': NETWORK_NAME,
                           'port_id': PORT}
        self.plugin.name_mapper = mock.Mock()
        l3_apic.apic_mapper.mapper_context = self.fake_transaction
        self.plugin.name_mapper.tenant.return_value = mocked.APIC_TENANT
        self.plugin.name_mapper.network.return_value = mocked.APIC_NETWORK
        self.plugin.name_mapper.endpoint_group.return_value = (
            mocked.APIC_NETWORK)
        self.plugin.name_mapper.subnet.return_value = mocked.APIC_SUBNET
        self.plugin.name_mapper.port.return_value = mocked.APIC_PORT
        self.plugin.name_mapper.router.return_value = mocked.APIC_ROUTER
        self.plugin.name_mapper.app_profile.return_value = mocked.APIC_AP
        self.plugin.single_tenant_mode = False

        self.contract = FakeContract()
        self.plugin.get_router = mock.Mock(
            return_value={'id': ROUTER, 'admin_state_up': True,
                          'tenant_id': TENANT})
        self.plugin.manager.apic.transaction = self.fake_transaction

        self.plugin._aci_mech_driver = mock.Mock()
        self.plugin._ml2_plugin = mock.Mock()
        self.plugin.ml2_plugin.get_subnet = mock.Mock(return_value=self.subnet)
        self.plugin.ml2_plugin.get_network = mock.Mock(
            return_value=self.network)
        self.plugin.ml2_plugin.get_port = mock.Mock(return_value=self.port)
        self.plugin.ml2_plugin.get_ports = mock.Mock(return_value=[self.port])
        self.plugin.get_floatingip = mock.Mock(return_value=self.floatingip)
        self.plugin.update_floatingip_status = mock.Mock()

        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   '_core_plugin').start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'add_router_interface').start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'remove_router_interface').start()
        mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins').start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'update_floatingip',
                   new=mock.Mock(return_value=self.floatingip)).start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'create_floatingip',
                   new=mock.Mock(return_value=self.floatingip)).start()
        mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                   'delete_floatingip').start()

        def _get_router_aci_tenant(router):
            return 'common'
        self.plugin.aci_mech_driver._get_router_aci_tenant = (
            _get_router_aci_tenant)
        self.addCleanup(self.plugin.manager.reset_mock)

    def _check_call_list(self, expected, observed):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        self.assertFalse(
            len(observed),
            msg='There are more calls than expected: %s' % str(observed))

    def _tenant(self):
        return ('common' if not self.plugin.single_tenant_mode else
                mocked.APIC_TENANT)

    def _test_add_router_interface(self, interface_info):
        mgr = self.plugin.manager
        mgr.reset_mock()
        self.plugin._aci_mech_driver._get_tenant_vrf.return_value = {
            'aci_tenant': 'common',
            'aci_name': 'some_name'}
        self.plugin._aci_mech_driver._get_network_aci_tenant.return_value = (
            mocked.APIC_TENANT)
        self.plugin._aci_mech_driver._get_network_app_profile.return_value = (
            mocked.APIC_AP)
        self.plugin.add_router_interface(self.context, ROUTER, interface_info)
        mgr.create_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                  owner=self._tenant(),
                                                  context='some_name',
                                                  transaction='transaction')
        mgr.add_router_interface.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_ROUTER, mocked.APIC_NETWORK,
            app_profile_name=mocked.APIC_AP)

    def _test_remove_router_interface(self, interface_info):
        mgr = self.plugin.manager
        self.plugin.remove_router_interface(self.context, ROUTER,
                                            interface_info)
        self.assertEqual(1, mgr.remove_router_interface.call_count)

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

    def test_floatingip_port_notify_on_create(self):
        # create floating-ip with mapped port
        self.plugin.create_floatingip(self.context,
                                      {'floatingip': self.floatingip})
        self.ml2_driver.notify_port_update_for_fip.assert_called_once_with(
            PORT)

    def test_floatingip_port_notify_on_reassociate(self):
        # associate with different port
        new_fip = {'port_id': 'port-another'}
        self.ml2_driver.notify_port_update_for_fip.reset_mock()
        self.plugin.update_floatingip(self.context, FLOATINGIP,
                                      {'floatingip': new_fip})
        self._check_call_list(
            [mock.call(PORT), mock.call('port-another')],
            self.ml2_driver.notify_port_update_for_fip.call_args_list)

    def test_floatingip_port_notify_on_disassociate(self):
        # dissociate mapped port
        self.ml2_driver.notify_port_update_for_fip.reset_mock()
        self.plugin.update_floatingip(self.context, FLOATINGIP,
                                      {'floatingip': {}})
        self.ml2_driver.notify_port_update_for_fip.assert_called_once_with(
            PORT)

    def test_floatingip_port_notify_on_delete(self):
        # delete
        self.ml2_driver.notify_port_update_for_fip.reset_mock()
        self.plugin.delete_floatingip(self.context, FLOATINGIP)
        self.ml2_driver.notify_port_update_for_fip.assert_called_once_with(
            PORT)

    def test_floatingip_status(self):
        # create floating-ip with mapped port
        fip = self.plugin.create_floatingip(self.context,
                                            {'floatingip': self.floatingip})
        self.plugin.update_floatingip_status.assert_called_once_with(
            mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)
        self.assertEqual(q_const.FLOATINGIP_STATUS_ACTIVE, fip['status'])

        # dissociate mapped-port
        self.plugin.update_floatingip_status.reset_mock()
        self.floatingip.pop('port_id')
        fip = self.plugin.update_floatingip(self.context, FLOATINGIP,
                                            {'floatingip': self.floatingip})
        self.plugin.update_floatingip_status.assert_called_once_with(
            mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_DOWN)
        self.assertEqual(q_const.FLOATINGIP_STATUS_DOWN, fip['status'])

        # re-associate mapped-port
        self.plugin.update_floatingip_status.reset_mock()
        self.floatingip['port_id'] = PORT
        fip = self.plugin.update_floatingip(self.context, FLOATINGIP,
                                            {'floatingip': self.floatingip})
        self.plugin.update_floatingip_status.assert_called_once_with(
            mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)
        self.assertEqual(q_const.FLOATINGIP_STATUS_ACTIVE, fip['status'])


class TestCiscoApicL3PluginPerTenantVRF(TestCiscoApicL3Plugin):

    def setUp(self):
        self.override_conf('per_tenant_context', True,
                           'ml2_cisco_apic')
        super(TestCiscoApicL3PluginPerTenantVRF, self).setUp()
