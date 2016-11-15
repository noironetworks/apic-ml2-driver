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

import mock
from neutron.common import constants as q_const
from neutron import context
from neutron import manager

import apicapi.apic_mapper  # noqa

from apic_ml2.neutron.services.l3_router import (
    apic_driver as ad)
from apic_ml2.neutron.services.l3_router import l3_apic
from apic_ml2.neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)
from neutron.tests.unit import testlib_api


TENANT = 'tenant1'
ROUTER = 'router1'
SUBNET = 'subnet1'
NETWORK = 'network1'
PORT = 'port1'
NETWORK_NAME = 'one_network'
FLOATINGIP = 'fip1'


class FakeContract(object):
    def __init__(self):
        self.contract_id = '123'


class TestCiscoApicL3Driver(testlib_api.SqlTestCase,
                            mocked.ControllerMixin,
                            mocked.ConfigMixin):
    def setUp(self):
        super(TestCiscoApicL3Driver, self).setUp()
        mock.patch('neutron.plugins.ml2.drivers.cisco.apic.'
                   'apic_model.ApicDbModel').start()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.mock_apic_manager_login_responses()
        self.ml2_driver = mock.Mock()
        ad.mechanism_apic.APICMechanismDriver.apic_manager = mock.Mock()
        ad.mechanism_apic.APICMechanismDriver.get_driver_instance = mock.Mock(
            return_value=self.ml2_driver)
        self.plugin = l3_apic.ApicL3ServicePlugin()
        ad.mechanism_apic.APICMechanismDriver.notify_port_update_for_fip = (
            mock.Mock())
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
        self.plugin._apic_driver.name_mapper = mock.Mock()
        apicapi.apic_mapper.mapper_context = self.fake_transaction
        apic_driver = self.plugin._apic_driver
        apic_driver.name_mapper.tenant.return_value = mocked.APIC_TENANT
        apic_driver.name_mapper.network.return_value = mocked.APIC_NETWORK
        apic_driver.name_mapper.endpoint_group.return_value = (
            mocked.APIC_NETWORK)
        apic_driver.name_mapper.subnet.return_value = mocked.APIC_SUBNET
        apic_driver.name_mapper.port.return_value = mocked.APIC_PORT
        apic_driver.name_mapper.router.return_value = mocked.APIC_ROUTER
        apic_driver.name_mapper.app_profile.return_value = mocked.APIC_AP
        apic_driver.single_tenant_mode = False

        self.contract = FakeContract()
        self.plugin.get_router = mock.Mock(
            return_value={'id': ROUTER, 'admin_state_up': True,
                          'tenant_id': TENANT, 'name': ROUTER + '-name'})
        apic_driver.manager.apic.transaction = self.fake_transaction

        self.plugin._apic_driver._aci_mech_driver = self.ml2_driver
        manager.NeutronManager.get_plugin = mock.Mock()
        manager.NeutronManager.get_plugin.get_subnet = mock.Mock(
            return_value=self.subnet)
        manager.NeutronManager.get_plugin.get_network = mock.Mock(
            return_value=self.network)
        manager.NeutronManager.get_plugin.get_port = mock.Mock(
            return_value=self.port)
        manager.NeutronManager.get_plugin.get_ports = mock.Mock(
            return_value=[self.port])
        self.plugin.get_floatingip = mock.Mock(return_value=self.floatingip)
        self.plugin.update_floatingip_status = mock.Mock()

        mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                   '_core_plugin').start()
        mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                   'add_router_interface').start()
        mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                   'remove_router_interface').start()
        mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins').start()
        mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                   'update_floatingip',
                   new=mock.Mock(return_value=self.floatingip)).start()
        mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                   'create_floatingip',
                   new=mock.Mock(return_value=self.floatingip)).start()
        mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                   'delete_floatingip').start()

        apic_driver.aci_mech_driver._get_router_aci_tenant = mock.Mock(
            return_value='common')
        self.addCleanup(self.plugin._apic_driver.manager.reset_mock)

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
        return ('common'
                if not self.plugin._apic_driver.single_tenant_mode else
                mocked.APIC_TENANT)

    def test_update_router_postcommit(self):
        apic_driver = self.plugin._apic_driver
        mgr = apic_driver.manager
        router = {'id': ROUTER,
                  'tenant_id': TENANT,
                  'admin_state_up': True,
                  'name': ROUTER + '-name'}
        apic_driver._aci_mech_driver._get_tenant_vrf.return_value = {
            'aci_tenant': 'common',
            'aci_name': 'some_name'}
        apic_driver.update_router_postcommit(self.context, router)
        mgr.create_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                  owner=self._tenant(),
                                                  context='some_name',
                                                  transaction='transaction')
        mgr.enable_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                  owner=self._tenant(),
                                                  transaction='transaction')
        mgr.update_name_alias.assert_called_once_with(
            mgr.apic.vzBrCP, self._tenant(), 'contract-%s' % ROUTER,
            nameAlias=ROUTER + '-name')
        router['admin_state_up'] = False
        mgr.reset_mock()
        apic_driver.update_router_postcommit(self.context, router)
        mgr.create_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                  owner=self._tenant(),
                                                  context='some_name',
                                                  transaction='transaction')
        mgr.disable_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                   owner=self._tenant(),
                                                   transaction='transaction')
        mgr.update_name_alias.assert_called_once_with(
            mgr.apic.vzBrCP, self._tenant(), 'contract-%s' % ROUTER,
            nameAlias=ROUTER + '-name')

    def test_create_router_postcommit(self):
        rtr = {'id': ROUTER, 'tenant_id': TENANT, 'admin_state_up': True}
        apic_driver = self.plugin._apic_driver
        apic_driver.create_router_postcommit(self.context, rtr)
        md = apic_driver._aci_mech_driver
        md.create_vrf_per_router.assert_called_once_with(rtr)

    def test_delete_router_precommit(self):
        apic_driver = self.plugin._apic_driver
        mgr = apic_driver.manager
        apic_driver.delete_router_precommit(self.context, ROUTER)
        mgr.delete_router.assert_called_once_with(mocked.APIC_ROUTER)
        md = apic_driver._aci_mech_driver
        md.delete_vrf_per_router.assert_called_once_with(
            {'id': ROUTER, 'tenant_id': TENANT, 'name': ROUTER + '-name',
             'admin_state_up': True})

    def _test_add_router_interface_postcommit(self, interface_info):
        apic_driver = self.plugin._apic_driver
        mgr = apic_driver.manager
        mgr.reset_mock()
        apic_driver._aci_mech_driver._get_tenant_vrf.return_value = {
            'aci_tenant': 'common',
            'aci_name': 'some_name'}
        apic_driver._aci_mech_driver._get_network_aci_tenant.return_value = (
            mocked.APIC_TENANT)
        apic_driver._aci_mech_driver._get_network_app_profile.return_value = (
            mocked.APIC_AP)
        apic_driver.add_router_interface_postcommit(self.context,
                                                    ROUTER, interface_info)
        mgr.create_router.assert_called_once_with(mocked.APIC_ROUTER,
                                                  owner=self._tenant(),
                                                  context='some_name',
                                                  transaction='transaction')
        mgr.add_router_interface.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_ROUTER, mocked.APIC_NETWORK,
            app_profile_name=mocked.APIC_AP)
        mgr.update_name_alias.assert_called_once_with(
            mgr.apic.vzBrCP, self._tenant(), 'contract-%s' % ROUTER,
            nameAlias=ROUTER + '-name')

    def test_add_router_interface_postcommit_subnet(self):
        self._test_add_router_interface_postcommit(
            self.interface_info['subnet'])

    def test_add_router_interface_postcommit_port(self):
        self._test_add_router_interface_postcommit(self.interface_info['port'])

    def _test_remove_router_interface_precommit(self, interface_info):
        plugin = self.plugin._core_plugin
        apic_driver = self.plugin._apic_driver
        mgr = apic_driver.manager
        apic_driver.remove_router_interface_precommit(self.context, ROUTER,
                                                      interface_info)
        self.assertEqual(1, mgr.remove_router_interface.call_count)
        plugin.update_port_status.assert_called_once_with(
            self.context, mock.ANY, q_const.PORT_STATUS_DOWN)

    def test_remove_router_interface_precommit_subnet(self):
        self._test_remove_router_interface_precommit(
            self.interface_info['subnet'])

    def test_remove_router_interface_precommit_port(self):
        self._test_remove_router_interface_precommit(
            self.interface_info['port'])

    def test_create_floatingip_postcommit(self):
        fip = {'floatingip': self.floatingip,
               'id': FLOATINGIP, 'port_id': PORT}
        apic_driver = self.plugin._apic_driver
        apic_driver.create_floatingip_postcommit(self.context, fip)
        self.ml2_driver.notify_port_update_for_fip.assert_called_once_with(
            PORT)
        apic_driver._plugin.update_floatingip_status.assert_called_once_with(
            mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)
        self.assertEqual(q_const.FLOATINGIP_STATUS_ACTIVE, fip['status'])

    def test_update_floatingip_precommit(self):
        fip = {'floatingip': self.floatingip}
        apic_driver = self.plugin._apic_driver
        apic_driver.update_floatingip_precommit(self.context, FLOATINGIP, fip)
        self.assertEqual(PORT, self.context.port_id_list[0])

    def test_update_floatingip_postcommit(self):
        fip = {'floatingip': self.floatingip,
               'id': FLOATINGIP, 'port_id': PORT}
        self.context.port_id_list = [self.port['id']]
        apic_driver = self.plugin._apic_driver
        apic_driver.update_floatingip_postcommit(self.context, FLOATINGIP, fip)
        self.assertEqual(self.port['id'], self.context.port_id_list[0])
        self.assertEqual(PORT, self.context.port_id_list[1])
        calls = [mock.call(self.port['id']), mock.call(PORT)]
        self.ml2_driver.notify_port_update_for_fip.assert_has_calls(calls)

    def test_delete_floatingip_precommit(self):
        apic_driver = self.plugin._apic_driver
        apic_driver.delete_floatingip_precommit(self.context, FLOATINGIP)
        self.assertEqual(PORT, self.context.port_id_list[0])

    def test_delete_floatingip_postcommit(self):
        self.context.port_id_list = [PORT]
        apic_driver = self.plugin._apic_driver
        apic_driver.delete_floatingip_postcommit(self.context, FLOATINGIP)
        self.ml2_driver.notify_port_update_for_fip.assert_called_once_with(
            PORT)
