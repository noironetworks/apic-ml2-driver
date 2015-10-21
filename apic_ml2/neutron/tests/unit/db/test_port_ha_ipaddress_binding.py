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

from neutron import context
from neutron.openstack.common import importutils
from neutron.tests.unit import testlib_api
from oslo.db import exception as exc

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class PortToHAIPAddressBindingTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(PortToHAIPAddressBindingTestCase, self).setUp()
        self.plugin = importutils.import_object(DB_PLUGIN_KLASS)
        self.context = context.get_admin_context()
        self.net1_data = {'network': {'id': 'fake-net1-id',
                                      'name': 'net1',
                                      'admin_state_up': True,
                                      'tenant_id': 'test-tenant',
                                      'shared': False}}
        self.net2_data = {'network': {'id': 'fake-net2-id',
                                      'name': 'net2',
                                      'admin_state_up': True,
                                      'tenant_id': 'test-tenant',
                                      'shared': False}}
        self.port1_data = {'port': {'id': 'fake-port1-id',
                                    'name': 'port1',
                                    'network_id': 'fake-net1-id',
                                    'tenant_id': 'test-tenant',
                                    'device_id': 'fake_device',
                                    'device_owner': 'fake_owner',
                                    'fixed_ips': [],
                                    'mac_address': 'fake-mac',
                                    'admin_state_up': True}}
        self.port2_data = {'port': {'id': 'fake-port2-id',
                                    'name': 'port2',
                                    'network_id': 'fake-net2-id',
                                    'tenant_id': 'test-tenant',
                                    'device_id': 'fake_device',
                                    'device_owner': 'fake_owner',
                                    'fixed_ips': [],
                                    'mac_address': 'fake-mac',
                                    'admin_state_up': True}}
        self.ha_ip1 = "ha-ip-1"
        self.ha_ip2 = "ha-ip-2"
        self.plugin.create_network(self.context, self.net1_data)
        self.plugin.create_network(self.context, self.net2_data)
        self.port1 = self.plugin.create_port(self.context, self.port1_data)
        self.port2 = self.plugin.create_port(self.context, self.port2_data)
        self.port_haip = ha.PortForHAIPAddress()

    def test_set_and_get_port_to_ha_ip_binding(self):
        # Test new HA IP address to port binding can be created
        obj = self.port_haip.set_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        self.assertEqual(self.port1['id'], obj['port_id'])
        self.assertEqual(self.ha_ip1, obj['ha_ip_address'])
        # In this test case we also test that same HA IP address can be set/get
        # for two different ports in different networks
        obj = self.port_haip.set_port_id_for_ha_ipaddress(
            self.port2['id'], self.ha_ip1)
        self.assertEqual(self.port2['id'], obj['port_id'])
        self.assertEqual(self.ha_ip1, obj['ha_ip_address'])
        # Test get
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port2['network_id'])
        self.assertEqual(self.port2['id'], obj['port_id'])

    def test_port_to_multiple_ha_ip_binding(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip1)
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip2)
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip2, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])

    def test_delete_port_for_ha_ip_binding(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip1)
        result = self.port_haip.delete_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        self.assertEqual(1, result)
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.port2['network_id'], self.ha_ip1)
        self.assertIsNone(obj)

    def test_get_ha_ip_addresses_for_port(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip1)
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip2)
        ha_ips = self.port_haip.get_ha_ipaddresses_for_port(self.port1['id'])
        self.assertEqual(sorted([self.ha_ip1, self.ha_ip2]), ha_ips)

    def test_idempotent(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip1)
        obj = self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip1)
        self.assertEqual(self.port1['id'], obj['port_id'])
        self.assertEqual(self.ha_ip1, obj['ha_ip_address'])

    def test_set_non_existing_port(self):
        self.assertRaises(exc.DBReferenceError,
                          self.port_haip.set_port_id_for_ha_ipaddress,
                          "fake", self.ha_ip1)

    def test_delete_non_existing_entry(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
            self.ha_ip1)
        result = self.port_haip.delete_port_id_for_ha_ipaddress(
            self.port1['id'], "fake")
        self.assertEqual(0, result)
        result = self.port_haip.delete_port_id_for_ha_ipaddress("fake",
            self.ha_ip1)
        self.assertEqual(0, result)
