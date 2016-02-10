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

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.tests.unit import testlib_api
from oslo_log import log

from apic_ml2.neutron.db import l3out_vlan_allocation as l3out_vlan_alloc

LOG = log.getLogger(__name__)


class L3outVlanAllocationTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(L3outVlanAllocationTestCase, self).setUp()
        self.context = context.get_admin_context()
        ext_net_dict = {'Mgmt-Out': {'router_id': '1.0.0.2',
                                     'host_pool_cidr': '10.1.2.1/24',
                                     'port': '1/48',
                                     'switch': '401',
                                     'gateway_ip': '1.103.2.1',
                                     'router_type': 'asr',
                                     'vlan_range': '1500:1501',
                                     'cidr_exposed': '1.103.2.254/24'},
                        'DC-Out': {'router_id': '1.0.0.1',
                                   'host_pool_cidr': '10.1.2.1/24',
                                   'port': '1/48',
                                   'switch': '401',
                                   'gateway_ip': '1.103.2.1',
                                   'router_type': 'asr',
                                   'vlan_range': '1051:1055',
                                   'cidr_exposed': '1.103.2.254/24'},
                        }

        self.l3out_vlan_alloc = l3out_vlan_alloc.L3outVlanAlloc()
        self.l3out_vlan_alloc.sync_vlan_allocations(ext_net_dict)

    def test_reserve_vlan(self):
        vlan_min, vlan_max = self.l3out_vlan_alloc.l3out_vlan_ranges[
            'Mgmt-Out']
        LOG.info(("vlan range: %d - %d"), vlan_min, vlan_max)

        vlan_id1 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'admin')
        LOG.info(("vlan reserved: %d"), vlan_id1)
        self.assertTrue(vlan_min <= vlan_id1 <= vlan_max)

        # it should reserve the same vlan with the same l3 network + vrf
        vlan_id2 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'admin')
        self.assertEqual(vlan_id1, vlan_id2)

        vlan_id3 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'demo')
        LOG.info(("vlan reserved: %d"), vlan_id3)
        self.assertTrue(vlan_min <= vlan_id3 <= vlan_max)

    def test_exception_thrown_reserve_vlan_when_full(self):
        vlan_id1 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'test1')
        vlan_id2 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'test2')
        self.assertNotEqual(vlan_id1, vlan_id2)

        self.assertRaises(l3out_vlan_alloc.NoVlanAvailable,
                          self.l3out_vlan_alloc.reserve_vlan,
                          'Mgmt-Out', 'test3')

        self.l3out_vlan_alloc.release_vlan('Mgmt-Out', 'test1')
        vlan_id5 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'test3')
        self.assertEqual(vlan_id1, vlan_id5)

        # test when the vlan pool is full again with different vrf
        self.assertRaises(l3out_vlan_alloc.NoVlanAvailable,
                          self.l3out_vlan_alloc.reserve_vlan,
                          'Mgmt-Out', 'test1')

        # test when wrong L3 out network name
        self.assertRaises(l3out_vlan_alloc.NoVlanAvailable,
                          self.l3out_vlan_alloc.reserve_vlan,
                          'garbage', 'test3')

    def test_no_exception_thrown_release_no_vlan(self):
        self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'test1')
        self.l3out_vlan_alloc.release_vlan('Mgmt-Out', 'garbage')

    def test_get_vlan_allocated(self):
        vlan_id1 = self.l3out_vlan_alloc.reserve_vlan('Mgmt-Out', 'test')
        LOG.info(("vlan reserved: %d"), vlan_id1)

        vlan_id2 = l3out_vlan_alloc.L3outVlanAlloc.get_vlan_allocated(
            'Mgmt-Out', 'test')
        LOG.info(("vlan allocated: %d"), vlan_id2)
        self.assertEqual(vlan_id1, vlan_id2)

        vlan_id3 = l3out_vlan_alloc.L3outVlanAlloc.get_vlan_allocated(
            'Mgmt-Out', 'garbage')
        LOG.info(("vlan allocated: %s"), vlan_id3)
        self.assertIsNone(vlan_id3)

    def test_bad_range_throw_exception(self):
        bad_ext_net_dict = {
            'BadRange-Out': {
                'router_id': '1.0.0.1',
                'vlan_range': '4000:5000',
                'cidr_exposed': '1.103.2.254/24'
            }
        }
        bad_l3out_vlan_alloc = l3out_vlan_alloc.L3outVlanAlloc()
        self.assertRaises(n_exc.NetworkVlanRangeError,
                          bad_l3out_vlan_alloc.sync_vlan_allocations,
                          bad_ext_net_dict)

    def test_no_range_no_exception(self):
        ext_net_dict = {
            'NoRange-Out': {
                'router_id': '1.0.0.1',
                'cidr_exposed': '1.103.2.254/24'
            }
        }
        no_range_l3out_vlan_alloc = l3out_vlan_alloc.L3outVlanAlloc()
        no_range_l3out_vlan_alloc.sync_vlan_allocations(ext_net_dict)
