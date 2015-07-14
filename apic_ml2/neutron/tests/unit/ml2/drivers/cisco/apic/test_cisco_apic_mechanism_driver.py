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

sys.modules["apicapi"] = mock.Mock()

from neutron.common import constants as n_constants
from neutron import context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.tests import base
from neutron.tests.unit import test_db_plugin as test_plugin


from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    mechanism_apic as md)
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    rpc as mech_rpc)
from apic_ml2.neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)


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


def echo(context, id):
    return id


class MechanismRpcTestCase(test_plugin.NeutronDbPluginV2TestCase,
                           mocked.ControllerMixin, mocked.ConfigMixin,
                           mocked.ApicDBTestBase):

    def setUp(self, plugin_name=None, service_plugins=None):
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        self.override_conf('integrated_topology_service', True,
                           'ml2_cisco_apic')
        plugin_name = plugin_name or PLUGIN_NAME
        service_plugins = service_plugins or {'L3_ROUTER_NAT': 'cisco_apic_l3'}
        super(MechanismRpcTestCase, self).setUp(
            plugin_name, service_plugins=service_plugins)
        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.remove_networks_from_down_agents = mock.Mock()
        self.plugin.is_agent_down = mock.Mock(return_value=False)
        self.driver = self.plugin.mechanism_manager.mech_drivers[
            'cisco_apic_ml2'].obj
        self.driver.name_mapper.tenant = echo
        self.driver.name_mapper.network = echo
        self.driver.name_mapper.subnet = echo
        self.driver.name_mapper.port = echo
        self.driver.name_mapper.router = echo
        self.driver.name_mapper.pre_existing = echo
        self.driver.name_mapper.echo = echo
        self.driver.name_mapper.app_profile.return_value = mocked.APIC_AP
        self.driver.apic_manager.apic.transaction = self.fake_transaction
        self.rpc = self.driver.endpoints[0]
        self.db = apic_model.ApicDbModel()

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

    def _add_hosts_to_apic(self, num):
        for x in range(1, num + 1):
            self.db.add_hostlink('h%s' % x, 'static', None, str(x), '1',
                                 str(x))
        self.rpc.peers = self.rpc._load_peers()

    def test_rpc_endpoint_set(self):
        self.assertEqual(1, len(self.driver.endpoints))
        rpc = self.driver.endpoints[0]
        self.assertIsInstance(rpc, mech_rpc.ApicTopologyRpcCallbackMechanism)

    def test_peers_loaded(self):
        # Verify static configured hosts in rpc peers
        self._add_hosts_to_apic(2)

        peers = self.rpc._load_peers()
        self.assertEqual(2, len(peers))
        self.assertIn(('h1', 'static'), peers)
        self.assertIn(('h2', 'static'), peers)

    def test_remove_hostlink(self):
        # Test removal of one link
        self._add_hosts_to_apic(3)

        net = self.create_network()['network']
        sub = self.create_subnet(
            network_id=net['id'], cidr='192.168.0.0/24',
            ip_version=4)
        # Create two ports
        with self.port(subnet=sub) as p1:
            with self.port(subnet=sub) as p2:
                self._bind_port_to_host(p1['port']['id'], 'h1')
                self._bind_port_to_host(p2['port']['id'], 'h2')
                self.driver.apic_manager.reset_mock()

                # Remove H1 interface from ACI
                self.rpc.update_link(mock.Mock(), 'h1', 'static', None, 0, '1',
                                     '1')
                # Assert H1 on net vlan static paths deleted
                (self.driver.apic_manager.ensure_path_deleted_for_port.
                    assert_called_once_with(self._tenant_id, net['id'], 'h1'))

                self.driver.apic_manager.reset_mock()

                # Unbound
                self.rpc.update_link(mock.Mock(), 'h3', 'static', None, 0, '1',
                                     '3')
                self.assertEqual(
                    0, self.driver.apic_manager.ensure_path_deleted_for_port.
                    call_count)

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
                    self._bind_port_to_host(p3['port']['id'], 'h4')
                    self.driver.apic_manager.reset_mock()

                    # Add H3 interface from ACI
                    self.rpc.update_link(
                        mock.Mock(), 'h3', 'static', None, '3', '1', '3')
                    # No path created since no port is bound on H3
                    self.assertEqual(
                        0,
                        self.driver.apic_manager.ensure_path_created_for_port.
                        call_count)
                    self.driver.apic_manager.reset_mock()

                    # Add H4 interface from ACI
                    self.rpc.update_link(
                        mock.Mock(), 'h4', 'static', None, '4', '1', '4')

                    # P3 was bound in H4
                    net = self.show_network(net['id'],
                                            is_admin_context=True)['network']
                    (self.driver.apic_manager.ensure_path_created_for_port.
                        assert_called_once_with(
                            self._tenant_id, net['id'], 'h4',
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
                    self.driver.apic_manager.reset_mock()
                    # Change host interface
                    self.rpc.update_link(
                        mock.Mock(), 'h1', 'static', None, '1', '1', '24')

                    # Ports' path have been deleted and reissued two times (one
                    # for network)
                    mgr = self.driver.apic_manager
                    expected_calls_remove = [
                        mock.call(self._tenant_id, net1['id'], 'h1'),
                        mock.call(self._tenant_id, net2['id'], 'h1')]

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
                        mgr.ensure_path_deleted_for_port.call_args_list)
                    self._check_call_list(
                        expected_calls_add,
                        mgr.ensure_path_created_for_port.call_args_list)


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
        md.APICMechanismDriver.get_base_synchronizer = mock.Mock()
        self.driver.initialize()
        self.driver.vif_type = 'test-vif_type'
        self.driver.cap_port_filter = 'test-cap_port_filter'
        self.driver.name_mapper = mock.Mock()
        self.driver.name_mapper.tenant = echo
        self.driver.name_mapper.network = echo
        self.driver.name_mapper.subnet = echo
        self.driver.name_mapper.port = echo
        self.driver.name_mapper.router = echo
        self.driver.name_mapper.pre_existing = echo
        self.driver.name_mapper.echo = echo
        self.driver.name_mapper.app_profile.return_value = mocked.APIC_AP
        self.driver.apic_manager = mock.Mock(
            name_mapper=mock.Mock(), ext_net_dict=self.external_network_dict)

        self.driver.apic_manager.apic.transaction = self.fake_transaction

    def test_initialize(self):
        mgr = self.driver.apic_manager
        mgr.ensure_infra_created_on_apic.assert_called_once()
        mgr.ensure_bgp_pod_policy_created_on_apic.assert_called_once()

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
            mocked.APIC_TENANT, mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, transaction='transaction')

    def test_create_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1,
                                          device_owner='any')
        mgr = self.driver.apic_manager
        self.driver.create_port_postcommit(port_ctx)
        mgr.ensure_path_created_for_port.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, transaction='transaction')

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
            mocked.APIC_TENANT, mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, transaction='transaction')

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

    def test_update_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
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
            port_ctx.current['device_id'])
        mgr.ensure_context_enforced.assert_called_once()
        mgr.ensure_external_routed_network_created.assert_called_once_with(
            mocked.APIC_NETWORK, transaction='transaction')
        mgr.ensure_logical_node_profile_created.assert_called_once_with(
            mocked.APIC_NETWORK, mocked.APIC_EXT_SWITCH,
            mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT,
            mocked.APIC_EXT_ENCAP, mocked.APIC_EXT_CIDR_EXPOSED,
            transaction='transaction')
        mgr.ensure_static_route_created.assert_called_once_with(
            mocked.APIC_NETWORK, mocked.APIC_EXT_SWITCH,
            mocked.APIC_EXT_GATEWAY_IP, transaction='transaction')
        mgr.ensure_external_epg_created.assert_called_once_with(
            mocked.APIC_NETWORK, transaction='transaction')
        mgr.ensure_external_epg_consumed_contract.assert_called_once_with(
            mocked.APIC_NETWORK, mgr.get_router_contract.return_value,
            transaction='transaction')
        mgr.ensure_external_epg_provided_contract.assert_called_once_with(
            mocked.APIC_NETWORK, mgr.get_router_contract.return_value,
            transaction='transaction')

    def test_update_pre_gw_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK_PRE,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK_PRE,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        mgr.get_router_contract.return_value = mocked.FakeDbContract(
            mocked.APIC_CONTRACT)
        self.driver.update_port_postcommit(port_ctx)
        mgr.get_router_contract.assert_called_once_with(
            port_ctx.current['device_id'])
        mgr.ensure_context_enforced.assert_called_once()
        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)

        mgr.ensure_external_epg_consumed_contract.assert_called_once_with(
            mocked.APIC_NETWORK_PRE + '-name',
            mgr.get_router_contract.return_value,
            transaction='transaction', external_epg=mocked.APIC_EXT_EPG)
        mgr.ensure_external_epg_provided_contract.assert_called_once_with(
            mocked.APIC_NETWORK_PRE + '-name',
            mgr.get_router_contract.return_value,
            transaction='transaction', external_epg=mocked.APIC_EXT_EPG)

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
            mocked.APIC_ROUTER, mocked.APIC_NETWORK)

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
        self.driver.delete_port_postcommit(port_ctx)
        mgr.delete_external_epg_contract.assert_called_once_with(
            mocked.APIC_ROUTER, mocked.APIC_NETWORK_PRE + '-name',
            external_epg=mocked.APIC_EXT_EPG)

    def test_update_gw_port_postcommit_fail_contract_create(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1, external=True)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1, gw=True)
        mgr = self.driver.apic_manager
        self.driver.update_port_postcommit(port_ctx)
        mgr.ensure_external_routed_network_deleted.assert_called_once()

    def test_create_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1)
        mgr = self.driver.apic_manager
        self.driver.create_network_postcommit(ctx)
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK, transaction='transaction')
        mgr.ensure_epg_created.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK, transaction='transaction')

    def test_create_external_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver.create_network_postcommit(ctx)
        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.ensure_epg_created.called)

    def test_delete_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1)
        mgr = self.driver.apic_manager
        self.driver.delete_network_postcommit(ctx)
        mgr.delete_bd_on_apic.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK, transaction='transaction')
        mgr.delete_epg_for_network.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK, transaction='transaction')

    def test_delete_external_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver.delete_network_postcommit(ctx)
        mgr.delete_external_routed_network.assert_called_once_with(
            mocked.APIC_NETWORK)

    def test_delete_pre_external_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK_PRE,
                                        TEST_SEGMENT1, external=True)
        mgr = self.driver.apic_manager
        self.driver.delete_network_postcommit(ctx)
        self.assertFalse(mgr.delete_external_routed_network.called)

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
            mocked.APIC_TENANT, mocked.APIC_NETWORK,
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

    def _get_network_context(self, tenant_id, net_id, seg_id=None,
                             seg_type='vlan', external=False):
        network = {'id': net_id,
                   'name': net_id + '-name',
                   'tenant_id': tenant_id,
                   'provider:segmentation_id': seg_id}
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

    def _get_port_context(self, tenant_id, net_id, vm_id, network, host,
                          gw=False, device_owner='compute'):
        port = {'device_id': vm_id,
                'device_owner': device_owner,
                'binding:host_id': host,
                'tenant_id': tenant_id,
                'id': mocked.APIC_PORT,
                'name': mocked.APIC_PORT,
                'network_id': net_id}
        if gw:
            port['device_owner'] = n_constants.DEVICE_OWNER_ROUTER_GW
            port['device_id'] = mocked.APIC_ROUTER
        return FakePortContext(port, network)


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, network, segments):
        self._network = network
        self._segments = segments

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
        self._plugin.get_network.return_value = {}

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

    @property
    def current(self):
        return self._port

    @property
    def network(self):
        return self._network

    @property
    def bound_segment(self):
        return self._bound_segment

    def set_binding(self, segment_id, vif_type, cap_port_filter):
        pass

    @property
    def host(self):
        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        return self._original_port.get(portbindings.HOST_ID)
