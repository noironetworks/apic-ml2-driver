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

import contextlib
import mock
import requests

from neutron import context
from neutron.plugins.ml2 import config  # noqa
from neutron.tests import base
from oslo.config import cfg
import webob

OK = requests.codes.ok

APIC_HOSTS = ['fake.controller.local']
APIC_PORT = 7580
APIC_USR = 'notadmin'
APIC_PWD = 'topsecret'

APIC_TENANT = 'citizen14'
APIC_NETWORK = 'network99'
APIC_NETWORK_PRE = 'network_pre'
APIC_NETWORK_NO_NAT = 'network_no_nat'
APIC_EXT_EPG = 'external_epg'
APIC_NETNAME = 'net99name'
APIC_SUBNET = '10.3.2.1/24'
APIC_L3CTX = 'layer3context'
APIC_AP = 'appProfile001'
APIC_EPG = 'endPointGroup001'

APIC_CONTRACT = 'signedContract'
APIC_SUBJECT = 'testSubject'
APIC_FILTER = 'carbonFilter'
APIC_ENTRY = 'forcedEntry'

APIC_SYSTEM_ID = 'sysid'
APIC_DOMAIN = 'cumuloNimbus'

APIC_NODE_PROF = 'red'
APIC_LEAF = 'green'
APIC_LEAF_TYPE = 'range'
APIC_NODE_BLK = 'blue'
APIC_PORT_PROF = 'yellow'
APIC_PORT_SEL = 'front'
APIC_PORT_TYPE = 'range'
APIC_PORT_BLK1 = 'block01'
APIC_PORT_BLK2 = 'block02'
APIC_ACC_PORT_GRP = 'alpha'
APIC_FUNC_PROF = 'beta'
APIC_ATT_ENT_PROF = 'delta'
APIC_VLAN_NAME = 'gamma'
APIC_VLAN_MODE = 'dynamic'
APIC_VLANID_FROM = 2900
APIC_VLANID_TO = 2999
APIC_VLAN_FROM = 'vlan-%d' % APIC_VLANID_FROM
APIC_VLAN_TO = 'vlan-%d' % APIC_VLANID_TO

APIC_ROUTER = 'router_id'

APIC_EXT_SWITCH = '203'
APIC_EXT_MODULE = '1'
APIC_EXT_PORT = '34'
APIC_EXT_ENCAP = 'vlan-100'
APIC_EXT_CIDR_EXPOSED = '10.10.40.2/16'
APIC_EXT_GATEWAY_IP = '10.10.40.1'

APIC_KEY = 'key'

KEYSTONE_TOKEN = '123Token123'

APIC_UPLINK_PORTS = ['uplink_port']

SERVICE_HOST = 'host1'
SERVICE_HOST_IFACE = 'eth0'
SERVICE_HOST_MAC = 'aa:ee:ii:oo:uu:yy'

SERVICE_PEER_CHASSIS_NAME = 'leaf4'
SERVICE_PEER_CHASSIS = 'topology/pod-1/node-' + APIC_EXT_SWITCH
SERVICE_PEER_PORT_LOCAL = 'Eth%s/%s' % (APIC_EXT_MODULE, APIC_EXT_PORT)
SERVICE_PEER_PORT_DESC = ('topology/pod-1/paths-%s/pathep-[%s]' %
                          (APIC_EXT_SWITCH, SERVICE_PEER_PORT_LOCAL.lower()))


class ControllerMixin(object):

    """Mock the controller for APIC driver and service unit tests."""

    def __init__(self):
        self.response = None

    def _tenant(self, ext_nat=False, vrf=False, neutron_tenant=None):
        if self.driver.single_tenant_mode:
            return APIC_SYSTEM_ID
        if self.driver.per_tenant_context and not ext_nat:
            return neutron_tenant or APIC_TENANT
        if not self.driver.per_tenant_context and vrf:
            return 'common'
        if ext_nat:
            return 'common'
        return neutron_tenant or APIC_TENANT

    def _network_vrf_name(self, nat_vrf=False, net_name=None):
        if nat_vrf:
            return "NAT-vrf-%s" % (net_name or APIC_NETWORK)
        if self.driver.single_tenant_mode:
            return APIC_TENANT
        return 'shared'

    def _router_tenant(self):
        if self.driver.single_tenant_mode:
            return APIC_SYSTEM_ID
        return 'common'

    def _app_profile(self, neutron_tenant=None):
        if self.driver.single_tenant_mode:
            return neutron_tenant or APIC_TENANT
        return APIC_SYSTEM_ID

    def set_up_mocks(self):
        # The mocked responses from the server are lists used by
        # mock.side_effect, which means each call to post or get will
        # return the next item in the list. This allows the test cases
        # to stage a sequence of responses to method(s) under test.
        self.response = {'post': [], 'get': []}
        self.reset_reponses()

    def reset_reponses(self, req=None):
        # Clear all staged responses.
        reqs = req and [req] or ['post', 'get']  # Both if none specified.
        for req in reqs:
            del self.response[req][:]
            self.restart_responses(req)

    def restart_responses(self, req):
        responses = mock.MagicMock(side_effect=self.response[req])
        if req == 'post':
            requests.Session.post = responses
        elif req == 'get':
            requests.Session.get = responses

    def mock_response_for_post(self, mo, **attrs):
        attrs['debug_mo'] = mo  # useful for debugging
        self._stage_mocked_response('post', OK, mo, **attrs)

    def _stage_mocked_response(self, req, mock_status, mo, **attrs):
        response = mock.MagicMock()
        response.status_code = mock_status
        mo_attrs = attrs and [{mo: {'attributes': attrs}}] or []
        response.json.return_value = {'imdata': mo_attrs}
        self.response[req].append(response)

    def mock_apic_manager_login_responses(self, timeout=300):
        # APIC Manager tests are based on authenticated session
        self.mock_response_for_post('aaaLogin', userName=APIC_USR,
                                    token='ok', refreshTimeoutSeconds=timeout)

    @contextlib.contextmanager
    def fake_transaction(self, *args, **kwargs):
        yield 'transaction'


class ConfigMixin(object):

    """Mock the config for APIC driver and service unit tests."""

    def __init__(self):
        self.mocked_parser = None

    def set_up_mocks(self):
        # Mock the configuration file
        base.BaseTestCase.config_parse()

        # Configure global option apic_system_id
        cfg.CONF.set_override('apic_system_id', APIC_SYSTEM_ID)

        # Configure option keystone_authtoken
        cfg.CONF.keystone_authtoken = KEYSTONE_TOKEN

        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['openvswitch', 'cisco_apic_ml2'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
                cfg.CONF.set_override(opt, val, 'ml2')

        # Configure the ML2 type_vlan opts
        ml2_type_vlan_opts = {
            'vlan_ranges': ['physnet1:100:199'],
        }
        cfg.CONF.set_override('network_vlan_ranges',
                              ml2_type_vlan_opts['vlan_ranges'],
                              'ml2_type_vlan')
        self.vlan_ranges = ml2_type_vlan_opts['vlan_ranges']

        # Configure the Cisco APIC mechanism driver
        apic_test_config = {
            'apic_hosts': APIC_HOSTS,
            'apic_username': APIC_USR,
            'apic_password': APIC_PWD,
            'apic_domain_name': APIC_SYSTEM_ID,
            'apic_vlan_ns_name': APIC_VLAN_NAME,
            'apic_vlan_range': '%d:%d' % (APIC_VLANID_FROM, APIC_VLANID_TO),
            'apic_node_profile': APIC_NODE_PROF,
            'apic_entity_profile': APIC_ATT_ENT_PROF,
            'apic_function_profile': APIC_FUNC_PROF,
            'apic_host_uplink_ports': APIC_UPLINK_PORTS
        }
        for opt, val in apic_test_config.items():
            cfg.CONF.set_override(opt, val, 'ml2_cisco_apic')
        self.apic_config = cfg.CONF.ml2_cisco_apic

        # Configure switch topology
        apic_switch_cfg = {
            'apic_switch:101': {'ubuntu1,ubuntu2': ['3/11']},
            'apic_switch:102': {'rhel01,rhel02': ['4/21'],
                                'rhel03': ['4/22']},
        }
        self.switch_dict = {
            '101': {
                '3/11': ['ubuntu1', 'ubuntu2'],
            },
            '102': {
                '4/21': ['rhel01', 'rhel02'],
                '4/22': ['rhel03'],
            },
        }
        self.vpc_dict = {
            '201': '202',
            '202': '201',
        }
        self.external_network_dict = {
            APIC_NETWORK + '-name': {
                'switch': APIC_EXT_SWITCH,
                'port': APIC_EXT_MODULE + '/' + APIC_EXT_PORT,
                'encap': APIC_EXT_ENCAP,
                'cidr_exposed': APIC_EXT_CIDR_EXPOSED,
                'gateway_ip': APIC_EXT_GATEWAY_IP,
            },
            APIC_NETWORK_PRE + '-name': {
                'switch': APIC_EXT_SWITCH,
                'port': APIC_EXT_MODULE + '/' + APIC_EXT_PORT,
                'encap': APIC_EXT_ENCAP,
                'cidr_exposed': APIC_EXT_CIDR_EXPOSED,
                'gateway_ip': APIC_EXT_GATEWAY_IP,
                'preexisting': True,
                'external_epg': APIC_EXT_EPG,
            },
            APIC_NETWORK_NO_NAT + '-name': {
                'switch': APIC_EXT_SWITCH,
                'port': APIC_EXT_MODULE + '/' + APIC_EXT_PORT,
                'encap': APIC_EXT_ENCAP,
                'cidr_exposed': APIC_EXT_CIDR_EXPOSED,
                'gateway_ip': APIC_EXT_GATEWAY_IP,
                'enable_nat': False,
            },
        }
        self.mocked_parser = mock.patch.object(
            cfg, 'MultiConfigParser').start()
        self.mocked_parser.return_value.read.return_value = [apic_switch_cfg]
        self.mocked_parser.return_value.parsed = [apic_switch_cfg]

    def override_conf(self, opt, val, group):
        cfg.CONF.set_override(opt, val, group)


class FakeDbContract(object):

    def __init__(self, contract_id):
        self.contract_id = contract_id


class ApiManagerMixin(object):

    def _create_resource(self, type, expected_res_status=None,
                         is_admin_context=False, api=None, **kwargs):
        plural = get_resource_plural(type)

        data = {type: {'tenant_id': self._tenant_id}}
        data[type].update(**kwargs)

        req = self.new_create_request(plural, data, self.fmt)
        req.environ['neutron.context'] = context.Context(
            '', kwargs.get('tenant_id', self._tenant_id) if not
            is_admin_context else self._tenant_id, is_admin_context)
        res = req.get_response(api or self.api)

        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)

        return self.deserialize(self.fmt, res)

    def _update_resource(
            self, id, type, expected_res_status=None, is_admin_context=False,
            api=None, **kwargs):
        plural = get_resource_plural(type)
        data = {type: kwargs}
        tenant_id = kwargs.pop('tenant_id', self._tenant_id)
        # Create PT with bound port
        req = self.new_update_request(plural, data, id, self.fmt)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id if not is_admin_context else self._tenant_id,
            is_admin_context)
        res = req.get_response(api or self.api)

        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _show_resource(self, id, plural, expected_res_status=None,
                       is_admin_context=False, tenant_id=None, api=None):
        req = self.new_show_request(plural, id, fmt=self.fmt)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id, is_admin_context)
        res = req.get_response(api or self.api)

        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _delete_resource(self, id, plural, is_admin_context=False,
                         expected_res_status=None, tenant_id=None, api=None):
        req = self.new_delete_request(plural, id)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id, is_admin_context)
        res = req.get_response(api or self.api)
        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        if res.status_int != 204:
            return self.deserialize(self.fmt, res)


class ApicDBTestBase(ApiManagerMixin):

    fmt = 'json'

    def __getattr__(self, item):

        # Update Method
        if item.startswith('update_'):
            resource = item[len('update_'):]
            plural = get_resource_plural(resource)

            def update_wrapper(id, **kwargs):
                return self._update_resource(id, resource, **kwargs)
            return update_wrapper
        # Show Method
        if item.startswith('show_'):
            resource = item[len('show_'):]
            plural = get_resource_plural(resource)

            def show_wrapper(id, **kwargs):
                return self._show_resource(id, plural, **kwargs)
            return show_wrapper
        # Create Method
        if item.startswith('create_'):
            resource = item[len('create_'):]
            plural = get_resource_plural(resource)

            def create_wrapper(**kwargs):
                return self._create_resource(resource, **kwargs)
            return create_wrapper
        # Delete Method
        if item.startswith('delete_'):
            resource = item[len('delete_'):]
            plural = get_resource_plural(resource)

            def delete_wrapper(id, **kwargs):
                return self._delete_resource(id, plural, **kwargs)
            return delete_wrapper

        raise AttributeError


def get_resource_plural(resource):
    if resource.endswith('y'):
        resource_plural = resource.replace('y', 'ies')
    else:
        resource_plural = resource + 's'

    return resource_plural
