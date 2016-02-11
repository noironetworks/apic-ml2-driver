# Copyright (c) 2016 Cisco Systems
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

import netaddr
import tempfile
import time

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    network_constraints as anc)
from neutron.tests import base


class TestNetworkConstraints(base.BaseTestCase):

    class MockSource(anc.NetworkConstraintsSource):
        def get_subnet_constraints(self, tenant, network):
            def_scope = anc.SCOPE_PUBLIC
            cons = None
            s1 = netaddr.IPSet(['10.10.10.1/24', '10.10.20.1/24'])
            s2 = netaddr.IPSet(['20.10.10.0/24', '20.10.20.0/24'])
            s3 = netaddr.IPSet(['30.10.10.0/24', '30.10.20.0/24'])
            s4 = netaddr.IPSet(['10.20.0.0/16'])
            c = netaddr.IPSet(['5.5.0.0/16'])
            t_cons = None
            if tenant == 't1':
                t_cons = {'public': s4, 'default': 'private'}

            if tenant == 't1' and network == 'net1':
                cons = {'public': s1, 'private': s2, 'deny': s3,
                        'default': 'private'}
            elif tenant == 't1' and network == 'net2':
                cons = {'default': 'deny'}
            elif tenant == 't1' and network == 'net3':
                cons = {}
            elif tenant == 't1' and network == 'net4':
                cons = {'private': [], 'deny': None, 'default': None}
            elif tenant == 't2' and network == 'net1':
                cons = {'public': s1 | c, 'private': s2 | c, 'deny': s3 | c}
            elif tenant == 't2' and network == 'net2':
                cons = {'public': s1 | c, 'private': s2 | c, 'deny': []}
            elif tenant == 't2' and network == 'net3':
                cons = {'public': s1 | c, 'private': s2, 'deny': s3 | c}
            elif tenant == 't2' and network == 'net4':
                cons = {'public': s1, 'private': s2 | c, 'deny': s3 | c}
            return (def_scope, t_cons, cons)

    def setUp(self):
        super(TestNetworkConstraints, self).setUp()
        self.net_cons = anc.NetworkConstraints(self.MockSource())

    def test_no_source(self):
        net_cons = anc.NetworkConstraints(None)
        self.assertEqual(
            None,
            net_cons.get_subnet_scope('t1', 'net1', '10.10.10.0/28'))
        self.assertEqual(
            None,
            net_cons.get_subnet_scope('t1', 'net1', '0.0.0.0/0'))

    def test_subnet_scope(self):
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('t1', 'net1', '10.10.10.0/28'))
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('t1', 'net1', '10.10.20.0/28'))

        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net1', '20.10.10.1/28'))
        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net1', '20.10.20.1/28'))

        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t1', 'net1', '30.10.10.1/28'))
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t1', 'net1', '30.10.20.1/28'))
        # supersets of deny
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t1', 'net1', '30.10.10.1/16'))
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t1', 'net1', '30.10.20.1/16'))

    def test_tenant_subnet_scope(self):
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('t1', 'net3', '10.20.0.0/28'))
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('t1', 'net4', '10.20.0.0/26'))
        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net3', '20.10.10.0/28'))
        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net4', '20.10.10.0/28'))

    def test_network_default_subnet_scope(self):
        # supersets of public/private
        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net1', '10.10.10.0/20'))
        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net1', '20.10.10.1/20'))

        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t1', 'net1', '40.10.10.1/28'))
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t1', 'net2', '10.10.10.1/28'))

    def test_global_default_subnet_scope(self):
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('t2', 'net3', '10.30.10.1/24'))
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('t2', 'net4', '20.30.10.1/24'))
        self.assertEqual(
            anc.SCOPE_PUBLIC,
            self.net_cons.get_subnet_scope('foo', 'bar', '10.10.10.1/24'))

    def test_overlapping_subnet_scope(self):
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t2', 'net1', '5.5.10.128/25'))
        self.assertEqual(
            anc.SCOPE_PRIVATE,
            self.net_cons.get_subnet_scope('t2', 'net2', '5.5.10.128/25'))
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t2', 'net3', '5.5.10.128/25'))
        self.assertEqual(
            anc.SCOPE_DENY,
            self.net_cons.get_subnet_scope('t2', 'net4', '5.5.10.128/25'))


class TestConfigFileSource(base.BaseTestCase):
    def setUp(self):
        super(TestConfigFileSource, self).setUp()
        self.file_data = """
[DEFAULT]
subnet_scope = public

[t1/net1]
public = 10.10.10.1/24 ,   10.10.20.1/24 ,
private = 20.10.10.0.0/1,20.10.20.0/24
deny = 20.10.10.0/24
default = foo

[t1/net2]
public = 10.10.10.1/24
private = 20.10.10.0/31,20.10.10.0/24
default = deny

[t1/net3]
default = deny

[t1]
public = 10.20.0.0/16
default = private

[t1:net_unk]
default = deny
"""
        with tempfile.NamedTemporaryFile(delete=False) as fd:
            self.cons_file_name = fd.name

    def _write_constraints_file(self, data):
        with open(self.cons_file_name, 'w') as fd:
            fd.write(data)

    def test_non_existent(self):
        ncs = anc.ConfigFileSource("foo")
        self.assertEqual((None, {}, {}), ncs.get_subnet_constraints('t', 'n'))

    def test_no_default_scope(self):
        self._write_constraints_file(self.file_data.replace('DEFAULT', 'a'))
        ncs = anc.ConfigFileSource(self.cons_file_name)
        self.assertEqual((None,
                          {'public': netaddr.IPSet(['10.20.0.0/16']),
                           'default': 'private'},
                          {'default': 'deny'}),
                         ncs.get_subnet_constraints('t1', 'net3'))

    def test_parse(self):
        self._write_constraints_file(self.file_data)
        ncs = anc.ConfigFileSource(self.cons_file_name)
        self.assertEqual(
            (anc.SCOPE_PUBLIC,
             {'public': netaddr.IPSet(['10.20.0.0/16']),
              'default': 'private'},
             {'public': netaddr.IPSet(['10.10.10.1/24', '10.10.20.1/24']),
              'private': None,
              'deny': netaddr.IPSet(['20.10.10.0/24']),
              'default': None}),
            ncs.get_subnet_constraints('t1', 'net1'))

        self.assertEqual(
            (anc.SCOPE_PUBLIC,
             {'public': netaddr.IPSet(['10.20.0.0/16']),
              'default': 'private'},
             {'public': netaddr.IPSet(['10.10.10.1/24']),
              'private': netaddr.IPSet(['20.10.10.0/24']),
              'default': 'deny'}),
            ncs.get_subnet_constraints('t1', 'net2'))

        self.assertEqual((anc.SCOPE_PUBLIC,
                          {'public': netaddr.IPSet(['10.20.0.0/16']),
                           'default': 'private'},
                          {}),
                         ncs.get_subnet_constraints('t1', 'net_unk'))

    def test_auto_refresh(self):
        self._write_constraints_file(self.file_data)
        ncs = anc.ConfigFileSource(self.cons_file_name)
        self.assertEqual((anc.SCOPE_PUBLIC,
                          {'public': netaddr.IPSet(['10.20.0.0/16']),
                           'default': 'private'},
                          {'default': 'deny'}),
                         ncs.get_subnet_constraints('t1', 'net3'))
        time.sleep(0.1)

        data = self.file_data.replace('subnet_scope = public',
                                      'subnet_scope = deny')
        data = data.replace('t1/net3', 't2/net3')
        self._write_constraints_file(data)

        self.assertEqual((anc.SCOPE_DENY,
                          {'public': netaddr.IPSet(['10.20.0.0/16']),
                           'default': 'private'},
                          {}),
                         ncs.get_subnet_constraints('t1', 'net3'))
        self.assertEqual((anc.SCOPE_DENY, {}, {'default': 'deny'}),
                         ncs.get_subnet_constraints('t2', 'net3'))
