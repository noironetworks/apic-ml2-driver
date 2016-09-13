# Copyright (c) 2016 Cisco Systems Inc.
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
import os

from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

SCOPE_PUBLIC = 'public'
SCOPE_PRIVATE = 'private'
SCOPE_DENY = 'deny'


class NetworkConstraintsSource(object):
    def __init__(self):
        pass

    def get_subnet_constraints(self, tenant, network):
        """Returns (default-scope, scope-for-tenant, scope-for-network) """
        return (None, None, None)

    def get_allow_vm_names(self, tenant, vrf):
        """Returns [<regex1>, <regex2>, ...] """
        return None


class NetworkConstraints(object):
    def __init__(self, constraints_source):
        self.source = constraints_source

    def get_subnet_scope(self, tenant, network, cidr):
        scope = None
        cidr = netaddr.IPNetwork(cidr)
        if self.source:
            def_scope, tenant_cons, net_cons = (
                self.source.get_subnet_constraints(tenant, network))
            scope = def_scope or scope
            for constraints in [net_cons, tenant_cons]:
                if constraints:
                    # scope is deny if there is any overlap with deny set
                    # scope is public/private if subset of public/private set
                    if netaddr.IPSet(cidr) & (constraints.get('deny') or
                                              netaddr.IPSet()):
                        return SCOPE_DENY
                    elif cidr in (constraints.get('private') or
                                  netaddr.IPSet()):
                        return SCOPE_PRIVATE
                    elif cidr in (constraints.get('public') or
                                  netaddr.IPSet()):
                        return SCOPE_PUBLIC
                    elif constraints.get('default'):
                        return constraints.get('default')
        return scope

    def get_allow_vm_names(self, tenant, vrf):
        if self.source:
            return self.source.get_allow_vm_names(tenant, vrf)


class ConfigFileSource(NetworkConstraintsSource):
    def __init__(self, config_file):
        self.config_file = config_file
        self.last_refresh_time = 0
        self.subnet_default_scope = None
        self.subnet_constraints = {}
        self.allow_vm_names_list = {}
        self._refresh()

    def get_subnet_constraints(self, tenant, network):
        self._refresh()
        return (self.subnet_default_scope,
                self.subnet_constraints.get((tenant, None), {}),
                self.subnet_constraints.get((tenant, network), {}))

    def get_allow_vm_names(self, tenant, vrf):
        self._refresh()
        return self.allow_vm_names_list.get((tenant, vrf), [])

    def _refresh(self):
        try:
            mod_time = os.path.getmtime(self.config_file)
        except os.error as e:
            LOG.warning('Failed to read file modification time: %s', e)
            return
        if self.last_refresh_time < mod_time:
            self._parse_file()
            self.last_refresh_time = mod_time

    def _parse_file(self):
        cfg_parser = cfg.MultiConfigParser()
        try:
            cfg_parser.read([self.config_file])
        except Exception as e:
            LOG.warning('Failed to parse file %(file)s: %(exc)s',
                        {'file': self.config_file, 'exc': e})
            return

        def sanitize_scope(scope):
            if scope:
                scope = scope.strip().lower()
                if scope in [SCOPE_PUBLIC, SCOPE_PRIVATE, SCOPE_DENY]:
                    return scope
            return None

        def parse_cidr_list(cidrs):
            try:
                return netaddr.IPSet(
                    [c for c in cidrs.split(',') if c.strip()])
            except Exception as e:
                LOG.warning('Failed to parse CIDRs: %(cidr)s: %(exc)s',
                            {'cidr': cidrs, 'exc': e})
                return None

        def parse_allow_vm_names(vm_names):
            try:
                return [name.strip() for name in vm_names.split(',')]
            except Exception as e:
                LOG.warning('Failed to parse vm_names: %(vm_names)s: %(exc)s',
                            {'vm_names': vm_names, 'exc': e})
                return None

        def_scope = None
        constraints = {}
        allow_vm_names = {}
        LOG.debug('Parsing network constraints file %s', self.config_file)
        for cfg_file in cfg_parser.parsed:
            for section_name in cfg_file.keys():
                if section_name == 'DEFAULT':
                    def_scope = sanitize_scope(
                        cfg_file[section_name].get('subnet_scope', [None])[0])
                    LOG.debug('Default subnet scope: %s', def_scope)
                else:
                    net = tuple(section_name.split('/', 1))
                    if len(net) < 2:    # tenant case
                        net += tuple([None])
                    allow_vm_names[net] = []
                    constraints[net] = {}
                    for k, v in cfg_file[section_name].iteritems():
                        k = k.lower()
                        if k in ['public', 'private', 'deny']:
                            constraints[net][k] = parse_cidr_list(v[0])
                        elif k == 'default':
                            constraints[net][k] = sanitize_scope(v[0])
                        elif k == 'allow_vm_names':
                            allow_vm_names[net] = parse_allow_vm_names(v[0])
                    if constraints[net]:
                        LOG.debug('Constraints for network %(n)s - %(c)s',
                                  {'n': net, 'c': constraints[net]})
                    else:
                        LOG.debug('Constraints for vrf %(n)s - %(c)s',
                                  {'n': net, 'c': allow_vm_names[net]})
        self.subnet_default_scope = def_scope
        self.subnet_constraints = constraints
        self.allow_vm_names_list = allow_vm_names
