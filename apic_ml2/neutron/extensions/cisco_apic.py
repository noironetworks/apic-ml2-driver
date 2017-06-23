# Copyright (c) 2017 Cisco Systems Inc.
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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron_lib.api import converters as conv

ALIAS = 'cisco-apic'
ALLOW_ROUTE_LEAK = 'apic:allow_route_leak'

NET_ATTRIBUTES = {
    ALLOW_ROUTE_LEAK: {
        'allow_post': True, 'allow_put': False,
        'is_visible': True, 'default': False,
        'convert_to': conv.convert_to_boolean,
    },
}


EXTENDED_ATTRIBUTES_2_0 = {
    attributes.NETWORKS: dict(NET_ATTRIBUTES.items()),
}


class Cisco_apic(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco APIC"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Extension exposing mapping of Neutron resources to Cisco "
                "APIC constructs")

    @classmethod
    def get_updated(cls):
        return "2017-05-10T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
