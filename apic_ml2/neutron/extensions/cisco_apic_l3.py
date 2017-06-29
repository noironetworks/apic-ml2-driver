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
from neutron.extensions import l3

ALIAS = 'cisco-apic-l3'
USE_ROUTING_CONTEXT = 'apic:use_routing_context'


EXT_GW_ATTRIBUTES = {
    USE_ROUTING_CONTEXT: {
        'allow_post': True, 'allow_put': False,
        'is_visible': True, 'default': None,
        'validate': {'type:uuid_or_none': None},
    }
}

EXTENDED_ATTRIBUTES_2_0 = {
    l3.ROUTERS: dict(EXT_GW_ATTRIBUTES.items())
}


class Cisco_apic_l3(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco APIC L3"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Extension exposing mapping of Neutron L3 resources to Cisco "
                "APIC constructs")

    @classmethod
    def get_updated(cls):
        return "2017-06-06T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
