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
from neutron.i18n import _LI
from neutron.plugins.ml2 import driver_api
from oslo_log import log

from apic_ml2.neutron import extensions as extensions_pkg
from apic_ml2.neutron.extensions import cisco_apic
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    extension_db as extn_db)

LOG = log.getLogger(__name__)


class ApicExtensionDriver(driver_api.ExtensionDriver,
                          extn_db.ExtensionDbMixin):

    def __init__(self):
        LOG.info(_LI("APIC ML2 Extension Driver __init__"))

    def initialize(self):
        LOG.info(_LI("APIC ML2 Extension Driver initializing"))
        extensions.append_api_extensions_path(extensions_pkg.__path__)

    @property
    def extension_alias(self):
        return "cisco-apic"

    def extend_network_dict(self, session, base_model, result):
        res_dict = self.get_network_extn_db(session, result['id'])
        result[cisco_apic.ALLOW_ROUTE_LEAK] = res_dict.get(
            cisco_apic.ALLOW_ROUTE_LEAK, False)

    def process_create_network(self, plugin_context, data, result):
        res_dict = {cisco_apic.ALLOW_ROUTE_LEAK:
                    data.get(cisco_apic.ALLOW_ROUTE_LEAK, False)}
        self.set_network_extn_db(plugin_context.session, result['id'],
                                 res_dict)
        result.update(res_dict)
