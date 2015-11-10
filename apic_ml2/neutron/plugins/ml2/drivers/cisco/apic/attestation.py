# Copyright (c) 2014 Cisco Systems Inc.
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

import base64
import hashlib
import hmac
import time

from apicapi import exceptions as aex
from oslo.serialization import jsonutils as json

BIG_VALIDITY = 1000 * 60 * 60 * 24 * 365 * 100  # Just a long validity for now


class EndpointAttestator(object):

    def __init__(self, apic_manager):
        self.apic = apic_manager

    def get_endpoint_attestation(self, port_id, host, epg_name, epg_tenant):
        host_config = self.apic.db.get_switch_and_port_for_host(host)
        if not host_config:
                raise aex.ApicHostNotConfigured(host=host)
        attestation = {
            "ports": [],
            "endpoint-group": {
                "policy-space-name": epg_tenant,
                "endpoint-group-name": epg_name
            },
            "timestamp": int(round(time.time() * 1000)),
            "validity": BIG_VALIDITY
        }

        for switch, module, port in host_config:
            attestation['ports'].append(
                {"switch": str(switch), "port": str(module) + '/' + str(port)})

        validator = json.dumps(attestation, sort_keys=True)
        mac = hmac.new(self.apic.vmm_shared_secret, msg=validator,
                       digestmod=hashlib.sha256).digest()
        return [{"name": port_id, "validator": base64.b64encode(validator),
                 "validator-mac": base64.b64encode(mac)}]
