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
from eventlet import greenthread
from eventlet import semaphore
import hashlib
import hmac
import os
import random
import time

from apicapi import exceptions as aexc
from neutron import context
from oslo_log import log as logging
from oslo_serialization import jsonutils as json

from apic_ml2.neutron.db import attestation as db

LOG = logging.getLogger(__name__)


class EndpointAttestator(object):

    _THREAD = None

    def __init__(self, apic_manager, rpc_notifier, conf):
        self.apic = apic_manager
        self.vault = db.KeyVaultManager()
        self.default_validity = conf.attestation_key_validity
        self.sync_interval = conf.attestation_key_synchronization_interval
        self.enabled = conf.attestation_enabled
        self.notifier = rpc_notifier
        # Need a session for querying existing objects
        self.context = context.get_admin_context()
        self.restarted = True
        # REVISIT(ivar) Each worker will have its own semaphore.
        # Will be used when user interaction will be allowed on attestation
        self.alarm = semaphore.Semaphore()

    def _timestamp(self):
        return int(round(time.time() * 1000))

    def _key_expiration(self, key):
        return int(key['timestamp']) + int(key['validity']) - self._timestamp()

    def _drift_key_validity(self, key):
        validity = int(key['validity'])
        return str(validity + int(round(random.uniform(0,
                                                       2 * validity * 0.1))))

    def _generate_key_parameters(self):
        # returns Base64 codification of Key, the current timestamp, and the
        # key validity
        return (base64.b64encode(os.urandom(32)), self._timestamp(),
                self.default_validity)

    def _calculate_alarm_timeout(self, current_key):
        # Timeout value must be strictly positive
        return max(0.1, min(self.sync_interval,
                            self._key_expiration(current_key)))

    def _main_loop(self):
        """Main loop body.

        exception handling is delegated to caller.
        """

        if self.restarted:
            LOG.debug("Attestation was restarted")
            # Create initial key
            if self.vault.set_initial_key_if_not_exists(
                    *self._generate_key_parameters()):
                # REVISIT(ivar): initialization time. Do we need to notify all
                # the Ports?
                LOG.debug("Initial attestation key properly set")
            else:
                LOG.info("Initial attestation key already existed")
            self.restarted = False
        # If both keys are present, push into APIC. In a concurrent environment
        # this could cause older value to get into APIC. This situation will
        # automatically recover after *validity* time is past. To avoid such
        # long waits a synchronization interval can be set.
        curr, prev = self.vault.get_current_and_previous_keys()
        if curr and prev:
            LOG.debug("Sending attestation secret to APIC")
            self.apic.set_vmm_secret(current=curr['key'], previous=prev['key'])
        if curr:
            # Wait to expire the current key, set the alarm to the proper value
            self.alarm.acquire(timeout=self._calculate_alarm_timeout(curr))
            # Rotate the current key if needed
            if self._key_expiration(key=curr) <= 0:
                self.vault.rotate_current_key(*self._generate_key_parameters())
            # Caller will loop on this and push into APIC the keys if needed.
        else:
            # Something deleted the current Key (eg. attestation switched off
            # by another entity). Sleep sync_interval time to avoid overloading
            # the CPU
            LOG.warn("Some external entity deleted the attestation keys from "
                     "the database, verify that all the servers have coherent "
                     "attestation_enabled configuration value.")
            self.alarm.acquire(timeout=self.sync_interval)
        # Schedule other processes.
        greenthread.sleep(0)

    def cleanup_attestation(self):
        LOG.info("Cleaning up vault keys.")
        self.vault.cleanup_keys()
        try:
            self.apic.set_vmm_secret(current='', previous='')
        except aexc.ApicResponseNotOk:
            LOG.warn(_("APIC version not supporting attestation"))

    def start(self):
        if not EndpointAttestator._THREAD:
            EndpointAttestator._THREAD = greenthread.spawn(self.run)
        return EndpointAttestator._THREAD

    def run(self):
        """Main loop of the attestator"""
        while True:
            try:
                self._main_loop()
            except Exception as e:
                LOG.error(_("An exception has occurred on the validator main "
                          "loop."))
                LOG.exception(e)

    def wake_up(self):
        # TODO(ivar): RPC call could be connected to this method, so that
        # user interaction with the attestation (eg. create new key) can wake
        # up existing threads.
        self.alarm.release()

    def get_endpoint_attestation(self, port_id, host, epg_name, epg_tenant):
        host_config = self.apic.get_switch_and_port_for_host(host)
        with self.vault.session.begin(subtransactions=True):
            secret = self.vault.get_current_key()
            if not secret:
                return None
            attestation = {
                "ports": [],
                "policy-space-name": epg_tenant,
                "endpoint-group-name": epg_name,
                "timestamp": secret['timestamp'],
                "validity": self._drift_key_validity(secret),
            }

            for switch, port in host_config:
                attestation['ports'].append(
                    {"switch": str(switch), "port": str(port)})

            validator = json.dumps(attestation, sort_keys=True)
            mac = hmac.new(base64.b64decode(secret['key']),
                           msg=validator, digestmod=hashlib.sha256).digest()
            result = [{"name": port_id,
                       "validator": base64.b64encode(validator),
                       "validator-mac": base64.b64encode(mac)}]
            LOG.debug(
                "Attestation for %(arg)s is %(result)s",
                {'arg': (port_id, host, epg_name, epg_tenant),
                 'result': result})
            return result
