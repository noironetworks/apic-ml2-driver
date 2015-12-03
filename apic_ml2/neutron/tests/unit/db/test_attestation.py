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

import mock
from neutron import context
from neutron.tests.unit import testlib_api

from apic_ml2.neutron.db import attestation
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    attestation as attestator)
from apic_ml2.neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as common)


class AttestationDBTestCase(testlib_api.SqlTestCase, common.ConfigMixin):

    def setUp(self):
        super(AttestationDBTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.setup_attestation_db()

    def test_empty_vault(self):
        self.assertIsNone(self.vault.get_current_key())
        self.assertIsNone(self.vault.get_previous_key())

    def test_current_key(self):
        self.vault._create_key(
            'mykey', 10, 100, attestation.KeyVaultManager.KEY_TYPE_CURRENT)
        curr = self.vault.get_current_key()
        self.assertEqual('mykey', curr['key'])
        self.assertEqual(10, curr['timestamp'])
        self.assertEqual(100, curr['validity'])
        self.assertEqual(attestation.KeyVaultManager.KEY_TYPE_CURRENT,
                         curr['type'])
        # Previous key doesn't exist
        self.assertIsNone(self.vault.get_previous_key())

    def test_previous_key(self):
        self.vault._create_key(
            'mykey', 10, 100, attestation.KeyVaultManager.KEY_TYPE_PREVIOUS)
        prev = self.vault.get_previous_key()
        self.assertEqual('mykey', prev['key'])
        self.assertEqual(10, prev['timestamp'])
        self.assertEqual(100, prev['validity'])
        self.assertEqual(attestation.KeyVaultManager.KEY_TYPE_PREVIOUS,
                         prev['type'])

        # Current key doesn't exist
        self.assertIsNone(self.vault.get_current_key())

    def test_rotate_key(self):
        self.vault.rotate_current_key('mykey', 10, 100)

        # Current is empty
        curr = self.vault.get_current_key()
        self.assertIsNone(curr)

        # initialize key
        self.vault.set_initial_key_if_not_exists('mykey', 10, 100)

        # Rotate again
        self.vault.rotate_current_key('mynewkey', 20, 100)
        # Current is the new key
        curr = self.vault.get_current_key()
        self.assertEqual('mynewkey', curr['key'])
        self.assertEqual(20, curr['timestamp'])
        self.assertEqual(100, curr['validity'])
        self.assertEqual(attestation.KeyVaultManager.KEY_TYPE_CURRENT,
                         curr['type'])

        # Older one got moved to previous
        prev = self.vault.get_previous_key()
        self.assertEqual('mykey', prev['key'])
        self.assertEqual(10, prev['timestamp'])
        self.assertEqual(100, prev['validity'])
        self.assertEqual(attestation.KeyVaultManager.KEY_TYPE_PREVIOUS,
                         prev['type'])

        # Rotate again
        self.vault.rotate_current_key('mynewnewkey', 30, 100)
        curr = self.vault.get_current_key()
        self.assertEqual('mynewnewkey', curr['key'])
        prev = self.vault.get_previous_key()
        self.assertEqual('mynewkey', prev['key'])


class AttestatorTestCase(testlib_api.SqlTestCase, common.ConfigMixin):

    def setUp(self):
        super(AttestatorTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.apic_manager = mock.Mock()
        self.notifier = mock.Mock()
        self.cfg = mock.Mock()
        self.cfg.attestation_key_validity = 100
        self.cfg.attestation_key_synchronization_interval = 10
        self.cfg.attestation_enabled = True

        self.attestator = attestator.EndpointAttestator(
            self.apic_manager, self.notifier, self.cfg)
        self.setup_attestation_db()
        self.attestator.alarm = mock.Mock()

    def test_timestamp(self):
        self.assertIsInstance(self.attestator._timestamp(), int)

    def test_key_expiration(self):
        curr = self.vault.set_initial_key_if_not_exists('mykey', 10, 100)
        self.attestator._timestamp = mock.Mock(return_value=20)

        # Validity of the key should be 90 as 10 seconds passed from the
        # initial timestamp
        self.assertEqual(90, self.attestator._key_expiration(curr))

    def test_drift_key_validity(self):
        curr = self.vault.set_initial_key_if_not_exists('mykey', 10, 100)

        # Validity must be included between 90 and 110
        validities = set()
        for x in range(10):
            validity = self.attestator._drift_key_validity(curr)
            validities.add(validity)
            self.assertTrue(100 <= int(validity) <= 120,
                            "Actual validity is %s" % validity)
        # it's very unlikely that all the random values collided, so verify
        # that at least a bunch are unique
        self.assertTrue(len(validities) > 5)

    def test_alarm_timeout(self):
        # Should be 0.1 for an expired key, or the minimum between the sync
        # interval and the expiration
        curr = self.vault.set_initial_key_if_not_exists('mykey', 10, 100)
        # Key expired by 10 seconds
        self.attestator._timestamp = mock.Mock(return_value=120)
        self.assertEqual(0.1, self.attestator._calculate_alarm_timeout(curr))

        # Key expires in 90, way after the sync timeout (which is 10)
        self.attestator._timestamp = mock.Mock(return_value=20)
        self.assertEqual(10, self.attestator._calculate_alarm_timeout(curr))

        # Key is expiring pretty soon
        self.attestator._timestamp = mock.Mock(return_value=105)
        self.assertEqual(5, self.attestator._calculate_alarm_timeout(curr))

    def test_cleanup_attestation(self):
        self.vault.set_initial_key_if_not_exists('mykey', 10, 100)
        self.vault.rotate_current_key('newkey', 110, 100)
        curr, prev = self.vault.get_current_and_previous_keys()
        self.assertIsNotNone(curr)
        self.assertIsNotNone(prev)

        self.attestator.cleanup_attestation()
        curr, prev = self.vault.get_current_and_previous_keys()
        self.assertIsNone(curr)
        self.assertIsNone(prev)
        self.attestator.apic.set_vmm_secret.assert_called_once_with(
            current='', previous='')

    def test_main_loop(self):
        # First time into the loop, with restarted = to True, a key is
        # generated but APIC is not notified

        # We will find two keys being key expiration == 0
        self.attestator._key_expiration = mock.Mock(return_value=0)
        self.attestator._main_loop()

        curr, prev = self.vault.get_current_and_previous_keys()
        # Both keys exist
        self.assertTrue(curr and prev)
        self.assertFalse(self.attestator.apic.set_vmm_secret.called)

        # Second time in the loop, APIC is called with older set of Keys
        self.attestator._main_loop()
        self.attestator.apic.set_vmm_secret.assert_called_once_with(
            current=curr['key'], previous=prev['key'])

        # Key still expired, so a new set of key is now present
        older_curr = curr
        curr, prev = self.vault.get_current_and_previous_keys()
        self.assertTrue(curr and prev)
        self.assertEqual(older_curr['key'], prev['key'])
        self.attestator.apic.reset_mock()

        # This time loop with unexpired key
        self.attestator._key_expiration = mock.Mock(return_value=1)
        self.attestator._main_loop()

        # APIC still called with the previous values
        self.attestator.apic.set_vmm_secret.assert_called_once_with(
            current=curr['key'], previous=prev['key'])

        # No rotation happened
        older_curr, older_prev = curr, prev
        curr, prev = self.vault.get_current_and_previous_keys()
        self.assertEqual(older_curr, curr)
        self.assertEqual(older_prev, prev)
