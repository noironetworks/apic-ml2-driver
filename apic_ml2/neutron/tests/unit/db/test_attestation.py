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

from neutron import context
from neutron.db import model_base
from neutron.tests.unit import testlib_api

from apic_ml2.neutron.db import attestation


class AttestationDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(AttestationDBTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.vault = attestation.KeyVaultManager()
        engine = self.vault._FACADE.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

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
        self.vault.set_current_key_and_rotate('mykey', 10, 100)

        # Current is set, previous is empty
        curr = self.vault.get_current_key()
        self.assertEqual('mykey', curr['key'])
        self.assertEqual(10, curr['timestamp'])
        self.assertEqual(100, curr['validity'])
        self.assertEqual(attestation.KeyVaultManager.KEY_TYPE_CURRENT,
                         curr['type'])
        self.assertIsNone(self.vault.get_previous_key())

        # Rotate again
        self.vault.set_current_key_and_rotate('mynewkey', 20, 100)
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
        self.vault.set_current_key_and_rotate('mynewnewkey', 30, 100)
        curr = self.vault.get_current_key()
        self.assertEqual('mynewnewkey', curr['key'])
        prev = self.vault.get_previous_key()
        self.assertEqual('mynewkey', prev['key'])
