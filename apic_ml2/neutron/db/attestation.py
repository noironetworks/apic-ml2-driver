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

import sqlalchemy as sa

from neutron.db import model_base
from oslo_config import cfg
from oslo_db.sqlalchemy import session
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class KeyVault(model_base.BASEV2):

    """Storage for attestation keys.

    """

    __tablename__ = 'apic_ml2_attestation'

    key = sa.Column(sa.String(1024), nullable=False, primary_key=True)
    timestamp = sa.Column(sa.Integer, nullable=False)
    validity = sa.Column(sa.Integer, nullable=False)
    type = sa.Column(sa.String(30), nullable=False, unique=True)


class KeyVaultManager(object):

    _FACADE = None
    KEY_TYPE_CURRENT = 'CURRENT'
    KEY_TYPE_PREVIOUS = 'PREVIOUS'

    def __init__(self):
        if KeyVaultManager._FACADE is None:
            KeyVaultManager._FACADE = session.EngineFacade.from_config(
                cfg.CONF, sqlite_fk=True)
        self.session = KeyVaultManager._FACADE.get_session(
            autocommit=True, expire_on_commit=False)

    def _make_key_dict(self, key_db):
        """Transform KeyVault object into a dictionary"""
        return dict((x.name, getattr(key_db, x.name)) for x in
                    key_db.__table__.columns)

    def _current_key_query(self):
        return self.session.query(KeyVault).filter_by(
            type=KeyVaultManager.KEY_TYPE_CURRENT)

    def _previous_key_query(self):
        return self.session.query(KeyVault).filter_by(
            type=KeyVaultManager.KEY_TYPE_PREVIOUS)

    def _create_key(self, key, timestamp, validity, type):
        with self.session.begin(subtransactions=True):
            new_curr = KeyVault(
                key=key, timestamp=timestamp, validity=validity, type=type)
            self.session.add(new_curr)
            return new_curr

    def _get_current_key_db(self):
        with self.session.begin(subtransactions=True):
            query = self._current_key_query()
            return query.first()

    def _get_previous_key_db(self):
        with self.session.begin(subtransactions=True):
            query = self._previous_key_query()
            return query.first()

    def _delete_current_key_db(self):
        try:
            with self.session.begin(subtransactions=True):
                self._current_key_query().delete()
        except AttributeError as e:
            LOG.info(_("Current attestation key was already deleted."))
            LOG.debug("Current key deletion failed with error %s", e.message)

    def _delete_previous_key_db(self):
        try:
            with self.session.begin(subtransactions=True):
                self._previous_key_query().delete()
        except AttributeError as e:
            LOG.info(_("Previous attestation key was already deleted."))
            LOG.debug("Previous key deletion failed with error %s", e.message)

    def get_current_key(self):
        key_db = self._get_current_key_db()
        return self._make_key_dict(key_db) if key_db else None

    def get_previous_key(self):
        key_db = self._get_previous_key_db()
        return self._make_key_dict(key_db) if key_db else None

    def get_current_and_previous_keys(self):
        with self.session.begin(subtransactions=True):
            return self.get_current_key(), self.get_previous_key()

    def rotate_current_key(self, key, timestamp, validity):
        """Transactionally rotate the key.

        If no current key is set, this will be a noop and return None
        """
        with self.session.begin(subtransactions=True):
            # Delete previous key
            self._delete_previous_key_db()
            # Move current key to previous
            new_prev = self._get_current_key_db()
            if new_prev:
                new_prev.type = KeyVaultManager.KEY_TYPE_PREVIOUS
                self.session.merge(new_prev)
                # Add new key
                return self._make_key_dict(
                    self._create_key(key, timestamp, validity,
                                     KeyVaultManager.KEY_TYPE_CURRENT))
            return None

    def cleanup_keys(self):
        with self.session.begin(subtransactions=True):
            self._delete_previous_key_db()
            self._delete_current_key_db()

    def set_initial_key_if_not_exists(self, key, timestamp, validity):
        # Transactionally creates the current key if non existent, returns
        # the Key that was created if any
        with self.session.begin(subtransactions=True):
            if not self._get_current_key_db():
                return self._make_key_dict(
                    self._create_key(key, timestamp, validity,
                                     KeyVaultManager.KEY_TYPE_CURRENT))
            return None

    def expire_current_key(self, current_key, new_key, timestamp, validity):
        # Transactionally expires the attestation Key unless already expired
        # returns True if a Key is actually set
        with self.session.begin(subtransactions=True):
            curr = self.get_current_key() or {}
            if curr.get('key') == current_key:
                return self._make_key_dict(
                    self._create_key(new_key, timestamp, validity,
                                     KeyVaultManager.KEY_TYPE_CURRENT))
            return None
