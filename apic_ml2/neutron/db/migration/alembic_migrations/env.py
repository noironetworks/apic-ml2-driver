# Copyright 2012 New Dream Network, LLC (DreamHost)
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

from logging.config import fileConfig
from neutron.db import model_base

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config
neutron_config = config.neutron_config
fileConfig(config.config_file_name)
target_metadata = model_base.BASEV2.metadata


def run_migrations_offline():
    context.configure(url=neutron_config.database.connection,
                      version_table='apic_ml2_standalone_driver')

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = create_engine(
        neutron_config.database.connection,
        poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table='apic_ml2_standalone_driver'
    )

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
