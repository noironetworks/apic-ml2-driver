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

"""Increase hostlinks column size

Revision ID: 60741a4735ca
Revises: 500c1e2c01ee
Create Date: 2016-09-26 11:03:15.358466

"""

# revision identifiers, used by Alembic.
revision = '60741a4735ca'
down_revision = '500c1e2c01ee'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('cisco_ml2_apic_host_links', 'module',
                    type_=sa.String(64),
                    existing_nullable=False)
    op.alter_column('cisco_ml2_apic_host_links', 'port',
                    type_=sa.String(64),
                    existing_nullable=False)


def downgrade():
    op.alter_column('cisco_ml2_apic_host_links', 'module',
                    type_=sa.String(32),
                    existing_nullable=False)
    op.alter_column('cisco_ml2_apic_host_links', 'port',
                    type_=sa.String(32),
                    existing_nullable=False)
