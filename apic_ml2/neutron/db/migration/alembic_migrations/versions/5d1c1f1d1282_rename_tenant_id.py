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

"""Rename tenant_id to project_id

Revision ID: 5d1c1f1d1282
Revises: None
Create Date: 2017-04-04 15:05:45.523877

"""

# revision identifiers, used by Alembic.
revision = '5d1c1f1d1282'
down_revision = '60741a4735ca'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('cisco_ml2_apic_contracts', 'tenant_id',
                    new_column_name='project_id',
                    existing_type=sa.String(255))


def downgrade():
    op.alter_column('cisco_ml2_apic_contracts', 'project_id',
                    new_column_name='tenant_id',
                    existing_type=sa.String(255))
