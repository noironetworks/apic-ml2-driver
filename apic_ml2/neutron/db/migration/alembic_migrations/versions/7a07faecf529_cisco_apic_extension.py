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

"""Tables for cisco_apic extension attributes

Revision ID: 7a07faecf529
Revises: 5d1c1f1d1282
Create Date: 2017-05-10 14:18:11.909757

"""

# revision identifiers, used by Alembic.
revision = '7a07faecf529'
down_revision = '5d1c1f1d1282'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'apic_ml2_network_extensions',
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('allow_route_leak', sa.Boolean),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                name='apic_ml2_network_extn_fk_network',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )


def downgrade():
    pass
