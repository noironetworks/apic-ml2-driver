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
Revises: 60741a4735ca
Create Date: 2017-05-10 14:18:11.909757

"""

# revision identifiers, used by Alembic.
revision = '7a07faecf529'
down_revision = '60741a4735ca'

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
    op.create_table(
        'apic_ml2_router_extensions',
        sa.Column('router_id', sa.String(36), nullable=False),
        sa.Column('use_routing_context', sa.String(36)),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                name='apic_ml2_router_extn_fk_router_id',
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['use_routing_context'], ['routers.id'],
                                name='apic_ml2_router_extn_fk_routing_cxt',
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('router_id')
    )


def downgrade():
    pass
