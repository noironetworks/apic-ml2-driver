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

"""L3 out vlan allocation

Revision ID: 500c1e2c01ee
Revises: None
Create Date: 2016-02-05 02:08:54.252877

"""

# revision identifiers, used by Alembic.
revision = '500c1e2c01ee'
down_revision = '4c0c1e2c0160'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'apic_ml2_l3out_vlan_allocation',
        sa.Column('l3out_network', sa.String(length=64), nullable=False),
        sa.Column('vrf', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer, nullable=False),
        sa.Column('allocated', sa.Boolean, nullable=False),
        sa.PrimaryKeyConstraint('l3out_network', 'vlan_id'))

def downgrade():
    op.drop_table('apic_ml2_l3out_vlan_allocation')
