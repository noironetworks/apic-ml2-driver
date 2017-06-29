# Copyright (c) 2017 Cisco Systems Inc.
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

from neutron.db import model_base
import sqlalchemy as sa

from apic_ml2.neutron.extensions import cisco_apic
from apic_ml2.neutron.extensions import cisco_apic_l3


class NetworkExtensionDb(model_base.BASEV2):

    __tablename__ = 'apic_ml2_network_extensions'

    network_id = sa.Column(
        sa.String(36), sa.ForeignKey('networks.id', ondelete="CASCADE"),
        primary_key=True)
    allow_route_leak = sa.Column(sa.Boolean)


class RouterExtensionDb(model_base.BASEV2):

    __tablename__ = 'apic_ml2_router_extensions'

    router_id = sa.Column(
        sa.String(36), sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
    use_routing_context = sa.Column(
        sa.String(36), sa.ForeignKey('routers.id', ondelete="RESTRICT"))


class ExtensionDbMixin(object):

    def _set_if_not_none(self, res_dict, res_attr, db_attr):
        if db_attr is not None:
            res_dict[res_attr] = db_attr

    def get_network_extn_db(self, session, network_id):
        db_obj = (session.query(NetworkExtensionDb).filter_by(
                  network_id=network_id).first())
        result = {}
        if db_obj:
            self._set_if_not_none(result, cisco_apic.ALLOW_ROUTE_LEAK,
                                  db_obj['allow_route_leak'])
        return result

    def set_network_extn_db(self, session, network_id, res_dict):
        db_obj = (session.query(NetworkExtensionDb).filter_by(
                  network_id=network_id).first())
        db_obj = db_obj or NetworkExtensionDb(network_id=network_id)
        if cisco_apic.ALLOW_ROUTE_LEAK in res_dict:
            db_obj['allow_route_leak'] = res_dict[cisco_apic.ALLOW_ROUTE_LEAK]
        session.add(db_obj)

    def get_router_extn_db(self, session, router_id):
        db_obj = (session.query(RouterExtensionDb).filter_by(
                  router_id=router_id).first())
        result = {}
        if db_obj:
            self._set_if_not_none(result, cisco_apic_l3.USE_ROUTING_CONTEXT,
                                  db_obj['use_routing_context'])
        return result

    def set_router_extn_db(self, session, router_id, res_dict):
        if res_dict.get(cisco_apic_l3.USE_ROUTING_CONTEXT):
            db_obj = RouterExtensionDb(router_id=router_id)
            db_obj['use_routing_context'] = res_dict[
                cisco_apic_l3.USE_ROUTING_CONTEXT]
            session.add(db_obj)
