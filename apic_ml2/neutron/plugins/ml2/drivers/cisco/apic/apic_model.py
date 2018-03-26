# Copyright (c) 2014 Cisco Systems Inc.
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

import sys

import sqlalchemy as sa
from sqlalchemy import orm

from neutron import context as nctx
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.db import segments_db
from neutron.plugins.ml2 import models as models_ml2
from neutron_lib.db import model_base


def get_current_session():
    i = 1
    not_found = True
    try:
        while not_found:
            for val in sys._getframe(i).f_locals.itervalues():
                if isinstance(val, nctx.Context):
                    ctx = val
                    not_found = False
                    break
            i = i + 1
        return ctx.session
    except Exception:
        return


class RouterContract(model_base.BASEV2, model_base.HasProject):

    """Contracts created on the APIC.

    project_id represents the owner (APIC side) of the contract.
    router_id is the UUID of the router (Neutron side) this contract is
    referring to.
    """

    __tablename__ = 'cisco_ml2_apic_contracts'

    # TODO(HenryG): this must be changed to String(36) for Mitaka
    router_id = sa.Column(sa.String(64), sa.ForeignKey('routers.id'),
                          primary_key=True)


class HostLink(model_base.BASEV2):

    """Connectivity of host links."""

    __tablename__ = 'cisco_ml2_apic_host_links'

    host = sa.Column(sa.String(255), nullable=False, primary_key=True)
    ifname = sa.Column(sa.String(64), nullable=False, primary_key=True)
    ifmac = sa.Column(sa.String(32), nullable=True)
    swid = sa.Column(sa.String(32), nullable=False)
    module = sa.Column(sa.String(64), nullable=False)
    port = sa.Column(sa.String(64), nullable=False)


class ApicName(model_base.BASEV2):
    """Mapping of names created on the APIC."""

    __tablename__ = 'cisco_ml2_apic_names'

    neutron_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    neutron_type = sa.Column(sa.String(32), nullable=False, primary_key=True)
    apic_name = sa.Column(sa.String(255), nullable=False)


class ApicDbModel(object):

    """DB Model to manage all APIC DB interactions."""

    def get_session(self, session=None):
        return session or get_current_session() or db_api.get_session()

    def get_contract_for_router(self, router_id):
        """Returns the specified router's contract."""
        return self.get_session().query(RouterContract).filter_by(
            router_id=router_id).first()

    def write_contract_for_router(self, project_id, router_id, session=None):
        """Stores a new contract for the given tenant."""
        contract = RouterContract(project_id=project_id,
                                  router_id=router_id)
        session = self.get_session(session)
        with session.begin(subtransactions=True):
            session.add(contract)
        return contract

    def update_contract_for_router(self, project_id, router_id):
        session = self.get_session()
        with session.begin(subtransactions=True):
            contract = session.query(RouterContract).filter_by(
                router_id=router_id).with_lockmode('update').first()
            if contract:
                contract.project_id = project_id
                session.merge(contract)
            else:
                self.write_contract_for_router(project_id, router_id, session)

    def delete_contract_for_router(self, router_id):
        session = self.get_session()
        with session.begin(subtransactions=True):
            try:
                session.query(RouterContract).filter_by(
                    router_id=router_id).delete()
            except orm.exc.NoResultFound:
                return

    def add_hostlink(self, host, ifname, ifmac, swid, module, port):
        link = HostLink(host=host, ifname=ifname, ifmac=ifmac,
                        swid=swid, module=module, port=port)
        session = self.get_session()
        with session.begin(subtransactions=True):
            session.merge(link)

    def get_hostlinks(self):
        session = self.get_session()
        return session.query(HostLink).all()

    def get_hostlink(self, host, ifname):
        session = self.get_session()
        return session.query(HostLink).filter_by(
            host=host, ifname=ifname).first()

    def get_hostlinks_for_host(self, host):
        session = self.get_session()
        return session.query(HostLink).filter_by(
            host=host).all()

    def get_hostlinks_for_host_switchport(self, host, swid, module, port):
        session = self.get_session()
        return session.query(HostLink).filter_by(
            host=host, swid=swid, module=module, port=port).all()

    def get_hostlinks_for_switchport(self, swid, module, port):
        session = self.get_session()
        return session.query(HostLink).filter_by(
            swid=swid, module=module, port=port).all()

    def delete_hostlink(self, host, ifname):
        session = self.get_session()
        with session.begin(subtransactions=True):
            try:
                session.query(HostLink).filter_by(host=host,
                                                  ifname=ifname).delete()
            except orm.exc.NoResultFound:
                return

    def get_switches(self):
        session = self.get_session()
        return session.query(HostLink.swid).distinct()

    def get_modules_for_switch(self, swid):
        session = self.get_session()
        return session.query(
            HostLink.module).filter_by(swid=swid).distinct()

    def get_ports_for_switch_module(self, swid, module):
        session = self.get_session()
        return session.query(
            HostLink.port).filter_by(swid=swid, module=module).distinct()

    def get_switch_and_port_for_host(self, host):
        session = self.get_session()
        return session.query(
            HostLink.swid, HostLink.module, HostLink.port).filter_by(
                host=host).distinct()

    def get_tenant_network_vlan_for_host(self, host):
        pb = models_ml2.PortBinding
        po = models_v2.Port
        ns = segments_db.NetworkSegment
        session = self.get_session()
        return session.query(
            po.project_id, ns.network_id, ns.segmentation_id).filter(
            po.id == pb.port_id).filter(pb.host == host).filter(
                po.network_id == ns.network_id).distinct()

    def add_apic_name(self, neutron_id, neutron_type, apic_name,
                      session=None):
        name = ApicName(neutron_id=neutron_id,
                        neutron_type=neutron_type,
                        apic_name=apic_name)
        sess = self.get_session(session)
        with sess.begin(subtransactions=True):
            sess.add(name)

    def update_apic_name(self, neutron_id, neutron_type, apic_name,
                         session=None):
        sess = self.get_session(session)
        with sess.begin(subtransactions=True):
            name = sess.query(ApicName).filter_by(
                neutron_id=neutron_id,
                neutron_type=neutron_type).with_lockmode('update').first()
            if name:
                name.apic_name = apic_name
                sess.merge(name)
            else:
                self.add_apic_name(neutron_id, neutron_type, apic_name,
                                   session=sess)

    def get_apic_names(self):
        return self.get_session().query(ApicName).all()

    def get_apic_name(self, neutron_id, neutron_type):
        return self.get_session().query(ApicName.apic_name).filter_by(
            neutron_id=neutron_id, neutron_type=neutron_type).first()

    def delete_apic_name(self, neutron_id, session=None):
        sess = self.get_session(session)
        with sess.begin(subtransactions=True):
            try:
                sess.query(ApicName).filter_by(
                    neutron_id=neutron_id).delete()
            except orm.exc.NoResultFound:
                return
