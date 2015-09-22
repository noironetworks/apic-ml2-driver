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

from apicapi import apic_mapper
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.extensions import l3
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import mechanism_apic

LOG = logging.getLogger(__name__)


class InterTenantRouterInterfaceNotAllowedOnPerTenantContext(n_exc.BadRequest):
    message = _("Cannot attach s router interface to a network owned by "
                "another tenant when per_tenant_context is enabled.")


class ApicL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                          l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                          extraroute_db.ExtraRoute_db_mixin):
    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        super(ApicL3ServicePlugin, self).__init__()
        self.manager = mechanism_apic.APICMechanismDriver.get_apic_manager()
        self.name_mapper = self.manager.apic_mapper
        self.synchronizer = None
        self.manager.ensure_infra_created_on_apic()
        self.manager.ensure_bgp_pod_policy_created_on_apic()
        self._aci_mech_driver = None

    @property
    def aci_mech_driver(self):
        if not self._aci_mech_driver:
            plugin = manager.NeutronManager.get_plugin()
            self._aci_mech_driver = plugin.mechanism_manager.mech_drivers[
                'cisco_apic_ml2'].obj
        return self._aci_mech_driver

    def _map_names(self, context,
                   tenant_id, router_id, net_id, subnet_id):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            atenant_id = tenant_id and self.name_mapper.tenant(ctx, tenant_id)
            arouter_id = router_id and self.name_mapper.router(ctx, router_id)
            anet_id = net_id and self.name_mapper.network(ctx, net_id)
            asubnet_id = subnet_id and self.name_mapper.subnet(ctx, subnet_id)
        return atenant_id, arouter_id, anet_id, asubnet_id

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """Returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 using the APIC")

    def sync_init(f):
        def inner(inst, *args, **kwargs):
            if not inst.synchronizer:
                inst.synchronizer = (
                    mechanism_apic.APICMechanismDriver.
                    get_router_synchronizer(inst))
                inst.synchronizer.sync_router()
            return f(inst, *args, **kwargs)
        return inner

    def add_router_interface_postcommit(self, context, router_id,
                                        interface_info):
        # Update router's state first
        router = self.get_router(context, router_id)
        self.update_router_postcommit(context, router)

        # Add router interface
        if 'subnet_id' in interface_info:
            subnet = self.get_subnet(context, interface_info['subnet_id'])
            network_id = subnet['network_id']
        else:
            port = self.get_port(context, interface_info['port_id'])
            network_id = port['network_id']

        network = self.get_network(context, network_id)
        tenant_id = network['tenant_id']
        if (tenant_id != router['tenant_id'] and
                self.aci_mech_driver.per_tenant_context and
                not self.aci_mech_driver._is_nat_enabled_on_ext_net(network)):
            # This operation is disallowed. Can't trespass VRFs without NAT.
            raise InterTenantRouterInterfaceNotAllowedOnPerTenantContext()

        # Map openstack IDs to APIC IDs
        atenant_id, arouter_id, anetwork_id, _ = self._map_names(
            context, tenant_id, router_id, network_id, None)

        # Program APIC
        self.manager.add_router_interface(
            self.aci_mech_driver._get_network_aci_tenant(network),
            arouter_id, anetwork_id,
            app_profile_name=self.aci_mech_driver._get_network_app_profile(
                network))

    def remove_router_interface_precommit(self, context, router_id,
                                          interface_info):
        if 'subnet_id' in interface_info:
            subnet = self.get_subnet(context, interface_info['subnet_id'])
            network_id = subnet['network_id']
        else:
            port = self.get_port(context, interface_info['port_id'])
            network_id = port['network_id']

        network = self.get_network(context, network_id)
        tenant_id = network['tenant_id']

        # Map openstack IDs to APIC IDs
        atenant_id, arouter_id, anetwork_id, _ = self._map_names(
            context, tenant_id, router_id, network_id, None)

        # Program APIC
        self.manager.remove_router_interface(
            self.aci_mech_driver._get_network_aci_tenant(network),
            arouter_id, anetwork_id,
            app_profile_name=self.aci_mech_driver._get_network_app_profile(
                network))

    def delete_router_precommit(self, context, router_id):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            arouter_id = router_id and self.name_mapper.router(ctx, router_id)
        self.manager.delete_router(arouter_id)

    def update_router_postcommit(self, context, router):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            arouter_id = router['id'] and self.name_mapper.router(ctx,
                                                                  router['id'])
            tenant_id = self.aci_mech_driver._get_router_aci_tenant(router)

        with self.manager.apic.transaction() as trs:
            vrf = self.aci_mech_driver._get_tenant_vrf(router['tenant_id'])
            self.manager.create_router(arouter_id, owner=vrf['aci_tenant'],
                                       transaction=trs,
                                       context=vrf['aci_name'])
            if router['admin_state_up']:
                self.manager.enable_router(arouter_id, owner=tenant_id,
                                           transaction=trs)
            else:
                self.manager.disable_router(arouter_id, owner=tenant_id,
                                            transaction=trs)

    # Router API

    @sync_init
    def create_router(self, context, router):
        r = router['router']
        gw_info = r.pop(l3_db.EXTERNAL_GW_INFO, None)
        tenant_id = self._get_tenant_id_for_create(context, r)
        router_db = self._create_router_db(context, r, tenant_id)
        try:
            if gw_info:
                self._update_router_gw_info(context, router_db['id'],
                                            gw_info, router=router_db)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("An exception occurred while creating "
                                "the router: %s"), router)
                self.delete_router(context, router_db.id)

        return self._make_router_dict(router_db)

    @sync_init
    def update_router(self, context, id, router):
        result = super(ApicL3ServicePlugin, self).update_router(context,
                                                                id, router)
        self.update_router_postcommit(context, result)
        return result

    @sync_init
    def get_router(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_router(*args, **kwargs)

    @sync_init
    def get_routers(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_routers(*args, **kwargs)

    @sync_init
    def get_routers_count(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_routers_count(*args,
                                                                  **kwargs)

    def delete_router(self, context, router_id):
        self.delete_router_precommit(context, router_id)
        result = super(ApicL3ServicePlugin, self).delete_router(context,
                                                                router_id)
        return result

    # Router Interface API

    @sync_init
    def add_router_interface(self, context, router_id, interface_info):
        # Create interface in parent
        result = super(ApicL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)
        try:
            self.add_router_interface_postcommit(context, router_id,
                                                 interface_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Rollback db operation
                super(ApicL3ServicePlugin, self).remove_router_interface(
                    context, router_id, interface_info)
        return result

    def remove_router_interface(self, context, router_id, interface_info):
        self.remove_router_interface_precommit(context, router_id,
                                               interface_info)
        return super(ApicL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    # Floating IP API
    def create_floatingip(self, context, floatingip):
        res = super(ApicL3ServicePlugin, self).create_floatingip(
            context, floatingip)
        port_id = floatingip.get('floatingip', {}).get('port_id')
        self._notify_port_update(port_id)
        return res

    def update_floatingip(self, context, id, floatingip):
        port_id = [self._get_port_mapped_to_floatingip(context, id)]
        res = super(ApicL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)
        port_id.append(floatingip.get('floatingip', {}).get('port_id'))
        for p in port_id:
            self._notify_port_update(p)
        return res

    def delete_floatingip(self, context, id):
        port_id = self._get_port_mapped_to_floatingip(context, id)
        res = super(ApicL3ServicePlugin, self).delete_floatingip(context, id)
        self._notify_port_update(port_id)
        return res

    def _get_port_mapped_to_floatingip(self, context, fip_id):
        try:
            fip = self.get_floatingip(context, fip_id)
            return fip.get('port_id')
        except l3.FloatingIPNotFound:
            pass
        return None

    def _notify_port_update(self, port_id):
        l2 = mechanism_apic.APICMechanismDriver.get_driver_instance()
        if l2 and port_id:
            l2.notify_port_update(port_id)
