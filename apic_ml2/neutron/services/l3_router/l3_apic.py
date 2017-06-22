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

from neutron.common import constants as q_const
from neutron.common import exceptions as n_exc
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron.plugins.common import constants
from oslo_log import log as logging
from oslo_utils import excutils

from apic_ml2.neutron.services.l3_router import apic_driver

LOG = logging.getLogger(__name__)


# REVISIT: The following patch can be easily eliminated
# by using the project_id that is available in the context.
def _get_tenant_id_for_create(self, context, resource):
    if context.is_admin and 'tenant_id' in resource:
        tenant_id = resource['tenant_id']
    elif ('tenant_id' in resource and
          resource['tenant_id'] != context.project_id):
        reason = _('Cannot create resource for another tenant')
        raise n_exc.AdminRequired(reason=reason)
    else:
        tenant_id = context.project_id

    return tenant_id


common_db_mixin.CommonDbMixin._get_tenant_id_for_create = (
    _get_tenant_id_for_create)


class ApicL3ServicePlugin(common_db_mixin.CommonDbMixin,
                          extraroute_db.ExtraRoute_db_mixin,
                          l3_gwmode_db.L3_NAT_db_mixin):
    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute",
                                   "l3-flavors"]

    # Set this to False so that the mixin code doesn't try to call
    # _process_dns_floatingip_create_precommit
    _dns_integration = False
    def __init__(self):
        super(ApicL3ServicePlugin, self).__init__()
        self.synchronizer = None
        # NB(tbachman): the mechanism driver depends on the existence
        # of the _apic_driver member. If this member is changed or
        # deleted, the code in the mechanism driver should be changed
        # as well.
        self._apic_driver = apic_driver.ApicL3Driver(self)

    def _update_router_gw_info(self, context, router_id, info, router=None):
        super(ApicL3ServicePlugin, self)._update_router_gw_info(
            context, router_id, info, router)
        if info and 'network_id' in info:
            filters = {'device_id': [router_id],
                       'device_owner': [q_const.DEVICE_OWNER_ROUTER_GW],
                       'network_id': [info['network_id']]}
            ports = self._core_plugin.get_ports(context.elevated(),
                                                filters=filters)
            self._core_plugin.update_port_status(
                context, ports[0]['id'], q_const.PORT_STATUS_ACTIVE)

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """Returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 using the APIC")

    # Router API

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
        result = self._make_router_dict(router_db)
        self.create_router_postcommit(context, result)
        return result

    def create_router_postcommit(self, context, router):
        self._apic_driver.create_router_postcommit(context, router)

    def update_router(self, context, id, router):
        result = super(ApicL3ServicePlugin, self).update_router(context,
                                                                id, router)
        self._apic_driver.update_router_postcommit(context, result)
        return result

    def get_router(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_router(*args, **kwargs)

    def get_routers(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_routers(*args, **kwargs)

    def get_routers_count(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_routers_count(*args,
                                                                  **kwargs)

    def delete_router(self, context, router_id):
        self._apic_driver.delete_router_precommit(context, router_id)
        result = super(ApicL3ServicePlugin, self).delete_router(context,
                                                                router_id)
        return result

    # Router Interface API

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

    # Keep synchronizer happy
    def add_router_interface_postcommit(self, context, router_id,
                                        interface_info):
        self._apic_driver.add_router_interface_postcommit(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        self._apic_driver.remove_router_interface_precommit(context, router_id,
                                                            interface_info)
        return super(ApicL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    # Floating IP API
    def create_floatingip(self, context, floatingip):
        res = super(ApicL3ServicePlugin, self).create_floatingip(
            context, floatingip)
        self._apic_driver.create_floatingip_postcommit(context, res)
        return res

    def update_floatingip(self, context, id, floatingip):
        self._apic_driver.update_floatingip_precommit(context, id, floatingip)
        res = super(ApicL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)
        context.current = res
        self._apic_driver.update_floatingip_postcommit(context, id, floatingip)
        return res

    def delete_floatingip(self, context, id):
        self._apic_driver.delete_floatingip_precommit(context, id)
        res = super(ApicL3ServicePlugin, self).delete_floatingip(context, id)
        self._apic_driver.delete_floatingip_postcommit(context, id)
        return res


def add_flavor_id(plugin, router_res, router_db):
    router_res['flavor_id'] = router_db['flavor_id']


common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
    l3.ROUTERS, [add_flavor_id])
