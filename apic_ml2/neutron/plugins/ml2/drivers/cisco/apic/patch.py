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


from neutron import manager
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import plugin

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import exceptions


apic_stashed_create_network = plugin.Ml2Plugin.create_network
apic_stashed_get_plugin = manager.NeutronManager.get_plugin
apic_stashed_create_network_db = plugin.Ml2Plugin._create_network_db


def create_network(context, network):
    """Patch for ML2 create_network

    This patch will ignore the ReservedSynchronizationName exception.
    :param context:
    :param network:
    :return:
    """
    try:
        return apic_stashed_create_network(apic_stashed_get_plugin(), context,
                                           network)
    except exceptions.ReservedSynchronizationName:
        # Just Ignore the exception after deleting the network
        apic_stashed_get_plugin().delete_network(
            context, context._apic_stashed_net_id)
        return {}


def _create_network_db(context, network):
    result = apic_stashed_create_network_db(
        apic_stashed_get_plugin(), context, network)
    context._apic_stashed_net_id = result[0]['id']
    return result


def _call_on_drivers(method_name, context,
                     continue_on_failure=False):
    """Patch for _call_on_drivers

    Raise ReservedSynchronizationName when that occurs instead of swallowing
    it.
    :param method_name:
    :param context:
    :param continue_on_failure:
    :return:
    """
    errors = []
    for driver in (apic_stashed_get_plugin().mechanism_manager.
                   ordered_mech_drivers):
        try:
            getattr(driver.obj, method_name)(context)
        except Exception as e:
            managers.LOG.exception(
                managers._LE(
                    "Mechanism driver '%(name)s' failed in %(method)s"),
                {'name': driver.name, 'method': method_name}
            )
            errors.append(e)
            if not continue_on_failure:
                break
    if errors:
        for error in errors:
            if isinstance(error, exceptions.ReservedSynchronizationName):
                raise error
        raise managers.ml2_exc.MechanismDriverError(
            method=method_name
        )


@classmethod
def get_plugin(cls):
    plugin = apic_stashed_get_plugin()
    plugin.create_network = create_network
    plugin._create_network_db = _create_network_db
    plugin.mechanism_manager._call_on_drivers = _call_on_drivers
    return plugin

manager.NeutronManager.get_plugin = get_plugin
