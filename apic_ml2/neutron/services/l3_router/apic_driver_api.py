# Copyright (c) 2016 Cisco Systems Inc.
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


class ApicL3DriverBase(object):
    """APIC L3 driver abstract base class

       This is the APIC driver interface for L3 plugins. The purpose of
       this class is to define the APIC-specific API calls used by either
       the Neutron or Group Based Policy workflow as a result of a Layer 3
       API call.  This allows the driver to be used by other Layer 3 service
       plugins (e.g. the Cisco Router Service Plugin).
       """
    def update_router_postcommit(self, context, router):
        """Post-DB operation for update_router API

        This should be called after the DB operation to the
        router has been performed.
        """
        pass

    def delete_router_precommit(self, context, router_id):
        """Pre-DB operation for delete_router API

        This should be called before the DB operation to the
        router has been performed.
        """
        pass

    def add_router_interface_postcommit(self, context, router_id,
                                        interface_info):
        """Post-DB operation for add_router_interface API

        This should be called after the DB operation to the
        router has been performed.
        """
        pass

    def remove_router_interface_precommit(self, context, router_id,
                                          interface_info):
        """Pre-DB operation for remove_router_interface API

        This should be called before the DB operation to the
        router has been performed.
        """
        pass

    def create_floatingip_precommit(self, context, floatingip):
        """Pre-DB operation for create_floatingip API

        This should be called before the DB operation to the
        floating IP has been performed.
        """
        pass

    def create_floatingip_postcommit(self, context, floatingip):
        """Post-DB operation for create_floatingip API

        This should be called after the DB operation to the
        floating IP has been performed.
        """
        pass

    def update_floatingip_precommit(self, context, id, floatingip):
        """Pre-DB operation for update_floatingip API

        This should be called before the DB operation to the
        floating IP has been performed.
        """
        pass

    def update_floatingip_postcommit(self, context, id, floatingip):
        """Post-DB operation for update_floatingip API

        This should be called after the DB operation to the
        floating IP has been performed.
        """
        pass

    def delete_floatingip_precommit(self, context, id):
        """Pre-DB operation for delete_floatingip API

        This should be called before the DB operation to the
        floating IP has been performed.
        """
        pass

    def delete_floatingip_postcommit(self, context, id):
        """Post-DB operation for delete_floatingip API

        This should be called after the DB operation to the
        floating IP has been performed.
        """
        pass
