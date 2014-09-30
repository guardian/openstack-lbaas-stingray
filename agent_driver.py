# Copyright 2014 Guardian News & Media
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
#
# @author: Stephen Gran, Guardian News & Media
# @author: Andy Botting, Guardian News & Media

from oslo.config import cfg

from neutron.common import log
from neutron.openstack.common import log as logging

from neutron.services.loadbalancer.drivers.common import agent_driver_base
from neutron.services.loadbalancer.drivers.stingray import plugin_driver

AGENT_SCHEDULER_OPTS = [
    cfg.ListOpt('loadbalancer_instance_ports',
                default=[],
                help=_('Ports to update on vip modification.')),
]

cfg.CONF.register_opts(AGENT_SCHEDULER_OPTS)

LOG = logging.getLogger(__name__)


class StingrayAgentDriver(agent_driver_base.AgentDriverBase):
    device_driver = plugin_driver.DRIVER_NAME

    def _add_ip_to_port(self, context, port, vip):
        ips = [i['ip_address'] for i in port['allowed_address_pairs']]
        if vip['address'] not in ips:
            port['allowed_address_pairs'].append({
                'ip_address': vip['address'],
                'mac_address': port['mac_address']
            })
            self.plugin._core_plugin.update_port(context, port['id'],
                                                 {'port': port})

    def _del_ip_from_port(self, context, port, vip):
        ips = [i['ip_address'] for i in port['allowed_address_pairs']]
        if vip['address'] in ips:
            port['allowed_address_pairs'].remove({
                'ip_address': vip['address'],
                'mac_address': port['mac_address']
            })
            self.plugin._core_plugin.update_port(context, port['id'],
                                                 {'port': port})

    @log.log
    def create_vip(self, context, vip):
        super(StingrayAgentDriver, self).create_vip(context, vip)
        for port_id in cfg.CONF.loadbalancer_instance_ports:
            port = self.plugin._core_plugin.get_port(context, port_id)
            self._add_ip_to_port(context, port, vip)

    @log.log
    def update_vip(self, context, old_vip, vip):
        super(StingrayAgentDriver, self).update_vip(context, old_vip, vip)
        for port_id in cfg.CONF.loadbalancer_instance_ports:
            port = self.plugin._core_plugin.get_port(context, port_id)
            self._add_ip_to_port(context, port, vip)
            self._del_ip_from_port(context, port, old_vip)

    @log.log
    def delete_vip(self, context, vip):
        super(StingrayAgentDriver, self).delete_vip(context, vip)
        for port_id in cfg.CONF.loadbalancer_instance_ports:
            port = self.plugin._core_plugin.get_port(context, port_id)
            self._del_ip_from_port(context, port, vip)
