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
from neutron.common import utils as n_utils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer.agent import agent_device_driver
from neutron.services.loadbalancer.drivers.stingray import rest_client

LOG = logging.getLogger(__name__)
DRIVER_NAME = 'stingray'

OPTS = [
    cfg.ListOpt(
        'device_addresses',
        help=_('Hostnames/IP addresses of Stingray devices')
    ),
    cfg.StrOpt(
        'tm_username',
        help=_('Admin username to configure Stingray devices')
    ),
    cfg.StrOpt(
        'tm_password',
        help=_('Admin password to configure Stingray devices')
    ),
    cfg.StrOpt(
        'tm_community',
        help=_('SNMP community string for read-only queries')
    ),
    cfg.IntOpt(
        'device_port',
        default=9070,
        help=_('Port for Stingray RESTful API')
    ),
    cfg.StrOpt(
        'device_api_version',
        default='2.0',
        help=_('RESTful API version of Stingray device')
    ),
]

cfg.CONF.register_opts(OPTS, 'stingray')


class StingrayPluginDriver(agent_device_driver.AgentDeviceDriver):

    def __init__(self, conf, plugin_rpc):
        self.conf = conf
        self.plugin_rpc = plugin_rpc

        username = conf.stingray.tm_username
        password = conf.stingray.tm_password
        port = conf.stingray.device_port
        devices = conf.stingray.device_addresses
        community = conf.stingray.tm_community
        api_version = conf.stingray.device_api_version

        self.client = rest_client.StingrayRestClient(username,
                                                     password,
                                                     port,
                                                     devices,
                                                     community,
                                                     api_version)

    @classmethod
    def get_name(cls):
        return DRIVER_NAME

    @n_utils.synchronized('stingray-driver')
    def _deploy_config(self, logical_config):
        # do actual deploy only if vip and pool are configured and active
        if (not logical_config or
                'vip' not in logical_config or
                (logical_config['vip']['status'] not in
                 constants.ACTIVE_PENDING_STATUSES) or
                not logical_config['vip']['admin_state_up'] or
                (logical_config['pool']['status'] not in
                 constants.ACTIVE_PENDING_STATUSES) or
                not logical_config['pool']['admin_state_up']):
            return

        if self.client.exists(logical_config['pool']['id']):
            self.client.update(logical_config)
        else:
            self.client.create(logical_config)

    @log.log
    def _refresh_device(self, pool_id):
        logical_config = self.plugin_rpc.get_logical_device(pool_id)
        self._deploy_config(logical_config)

    @log.log
    def create_vip(self, vip):
        self._refresh_device(vip['pool_id'])

    @log.log
    def update_vip(self, old_vip, vip):
        self._refresh_device(vip['pool_id'])

    @log.log
    def delete_vip(self, vip):
        self.client.destroy_vip(vip)

    @log.log
    def create_pool(self, pool):
        # nothing to do here because a pool needs a vip to be useful
        self._refresh_device(pool['id'])

    @log.log
    def update_pool(self, old_pool, pool):
        self._refresh_device(pool['id'])

    @log.log
    def delete_pool(self, pool):
        # delete_pool may be called before vip deletion in case
        # pool's admin state set to down
        if self.client.exists(pool['id']):
            self.client.destroy_pool(pool)

    @log.log
    def create_member(self, member):
        self._refresh_device(member['pool_id'])

    @log.log
    def update_member(self, old_member, member):
        self._refresh_device(member['pool_id'])

    @log.log
    def delete_member(self, member):
        self._refresh_device(member['pool_id'])

    @log.log
    def create_pool_health_monitor(self, health_monitor, pool_id):
        self._refresh_device(pool_id)

    @log.log
    def update_pool_health_monitor(self, old_health_monitor, health_monitor,
                                   pool_id):
        self._refresh_device(pool_id)

    @log.log
    def delete_pool_health_monitor(self, health_monitor, pool_id):
        self._refresh_device(pool_id)

    @log.log
    def get_stats(self, pool_id):
        pass

    def deploy_instance(self, logical_config):
        pass

    def undeploy_instance(self, pool_id, cleanup_namespace=False):
        pass
