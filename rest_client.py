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

import json
import requests

from neutron.common import exceptions as n_exc
from neutron.common import log
from neutron.extensions import lbaas_agentscheduler
from neutron.openstack.common import log as logging

from pysnmp.entity.rfc3413.oneliner import cmdgen

LOG = logging.getLogger(__name__)


class StingrayRestClient(object):

    @log.log
    def __init__(self, username, password, port, devices, community,
                 api_version):
        self.headers = {'content-type': 'application/json'}

        self.username = username
        self.password = password
        self.devices = devices
        self.community = community
        self.api_version = api_version

        self.urls = ["https://%s:%d/api/tm/%s/config/active/" %
                     (x, port, api_version) for x in self.devices]
        self.pools = {}

    def _get_api_version(self):
        return [int(i) for i in self.api_version.split('.')]

    def _get_client(self):
        client = requests.Session()
        client.auth = (self.username, self.password)
        client.verify = False
        return client

    @log.log
    def get_connection(self, pool_id, req_string):
        for url in self.urls:
            LOG.debug("Attempting GET connection: %s" % url + req_string)
            try:
                return self._get_client().get(url + req_string)
            except requests.exceptions.ConnectionError:
                pass
        raise lbaas_agentscheduler.NoActiveLbaasAgent(pool_id=pool_id)

    @log.log
    def delete_connection(self, pool_id, req_string):
        for url in self.urls:
            LOG.debug("Attempting DELETE connection: %s" % url + req_string)
            try:
                response = self._get_client().delete(url + req_string,
                                                     headers=self.headers)
                if response.status_code in [400, 403, 405]:
                    resp = json.loads(response.content)
                    raise n_exc.Invalid(
                        _('Invalid return from Stingray (%d): %s' %
                            (response.status_code, resp))
                    )
                elif response.status_code in [200, 201, 204, 404]:
                    return True

            except requests.exceptions.ConnectionError:
                pass
        raise n_exc.Invalid(
            _('Invalid return from Stingray (%d): %s' %
                (response.status_code, json.dumps(response.content)))
        )

    @log.log
    def put_connection(self, pool_id, req_string, data):
        request_data = json.dumps(data)
        for url in self.urls:
            LOG.debug("Attempting PUT connection: %s with data: %s"
                      % (url + req_string, request_data))
            try:
                response = self._get_client().put(url + req_string,
                                                  data=request_data,
                                                  headers=self.headers)
                if response.status_code in [400, 403, 405]:
                    resp = json.loads(response.content)
                    raise n_exc.Invalid(
                        _('Invalid return from Stingray (%d): %s' %
                            (response.status_code, resp))
                    )
                elif response.status_code in [200, 201]:
                    return True

            except requests.exceptions.ConnectionError:
                pass
        raise lbaas_agentscheduler.NoActiveLbaasAgent(pool_id=pool_id)

    @log.log
    def create_pool(self, config):
        req_string = 'pools/' + config['pool']['id']

        pool_name = config['pool']['name']
        method = config['pool']['lb_method'].lower()

        nodes = [m['address'] + ':' + str(m['protocol_port'])
                   for m in config['members'] if m['admin_state_up']]
        disabled = [m['address'] + ':' + str(m['protocol_port'])
                   for m in config['members'] if not m['admin_state_up']]

        membersize = len(config['members']) or 1

        # VIP may not be defined yet
        vip = config.get('vip')
        if vip and vip['connection_limit'] > 0:
            conn_limit = int(vip['connection_limit'] / membersize)
        else:
            conn_limit = 1024

        # Health monitors may not be defined yet
        monitors = config.get('healthmonitors')
        if monitors:
            max_retries = monitors[0]['max_retries']
        else:
            max_retries = 3

        data = {
            'properties': {
                'auto_scaling': {
                    'cloud_credentials': '',
                    'cluster': '',
                    'data_center': '',
                    'data_store': '',
                    'enabled': False,
                    'external': True,
                    'hysteresis': 20,
                    'imageid': '',
                    'ips_to_use': 'publicips',
                    'last_node_idle_time': 3600,
                    'max_nodes': 4,
                    'min_nodes': 1,
                    'name': '',
                    'port': 80,
                    'refractory': 180,
                    'response_time': 1000,
                    'scale_down_level': 95,
                    'scale_up_level': 40,
                    'size_id': ''
                },
                'basic': {
                    'bandwidth_class': '',
                    'disabled': disabled,
                    'draining': [],
                    'failure_pool': '',
                    'max_idle_connections_pernode': 50,
                    'monitors': config['pool']['health_monitors'],
                    'node_connection_attempts': max_retries,
                    'nodes': nodes,
                    'note': pool_name,
                    'passive_monitoring': True,
                    'persistence_class': '',
                    'transparent': False
                },
                'connection': {
                    'max_connect_time': 4,
                    'max_connections_per_node': conn_limit,
                    'max_queue_size': 0,
                    'max_reply_time': 30,
                    'queue_timeout': 10
                },
                'ftp': {
                    'support_rfc_2428': False
                },
                'http': {
                    'keepalive': True,
                    'keepalive_non_idempotent': False
                },
                'load_balancing': {
                    'algorithm': method,
                    'node_weighting': [],
                    'priority_enabled': False,
                    'priority_nodes': 1,
                    'priority_values': []
                },
                'node': {
                    'close_on_death': False,
                    'retry_fail_time': 60
                },
                'smtp': {
                    'send_starttls': True
                },
                'ssl': {
                    'client_auth': False,
                    'enable': False,
                    'enhance': False,
                    'send_close_alerts': False,
                    'server_name': False,
                    'strict_verify': False
                },
                'tcp': {
                    'nagle': True
                },
                'udp': {
                    'accept_from': 'dest_only',
                    'accept_from_mask': ''
                }
            }
        }

        self.put_connection(config['pool']['id'], req_string, data)

    @log.log
    def create_vserver(self, config):
        # Virtual Server known as 'vserver' in API v1
        if self._get_api_version()[0] > 1:
            req_string = 'virtual_servers/' + config['pool']['id']
        else:
            req_string = 'vservers/' + config['pool']['id']

        vserver_name = config['pool'].get('name', config['pool']['id'])
        protocol = config['vip']['protocol'].lower()
        if protocol == 'tcp':
            protocol = 'client_first'
        running = config['vip']['admin_state_up']

        data = {
            'properties': {
                'aptimizer': {
                    'enabled': False,
                    'profile': []
                },
                'basic': {
                    'add_cluster_ip': True,
                    'add_x_forwarded_for': True,
                    'add_x_forwarded_proto': True,
                    'bandwidth_class': '',
                    'connect_timeout': 10,
                    'enabled': running,
                    'ftp_force_server_secure': True,
                    'glb_services': [],
                    'listen_on_any': False,
                    'listen_on_hosts': [],
                    'listen_on_traffic_ips': [config['vip']['id']],
                    'note': vserver_name,
                    'pool': config['pool']['id'],
                    'port': config['vip']['protocol_port'],
                    'protection_class': '',
                    'protocol': protocol,
                    'request_rules': [],
                    'response_rules': [],
                    'slm_class': '',
                    'so_nagle': False,
                    'ssl_client_cert_headers': 'none',
                    'ssl_decrypt': False
                },
                'connection': {
                    'keepalive': True,
                    'keepalive_timeout': 10,
                    'max_client_buffer': 65536,
                    'max_server_buffer': 65536,
                    'server_first_banner': '',
                    'timeout': 40,
                },
                'connection_errors': {
                    'error_file': 'Default'
                },
                'cookie': {
                    'domain': 'no_rewrite',
                    'new_domain': '',
                    'path_regex': '',
                    'path_replace': '',
                    'secure': 'no_modify'
                },
                'ftp': {
                    'data_source_port': 0,
                    'force_client_secure': True,
                    'port_range_high': 0,
                    'port_range_low': 0,
                    'ssl_data': True
                },
                'gzip': {
                    'compress_level': 1,
                    'enabled': False,
                    'include_mime': [
                        'text/html',
                        'text/plain'
                    ],
                    'max_size': 10000000,
                    'min_size': 1000,
                    'no_size': True
                },
                'http': {
                    'chunk_overhead_forwarding': 'lazy',
                    'location_regex': '',
                    'location_replace': '',
                    'location_rewrite': 'if_host_matches',
                    'mime_default': 'text/plain',
                    'mime_detect': False
                },
                'log': {
                    'client_connection_failures': False,
                    'enabled': False,
                    'filename': '%zeushome%/zxtm/log/%v.log',
                    'format': '%h %l %u %t \'%r\' %s %b \
                              \'%{Referer}i\' \'%{User-agent}i\'',
                    'server_connection_failures': False,
                    'ssl_failures': False
                },
                'request_tracing': {
                    'enabled': False,
                    'trace_io': False
                },
                'rtsp': {
                    'streaming_port_range_high': 0,
                    'streaming_port_range_low': 0,
                    'streaming_timeout': 30
                },
                'sip': {
                    'dangerous_requests': 'node',
                    'follow_route': True,
                    'max_connection_mem': 65536,
                    'mode': 'sip_gateway',
                    'rewrite_uri': False,
                    'streaming_port_range_high': 0,
                    'streaming_port_range_low': 0,
                    'streaming_timeout': 60,
                    'timeout_messages': True,
                    'transaction_timeout': 30
                },
                'smtp': {
                    'expect_starttls': True
                },
                'ssl': {
                    'add_http_headers': False,
                    'client_cert_cas': [],
                    'issued_certs_never_expire': [],
                    'ocsp_enable': False,
                    'ocsp_issuers': [],
                    'ocsp_max_response_age': 0,
                    'ocsp_time_tolerance': 30,
                    'ocsp_timeout': 10,
                    'prefer_sslv3': False,
                    'request_client_cert': 'dont_request',
                    'send_close_alerts': False,
                    'server_cert_default': '',
                    'server_cert_host_mapping': [],
                    'trust_magic': False
                },
                'syslog': {
                    'enabled': False,
                    'format': '%h %l %u %t \'%r\' %s %b \
                              \'%{Referer}i\' \'%{User-agent}i\'',
                    'ip_end_point': ''
                },
                'tcp': {
                    'proxy_close': False
                },
                'udp': {
                    'end_point_persistence': True,
                    'port_smp': False,
                    'response_datagrams_expected': 1,
                    'timeout': 7
                },
                'web_cache': {
                    'control_out': '',
                    'enabled': False,
                    'error_page_time': 30,
                    'max_time': 600,
                    'refresh_time': 2
                }
            }
        }

        self.put_connection(config['pool']['id'], req_string, data)

    @log.log
    def create_monitor(self, config):
        for monitor in config['healthmonitors']:
            req_string = 'monitors/' + monitor['id']
            monitor_type = str(monitor.get('type')).lower()
            if monitor_type == 'tcp':
                monitor_type = 'connect'
            url_path = str(monitor.get('url_path') or '/')

            http = {
                'authentication': '',
                'body_regex': '',
                'host_header': '',
                'path': url_path,
                'status_regex': ''
            }
            rtsp = {
                'body_regex': '',
                'path': '/',
                'status_regex': '^[234][0-9][0-9]$'
            }
            script = {
                'arguments': [],
                'program': ''
            }
            sip = {
                'body_regex': '',
                'status_regex': '^[234][0-9][0-9]$',
                'transport': 'udp'
            }
            tcp = {
                'close_string': '',
                'max_response_len': 2048,
                'response_regex': '.+',
                'write_string': ''
            }
            udp = {
                'accept_all': False
            }

            if monitor_type == 'http':
                http['status_regex'] = monitor['expected_codes']

            data = {
                'properties': {
                    'basic': {
                        'back_off': True,
                        'delay': monitor['delay'],
                        'failures': monitor['max_retries'],
                        'machine': '',
                        'note': 'Monitor for ' + config['pool']['id'],
                        'scope': 'pernode',
                        'timeout': monitor['timeout'],
                        'type': monitor_type,
                        'use_ssl': False,
                        'verbose': False,
                    },
                    'http': http,
                    'rtsp': rtsp,
                    'script': script,
                    'sip': sip,
                    'udp': udp,
                    'tcp': tcp,
                }
            }
            self.put_connection(config['pool']['id'], req_string, data)

    @log.log
    def create_vip(self, config):
        # Traffic IP Group known as 'flipper' in API v1
        if self._get_api_version()[0] > 1:
            req_string = 'traffic_ip_groups/' + config['vip']['id']
        else:
            req_string = 'flipper/' + config['vip']['id']

        vip_name = config['vip'].get('name', config['vip']['id'])
        data = {
            'properties': {
                'basic': {
                    'enabled': True,
                    'hash_source_port': False,
                    'ip_mapping': [],
                    'ipaddresses': [config['vip']['address']],
                    'keeptogether': False,
                    'location': 0,
                    'machines': self.devices,
                    'mode': 'singlehosted',
                    'multicast': '',
                    'note': vip_name,
                    'slaves': []
                }
            }
        }

        self.put_connection(config['pool']['id'], req_string, data)

    @log.log
    def create(self, logical_config):
        if logical_config['healthmonitors']:
            self.create_monitor(logical_config)
        if 'vip' in logical_config:
            self.create_vip(logical_config)
        self.create_pool(logical_config)
        if 'vip' in logical_config:
            self.create_vserver(logical_config)

    @log.log
    def update(self, logical_config):
        # Update is same process as create
        return self.create(logical_config)

    @log.log
    def destroy_monitor(self, pool_id, monitor):
        req_string = 'monitors/' + monitor.monitor_id
        self.delete_connection(pool_id, req_string)

    @log.log
    def destroy_vip(self, vip):
        # Traffic IP Group known as 'flipper' in API v1
        if self._get_api_version()[0] > 1:
            req_string = 'traffic_ip_groups/' + vip['id']
        else:
            req_string = 'flipper/' + vip['id']
        self.delete_connection(vip['pool_id'], req_string)

    @log.log
    def destroy_pool(self, pool):
        # Virtual Server known as 'vserver' in API v1
        if self._get_api_version()[0] > 1:
            req_string = 'virtual_servers/' + pool['id']
        else:
            req_string = 'vservers/' + pool['id']
        self.delete_connection(pool['id'], req_string)

        req_string = 'pools/' + pool['id']
        self.delete_connection(pool['id'], req_string)

        self.pools.pop(pool['id'], None)

    @log.log
    def exists(self, pool_id):
        response = self.get_connection(pool_id, 'pools/' + pool_id)
        if response.status_code == 200:
            return True
        if response.status_code == 404:
            return False

        resp = json.loads(response.content)
        raise n_exc.Invalid(_('Invalid return from Stingray (%d): %s' %
                              (response.status_code, resp)))

    @log.log
    def _list_pools(self):
        for url in self.urls:
            try:
                response = self._get_client().get(url + 'pools')
                resp = json.loads(response.content)
                return [p.get('name') for p in resp['children']]
            except requests.exceptions.ConnectionError:
                pass

    @log.log
    def remove_orphans(self, known_pool_ids):
        pools = _list_pools()
        if not pools:
            return

        orphans = (pool_id for pool_id in pools
                   if pool_id not in known_pool_ids)
        for pool_id in orphans:
            if self.exists(pool_id):
                LOG.debug("Removing orphan pool: %s" % pool_id)
                self.destroy_pool(pool_id)

    def _oid_for_pool(self, pool_id):
        if self.pools.get(pool_id):
            return self.pools[pool_id]
        for stm in self.devices:
            getter = SNMPGetter(stm, self.community)
            pool_data = getter.getnext_oid_data('1.3.6.1.4.1.7146.1.2.2.2.1.1')
            for pool in pool_data:
                if pool[0][1] == pool_id:
                    self.pools[pool_id] = list(pool[0][0])
                    return self.pools[pool_id]
        return None

    @log.log
    def get_stats(self, pool_id):

        ret = {'bytes_in': 0,
               'bytes_out': 0,
               'active_connections': 0,
               'total_connections': 0}

        oid = self._oid_for_pool(pool_id)
        if oid is not None:
            for stm in self.devices:
                getter = SNMPGetter(stm, self.community)
                oid[12] = 9
                ret['active_connections'] += \
                    int(getter.get_oid_data(tuple(oid))[0][1])
                oid[12] = 11
                ret['total_connections'] += \
                    int(getter.get_oid_data(tuple(oid))[0][1])
                oid[12] = 31
                ret['bytes_in'] += \
                    int(getter.get_oid_data(tuple(oid))[0][1])
                oid[12] = 32
                ret['bytes_out'] += \
                    int(getter.get_oid_data(tuple(oid))[0][1])
            if ret['bytes_in'] > 0:
                return ret


class SNMPGetter(object):
    """Custom SNMP Getter class to simplify SNMP get/getnext calls"""
    def __init__(self, ip, community):
        self.ip = ip
        self.generator = cmdgen.CommandGenerator()
        # First argument is arbitrary string
        # Second argument is the actual community string
        # Final argument magic number 1 means version SNMP v2c
        self.comm_data = cmdgen.CommunityData('lbaas', community, 1)
        # Take (host, port) tuple
        self.transport = cmdgen.UdpTransportTarget((self.ip, 161))

    def _mib2tuple(self, mib):
        # pysnmp does not want "'.1.3.6.1.4.1.789.1.2.1.8.0'"
        # it wants (1, 3, 6, 1, 4, 1, 789, 1, 2, 1, 8, 0)
        # No, I don't know why
        if isinstance(mib, str):
            mib = tuple(int(x) for x in mib.lstrip('.').split('.'))
        return mib

    def get_data(self, func, orig_mib):
        mib = self._mib2tuple(orig_mib)
        res = (errorIndication, errorStatus, errorIndex, varBinds)\
            = func(self.comm_data, self.transport, mib)

        if errorIndication is not None or errorStatus is True:
            LOG.debug("%s %s: %s" % (self.ip, orig_mib, errorIndication))
            return None
        else:
            return varBinds

    def getnext_oid_data(self, mib):
        func = self.generator.nextCmd
        # GetNext calls need to return an array of arrays of lists
        return self.get_data(func, mib) or [[(mib, 0)]]

    def get_oid_data(self, mib):
        func = self.generator.getCmd
        # Get calls need to return an array of lists
        return self.get_data(func, mib) or [(mib, 0)]
