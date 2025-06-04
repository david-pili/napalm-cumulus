# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Cumulus.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime

import napalm.base.constants as C
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    MergeConfigException,
)
from napalm.base.utils import string_parsers
from netmiko import ConnectHandler
from netmiko.cli_tools.outputters import output_json

try:
    from netmiko.ssh_exception import NetMikoTimeoutException
except ModuleNotFoundError:
    from netmiko.exceptions import NetMikoTimeoutException
from pytz import timezone

from math import log10, floor

def find_exp(number) -> int:
    if number == 0:
        return 0
    base10 = log10(abs(number))
    return abs(floor(base10))

def parse_dbm(power_str: str) -> float:
    """
    Extracts the dBm value from a string like "0.7433 mW / -1.29 dBm"
    """
    try:
        return float(power_str.split("/")[-1].strip().split()[0])
    except Exception:
        return 0.0  # Default fallback if the format is unexpected


def parse_current(current_str: str) -> float:
    """
    Extracts the current value from a string like "5.500 mA"
    """
    try:
        return float(current_str.strip().split()[0])
    except Exception:
        return 0.0


class CumulusDriver(NetworkDriver):
    """Napalm driver for Cumulus."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.force = False
        self.loaded = False
        self.changed = False
        self.has_sudo = False
        self.use_nvue = False

        if optional_args is None:
            optional_args = {}

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'secret': None,
            'allow_agent': False
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {
            k: optional_args.get(k, v)
            for k, v in netmiko_argument_map.items()
        }
        self.port = optional_args.get('port', 22)
        self.sudo_pwd = optional_args.get('sudo_pwd', self.password)
        self.retrieve_details = optional_args.get('retrieve_details', False)
        self.has_sudo = optional_args.get('has_sudo', False)
        self.force = optional_args.get('force', False)

    def open(self):
        try:
            self.device = ConnectHandler(device_type='linux',
                                         host=self.hostname,
                                         username=self.username,
                                         password=self.password,
                                         **self.netmiko_optional_args)
            # Enter root mode.
            if self.has_sudo and self.netmiko_optional_args.get('secret'):
                self.device.enable()
            if self.has_sudo:
                response = self.device.send_command_timing('sudo su')
                if '[sudo]' in response:
                    self.device.send_command_timing(self.sudo_pwd)
                    self.device.base_prompt = "#"
        except NetMikoTimeoutException:
            raise ConnectionException('Cannot connect to {}'.format(self.hostname))
        except ValueError:
            raise ConnectionException('Cannot become root.')
        build_output = self._send_command("nv show system")
        if "Cumulus Linux 5" in build_output:
            self.use_nvue = True

    def close(self):
        self.device.disconnect()

    def is_alive(self):
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def load_merge_candidate(self, filename=None, config=None):
        if not filename and not config:
            raise MergeConfigException('filename or config param must be provided.')

        self.loaded = True

        if filename is not None:
            with open(filename, 'r') as f:
                candidate = f.readlines()
        else:
            candidate = config

        if not isinstance(candidate, list):
            candidate = [candidate]

        candidate = [line for line in candidate if line]
        for command in candidate:
            if 'sudo' not in command:
                command = '{0}'.format(command)
            output = self._send_command(command)
            if "error" in output or "not found" in output:
                raise MergeConfigException("Command '{0}' cannot be applied.".format(command))

    def discard_config(self):
        if self.loaded:
            if self.use_nvue:
                self._send_command('nv config detach')
            else:
                self._send_command('net abort')
            self.loaded = False

    def compare_config(self):
        if self.loaded and self.use_nvue:
            return self._send_command('nv config diff --color off')
        elif self.loaded:
            full_diff = self._send_command('net pending')
            # ignore commands that matched the existing config
            trimmed_diff = full_diff.split("net add/del commands")[0].strip()
            if trimmed_diff != '':
                return re.sub(r'\x1b\[\d+m', '', full_diff)
        return ''

    def commit_config(self, message=""):
        if not self.loaded:
            return
        if self.use_nvue:
            response = self._send_command('nv config apply')
            if "[y/N]" in response:
                if self.force:
                    self._send_command('y')
                else:
                    self._send_command('n')
                    self.discard_config()
                    err_msg = response.split("Warning:")[1].split("Are you")[0].strip()
                    raise MergeConfigException(f"Config cannot be applied. { err_msg }")
        else:
            self._send_command('net commit')
        self.changed = True
        self.loaded = False

    def rollback(self):
        if self.changed:
            if self.use_nvue:
                history_output = self._send_command('nv config history |grep rev_id:')
                rev_history = history_output.splitlines()
                previous_rev = rev_history[1].split()[1].strip("'")
                self._send_command(f'nv config apply { previous_rev }')
            else:
                self._send_command('net rollback last')
            self.changed = False

    def _send_command(self, command):
        return self.device.send_command_timing(command)

    def get_facts(self):
        facts = {}
        command = 'nv show system -o json'
        try:
            system = json.loads(self._send_command(command))
        except ValueError:
            system = json.loads(self.device.send_command(command))
        # Get "net show system" output.
        command = 'decode-syseeprom -j'
        try:
            eeprom = json.loads(self._send_command(command))
        except ValueError:
            eeprom = json.loads(self.device.send_command(command))
        interfaces = self._send_command('nv show interface -o json')
        # Handling bad send_command_timing return output.
        try:
            interfaces = json.loads(interfaces)
        except ValueError:
            interfaces = json.loads(self.device.send_command('nv show interface -o json'))

        facts['hostname'] = facts['fqdn'] = system.get('hostname')
        facts['os_version'] = system.get('build')
        facts['vendor'] = eeprom.get('tlv').get('Manufacturer').get('value')
        facts['model'] = eeprom.get('tlv').get('Product Name').get('value')
        facts['uptime'] = system.get('uptime')
        facts['serial_number'] = eeprom.get('tlv').get('Serial Number').get('value')
        facts['interface_list'] = string_parsers.sorted_nicely(interfaces.keys())
        return facts

    def get_arp_table(self):

        """
        'show arp' output example:
        Address                  HWtype  HWaddress           Flags Mask            Iface
        10.129.2.254             ether   00:50:56:97:af:b1   C                     eth0
        192.168.1.134                    (incomplete)                              eth1
        192.168.1.1              ether   00:50:56:ba:26:7f   C                     eth1
        10.129.2.97              ether   00:50:56:9f:64:09   C                     eth0
        192.168.1.3              ether   00:50:56:86:7b:06   C                     eth1
        """
        output = self.device.send_command('arp -n')
        output = output.split("\n")
        output = output[1:]
        arp_table = list()

        for line in output:
            line = line.split()
            if "incomplete" in line[1]:
                macaddr = "00:00:00:00:00:00"
            else:
                macaddr = line[2]

            arp_table.append(
                {
                    'interface': line[-1],
                    'mac': macaddr,
                    'ip': line[0],
                    'age': 0.0
                }
            )
        return arp_table

    def get_ntp_stats(self):
        """
        'ntpq -np' output example
             remote           refid      st t when poll reach   delay   offset  jitter
        ==============================================================================
         116.91.118.97   133.243.238.244  2 u   51   64  377    5.436  987971. 1694.82
         219.117.210.137 .GPS.            1 u   17   64  377   17.586  988068. 1652.00
         133.130.120.204 133.243.238.164  2 u   46   64  377    7.717  987996. 1669.77
        """

        output = self.device.send_command("ntpq -np")
        output = output.split("\n")[2:]
        ntp_stats = list()

        for ntp_info in output:
            if len(ntp_info) > 0:
                remote, refid, st, t, when, hostpoll, reachability, delay, offset, \
                jitter = ntp_info.split()

                # 'remote' contains '*' if the machine synchronized with NTP server
                synchronized = "*" in remote

                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', remote)
                ip = match.group(1)

                when = when if when != '-' else 0

                ntp_stats.append({
                    "remote": ip,
                    "referenceid": refid,
                    "synchronized": bool(synchronized),
                    "stratum": int(st),
                    "type": t,
                    "when": when,
                    "hostpoll": int(hostpoll),
                    "reachability": int(reachability),
                    "delay": float(delay),
                    "offset": float(offset),
                    "jitter": float(jitter)
                })

        return ntp_stats

    def get_vlans(self):
        """Cumulus get_vlans."""
        command = 'nv show bridge port-vlan -o json'
        try:
            vlan_details = json.loads(self._send_command(command))
        except ValueError:
            vlan_details = json.loads(self.device.send_command(command))
        final_vlans = {}
        for domain_data in vlan_details["domain"].values():
            for port_name, port_data in domain_data.get("port", {}).items():
                for vlan_id_str in port_data.get("vlan", {}):
                    vlan_id = int(vlan_id_str)
                    if vlan_id not in final_vlans:
                        final_vlans[vlan_id] = {
                            "name": f"vlan{vlan_id}",
                            "interfaces": []
                        }
                    final_vlans[vlan_id]["interfaces"].append(port_name)

        return final_vlans

    def ping(self,
             destination,
             source=C.PING_SOURCE,
             ttl=C.PING_TTL,
             timeout=C.PING_TIMEOUT,
             size=C.PING_SIZE,
             count=C.PING_COUNT,
             vrf=C.PING_VRF,
             source_interface=C.PING_SOURCE_INTERFACE):

        deadline = timeout * count

        command = "ping %s " % destination
        command += "-t %d " % int(ttl)
        command += "-w %d " % int(deadline)
        command += "-s %d " % int(size)
        command += "-c %d " % int(count)
        if source != "":
            command += "interface %s " % source

        ping_result = dict()
        output_ping = self.device.send_command(command)

        if "Unknown host" in output_ping:
            err = "Unknown host"
        else:
            err = ""

        if err != "":
            ping_result["error"] = err
        else:
            # 'packet_info' example:
            # ['5', 'packets', 'transmitted,' '5', 'received,' '0%', 'packet',
            # 'loss,', 'time', '3997ms']
            packet_info = output_ping.split("\n")

            if ('transmitted' in packet_info[-2]):
                packet_info = packet_info[-2]
            else:
                packet_info = packet_info[-3]

            packet_info = [x.strip() for x in packet_info.split()]

            sent = int(packet_info[0])
            received = int(packet_info[3])
            lost = sent - received

            # 'rtt_info' example:
            # ["0.307/0.396/0.480/0.061"]
            rtt_info = output_ping.split("\n")

            if len(rtt_info[-1]) > 0:
                rtt_info = rtt_info[-1]
            else:
                rtt_info = rtt_info[-2]

            match = re.search(r"([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", rtt_info)

            if match is not None:
                rtt_min = float(match.group(1))
                rtt_avg = float(match.group(2))
                rtt_max = float(match.group(3))
                rtt_stddev = float(match.group(4))
            else:
                rtt_min = None
                rtt_avg = None
                rtt_max = None
                rtt_stddev = None

            ping_responses = list()
            response_info = output_ping.split("\n")

            for res in response_info:
                match_res = re.search(r"from\s([\d\.]+).*time=([\d\.]+)", res)
                if match_res is not None:
                    ping_responses.append(
                        {
                            "ip_address": match_res.group(1),
                            "rtt": float(match_res.group(2))
                        }
                    )

            ping_result["success"] = dict()

            ping_result["success"] = {
                "probes_sent": sent,
                "packet_loss": lost,
                "rtt_min": rtt_min,
                "rtt_max": rtt_max,
                "rtt_avg": rtt_avg,
                "rtt_stddev": rtt_stddev,
                "results": ping_responses
            }

            return ping_result

    def _get_interface_neighbors(self, lldp):
        neighbors = []
        for neighbor in lldp.get('neighbor').values():
            hostname = neighbor.get("chassis").get('system-name')
            port = neighbor.get('port').get('name')
            neighbors.append({
                'hostname': hostname,
                'port': port,
            })

        return neighbors
    def _get_interface_neighbors_detail(self,name, lldp):
        neighbors = []
        command = 'nv show interface {} -o json'.format(name)
        if_output = {}
        try:
            if_output = json.loads(self._send_command(command))
        except ValueError:
            if_output = json.loads(self.device.send_command(command))
        parent_interface = if_output.get('parent')
        for neighbor in lldp.get('neighbor').values():
            chassis = neighbor.get('chassis')
            port = neighbor.get('port')
            caps = []
            reported_caps = chassis.get('capability')
            if reported_caps:
                if 'is-bridge' in reported_caps.keys():
                    caps.append('bridge')
                if 'is-router' in reported_caps.keys():
                    caps.append('router')
            elem = {
                'parent_interface': parent_interface,
                'remote_chassis_id': chassis.get('chassis-id'),
                'remote_system_name': chassis.get('system-name'),
                'remote_port': port.get('name'),
                'remote_port_description': port.get('description'),
                'remote_system_description': chassis.get('system-description'),
                'remote_system_capab': caps,
                'remote_system_enable_capab': caps,
            }
            neighbors.append(elem)
        return neighbors

    def get_lldp_neighbors(self):
        """Cumulus get_lldp_neighbors."""
        lldp = {}
        command = 'nv show interface lldp -o json'

        try:
            lldp_output = json.loads(self._send_command(command))
        except ValueError:
            lldp_output = json.loads(self.device.send_command(command))

        for interface, neighbors in lldp_output.items():
            lldp_info = neighbors.get('lldp')
            if lldp_info:
                lldp[interface] = self._get_interface_neighbors(lldp_info)
        return lldp

    def get_lldp_neighbors_detail(self, interface=""):
        """Cumulus getlldp_neighbors_detail.
        :param interface:
        """
        lldp = {}
        command = 'nv show interface lldp-detail -o json'
        if interface:
            command = f'nv show interface {interface} lldp-detail -o json'
        try:
            lldp_output = json.loads(self._send_command(command))
        except ValueError:
            lldp_output = json.loads(self.device.send_command(command))


        for name,interface in lldp_output.items():
            lldp_info = interface.get('lldp')
            if lldp_info:
                lldp[name] = self._get_interface_neighbors_detail(name, lldp_info)

        return lldp

    def get_interfaces(self):
        interfaces = {}
        # Get 'net show interface all json' output.
        output = self._send_command('nv show interface mac -o json')
        output_desc = self._send_command('nv show interface description -o json')
        # Handling bad send_command_timing return output.
        try:
            output_json = json.loads(output)
        except ValueError:
            output_json = json.loads(self.device.send_command('nv show interface mac -o json'))
        try:
            desc_json = json.loads(output_desc)
        except ValueError:
            desc_json = json.loads(self._send_command('nv show interface description -o json'))
        for interface_name, interface_cu in output_json.items():
            interface = {}
            link = interface_cu.get('link')

            interface['is_enabled'] = link.get('admin-status') == 'up'
            interface['is_up'] = link.get('oper-status') == 'up'
            interface['description'] = desc_json.get(interface_name).get('link').get('description')
            speed = link.get('speed')
            if not speed:
                interface['speed'] = -1
            elif speed.endswith('G'):
                interface['speed'] = int(speed.rstrip('G')) * 1024
            else:
                interface['speed'] = int(speed[:-1])

            interface['mac_address'] = link.get('mac-address')
            interface['mtu'] = link.get('mtu')
            interface['last_flapped'] = -1
            interfaces[interface_name] = interface

        if not self.retrieve_details:
            return interfaces

        for interface_name in interfaces.keys():
            command = "vtysh -c 'show interface %s'" % interface_name
            quagga_show_int_output = self._send_command(command)
            # Get the link up and link down datetimes if available.
            for line in quagga_show_int_output.splitlines():
                if 'Link ups' in line:
                    if '(never)' in line.split()[4]:
                        last_flapped_1 = False
                    else:
                        last_flapped_1 = True
                        last_flapped_1_date = line.split()[4] + " " + line.split()[5]
                        last_flapped_1_date = datetime.strptime(
                            last_flapped_1_date, "%Y/%m/%d %H:%M:%S.%f")
                if 'Link downs' in line:
                    if '(never)' in line.split()[4]:
                        last_flapped_2 = False
                    else:
                        last_flapped_2 = True
                        last_flapped_2_date = line.split()[4] + " " + line.split()[5]
                        last_flapped_2_date = datetime.strptime(
                            last_flapped_2_date, "%Y/%m/%d %H:%M:%S.%f")
            # Compare the link up and link down datetimes to determine the most recent and
            # set that as the last flapped after converting to seconds.
            if last_flapped_1 and last_flapped_2:
                last_delta = last_flapped_1_date - last_flapped_2_date
                if last_delta.days >= 0:
                    last_flapped = last_flapped_1_date
                else:
                    last_flapped = last_flapped_2_date
            elif last_flapped_1:
                last_flapped = last_flapped_1_date
            elif last_flapped_2:
                last_flapped = last_flapped_2_date
            else:
                last_flapped = -1

            if last_flapped != -1:
                # Get remote timezone.
                tmz = self.device.send_command('cat /etc/timezone')
                now_time = datetime.now(timezone(tmz))
                last_flapped = last_flapped.replace(tzinfo=timezone(tmz))
                last_flapped = (now_time - last_flapped).total_seconds()
            interfaces[interface_name]['last_flapped'] = float(last_flapped)
        return interfaces

    def get_interface_mode(self, interface_name):
        interfaces = {}
        # Get 'net show interface all json' output.
        output = self._send_command('nv show interface {} -o json'.format(interface_name))
        # Handling bad send_command_timing return output.
        try:
            output_json = json.loads(output)
        except ValueError:
            output_json = json.loads(self.device.send_command('nv show interface {} -o json'.format(interface_name)))
        return output_json['mode']. \
            lower(). \
            rstrip('/l2'). \
            rstrip('/l3')

    def get_interfaces_ip(self):
        # Get net show interface all json output.
        output = self._send_command('nv show interface -o json')
        # Handling bad send_command_timing return output.
        try:
            output_json = json.loads(output)
        except ValueError:
            output_json = json.loads(self.device.send_command('33'))

        def rec_dd():
            return defaultdict(rec_dd)

        interfaces_ip = rec_dd()

        for interface, values in output_json.items():
            for ip_address in values.get('ip').get('address'):
                ip_ver = ipaddress.ip_interface(ip_address).version
                ip_ver = 'ipv{}'.format(ip_ver)
                ip, prefix = ip_address.split('/')
                interfaces_ip[interface][ip_ver][ip] = {'prefix_length': int(prefix)}

        return interfaces_ip

    def get_environment(self):
        fans = {}
        temperature = {}
        power = {}
        cpu = {}
        power_output = self._send_command('nv show platform environment psu -o json')
        # Handling bad send_command_timing return output.
        try:
            power_json = json.loads(power_output)
        except ValueError:
            power_json = json.loads(self.device.send_command('nv show platform environment psu -o json'))
        for name,values in power_json.items():
            power[name] ={
                'status': values.get('state') == 'ok',
                'capacity': float(values.get('capacity')),
                'output': float(values.get('power'))

            }
        temp_output = self._send_command('nv show platform environment temperature -o json')
        # Handling bad send_command_timing return output.
        try:
            temp_json = json.loads(temp_output)
        except ValueError:
            temp_json = json.loads(self.device.send_command('nv show platform environment temperature -o json'))

        for name,values in temp_json.items():
            temper = float(values.get('current'))
            maximum = float(values.get('max'))
            crit = float(values.get('crit'))
            temperature[name] = {
                'temperature': temper,
                'is_alert': temper >= maximum,
                'is_critical': temper >= crit
            }
        fan_output = self._send_command('nv show platform environment fan -o json')
        # Handling bad send_command_timing return output.
        try:
            fan_json = json.loads(fan_output)
        except ValueError:
            fan_json = json.loads(self.device.send_command('nv show platform environment fan -o json'))
        for name,values in fan_json.items():
            fans[name] = {
                'sate': values.get('state') == 'ok'
            }
        cpu_output = self._send_command('nv show system cpu -o json')
        # Handling bad send_command_timing return output.
        try:
            cpu_json = json.loads(cpu_output)
        except ValueError:
            cpu_json = json.loads(self.device.send_command('nv show system cpu -o json'))

        cpu[cpu_json.get('model')] =  cpu_json.get('utilization')
        memory_output = self._send_command('nv show system memory -o json')
        # Handling bad send_command_timing return output.
        try:
            memory_json = json.loads(memory_output)
        except ValueError:
            memory_json = json.loads(self.device.send_command('nv show system memory -o json'))

        memory = {
            'available_ram': memory_json.get('Physical').get('total'),
            'used_ram': memory_json.get('Physical').get('used')
        }
        return {
            "fans": fans,
            "temperature": temperature,
            "power": power,
            "cpu": cpu,
            "memory": memory
        }

    def get_optics(self):
        command = 'nv show platform transceiver detail -o json'
        try:
            optics = json.loads(self._send_command(command))
        except ValueError:
            optics = json.loads(self.device.send_command(command))
        result = {}

        for intf_name, intf_data in optics.items():
            channels = []
            for ch_key, ch_data in intf_data.get("channel", {}).items():
                index = int(ch_key.replace("channel-", ""))
                rx_dbm = parse_dbm(ch_data["rx-power"]["power"])
                tx_dbm = parse_dbm(ch_data["tx-power"]["power"])
                bias = parse_current(ch_data["tx-bias-current"]["current"])

                channel = {
                    "index": index,
                    "state": {
                        "input_power": {
                            "instant": rx_dbm,
                            "avg": rx_dbm,
                            "min": rx_dbm,
                            "max": rx_dbm
                        },
                        "output_power": {
                            "instant": tx_dbm,
                            "avg": tx_dbm,
                            "min": tx_dbm,
                            "max": tx_dbm
                        },
                        "laser_bias_current": {
                            "instant": bias,
                            "avg": bias,
                            "min": bias,
                            "max": bias
                        }
                    }
                }
                channels.append(channel)

            result[intf_name] = {
                "physical_channels": {
                    "channel": channels
                }
            }

        return result

    def get_interfaces_phy_details(self):
        interfaces = self._send_command('nv show interface -o json')
        # Handling bad send_command_timing return output.
        try:
            interfaces = json.loads(interfaces)
        except ValueError:
            interfaces = json.loads(self.device.send_command('nv show interface -o json'))
        interface_list = string_parsers.sorted_nicely(interfaces.keys())

        results = {}
        for interface in interface_list:
            if 'swp' not in interface:
                continue
            command = f'nv show interface {interface} link phy-detail -o json'
            try:
                phy_detail = json.loads(self._send_command(command))
            except ValueError:
                phy_detail = json.loads(self.device.send_command(command))
            phy_detail['warning'] = False
            for k,v in phy_detail.items():
                if 'raw-ber' not in k:
                    continue
                if find_exp(float(v)) < 8:
                    phy_detail['warning'] = True
            phy_detail['alarm'] = phy_detail['effective-errors'] != 0
            print(interface)
            results[interface] = phy_detail
        return results