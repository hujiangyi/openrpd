#
# Copyright (c) 2018 Cisco and/or its affiliates, and
#                    Cable Television Laboratories, Inc. ("CableLabs")
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import socket
import psutil
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.gpb.RpdInfo_pb2 import t_RpdInfo
from rpd.common.utils import Convert
from rpd.rcp.rcp_lib.rcp_tlv_def import INETADDRESSTYPE_IPV4, INETADDRESSTYPE_IPV6


class RpdInfoUtils(object):

    __metaclass__ = AddLoggerToClass

    IPADDR_STATUS_1_PREFERRED = 1
    IPADDR_ORIGIN_1_OTHER = 1
    IPADDR_ORIGIN_4_DHCP = 4
    IPADDR_ORIGIN_5_ROUTERADV = 5
    INETADDRESSTYPE_IPV4 = INETADDRESSTYPE_IPV4[0]
    INETADDRESSTYPE_IPV6 = INETADDRESSTYPE_IPV6[0]

    """
     param ipaddr: tmp value store ipaddr info , get from system fun
     param ipaddr_info: 100.15 IpAddress rcp msg
    """
    @staticmethod
    def set_ipaddr_info(ipaddr, ipaddr_info):
        ipaddr_info.AddrType = ipaddr.get('addrtype', 0)
        ipaddr_info.IpAddress = ipaddr.get('ip', "0.0.0.0")
        ipaddr_info.EnetPortIndex = ipaddr.get('interface', 0)
        ipaddr_info.Type = t_RpdInfo.t_IpAddress.IPADDR_TYPE_1_UNICAST
        ipaddr_info.PrefixLen = ipaddr.get('mask', 0)
        ipaddr_info.Origin = ipaddr.get('origin', t_RpdInfo.t_IpAddress.IPADDR_ORIGIN_1_OTHER)
        ipaddr_info.Status = ipaddr.get('status', t_RpdInfo.t_IpAddress.IPADDR_STATUS_5_UNKNOWN)
        ipaddr_info.Created = ipaddr.get('changed', 0)
        ipaddr_info.LastChanged = ipaddr.get('lastchanged', 0)

    @staticmethod
    def ip_exchange_mask(mask):
        prefix = 0
        if not mask:
            return prefix
        else:
            if ':' in mask:  # ipv6
                for i in mask.split(':'):
                    if i != '':
                        prefix += bin(int(i, 16)).count('1')
                return prefix
            else:  # ipv4
                for i in mask.split('.'):
                    prefix += bin(int(i)).count('1')
            return prefix

    @staticmethod
    def convert_ipv6(addr):
        index = addr.find('%')
        if index > 0:
            tmp_ipv6 = repr(addr)
            addr = tmp_ipv6[1:index + 1]
        return addr

    @staticmethod
    def get_ipaddr_info():
        ipaddr_info_list = []
        if_ipaddr_dict = {}
        if_addrs = psutil.net_if_addrs()
        for ifname in if_addrs.keys():
            if_ipaddr_dict['interface'] = ifname
            for snic in if_addrs[ifname]:
                if snic.family == socket.AF_INET:
                    if_ipaddr_dict['addrtype'] = RpdInfoUtils.INETADDRESSTYPE_IPV4
                    if_ipaddr_dict['ip'] = snic.address
                    if_ipaddr_dict['mask'] = RpdInfoUtils.ip_exchange_mask(snic.netmask)
                    if_ipaddr_dict['status'] = RpdInfoUtils.IPADDR_STATUS_1_PREFERRED
                    if_ipaddr_dict['origin'] = RpdInfoUtils.IPADDR_ORIGIN_4_DHCP
                    ipaddr_info = if_ipaddr_dict.copy()
                    ipaddr_info_list.append(ipaddr_info)
                elif snic.family == socket.AF_INET6:
                    if_ipaddr_dict['addrtype'] = RpdInfoUtils.INETADDRESSTYPE_IPV6
                    if_ipaddr_dict['ip'] = RpdInfoUtils.convert_ipv6(snic.address)
                    if_ipaddr_dict['mask'] = RpdInfoUtils.ip_exchange_mask(snic.netmask)
                    if_ipaddr_dict['status'] = RpdInfoUtils.IPADDR_STATUS_1_PREFERRED
                    if_ipaddr_dict['scope'] = RpdInfoUtils.read_ipv6_scope(ifname, snic.address)
                    if if_ipaddr_dict['mask'] == 128 and if_ipaddr_dict['scope'] == 0:
                        if_ipaddr_dict['origin'] = RpdInfoUtils.IPADDR_ORIGIN_4_DHCP
                    elif if_ipaddr_dict['mask'] == 64 and if_ipaddr_dict['scope'] == 0:
                        if_ipaddr_dict['origin'] = RpdInfoUtils.IPADDR_ORIGIN_4_DHCP
                    else:
                        if_ipaddr_dict['origin'] = RpdInfoUtils.IPADDR_ORIGIN_1_OTHER
                    ipaddr_info = if_ipaddr_dict.copy()
                    ipaddr_info_list.append(ipaddr_info)
        return ipaddr_info_list

    @staticmethod
    def getSysUpTime():
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        uptime_seconds = int(uptime_seconds * 100) % (0xFFFFFFFF)
        return uptime_seconds

    @staticmethod
    def read_ipv6_scope(interface, ip):
        scope = 11  # unknown scope
        ipv6_info = open("/proc/net/if_inet6", "r").readlines()
        for info in ipv6_info:
            if interface in info:
                if_ip = Convert.format_proc_address(info.split(' ')[0])
                if if_ip == ip:
                    scope = int(info.split(' ')[3])
        return scope

    @staticmethod
    def get_ipv4_arp_retransmit_time(if_name):
        retrans_time_ms = 1000
        try:
            with open("/proc/sys/net/ipv4/neigh/" + str(if_name) + "/retrans_time_ms", "r") as f:
                retrans_time_ms = int(f.read().split()[0])
        except IOError:
            pass
        return retrans_time_ms

    @staticmethod
    def get_ipv6_arp_retransmit_time(interface):
        retrans_time_ms = 1000
        try:
            path = "/proc/sys/net/ipv6/neigh/" + str(interface)
            with open(path + "/retrans_time_ms", "r") as f:
                retrans_time_ms = int(f.read().split()[0])
        except IOError:
            pass
        return retrans_time_ms

    @staticmethod
    def get_ipv6_arp_reachable_time(interface):
        reachable_time_ms = 30000
        try:
            path = "/proc/sys/net/ipv6/neigh/" + str(interface)
            with open(path + "/base_reachable_time_ms", "r") as f:
                reachable_time_ms = int(f.read().split()[0])
        except IOError:
            pass
        return reachable_time_ms
