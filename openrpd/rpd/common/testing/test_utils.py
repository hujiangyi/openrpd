#
# Copyright (c) 2016 Cisco and/or its affiliates, and
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

import unittest
import os
from rpd.common.utils import Convert, Print, SysTools
from rpd.common.rpdinfo_utils import RpdInfoUtils
from rpd.common.ipc_gpb_utils import PathConverter, PathBuilder, PathDirector
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_Path
from rpd.gpb.rcp_pb2 import t_RcpMessage


class TestUtils(unittest.TestCase):

    @Print.test_markers
    def test_IP_positive(self):
        ip4_str = "1.2.3.4"
        ip4_tuple = (0x1, 0x2, 0x3, 0x4)
        self.assertEqual(Convert.ipaddr_to_tuple_of_bytes(ip4_str), ip4_tuple)

        ip6_str = '1111::2222'
        ip6_tuple = (0x11, 0x11, 0x0, 0x0,
                     0x0, 0x0, 0x0, 0x0,
                     0x0, 0x0, 0x0, 0x0,
                     0x0, 0x0, 0x22, 0x22)
        self.assertEqual(Convert.ipaddr_to_tuple_of_bytes(ip6_str), ip6_tuple)

        ip6_str = '::'
        ip6_tuple = (0x0, 0x0, 0x0, 0x0,
                     0x0, 0x0, 0x0, 0x0,
                     0x0, 0x0, 0x0, 0x0,
                     0x0, 0x0, 0x0, 0x0)
        self.assertEqual(Convert.ipaddr_to_tuple_of_bytes(ip6_str), ip6_tuple)

    @Print.test_markers
    def test_IP_negative(self):

        self.assertIsNone(Convert.ipaddr_to_tuple_of_bytes(1))
        self.assertIsNone(Convert.ipaddr_to_tuple_of_bytes("1.2.3.4.5"))
        self.assertIsNone(Convert.ipaddr_to_tuple_of_bytes(""))
        self.assertIsNone(Convert.ipaddr_to_tuple_of_bytes("1.2.3..4"))
        self.assertIsNone(Convert.ipaddr_to_tuple_of_bytes("1.2.256.4"))
        self.assertIsNone(Convert.ipaddr_to_tuple_of_bytes(":::"))

    @Print.test_markers
    def test_MAC_positive(self):
        mac_str = "01:02:03:04:05:06"
        mac_tuple = (1, 2, 3, 4, 5, 6)
        self.assertEqual(Convert.mac_to_tuple_of_bytes(mac_str), mac_tuple)

    @Print.test_markers
    def test_MAC_negative(self):
        self.assertIsNone(Convert.mac_to_tuple_of_bytes(1))
        self.assertIsNone(Convert.mac_to_tuple_of_bytes(""))
        self.assertIsNone(Convert.mac_to_tuple_of_bytes("11:"))
        self.assertIsNone(Convert.mac_to_tuple_of_bytes("01:02:03:04:05"))
        self.assertIsNone(Convert.mac_to_tuple_of_bytes("GG:02:03:04:05:06"))
        self.assertIsNone(Convert.mac_to_tuple_of_bytes("125:02:03:04:05"))

    @Print.test_markers
    def test_type_checkers(self):
        # is_valid_ipv4_address
        self.assertTrue(Convert.is_valid_ipv4_address('192.168.16.2'))
        self.assertTrue(Convert.is_valid_ipv4_address('255.255.255.255'))
        self.assertFalse(Convert.is_valid_ipv4_address('192.168.16.'))
        self.assertFalse(Convert.is_valid_ipv4_address('.168.16.48'))
        self.assertFalse(Convert.is_valid_ipv4_address('test'))
        self.assertFalse(Convert.is_valid_ipv4_address('5'))
        self.assertFalse(Convert.is_valid_ipv4_address('1.1.1.1,2.2.2.2'))
        # is_valid_ipv6_address
        self.assertFalse(Convert.is_valid_ipv6_address('192.168.16.2'))
        self.assertTrue(Convert.is_valid_ipv6_address('::'))
        self.assertTrue(Convert.is_valid_ipv6_address('1::'))
        self.assertTrue(Convert.is_valid_ipv6_address('1::5'))
        self.assertTrue(Convert.is_valid_ipv6_address('1::5:5'))
        self.assertFalse(Convert.is_valid_ipv6_address('myhost.com'))
        self.assertFalse(Convert.is_valid_ipv6_address('test'))
        # is_valid_ip_address
        self.assertTrue(Convert.is_valid_ip_address('192.168.16.2'))
        self.assertTrue(Convert.is_valid_ip_address('1::5'))
        self.assertFalse(Convert.is_valid_ip_address('myhost.com'))
        # is_int_value
        self.assertTrue(Convert.is_int_value('-1'))
        self.assertTrue(Convert.is_int_value('0'))
        self.assertTrue(Convert.is_int_value('5000'))
        self.assertTrue(Convert.is_int_value('5000000000'))
        self.assertFalse(Convert.is_int_value('test'))
        self.assertFalse(Convert.is_int_value('5.5'))
        self.assertFalse(Convert.is_int_value('5,5'))

    def test_bytes_convert(self):
        illegal_var = '01:02:03:192.168.0.1:0a:0b:'
        try:
            Convert.bytes_to_mac_str(illegal_var)
        except TypeError:
            pass
        else:
            self.fail('illegal mac been converted')

        try:
            Convert.bytes_to_ipv4_str(illegal_var)
        except TypeError:
            pass
        else:
            self.fail('illegal ipv4 been converted')

        try:
            Convert.bytes_to_ipv6_str(illegal_var)
        except TypeError:
            pass
        else:
            self.fail('illegal ipv6 been converted')

        try:
            Convert.bytes_to_ip_addr(illegal_var)
        except TypeError:
            pass
        else:
            self.fail('illegal ip been converted')

        # try:
        ret = Convert.mac_to_tuple_of_bytes('-1:-2:-3:-4:-5')
        # except ValueError:
        #    pass
        # else:
        #    self.fail('illegal mac been converted: %s' % ret)
        self.assertIsNone(ret, 'illegal mac been converted: %s' % ret)

        self.assertFalse(Convert.is_valid_ipv4_address('a.b.c.d'))

    def test_sys_tools(self):
        SysTools.touch('/tmp/test_utils')
        SysTools.REBOOT_SKIP_FILES = ('/tmp/test_utils')

        self.assertFalse(SysTools.is_system_openwrt())
        self.assertEqual(SysTools.get_mac_address('if_test'), "00:00:00:00:00:00")
        self.assertEqual(SysTools.get_sys_mac_address(), "00:00:00:00:00:00")

        with open('/tmp/test_mac', 'w') as f:
            f.write('01:02:03:04:05:06')
            f.close()
        SysTools.SYS_MAC_FILE = '/tmp/test_mac'
        self.assertEqual(SysTools.get_sys_mac_address(), "01:02:03:04:05:06")
        SysTools.SYS_MAC_FILE = '/etc/gshadow'
        self.assertEqual(SysTools.get_sys_mac_address(), "00:00:00:00:00:00")

        print(SysTools.get_host_name())
        print(SysTools.get_ip_address('if_test'))
        if not SysTools.reboot():
            SysTools.sys_failure_reboot('skip files exist')
        SysTools.external_reboot(('test', 'test'))
        if os.path.exists('/tmp/test_utils'):
            os.remove('/tmp/test_utils')

        # d = Dispatcher()
        # timestamp = time.time() + 1000
        # SysTools.set_system_time(d, timestamp)
        # SysTools.touch('/etc/openwrt_release')
        # SysTools.set_system_time(d, timestamp)
        # time.sleep(2)
        # self.assertTrue(timestamp > time.time()) #should no permission to change system time
        # del d
        # if os.path.exists('/etc/openwrt_release'):
        #     os.remove('/etc/openwrt_release')
        self.assertIsNotNone(SysTools.sys_up_time())
        ret = SysTools.if_indextoname(1)
        print "ifname of index 1:", ret
        self.assertIsNotNone(ret)
        ret = SysTools.if_indextoname("test")
        self.assertIsNone(ret)
        ret = SysTools.if_indextoname(600)
        self.assertIsNone(ret)

        ret = SysTools.if_nametoindex("lo")
        print "ifindex of lo:", ret
        self.assertIsNotNone(ret)
        ret = SysTools.if_nametoindex(5)
        self.assertIsNone(ret)
        ret = SysTools.if_nametoindex("dafsd")
        self.assertIsNone(ret)
        ret = SysTools.is_if_oper_up('eth0')
        self.assertTrue(ret)

    def test_compip(self):
        ret = Convert.compare_ip("10.79.41.31", "10.79.41.31")
        self.assertEquals(ret, 0)
        ret = Convert.compare_ip("10.79.41.30", "10.79.41.31")
        self.assertEquals(ret, -1)
        ret = Convert.compare_ip("10.79.41.30", "10.25.41.31")
        self.assertEquals(ret, 1)
        ret = Convert.compare_ip("fe80::6a5b:35ff:feb2:8dcf", "fe80::6a5b:35ff:feb2:8d6f")
        self.assertEquals(ret, 1)

    def test_rpdinfo_utils(self):
        ipaddr = {
            'addrtype': RpdInfoUtils.INETADDRESSTYPE_IPV4,
            'ip': '60.10.10.3',
            'mask': 64,
            'status': RpdInfoUtils.IPADDR_STATUS_1_PREFERRED,
            'origin': RpdInfoUtils.IPADDR_ORIGIN_4_DHCP,
        }
        rsp = t_RcpMessage()
        ipaddr_info = rsp.RpdDataMessage.RpdData.RpdInfo.IpAddress.add()
        RpdInfoUtils.set_ipaddr_info(ipaddr, ipaddr_info)
        self.assertEqual(RpdInfoUtils.ip_exchange_mask('255.0.0.0'), 8)
        self.assertEqual(RpdInfoUtils.ip_exchange_mask('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), 128)
        self.assertEqual(RpdInfoUtils.convert_ipv6('fe80::204:9fff:fe31:231%vbh0'), 'fe80::204:9fff:fe31:231')
        self.assertEqual(RpdInfoUtils.get_ipv6_arp_retransmit_time('vbh0'), 1000)
        self.assertEqual(RpdInfoUtils.get_ipv6_arp_retransmit_time('eth0'), 1000)
        self.assertEqual(RpdInfoUtils.get_ipv6_arp_reachable_time('vbh0'), 30000)
        self.assertEqual(RpdInfoUtils.get_ipv6_arp_reachable_time('eth0'), 30000)
        print(RpdInfoUtils.get_ipaddr_info())
        self.assertEqual(RpdInfoUtils.read_ipv6_scope('vbh0', 'ip'), 11)


class TestIPC_GPB_Utils(unittest.TestCase):

    def test_path(self):
        path_cfg_eth1 = "cfg.interface.ethernet.vlan1".split('.')
        path_cfg_eth2 = "cfg.interface.ethernet.vlan2".split('.')
        path_cfg_wlan1 = "cfg.interface.wlan.vlan1".split('.')
        path_cfg_wlan2 = "cfg.interface.wlan.vlan2".split('.')

        fake_path = t_Path()
        fake_path.Name = ''

        pDir = PathDirector()
        default_gpb_path = pDir.get_cfg_path(fake_path)
        self.assertIsNotNone(default_gpb_path)
        gpb_path = pDir.get_cfg_path(t_Path())
        self.assertIsNotNone(gpb_path)
        path_dict = {'ssd': None}
        gpb_dict_path = pDir.get_cfg_path(t_Path(), path_dict)
        self.assertIsNotNone(gpb_dict_path)
        oper_path = pDir.get_oper_path(t_Path())
        self.assertIsNotNone(oper_path)
        cap_path = pDir.get_rpd_capabilities_path(t_Path())
        self.assertIsNotNone(cap_path)

        pbuilder = PathBuilder()

        pbuilder.set_root(t_Path())
        pbuilder.add_subpath_sequence(path_cfg_eth1)
        pbuilder.add_subpath_sequence(path_cfg_eth2)
        path_gpb_eth = pbuilder.get_result()
        self.assertIsNotNone(path_gpb_eth)

        path_dict_eth = PathConverter.path_gpb_to_dict(path_gpb_eth)
        self.assertIsNotNone(path_dict_eth)

        pbuilder.set_root(t_Path())
        pbuilder.add_subpath_sequence(path_cfg_wlan1)
        pbuilder.add_subpath_sequence(path_cfg_wlan2)
        path_gpb_wlan = pbuilder.get_result()
        self.assertIsNotNone(path_gpb_wlan)

        path_dict_wlan = PathConverter.path_gpb_to_dict(path_gpb_wlan)
        self.assertIsNotNone(path_dict_wlan)

        pbuilder.set_root(t_Path())
        try:
            pbuilder.add_subpath_dict(None)
        except AttributeError:
            pass
        else:
            self.fail('should block None path dict')
        pbuilder.add_subpath_dict(path_dict_eth)
        pbuilder.add_subpath_dict(path_dict_wlan)
        path_gpb_all = pbuilder.get_result()
        self.assertIsNotNone(path_gpb_all)

        path_list_lists = PathConverter.\
            path_gpb_to_list_of_lists(path_gpb_all)
        self.assertIsNotNone(path_list_lists)

        path_dict_all = PathConverter.path_gpb_to_dict(path_gpb_all)
        self.assertIsNotNone(path_dict_all)

        path_dict_to_gpb = PathConverter.path_dict_to_gpb(path_dict_all,
                                                          t_Path())
        self.assertIsNotNone(path_dict_to_gpb)

        path_list_to_gpb = PathConverter.path_sequence_to_gpb(path_cfg_wlan1,
                                                              t_Path())
        self.assertIsNotNone(path_list_to_gpb)

        path_gpb_all_str = path_gpb_all.SerializeToString()
        _path_gpb_all = PathConverter.path_dict_to_gpb(path_dict_all,
                                                       t_Path())
        path_dict_all_str = _path_gpb_all.SerializeToString()
        _path_dict_all = PathConverter.path_gpb_to_dict(path_gpb_all)

        self.assertEqual(path_gpb_all_str, path_dict_all_str,
                         "Serialized GPBs are not equal")
        self.assertEqual(path_dict_all, _path_dict_all,
                         "Converted dictionary is different")

        _path_list = PathConverter.\
            path_gpb_to_list_of_lists(path_list_to_gpb)[0]
        self.assertEqual(path_cfg_wlan1, _path_list,
                         "Path lists are not equal")


class TestRpdLog(unittest.TestCase):

    __metaclass__ = AddLoggerToClass

    def test_rSysLog(self):
        # rsyslog = RSyslog()
        # config no remote syslog server
        # rsyslog.config_rsyslog('10.79.41.148')
        # log_level = {'error':3}
        # rsyslog.config_rsyslog_loglevel(3)
        # self.assertEqual(rsyslog.rsyslog_loglevel, 'error', 'loglevel setting failed')
        pass

    def test_rpd_logging(self):
        # os.system('export LOG_PATH=/tmp/log_test')
        os.environ['LOG_PATH'] = '/tmp/log_test'
        self.logger.critical(os.getenv('LOG_PATH'))
        setup_logging("HAL", filename="test.log", env_key='LOG_PATH')
        if os.path.exists('/tmp/log_test'):
            os.remove('/tmp/log_test')

    def test_logmem(self):
        ret = True
        try:
            SysTools.logmem("dummy tag")
            SysTools.logmem("")
            SysTools.logmem(1)
            SysTools.logmem(None)
        except Exception:
            ret = False
        self.assertTrue(ret)


if __name__ == "__main__":
    unittest.main()
