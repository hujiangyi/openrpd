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

import zmq
import socket
import fcntl
import struct
import platform
import time
import os
import psutil
import ctypes.util
from subprocess import call, check_output, CalledProcessError
from datetime import datetime
from struct import pack
import array
from os.path import exists
from binascii import hexlify
from functools import wraps
import ipaddress
from rpd.rcp.gcp.gcp_lib.gcp_data_description import DataDescription
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.rpd_event_def import RPD_EVENT_CONNECTIVITY_SYS_REBOOT, RPD_EVENT_CONNECTIVITY_REBOOT, \
    RPD_EVENT_CONNECTIVITY_DIAGNOSTIC_SELF_TEST_FAIL


class Convert(object):

    __metaclass__ = AddLoggerToClass

    @staticmethod
    def bytes_to_mac_str(buff):
        """Convert MAC address from binary to string.

        :param buff: 6 bytes long buffer
        :type buff: tuple
        :return: MAC address converted to string format separated by ':'
        :rtype: string

        """
        if len(buff) != DataDescription.B_SEQ_MAC_LEN:
            raise TypeError("Invalid input")
        return "%02X:%02X:%02X:%02X:%02X:%02X" % buff

    @staticmethod
    def bytes_to_ipv4_str(buff):
        """Convert IPv4 address from binary to string.

        :param buff: 4 bytes long buffer
        :type buff: tuple
        :return: IPv4 address converted to string format separated by '.'
        :rtype: string

        """
        if len(buff) != DataDescription.B_SEQ_IPv4_LEN:
            raise TypeError("Invalid input")
        return "%u.%u.%u.%u" % buff

    @staticmethod
    def bytes_to_ipv6_str(buff):
        """Convert IPv6 address from binary to string.

        :param buff: 16 bytes long buffer
        :type buff: tuple
        :return: IPv6 address converted to full (not using '::') string format
         separated by ':'
        :rtype: string

        """
        if len(buff) != DataDescription.B_SEQ_IPv6_LEN:
            raise TypeError("Invalid input")
        return "%02X%02X:%02X%02X:%02X%02X:%02X%02X:"\
               "%02X%02X:%02X%02X:%02X%02X:%02X%02X" % buff

    @staticmethod
    def bytes_to_ip_addr(buff):
        """Convert IP address (v4 or v6) from binary to string.

        :param buff: 4 or 16 bytes long buffer
        :type buff: tuple
        :return: IPv4 address converted to string format separated by '.' or
         IPv6 address converted to full (not using '::') string format
         separated by ':'
        :rtype: string

        """
        length = len(buff)
        if length == DataDescription.B_SEQ_IPv4_LEN:
            return Convert.bytes_to_ipv4_str(buff)
        elif length == DataDescription.B_SEQ_IPv6_LEN:
            return Convert.bytes_to_ipv6_str(buff)
        raise TypeError("Unexpected length of buffer")

    @staticmethod
    def ipaddr_to_tuple_of_bytes(value):
        """Convert IP address (v4 or v6) from string to binary format.

        :param string value: IP address to be converted For example:

         ipv4: 1.1.1.1, 255.255.255.255, 12.23.45.56

         ipv6: ::, 1::1, 1111::2222, ...
        :return: Converted value or None in case of any problems
        :rtype: None or tuple()

        """
        if not isinstance(value, basestring):
            Convert.logger.error(
                "Failed - expect string value '%s', received type '%s'",
                value, type(value))
            return None

        error_v4, error_v6 = '', ''

        # check IPv4
        try:
            new_value = tuple([int(item) for item in value.split('.')])
            if len(new_value) != DataDescription.B_SEQ_IPv4_LEN:
                Convert.logger.error(
                    "Failed, length error, string value is '{}', "
                    "length: '{}'".format(value, len(new_value)))
                raise ValueError('IPv4 invalid value')
        except Exception, error_v4:
            new_value = None  # could be IPv6

        # check IPv6
        if None is new_value:
            try:
                ipv6_str = hexlify(socket.inet_pton(socket.AF_INET6, value))
                new_value = tuple([int(ipv6_str[i:i + 2], 16)
                                   for i in range(0, len(ipv6_str), 2)])
            except Exception, error_v6:
                new_value = None  # neither IPv6

        if None is new_value:
            Convert.logger.warn(
                "Failed to covert value '%s', ipv4[%s] ipv6[%s]",
                value, error_v4, error_v6)
            return None
        for item in new_value:
            if not (0 <= item <= 255):
                Convert.logger.warn("Failed - tuple item '%s' expect range 0 "
                                    "<= item <= 255 in value '%s'  ",
                                    str, value)
                return None

        return new_value

    @staticmethod
    def mac_to_tuple_of_bytes(value):
        """Convert MAC address from string to binary format.

        :param string value: MAC address to be converted For example:

         ipv4: AA:BB:AA:BB:AA:CC
        :return: Converted value or None in case of any problems
        :rtype: None or tuple()

        """
        if not isinstance(value, basestring):
            Convert.logger.warn(
                "Failed - expect string value '%s', received type '%s'",
                value, type(value))
            return None

        try:
            new_value = []
            for item in value.split(':'):
                if len(item) == 2:
                    byte = int(item, 16)
                    if not (0 <= byte <= 255):
                        raise ValueError("Failed - tuple item '{}' expect "
                                         "range 0 <= item <= 255 in "
                                         "value '{}'".format(item, value))
                    new_value.append(byte)
                else:
                    raise ValueError("Failed - MAC '{}' format expect item"
                                     "len=2 received '{}' "
                                     "({})".format(value, len(item), item))

            new_value = tuple(new_value)
            if len(new_value) != DataDescription.B_SEQ_MAC_LEN:
                raise ValueError("Failed - expected result length '{}'"
                                 "received length"
                                 " '{}'".format(DataDescription.B_SEQ_MAC_LEN,
                                                len(new_value)))
        except:
            Convert.logger.exception("Failed - value '%s'", value)
            return None

        return new_value

    @staticmethod
    def pack_timestamp_to_string(timestamp):
        """from timestamp to utc string."""

        dt = datetime.utcfromtimestamp(timestamp)
        return pack("!HBBBBBB", dt.year, dt.month, dt.day, dt.hour,
                    dt.minute, dt.second, dt.microsecond / 100000)

    @staticmethod
    def format_proc_address(unformatted):
        groups = []
        try:
            for i in xrange(0, len(unformatted), 4):
                groups.append(unformatted[i:i + 4])
            formatted = ":".join(groups)
            # Compress the address.
            address = socket.inet_ntop(socket.AF_INET6,
                                       socket.inet_pton(socket.AF_INET6, formatted))
        except (socket.error, TypeError):
            return None
        return address

    @staticmethod
    def format_ip(address):
        addrinfo = socket.getaddrinfo(address, None)[0]
        return addrinfo[4][0]

    @staticmethod
    def is_valid_ipv4_address(address):
        """Check if string contains valid IPv4 address.

        :param string address: string to be checked
        :return: whether string is valid address or not
        :rtype: bool

        """
        # inet_aton accepts also 2.2.2
        if address.count('.') != 3:
            return False
        # filter out addresses with unexpected characters, like 1.2x2.2.2
        if any(char not in '0123456789.' for char in address):
            return False
        # inet_pton is available only on some platforms, but
        # inet_aton is less restrictive (this is why we need checks above)
        try:
            socket.inet_aton(address)
        except (socket.error, TypeError):
            return False
        return True

    @staticmethod
    def is_valid_ipv6_address(address):
        """Check if string contains valid IPv6 address.

        :param string address: string to be checked
        :return: whether string is valid address or not
        :rtype: bool

        """
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except (socket.error, TypeError):
            return False
        return True

    @staticmethod
    def is_valid_ip_address(address):
        """Check if string contains valid IP address (IPv4 or IPv6).

        :param string address: string to be checked
        :return: whether string is valid address or not
        :rtype: bool

        """
        return Convert.is_valid_ipv6_address(
            address) or Convert.is_valid_ipv4_address(address)

    @staticmethod
    def is_int_value(int_value):
        """Check if string contains valid integer value.

        :param string int_value: string value to be checked
        :return: whether string is valid integer value or not
        :rtype: bool

        """
        try:
            int(int_value)
        except ValueError:
            return False
        return True

    @staticmethod
    def is_ipv6_equal(ip1, ip2):
        """Check if ipv6 address ip1 and ip2 is equal.

        :param ip1: string ipv6 address
        :param ip2: string ipv6 address
        :return: equal or not
        :rtype: bool

        """
        return socket.inet_pton(socket.AF_INET6, ip1) == socket.inet_pton(socket.AF_INET6, ip2)

    @staticmethod
    def is_ip_address_equal(ip1, ip2):
        """Check if ip address ip1 and ip2 is equal.

        :param ip1: string ip address
        :param ip2: string ip address
        :return: equal or not
        :rtype: bool

        """
        if Convert.is_valid_ipv6_address(ip1) and Convert.is_valid_ipv6_address(ip2):
            if Convert.is_ipv6_equal(ip1, ip2):
                return True
        else:
            return ip1 == ip2

        return False

    @staticmethod
    def compare_ip(ip1, ip2):
        if not isinstance(ip1, unicode):
            ip1_str = unicode(ip1, 'utf-8')
        if not isinstance(ip2, unicode):
            ip2_str = unicode(ip2, 'utf-8')
        addr1 = ipaddress.ip_address(ip1_str)
        addr2 = ipaddress.ip_address(ip2_str)
        if addr1 > addr2:
            return 1
        elif addr1 < addr2:
            return -1
        else:
            return 0


class Print(object):

    __metaclass__ = AddLoggerToClass

    @staticmethod
    def test_markers(f):
        """Decorator to print test header & footer.

        :param f: function to be decorated

        """
        @wraps(f)
        def wrapper(*args, **kwds):
            Print._test_start(f.__name__)
            ret = f(*args, **kwds)
            Print._test_stop(f.__name__)
            return ret
        return wrapper

    @staticmethod
    def _test_start(func_name):
        Print.logger.debug("\n TC: --- %s START ---", func_name)

    @staticmethod
    def _test_stop(func_name):
        Print.logger.debug("\n TC: --- %s STOP --- ", func_name)


class SysTools(object):

    __metaclass__ = AddLoggerToClass

    REBOOT_SKIP_FILES = ('/bootflash/openrpd_skip_system_reboot',
                         '/tmp/openrpd_skip_system_reboot')
    RESET_LOG_FILE = "/rpd/log/resetlog"
    RESET_REASON_FILE = "/rpd/log/lastresetreason"

    RESET_LOG_FILE_SIZE = 1024 * 1024 * 1

    SYS_MAC_FILE = "/tmp/sw/chasfs/RpdCapabilities/RpdIdentification/DeviceMacAddress"

    supported_proto = ['provision', 'dhcpv6', 'dhcp']

    @staticmethod
    def is_system_openwrt():
        """Check if operating system on machine is OpenWRT.

        :return: True if running on OpenWRT
        :rtype: bool

        """
        wrt_filename = '/etc/openwrt_release'
        try:
            return exists(wrt_filename)
        except:  # pragma: no cover
            SysTools.logger.debug("Reading file: '%s' failed", wrt_filename)
            return False

    @staticmethod
    def get_mac_address(ifname):
        """Get MAC address of specified interface.

        :param string ifname: name of network interface
        :return: MAC address string separated by ":",
         NULL MAC address in case of failure
        :rtype: string

        """
        try:
            return open('/sys/class/net/' + ifname + '/address') \
                .readline().strip()
        except:
            SysTools.logger.error("Failed to get mac-address of %s", ifname)
            return "00:00:00:00:00:00"

    @staticmethod
    def is_if_oper_up(ifname):
        """Get the physical link state of specified interface.

        :param string ifname: name of network interface
        :return: True if physical link UP, else False
        :rtype: bool

        """
        try:
            return open('/sys/class/net/' + ifname + '/carrier') \
                .readline().strip() == '1'
        except:
            SysTools.logger.error("Failed to get carrier of %s", ifname)
            return False

    @staticmethod
    def if_nametoindex(ifname):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        if not isinstance(ifname, str):
            return None
        ret = libc.if_nametoindex(ifname)
        if not ret:
            return None
        return ret

    @staticmethod
    def if_indextoname(ifindex):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        if not isinstance(ifindex, int):
            return None
        libc.if_indextoname.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        libc.if_indextoname.restype = ctypes.c_char_p

        ifname = ctypes.create_string_buffer(32)
        ifname = libc.if_indextoname(ifindex, ifname)
        if not ifname:
            return None
        return ifname

    @staticmethod
    def get_sys_mac_address():
        """Get MAC address of specified interface.

        :return: MAC address string separated by ":",
         NULL MAC address in case of failure
        :rtype: string

        """
        mac = "00:00:00:00:00:00"
        try:
            if os.path.exists(SysTools.SYS_MAC_FILE):
                with open(SysTools.SYS_MAC_FILE, 'r') as fd:
                    mac = fd.readline().strip()
        except:
            SysTools.logger.error("Failed to get sys-mac-address from %s",
                                  SysTools.SYS_MAC_FILE)
        return mac

    @staticmethod
    def get_host_name(default="RPD"):
        """Get machine hostname.

        :param string default: hostname to be returned in case of failure
        :return: string with hostname
        :rtype: string

        """
        try:
            return socket.gethostname()
        except:
            SysTools.logger.error(
                "Failed to get device hostname, use the default name:%s", default)
            return default

    @staticmethod
    def get_wan_interface_list():
        intf_list = []
        output = check_output(['uci', 'show', 'network'])
        network_list = output.strip().split('\n')
        for config in network_list:
            cfg, option = config.split('=')
            if cfg == 'network.wan.ifname' or cfg == 'network.wan6.ifname':
                intf = option
                intf = filter(str.isalnum, intf)
                intf_list.append(intf)
        return intf_list

    @staticmethod
    def get_interface():
        """
        usage: This function is used for get the network interface name of local ip address
        output:  
               Get the interface name via show command "uci show network".
               return network.wan.ifname value
        notice: TBD, it will be removed or replaced later.
        """
        intf = 'eth0'
        output = check_output(['uci', 'show', 'network'])
        network_list = output.strip().split('\n')
        for config in network_list:
            cfg, option = config.split('=')
            if cfg == 'network.wan.ifname':
                intf = option
                break
        intf = filter(str.isalnum, intf)
        return intf

    @staticmethod
    def get_ip_address(ifname, family=socket.AF_INET):
        """Get the IP address by the interface name, if there is no IP address
        or there is no such interface, we will return None."""
        if family == socket.AF_INET:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
                                                  struct.pack('256s', ifname[:15]))[20:24])
            except IOError:
                return None
            return ip
        elif family == socket.AF_INET6:
            try:
                with open("/proc/net/if_inet6", "r") as f:
                    if6lines = f.readlines()
                    for line in if6lines:
                        val = line.split()
                        # filter LINKLOCAL address
                        if val[3] != '20' and val[-1] == str(ifname):
                            return Convert.format_proc_address(val[0])
                return None
            except Exception as e:
                SysTools.logger.error("can not get the ipv6 address of %s : %s", str(ifname), str(e))
                return None
        else:
            return None

    @staticmethod
    def reboot(reason='manual'):
        """reboot system function."""
        if 1==1 :
            return False
        SysTools.logger.critical("Rebooting by %s" % reason)
        # check if we can skip the reboot
        for skip_reboot_file in SysTools.REBOOT_SKIP_FILES:
            if os.path.exists(skip_reboot_file):
                SysTools.logger.info("Reboot system is skipped since skip file %s exists.", skip_reboot_file)
                return False
        else:  # pragma: no cover
            try:
                fd = open(SysTools.RESET_LOG_FILE, 'a+')
                fd.write(time.ctime() + ': ' + reason + '\n')
                fd.close()

                # Rotate if needed
                resetlog_size = os.path.getsize(SysTools.RESET_LOG_FILE)
                if resetlog_size > SysTools.RESET_LOG_FILE_SIZE:
                    os.system('/usr/sbin/log_rotate.sh /rpd/log/resetlog')
                    os.system('rm /rpd/log/resetlog')
                os.system('cp /tmp/fault_*.json /rpd/log/')
                os.system('dmesg >/tmp/dmesg_before_reboot.log')
                call(["/usr/sbin/log_rotate_before_reboot.sh"])
                call(["sync"])
                call(["reboot"])
            except IOError:
                pass

            return True

    @staticmethod
    def external_reboot(info):
        """external reboot by CLI or GDM"""

        text, reason = info
        SysTools.reboot(reason)

    @staticmethod
    def sys_failure_reboot(reason='system failure'):
        """system failure reboot"""

        SysTools.notify.error(RPD_EVENT_CONNECTIVITY_DIAGNOSTIC_SELF_TEST_FAIL[0], 'System failure',
                              'Diagnostic self test fail', 'Severity level=error')
        SysTools.notify.error(RPD_EVENT_CONNECTIVITY_SYS_REBOOT[0],
                              str(SysTools.sys_up_time() * 100),
                              SysTools.RESET_LOG_FILE, "")

        # add 8s sleep time for fault manager from syslog filter to fm and write json event
        time.sleep(8)

        SysTools.reboot(reason)

    @staticmethod
    def diagnostic_self_test_fail(reason='no errors found', additional_text='no errors found', severity_level='error'):
        """Diagnostic Self Test Failure."""

        SysTools.notify.error(RPD_EVENT_CONNECTIVITY_DIAGNOSTIC_SELF_TEST_FAIL[0],
                              reason, additional_text, severity_level)

    @staticmethod
    def reboot_blocked(reason='manual'):  # pragma: no cover
        ret = SysTools.reboot(reason)
        if not ret:
            while True:
                time.sleep(1)

    @staticmethod
    def is_vrpd():
        """To check if we are running on a virtual machine.

        Currently, we just check the CPU type. To fully confirm that
        we are running on virtual machine, we should use the determined flag.

        :return: True if we are running on vRPD, otherwise return False.

        """
        cpu_type = platform.machine()

        if cpu_type in ['i686', 'i386', 'x86_64', 'armv7l']:
            return True

        return False

    @staticmethod
    def touch(path):
        """touch a file."""
        with open(path, 'a'):
            os.utime(path, None)

    @staticmethod
    def read_file(file_path):
        """
        File content as below can use this function to read file.
        file content: key_info=value_info
                      key_info_1=value_info_1
        :param file_path: file path
        :return:
        """

        output_dict = dict()
        try:
            if os.path.exists(file_path):
                with open(file_path) as fd:
                    output = fd.readlines()
                for idx in range(len(output)):
                    key_info = output[idx].split('=')[0].strip()
                    value_info = output[idx].split('=')[1].strip()
                    output_dict[key_info] = value_info
                return output_dict
        except Exception as e:
            SysTools.logger.warning("Read file:%s failed, reason:%s" % (file_path, str(e)))

    @classmethod
    def set_system_time(cls, dispatcher, timestamp):  # pragma: no cover
        """Set system time to provided timestamp.

        :param dispatcher: used to update timers
        :param timestamp: POSIX timestamp
        :type timestamp: float
        :return:

        """

        if not cls.is_system_openwrt():
            return

        dispatcher.update_all_timers(timestamp - time.time())
        with open(os.devnull, "w") as dev_null:
            cls.logger.info("Setting system time to %s",
                            datetime.utcfromtimestamp(timestamp).strftime('%Y %b %d %H:%M:%S'))
            try:
                call(["date", "+%s", "-s", "@" + str(timestamp)],
                     stdout=dev_null)
            except OSError:
                cls.logger.exception("Failed to set system time")

    @staticmethod
    def sys_up_time():
        """api to get system uptime in seconds."""

        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        return int(uptime_seconds)

    @classmethod
    def get_logical_ifname(self, interface_name, proto='provision'):  # pragma: no cover
        """get logical interface name via physical interface name.
        :param interface_name: physical interface name
        :param proto: dhcpv6 or provision
        :return logical name
        """
        output = check_output(['uci', 'show', 'network'])
        network_list = output.strip().split('\n')
        for config in network_list:
            cfg, option = config.split('=')
            net_prex = cfg.split(".")
            if net_prex[-1] == "proto" and str(option) != proto:
                ifname = '.'.join(net_prex[:-1]) + '.ifname'
                interface = check_output(['uci', 'get', ifname]).split('\n')[0]
                if interface == interface_name:
                    return net_prex[1]
        return ''

    @classmethod
    def set_protocol(cls, interface_name, proto='provision'):  # pragma: no cover
        """set logical interface protocol.
        :param interface_name: logical interface name
        :param proto: dhcpv6 or provision
        :return True, False
        """
        if proto not in cls.supported_proto:
            return
        try:
            ret = cls.get_logical_ifname(interface_name, proto)
            if not ret:
                return
            os.system('uci set network.%s.proto=%s' % (ret, proto))
            os.system('uci commit network')
            os.system('/etc/init.d/network reload')
            if proto == cls.supported_proto[1]:
                os.system('sysctl -w net.ipv6.conf.%s.autoconf=0' % interface_name)
                os.system('sysctl -w net.ipv6.conf.%s.use_tempaddr=2' % interface_name)
            cls.logger.debug("set %s[%s] DCHP protocol to %s", interface_name, ret, proto)
        except OSError as e:
            cls.logger.error("Got exception:%s" % str(e))

    @classmethod
    def logmem(cls, tag):
        """api to log the memory usage rate."""

        cls.logger.info("----%s----", str(tag))
        mem = psutil.virtual_memory()
        cls.logger.info("total:%s M", mem.total / 1024 / 1024)
        cls.logger.info("available:%s M", mem.available / 1024 / 1024)
        cls.logger.info("used:%s M", mem.used / 1024 / 1024)
        cls.logger.info("free:%s M", mem.free / 1024 / 1024)
        cls.logger.info("active:%s M", mem.active / 1024 / 1024)
        cls.logger.info("inactive:%s M", mem.inactive / 1024 / 1024)
        cls.logger.info("buffers:%s M", mem.buffers / 1024 / 1024)
        cls.logger.info("cached:%s M", mem.cached / 1024 / 1024)
        cls.logger.info("shared:%s M", mem.shared / 1024 / 1024)

    @classmethod
    def is_last_reset_by_power_off(cls):
        with open(SysTools.RESET_REASON_FILE, "a+") as f:
            reason = f.read()
            return True if reason == "poweroff" else False
        return False

    @classmethod
    def check_ping_result(cls, addr):
        try:
            ping_cmd = "ping " + "-c 1 " + addr
            check_output(ping_cmd, shell=True)
        except CalledProcessError:
            return False
        return True


class IPCClient(object):
    __metaclass__ = AddLoggerToClass
    context = zmq.Context()

    def __init__(self, path):
        self.logger.debug("Create API client path=" + path)
        self.socket = self.context.socket(zmq.REQ)
        self.socket.connect(path)
        self.poll = zmq.Poller()
        self.poll.register(self.socket, zmq.POLLIN)

    def __del__(self):
        self.poll.unregister(self.socket)
        self.socket.close()
        self.logger.debug("del API client")

    def sendReq(self, req, timeout=2500):
        try:
            self.socket.send(req.SerializeToString())

            socks = dict(self.poll.poll(timeout))
            if socks and socks.get(self.socket) == zmq.POLLIN:
                bin = self.socket.recv()
            else:
                return None
        except Exception as e:
            self.logger.error("can not get Msg for l2tp %s", str(e))
            return None

        return bin


def singleton(cls):
    """
    This fucntion is used as a decorator pattern, which limit the object only
    one instance
    """
    instances = {}

    @wraps(cls)
    def _wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return _wrapper


class PingPackage(object):
    __metaclass__ = AddLoggerToClass

    ICMP_DATA_STR = 56
    ICMP_TYPE = 8
    ICMP_TYPE_IP6 = 128
    ICMP_CODE = 0
    ICMP_CHECKSUM = 0
    ICMP_ID = 0
    ICMP_SEQ_NR = 0

    @staticmethod
    def _get_cksum(packet):
        """
        Generates a checksum of a (ICMP) packet.
        :param packet:
        :return:
        """
        if len(packet) & 1:
            packet = packet + '\0'
        datas = array.array('h', packet)
        sum = 0
        for data in datas:
            sum += (data & 0xffff)
        hi = sum >> 16
        lo = sum & 0xffff
        sum = hi + lo
        sum = sum + (sum >> 16)
        return (~sum) & 0xffff

    @staticmethod
    def pack_package(id, size, ipv6):
        """
        Constructs a ICMP echo packet of variable size
        :param id:
        :param size:
        :param ipv6:
        :return:
        """
        if size < int(struct.calcsize("d")):
            return
        if ipv6:
            header = struct.pack('BbHHh', PingPackage.ICMP_TYPE_IP6,
                                 PingPackage.ICMP_CODE, PingPackage.ICMP_CHECKSUM,
                                 PingPackage.ICMP_ID, PingPackage.ICMP_SEQ_NR + id)
        else:
            header = struct.pack('bbHHh', PingPackage.ICMP_TYPE,
                                 PingPackage.ICMP_CODE, PingPackage.ICMP_CHECKSUM,
                                 PingPackage.ICMP_ID, PingPackage.ICMP_SEQ_NR + id)
        load = "-- ARP PING PACKAGE! --"
        size -= struct.calcsize("d")
        rest = ""
        if size > len(load):
            rest = load
            size -= len(load)

        rest += size * "X"
        data = struct.pack("d", time.time()) + rest
        packet = header + data
        checksum = PingPackage._get_cksum(packet)
        if ipv6:
            header = struct.pack('BbHHh', PingPackage.ICMP_TYPE_IP6,
                                 PingPackage.ICMP_CODE, checksum,
                                 PingPackage.ICMP_ID, PingPackage.ICMP_SEQ_NR + id)
        else:
            header = struct.pack('bbHHh', PingPackage.ICMP_TYPE,
                                 PingPackage.ICMP_CODE, checksum,
                                 PingPackage.ICMP_ID, PingPackage.ICMP_SEQ_NR + id)
        packet = header + data
        return packet
