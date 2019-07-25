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
import time
from subprocess import Popen
from signal import (signal, SIGUSR1, SIGUSR2, SIGTERM,
                    SIGINT, SIGQUIT)

from rpd.common.utils import SysTools
from rpd.gpb.dhcp_pb2 import t_DhcpMessage, t_DhcpData
from rpd.gpb.tpc_pb2 import t_TpcMessage

# These imports are intended for the RPD, so we will enclose it by the
# if statement
if SysTools.is_system_openwrt():
    from rpd.manager import Manager, ProcessInfo
    from glibc import (
        SIG_BLOCK, SIG_UNBLOCK, sigset_t, signalfd_siginfo, sigemptyset,
        sigaddset, sigprocmask)


@unittest.skipUnless(SysTools.is_system_openwrt(),
                     "Don't change system time on local machine")
class TestManager(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Save original value for REBOOT_HOLD variable and block it for testing
        cls.reboot_hold_backup = os.getenv("PC_REBOOT_HOLD", 'false')
        os.environ['PC_REBOOT_HOLD'] = 'true'

    @classmethod
    def tearDownClass(cls):
        # Restore reboot hold to original state
        if cls.reboot_hold_backup:
            os.environ['PC_REBOOT_HOLD'] = 'true'

    def setUp(self):
        self.mgr = Manager()

    def tearDown(self):
        del self.mgr

    @staticmethod
    def _get_remote_log_ip():
        from subprocess import PIPE

        grep_proc = Popen(["grep", "log_ip", "/etc/config/system"],
                          stdout=PIPE, stderr=PIPE)

        cut_proc = Popen(
            ["cut", "-d", "\'", "-f", "2"], stdin=grep_proc.stdout,
            stdout=PIPE)
        grep_proc.stdout.close()
        return cut_proc.communicate()[0]

    def test_remote_logging(self):
        backup_cfg_ip = self._get_remote_log_ip()
        # Clear remote logging configuration
        Manager.configure_remote_logging(None)
        self.assertEqual('', self._get_remote_log_ip())

        Manager.configure_remote_logging('1.1.1.1')
        self.assertEqual('1.1.1.1', self._get_remote_log_ip().strip())

        # Invalid value should be ignored
        Manager.configure_remote_logging('test')
        self.assertNotEqual('test', self._get_remote_log_ip().strip())

        Manager.configure_remote_logging('1::1')
        self.assertEqual('1::1', self._get_remote_log_ip().strip())

        Manager.configure_remote_logging(None)
        self.assertEqual('', self._get_remote_log_ip().strip())

        # Revert original value
        Manager.configure_remote_logging(backup_cfg_ip)

    def _sig_handler_fail(self, signum, frame):
        del signum
        del frame
        self.assertTrue(False, "Signal is not blocked")

    def _sig_handler_ok(self, signum, frame):
        pass

    def test_create_sigmask(self):
        from glibc import sigismember
        from signal import SIGABRT, SIGALRM, SIGHUP, getsignal
        from subprocess import PIPE

        siglist = [SIGINT, SIGQUIT, SIGTERM]
        default_handlers = {}

        mask = Manager.create_signal_mask()
        # Check if signals are in the mask & register callbacks
        for sig in siglist:
            self.assertTrue(sigismember(mask, sig))
            default_handlers[sig] = getsignal(sig)
            signal(sig, self._sig_handler_fail)

        # A few examples of not expected signals
        for sig in [SIGABRT, SIGALRM, SIGHUP]:
            self.assertFalse(sigismember(mask, sig))

        # Block signals in mask
        sigprocmask(SIG_BLOCK, mask, None)

        # Get line in format "SigBlk 00000000280b2603" from /proc/PID/status
        p1 = Popen(["grep", "SigBlk", "/proc/" + str(os.getpid()) + "/status"],
                   stdout=PIPE, stderr=PIPE)
        p2 = Popen(["cut", "-f", "2"], stdin=p1.stdout, stdout=PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        blocked_hex = p2.communicate()[0]
        blocked_bin = bin(int(blocked_hex, 16))

        # These signals should be blocked
        for sig in siglist:
            os.kill(os.getpid(), SIGTERM)
            self.assertEqual(blocked_bin[-sig], '1')

        # Replace signal handler to drop pending signals
        for sig in siglist:
            signal(sig, self._sig_handler_ok)

        sigprocmask(SIG_UNBLOCK, mask, None)

        # Restore original signal handlers
        for sig in siglist:
            signal(sig, default_handlers[sig])

    def test_msg_none(self):
        # Fill some random data to dhcp GPB message
        self.mgr.dhcp_data.LogServers.append('1.1.1.1')
        self.mgr.dhcp_data.TimeServers.append('2.2.2.2')
        self.mgr.dhcp_data.CCAPCores.append('3.3.3.3')
        self.mgr.dhcp_data.TimeOffset = 50
        # Send empty DHCP message and because of no DHCP process running,
        # this message should be ignored
        dhcp_msg = t_DhcpMessage()
        # Fill mandatory fields (required by GPB)
        dhcp_msg.Status = dhcp_msg.UPDATED
        msg_str = dhcp_msg.SerializeToString()
        self.mgr.dhcp_msg_cb(msg_str)
        # Check if values are still same
        self.assertEqual(self.mgr.dhcp_data.LogServers[0], '1.1.1.1')
        self.assertEqual(self.mgr.dhcp_data.TimeServers[0], '2.2.2.2')
        self.assertEqual(self.mgr.dhcp_data.CCAPCores[0], '3.3.3.3')
        self.assertEqual(self.mgr.dhcp_data.TimeOffset, 50)

    def test_msg_valid(self):
        # Valid case -> all data are here
        dhcp_data = t_DhcpData()
        dhcp_data.TimeServers.extend(['1.1.1.1', '2.2.2.2'])
        dhcp_data.LogServers.append('2.2.2.2')
        dhcp_data.CCAPCores.append('3.3.3.3')
        dhcp_data.TimeOffset = 50
        self.mgr.dhcp_data = dhcp_data
        # Filled data will be validated. Invalid data will be dropped
        self.mgr._verify_dhcp_data()
        self.assertEqual(len(self.mgr.dhcp_data.TimeServers), 2)
        self.assertEqual(self.mgr.dhcp_data.TimeServers[0], '1.1.1.1')
        self.assertEqual(self.mgr.dhcp_data.TimeServers[1], '2.2.2.2')
        self.assertEqual(len(self.mgr.dhcp_data.LogServers), 1)
        self.assertEqual(len(self.mgr.dhcp_data.CCAPCores), 1)
        self.assertEqual(self.mgr.dhcp_data.TimeOffset, 50)
        self.mgr.delete_dhcp_data()

    def test_msg_invalid(self):
        # Try some invalid cases, all values with IP address value format are
        # handled same way -> we don't need to try all combinations
        # Valid case -> all data are here
        dhcp_data = t_DhcpData()
        # 2 Invalid, 1 Valid
        dhcp_data.TimeServers.extend(['test', '2.2.2.2,3.2.2.2', '5.5.5.5'])
        # All invalid
        dhcp_data.LogServers.extend(['2.2.2.2.5', '::1.2.3'])
        # All valid
        dhcp_data.CCAPCores.extend(['3.3.3.3', '::'])
        # GPB don't allow us to set invalid data
        dhcp_data.TimeOffset = 50
        self.mgr.dhcp_data = dhcp_data
        # Filled data will be validated. Invalid data will be dropped
        self.mgr._verify_dhcp_data()
        self.assertEqual(len(self.mgr.dhcp_data.TimeServers), 1)
        self.assertEqual(self.mgr.dhcp_data.TimeServers[0], '5.5.5.5')
        self.assertEqual(len(self.mgr.dhcp_data.LogServers), 0)
        self.assertEqual(len(self.mgr.dhcp_data.CCAPCores), 2)
        self.assertEqual(self.mgr.dhcp_data.TimeOffset, 50)
        self.mgr.delete_dhcp_data()

    def test_reboot_var(self):
        # Verify if variable to disable reboot is working (it is already set
        # from setUpClass method)
        self.assertEqual(os.getenv('PC_REBOOT_HOLD', 'false').lower(), 'true')

        Manager.reboot()
        # Reboot is waiting 10 seconds, ...wait a few seconds more to be safe
        time.sleep(12)
        # Test passed ... if we are still alive

    def test_manager_with_interface(self):

        # Items (Device MAC address, host-name) field during initialization
        mac = ['cfg', 'RpdCapabilities', 'RpdIdentification',
               'DeviceMacAddress']
        device = ['cfg', 'RpdCapabilities', 'RpdIdentification', 'DeviceAlias']

        db_adapter = self.mgr.db_adapter
        self.assertEqual(db_adapter.get_leaf(Manager.hw_version_path),
                         Manager.hw_version)
        self.assertIsNotNone(db_adapter.get_leaf(mac))
        self.assertIsNotNone(db_adapter.get_leaf(device))

        # Write DHCP structure and read data one-by-one
        time_servers = ["1.2.3.1", "1.2.3.2"]
        log_servers = ["2.3.4.5", "2.3.4.6"]
        ccap_cores = ["3.3.4.5", "3.3.4.6", "5.5.4.56"]

        self.mgr.dhcp_data.TimeOffset = 10
        self.mgr.dhcp_data.TimeServers.extend(time_servers)
        self.mgr.dhcp_data.LogServers.extend(log_servers)
        self.mgr.dhcp_data.CCAPCores.extend(ccap_cores)

        self.assertTrue(db_adapter.set_leaf(self.mgr.dhcp_data_path,
                                            self.mgr.dhcp_data))

        self.assertItemsEqual(ccap_cores,
                              db_adapter.get_leaf(self.mgr.dhcp_data_path +
                                                  ['CCAPCores']))
        self.assertItemsEqual(time_servers,
                              db_adapter.get_leaf(self.mgr.dhcp_data_path +
                                                  ['TimeServers']))
        self.assertItemsEqual(log_servers,
                              db_adapter.get_leaf(self.mgr.dhcp_data_path +
                                                  ['LogServers']))

        self.mgr.delete_dhcp_data()
        self.assertIsNone(db_adapter.get_leaf(self.mgr.dhcp_data_path))

    def test_negative_no_time_servers(self):
        # DHCP file not created -> no time servers received

        # Overwrite DHCP file name to read non-existing/not-accessible file
        # Because file cannot be opened, update is ignored and manager will try
        # to use empty DHCP data (original, if there are any)

        self.mgr.fsm.current = 'dhcpv6_waiting'
        self.mgr._dhcp_data_ready()
        self.assertEqual(self.mgr.fsm.current, 'reboot')
        self.assertEqual(len(self.mgr.dhcp_data.TimeServers), 0)

        # Same test, but for DHCPv4
        self.mgr.fsm.current = 'dhcpv4_waiting'
        self.mgr._dhcp_data_ready()
        self.assertEqual(self.mgr.fsm.current, 'reboot')
        self.assertEqual(len(self.mgr.dhcp_data.TimeServers), 0)

    def test_ontime_cfged_no_ccap(self):
        self.mgr.fsm.current = 'log_waiting'
        self.mgr._ontime_cfged(None)
        self.assertEqual(self.mgr.fsm.current, 'reboot')

    def test_ontime_cfged_ccap_2_steps(self):
        # 1st dhcp update
        self.mgr.fsm.current = 'log_waiting'
        # no time server
        self.mgr.dhcp_data.CCAPCores.append("1.2.3.4")
        self.mgr._ontime_cfged(None)
        self.assertEqual(self.mgr.fsm.current, 'gcp_started')

        # 2nd dhcp update
        self.mgr.dhcp_data.Clear()
        self.mgr.fsm.current = 'log_waiting'
        self.mgr.dhcp_data.TimeServers.append("2.2.2.1")
        self.mgr.dhcp_data.CCAPCores.append("2.2.2.2")
        self.mgr._ontime_cfged(None)
        self.assertEqual(self.mgr.fsm.current, 'gcp_started')

    def test_tpc_response_no(self):
        # After first failed attempt to get time, it should be cleared to
        # zero (1.1.1970), so we set time to some different value and check

        # Set time to 2 min after epoch
        self.mgr.set_system_time(120)
        # Create some placeholder for TPC process (to be cleanup up in msg cb)
        self.mgr.processes['tpc'] = ProcessInfo(["test", "test"], "ipc://test")
        # Create simulated message to reset system time
        tpc_msg = t_TpcMessage()
        tpc_msg.Status = tpc_msg.FIRST_ATTEMPT_FAILED
        msg_str = tpc_msg.SerializeToString()
        self.mgr.tpc_msg_cb(msg_str)

        # less than 30 sec (timeouts included)
        self.assertLess(int(time.time()), 30)

    def test_tpc_response_yes(self):
        # Set time to 2 min after epoch
        self.mgr.set_system_time(120)
        self.mgr.fsm.current = 'time_waiting'
        # Create some placeholder for TPC process (to be cleanup up in msg cb)
        self.mgr.processes['tpc'] = ProcessInfo(["test", "test"], "ipc://test")
        # Create simulated message to change system time to value higher than
        # initial value
        tpc_msg = t_TpcMessage()
        tpc_msg.Status = tpc_msg.SUCCESS
        tpc_msg.Timestamp = 500
        msg_str = tpc_msg.SerializeToString()
        self.mgr.tpc_msg_cb(msg_str)

        # time should be >= initial value
        self.assertGreaterEqual(int(time.time()), 500)


if __name__ == "__main__":
    unittest.main()
