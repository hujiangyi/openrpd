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

import time
import unittest
from subprocess import Popen, PIPE

from rpd.tps import TimeServerManager
from rpd.common.utils import SysTools


@unittest.skipUnless(SysTools.is_system_openwrt(),
                     "Don't change system time on local machine")
class TestTps(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mgr = TimeServerManager()

    def tearDown(self):
        # Cleanup, we need to make sure time-server is killed
        self.mgr = TimeServerManager()
        self.mgr.stop_server()

    @staticmethod
    def _is_server_running(ipv6=False):
        netstat_proc = Popen(["netstat", "-ul"], stdout=PIPE, stderr=PIPE)
        # This is really applicable only to Busybox version of netstat
        # on NonWRT machine it's better to parse protocol field udp/udp6
        pattern = "{}:time".format("::" if ipv6 else "0.0.0.0")
        grep_proc = Popen(["grep", pattern], stdin=netstat_proc.stdout,
                          stdout=PIPE)
        netstat_proc.stdout.close()
        output = grep_proc.communicate()[0]
        return output != ''

    def common_test_start_stop(self, ipv6=False):
        self.assertTrue(self.mgr.start_server(ipv6=ipv6))
        # Check if server is running on correct IP version
        self.assertTrue(self._is_server_running(ipv6=ipv6))
        self.assertFalse(self._is_server_running(ipv6=not ipv6))
        # Stop server explicitly to run some additional checks
        self.assertTrue(self.mgr.stop_server())
        self.assertFalse(self.mgr.is_server_running())
        self.assertFalse(self._is_server_running())
        self.assertFalse(self._is_server_running(ipv6=True))

    def test_start_stop_v4(self):
        self.common_test_start_stop()

    def test_start_stop_v6(self):
        self.common_test_start_stop(ipv6=True)

    def test_delay(self):
        self.assertTrue(self.mgr.start_server(delay=5))
        self.assertFalse(self.mgr.is_server_running())
        time.sleep(6)
        self.assertTrue(self.mgr.is_server_running())
        # Stop is done in tearDown method
