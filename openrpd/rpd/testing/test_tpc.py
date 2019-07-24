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
from subprocess import Popen,call
import signal
import time

from rpd.common.utils import SysTools
from rpd.tps import TimeServerManager
from rpd.tpc import TimeClient


# @unittest.skipUnless(SysTools.is_system_openwrt(),
#                      "Don't change system time on local machine")
class TestTpc(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mgr = TimeServerManager()
        cls.ipv6_server_list = ["fe80::20c:29ff:fe13:f80e", "::1"]
        cls.ipv4_server_list = ['a.b.c.d',"1.2.3.4", "127.0.0.1"]

    def setUp(self):
        # Stop time-server on the test start to be sure no time-server is
        # running from previous tests
        self.assertTrue(self.mgr.stop_server())
        self.assertFalse(self.mgr.is_server_running())

    def tearDown(self):
        self.assertTrue(self.mgr.stop_server())
        self.assertFalse(self.mgr.is_server_running())

    def common_test_response_no(self, ipv6=False):
        # Try to get time without any time-server running
        server_list = self.ipv6_server_list if ipv6 else self.ipv4_server_list
        # Create client with decreased number of attempts
        client = TimeClient(collisions=3, ipv6=ipv6,port=37000)
        self.assertEqual(client.get_time_with_retries(server_list), 0)

    def test_process_system_time(self):
        currentPath = os.path.split(os.path.realpath(__file__))[0]
        dirs = currentPath.split("/")
        dir_len = len(dirs)
        # rpd_index = dirs.index("testing")-2
        rpd_index = dir_len-2
        root_path = "/".join(dirs[:rpd_index])
        print root_path
        self.assertTrue(self.mgr.start_server(ipv6=False,port=37000))

        #illegal ipc socket addr
        sock_addr = 'hahaha'
        server_list = '127.0.0.1'
        pid = Popen("coverage run --parallel-mode --rcfile="+root_path+"/.coverage.rc "
                            + "/".join(dirs[:rpd_index]) +
                            "/rpd/tpc.py --port 37000 --collisions 3 --servers "+server_list+
                            " --offset 8 --ipc-address "+sock_addr,
                            executable='bash', shell=True)
        time.sleep(25)
        if 0 == call(["pgrep", '-f', 'tpc.py']):
            pid.send_signal(signal.SIGINT)
            pid.wait()

        #illegal server list
        sock_addr = 'ipc:///tmp/zmq-test_tpc.ipc'
        server_list = 'a.b.c.d'
        pid = Popen("coverage run --parallel-mode --rcfile="+root_path+"/.coverage.rc "
                            + "/".join(dirs[:rpd_index]) +
                            "/rpd/tpc.py --port 37000 --collisions 3 --servers "+server_list+
                            " --offset 8 --ipc-address "+sock_addr,
                            executable='bash', shell=True)
        time.sleep(25)
        if 0 == call(["pgrep", '-f', 'tpc.py']):
            pid.send_signal(signal.SIGINT)
            pid.wait()

        #unreachable server list
        sock_addr = 'ipc:///tmp/zmq-test_tpc.ipc'
        server_list = '1.2.3.4'
        pid = Popen("coverage run --parallel-mode --rcfile="+root_path+"/.coverage.rc "
                            + "/".join(dirs[:rpd_index]) +
                            "/rpd/tpc.py --port 37000 --collisions 3 --servers "+server_list+
                            " --offset 8 --ipc-address "+sock_addr,
                            executable='bash', shell=True)
        time.sleep(25)
        if 0 == call(["pgrep", '-f', 'tpc.py']):
            pid.send_signal(signal.SIGINT)
            pid.wait()

        #try double connection
        self.assertTrue(self.mgr.start_server(ipv6=False,port=37000))
        sock_addr = 'ipc:///tmp/zmq-test_tpc.ipc'
        server_list = '127.0.0.1 127.0.0.1'
        Popen("coverage run --parallel-mode --rcfile="+root_path+"/.coverage.rc "
                            + "/".join(dirs[:rpd_index]) +
                            "/rpd/tpc.py --port 37000 --collisions 3 --servers "+server_list+
                            " --offset 8 --ipc-address "+sock_addr,
                            executable='bash', shell=True)

        #ipv6
        self.assertTrue(self.mgr.start_server(ipv6=True,port=37000))
        sock_addr = 'ipc:///tmp/zmq-test_tpc.ipc'
        server_list = '::1'
        pid = Popen("coverage run --parallel-mode --rcfile="+root_path+"/.coverage.rc "
                            + "/".join(dirs[:rpd_index]) +
                            "/rpd/tpc.py --ipv6 --collisions 3 --servers "+server_list+
                            ' --offset 8 --ipc-address '+sock_addr,
                            executable='bash', shell=True)
        time.sleep(20)
        if 0 == call(["pgrep", '-f', 'tpc.py']):
            pid.send_signal(signal.SIGINT)
            pid.wait()

    def test_response_no_v4(self):
        self.common_test_response_no()

    def test_response_no_v6(self):
        self.common_test_response_no(ipv6=True)

    def common_test_response_yes(self, ipv6=False):
        # Try to get time with one of two time-server running
        self.assertTrue(self.mgr.start_server(ipv6=ipv6,port=37000))

        server_list = self.ipv6_server_list if ipv6 else self.ipv4_server_list

        client = TimeClient(collisions=3,ipv6=ipv6,port=37000)
        self.assertNotEqual(client.get_time_with_retries(server_list), 0)

    def test_response_yes_v4(self):
        self.common_test_response_yes()

    def test_response_yes_v6(self):
        self.common_test_response_yes(ipv6=True)

    def common_test_response_yes_delay(self, ipv6=False):
        self.assertTrue(self.mgr.start_server(delay=2, ipv6=ipv6,port=37000))

        server_list = self.ipv6_server_list if ipv6 else self.ipv4_server_list

        client = TimeClient(collisions=3,ipv6=ipv6,port=37000)
        self.assertNotEqual(client.get_time_with_retries(server_list), 0)

    def test_response_yes_delay_v4(self):
        self.common_test_response_yes_delay()

    def test_response_yes_delay_v6(self):
        self.common_test_response_yes_delay(ipv6=True)


if __name__ == "__main__":
    unittest.main()
