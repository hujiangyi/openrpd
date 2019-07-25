#!/usr/bin/python
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

import argparse
import os
import unittest
import sys
from subprocess import CalledProcessError

from rpd_service_suite.it_api_topology import ItApiTopology


class TestServices(unittest.TestCase):
    DHCPV4_CMD = "netstat -l | grep 'bootps'"
    DHCPV6_CMD = "netstat -l | grep 'dhcpv6-server'"
    TPS_CMD = "netstat -l | grep 'time'"
    CCAPV4_CMD = "netstat -ln | grep '0.0.0.0:6000'"
    CCAPV6_CMD = "netstat -ln | grep '::6000'"

    def setUp(self):
        self.topology = ItApiTopology(open_rpd_image=None,
                                      service_suite_image=args.server_image)
        self.server = self.topology.create_vm_service_suite("ServiceSuite1",
                                                            start=False)
        self.topology.start_and_wait_for_all()

    def tearDown(self):
        self.topology.cleanup()

    def test_dhcpv6(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(dhcpv6=True)))
        self.server.run_command(self.DHCPV6_CMD)

    def test_dhcpv4(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(dhcpv4=True)))
        self.server.run_command(self.DHCPV4_CMD)

    def test_tps(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(tps=True)))
        self.server.run_command(self.TPS_CMD)

    def test_ccapv4(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(ccapv4=True)))
        self.server.run_command(self.CCAPV4_CMD)

    def test_ccapv6(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(ccapv6=True)))
        self.server.run_command(self.CCAPV6_CMD)

    def test_all_v4(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(dhcpv4=True, tps=True,
                                               ccapv4=True)))
        for cmd in [self.DHCPV4_CMD, self.TPS_CMD, self.CCAPV4_CMD]:
            self.server.run_command(cmd)

    def test_all_v6(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(dhcpv6=True, tps=True,
                                               ccapv6=True)))
        for cmd in [self.DHCPV6_CMD, self.TPS_CMD, self.CCAPV6_CMD]:
            self.server.run_command(cmd)

    def test_both_dhcp_servers(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(dhcpv6=True, dhcpv4=True)))
        for cmd in [self.DHCPV6_CMD, self.DHCPV4_CMD]:
            self.server.run_command(cmd)

    def test_stop_all(self):
        self.assertIsNotNone(self.server.vm_command(
            self.server.prepare_config_message(dhcpv6=False, dhcpv4=False,
                                               tps=False, ccapv4=False,
                                               ccapv6=False)))
        for cmd in [self.DHCPV6_CMD, self.DHCPV4_CMD, self.TPS_CMD,
                    self.CCAPV4_CMD, self.CCAPV6_CMD]:
            with self.assertRaises(CalledProcessError):
                self.server.run_command(cmd)

    def test_start_stop_repeated(self):
        self.test_all_v6()
        self.test_stop_all()
        self.test_all_v6()

    def test_double_stop(self):
        self.test_all_v6()
        self.test_stop_all()
        self.test_stop_all()

    def test_double_start(self):
        self.test_all_v4()
        self.test_all_v4()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-image', required=True)
    parser.add_argument('--test')
    args = parser.parse_args()

    # Check arguments
    if not os.path.exists(args.server_image):
        parser.error("Image file not found: {}".format(args.server_image))

    # remove RPD-image argument
    sys.argv.pop()

    if args.test is None:
        unittest.main()
    else:
        suite = unittest.TestSuite()
        suite.addTest(TestServices(args.test))
        unittest.TextTestRunner().run(suite)
