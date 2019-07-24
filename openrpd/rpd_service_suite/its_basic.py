#!/usr/bin/python
#
# Copyright (c) 2016 Cisco and/or its affiliates, and
#                    Teleste Corporation, and
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
import subprocess
import time

from rpd_service_suite.topology import VirtMachine, VMMode
from rpd_service_suite.it_api_topology import ItApiTopology
from rpd.gpb.it_api_msgs_pb2 import (t_ItApiRpdMessage,
                                     t_ItApiServiceSuiteMessage)
from rpd.common.utils import Convert
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_RcpMessage
import rpd.l2tp.l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2


#
# Implements basic ITs using IT API classes.
#
RPD_IMG = None
SERVICE_SUITE_IMG = None


class BasicITs(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    prov_state = [{"INIT": "N"}, {"init(dot1x)": "N"}, {"init(dhcp)": "N"},
                  {"init(tod)": "N"}, {"init(ipsec)": "N"}, {"init(gcp)": "N"},
                  {"init(clock)": "N"}, {"init(l2tp)": "N"}, {"online": "N"}]
    prov_index = {"INIT": 0, "init(dot1x)": 1, "init(dhcp)": 2,
                  "init(tod)": 3, "init(ipsec)": 4, "init(gcp)": 5,
                  "init(clock)": 6, "init(l2tp)": 7, "online": 8}

    def poll_result(self, cb, args=None, attempts=1, msg=None, delay=1):
        """Calls cb multiple times until correct value is returned.

        :param cb: Callback to be called
        :param args: List of arguments to be passed to callback
        :param attempts: Number of attempts
        :param msg: Message to be printed, when result cannot be obtained
                    in specified time
        :param delay: Time to wait between attempts in seconds
        :return: Value returned by callback

        """
        for attempt in range(attempts):
            if args is None:
                args = []
            self.logger.debug("%s Attempt %d", cb.__name__, attempt + 1)
            ret = cb(*args)
            if not (ret is False or ret is None):
                return ret
            time.sleep(delay)

        self.assertTrue(False, (msg if msg
                                else "Timeout expired: Cb: %s" % cb.__name__))

    @staticmethod
    def check_session(rpd_vm):
        msg = t_ItApiRpdMessage()
        msg.ItApiRpdMessageType = msg.IT_API_RPD_GET
        try:
            reply = rpd_vm.vm_command(msg)
            if (reply and reply.result == reply.IT_API_RESULT_OK):
                BasicITs.logger.info("Latest provision_state is %s",
                                     reply.ItMsgPayload)
                idx = BasicITs.prov_index[reply.ItMsgPayload]
                if BasicITs.prov_state[idx][reply.ItMsgPayload] == "OK":
                    pass
                else:
                    for pre in range(idx):
                        key = BasicITs.prov_state[pre].keys()[0]
                        if BasicITs.prov_state[pre][key] != "OK":
                            BasicITs.prov_state[pre][key] = "OK"
                            BasicITs.logger.info(
                                "Provision state reach: %s", key)
                    BasicITs.prov_state[idx][reply.ItMsgPayload] = "OK"
                    BasicITs.logger.info(
                        "Provision state reach: %s", reply.ItMsgPayload)
                if BasicITs.prov_state[8]["online"] == "OK":
                    return True
                else:
                    return False
        except:
            pass
        return False

    @staticmethod
    def check_rcp(rpd_vm):
        msg = t_ItApiRpdMessage()
        msg.ItApiRpdMessageType = msg.IT_API_RPD_GET_RCP_CFG
        try:
            reply = rpd_vm.vm_command(msg)
            if (reply and reply.result == reply.IT_API_RESULT_OK):
                RcpContent = t_RcpMessage()
                RcpContent.ParseFromString(reply.ItMsgPayload)
                BasicITs.logger.info("Got Rcp config:%s", RcpContent)
                return True
        except:
            pass
        return False

    @staticmethod
    def check_l2tp(rpd_vm):
        msg = t_ItApiRpdMessage()
        msg.ItApiRpdMessageType = msg.IT_API_RPD_GET_L2TP_CFG
        try:
            reply = rpd_vm.vm_command(msg)
            if (reply and reply.result == reply.IT_API_RESULT_OK):
                L2tpContent = L2tpv3Hal_pb2.t_l2tpSessionReq()
                L2tpContent.ParseFromString(reply.ItMsgPayload)
                BasicITs.logger.info("Got l2tp config:%s", L2tpContent)
                return True
        except:
            pass
        return False

    def setUp(self):
        self.topology = ItApiTopology(RPD_IMG, SERVICE_SUITE_IMG)

    def tearDown(self):
        self.topology.cleanup()

    def test_01_basic_init(self):
        serv = None
        rpd1 = None
        try:
            self.logger.info("Starting ServiceSuite VM")
            serv = self.topology.create_vm_service_suite("ServiceSuite1")

            self.logger.info("Configuring ServiceSuite VM")
            msg = serv.prepare_config_message(dhcpv4=True, dhcpv6=False, tps=True,
                                              ccapv4=True)

            msg.ServiceConfigureMessage.CcapCoreV4.IPv4Address = \
                serv.ip_addresses[1]
            reply = serv.vm_command(msg)
            self.logger.info("Received reply to service configuration:")
            self.logger.info("%s", reply)
            self.assertIsNotNone(reply, "Not any reply message received from RPD")
            self.assertEqual(reply.MessageResult,
                             reply.IT_API_SERVICE_SUITE_RESULT_OK,
                             "Unexpected configuration result: {}".format(
                                 reply.MessageResult))

            self.logger.info("Starting RPD VM")
            rpd1 = self.topology.create_vm_open_rpd("RPD1")

            # Wait for a while, then start l2tp
            wait_time = 120
            self.logger.info("Wait for %d seconds, then start L2TP", wait_time)
            time.sleep(wait_time)
            msg = t_ItApiServiceSuiteMessage()
            msg.MessageType = msg.IT_API_SERVICE_SUITE_L2TP
            self.logger.info("Configure L2TP")
            reply = serv.vm_command(msg)
            self.logger.info("Received reply to service l2tp configuration:")
            self.logger.info("%s", reply)
            self.assertEqual(reply.MessageResult,
                             reply.IT_API_SERVICE_SUITE_RESULT_OK,
                             "Unexpected configuration result: {}".format(reply.MessageResult))

            self.poll_result(self.check_session, [rpd1], 30,
                             "Provision didn't reach final state")

            self.poll_result(self.check_rcp, [rpd1], 10,
                             "Fail to get Rcp config!")

            self.poll_result(self.check_l2tp, [rpd1], 20,
                             "Fail to get l2tp config!")

            # self.assertTrue(True)
            # time.sleep(200000)
        finally:
            if serv is not None:
                serv.get_logs("test_01_basic_init")
            if rpd1 is not None:
                rpd1.get_logs("test_01_basic_init")

    @unittest.skip('skip IT test case 2')
    def test_02_basic_redirect(self):
        self.logger.info("Starting ServiceSuite VMs")
        serv1 = self.topology.create_vm_service_suite("ServiceSuite1", False)
        serv2 = self.topology.create_vm_service_suite("ServiceSuite2", False)
        self.topology.start_and_wait_for_all()

        # Configure ServiceSuite1
        self.logger.info("Configuring ServiceSuite1 VM")
        msg = serv1.prepare_config_message(dhcpv4=True, dhcpv6=True, tps=True,
                                           ccapv6=True)
        msg.ServiceConfigureMessage.CcapCoreV6.IPv6Address = \
            serv1.ipv6_addresses[1]
        self.logger.debug("Setting CCAP IPv6: %s", serv1.ipv6_addresses[1])
        scenario = msg.ServiceConfigureMessage.CcapCoreV6.ClientScenarios.add()
        scenario.ScenarioType = scenario.SCENARIO_REDIRECT
        scenario.redirect_ip_addr = serv2.ipv6_addresses[1]

        reply = serv1.vm_command(msg)
        self.logger.debug("Received reply to service configuration:")
        self.logger.debug("%s", reply)
        self.assertIsNotNone(reply, "Not any reply message received from RPD")
        self.assertEqual(reply.MessageResult,
                         reply.IT_API_SERVICE_SUITE_RESULT_OK,
                         "Unexpected configuration result: {}".format(
                             reply.MessageResult))

        # Configure ServiceSuite 2
        self.logger.info("Configuring ServiceSuite2 VM")
        msg = serv2.prepare_config_message(dhcpv4=False, dhcpv6=False,
                                           tps=False, ccapv6=True)
        msg.ServiceConfigureMessage.CcapCoreV6.IPv6Address = \
            serv2.ipv6_addresses[1]
        self.logger.debug("Setting CCAP IPv6: %s", serv2.ipv6_addresses[1])
        reply = serv2.vm_command(msg)
        self.logger.debug("Received reply to service configuration:")
        self.logger.debug("%s", reply)
        self.assertIsNotNone(reply, "Not any reply message received from RPD")
        self.assertEqual(reply.MessageResult,
                         reply.IT_API_SERVICE_SUITE_RESULT_OK,
                         "Unexpected configuration result: {}".format(
                             reply.MessageResult))

        self.logger.info("Starting RPD VM")
        rpd1 = self.topology.create_vm_open_rpd("RPD1")

        self.poll_result(self.check_session, [rpd1], 30,
                         "Ccap core capabilities not set")

        msg = t_ItApiRpdMessage()
        msg.ItApiRpdMessageType = msg.IT_API_RPD_GET
        ret = rpd1.vm_command(msg)
        self.logger.info("Received DatabaseContent:")
        self.logger.info("%s", ret)
        self.assertIsNotNone(reply, "Not any reply message received from RPD")

        expected_ccap_ip = Convert.ipaddr_to_tuple_of_bytes(
            serv2.ipv6_addresses[1])
        expected_ccap_ip = Convert.bytes_to_ipv6_str(expected_ccap_ip)
        received_ccap_ip = \
            ret.DatabaseContent.cfg.CcapCoreIdentification[0].CoreIpAddress
        self.logger.info("Comparing CCAP IPs: received: %s, expected: %s",
                         received_ccap_ip, expected_ccap_ip)
        self.assertEqual(expected_ccap_ip,
                         received_ccap_ip,
                         "Invalid CcapCore IP address: {}, "
                         "expected: {}".format(received_ccap_ip,
                                               expected_ccap_ip))

    # Basic CLI Test
    @unittest.skip('Skip CLI Test')
    def test_03_basic_cli(self):
        # Run Service Suite
        self.logger.info("Starting ServiceSuite VM")
        serv3 = self.topology.create_vm_service_suite("ServiceSuite3")

        self.logger.info("Configuring ServiceSuite VM")
        msg = serv3.prepare_config_message(dhcpv4=True, dhcpv6=True, tps=True,
                                           ccapv4=True)
        msg.ServiceConfigureMessage.CcapCoreV4.IPv4Address = \
            serv3.ip_addresses[1]
        serv3.vm_command(msg)

        # Create RPD
        self.logger.info("Starting RPD VM. Testing CLI Implementation..")
        rpd3 = self.topology.create_vm_open_rpd("RPD3")
        time.sleep(30)
        # Communicate with RPD, get the XML file from RPD
        import paramiko
        from scp import SCPClient

        remotePath = '/etc/clish/rpd.xml'
        localPath = './'
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(rpd3.get_ip_address(), username='root', password='lab123',
                        timeout=30)
            scp = SCPClient(ssh.get_transport())
            scp.get(remotePath, localPath)
            scp.close()
            ssh.close()
        except paramiko.SSHException:
            self.logger.error("Failed to get XML file")
            raise

        # Parse command names and actions from the XML file
        from xml.dom import minidom
        try:
            localPath += 'rpd.xml'
            dom = minidom.parse(localPath)
            Command = dom.getElementsByTagName('COMMAND')
            subprocess.call(['rm', localPath])
        except:
            self.logger.error("Failed to parse XML file")
            raise

        # The CLI checking result that is supposed to be returned
        cli_output = "CLI_RESULT_OK"
        time.sleep(50)
        # Run parsed commands to test
        for comm in Command:
            comm_name = comm.getAttribute('name')
            exec_list = comm.getElementsByTagName('ACTION')
            for c in exec_list:
                command_execution = c.childNodes[0].nodeValue
                reply = rpd3.run_command(command_execution)
                # print command name
                self.logger.info('Testing CLI Command: ' + comm_name)
                self.logger.info("\nCommand Output: %s", ''.join(map(str, reply)))

                self.assertEqual(str(reply[0].strip()), cli_output,
                                 "Error on Command: " + comm_name + " " + command_execution)

                # TODO
                # Add more test cases


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--rpd-image')
    parser.add_argument('--server-image')
    parser.add_argument('--test')
    parser.add_argument('--force-cleanup', action='store_true', default=False)
    parser.add_argument('--qemu', action='store_true', default=False)
    args = parser.parse_args()

    setup_logging("IT", filename="IT-Case.log")

    if args.force_cleanup:
        BasicITs.logger.info("Destroying all VMs")
        ItApiTopology._kill_everything()
        exit(0)
    else:
        if None in [args.rpd_image, args.server_image]:
            parser.error("RPD and server images are mandatory")

    if args.qemu:
        VirtMachine.VM_MODE = VMMode.QEMU
        sys.argv.pop()

    # Check arguments
    if not os.path.exists(args.rpd_image):
        parser.error("RPD image file not found: {}".format(args.rpd_image))
    if not os.path.exists(args.server_image):
        parser.error("Server image file not found: {}".format(
            args.server_image))

    RPD_IMG = args.rpd_image
    SERVICE_SUITE_IMG = args.server_image

    # remove arguments for this script
    sys.argv.pop()
    sys.argv.pop()
    if args.test is None:
        unittest.main()
    else:
        suite = unittest.TestSuite()
        try:
            suite.addTest(BasicITs(args.test))
        except ValueError:
            parser.error("Test with name: '{}' not found".format(args.test))
        unittest.TextTestRunner().run(suite)
