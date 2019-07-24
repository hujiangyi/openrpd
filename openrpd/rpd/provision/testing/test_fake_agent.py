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
import unittest
import os
import time
from rpd.common.rpd_logging import setup_logging
from rpd.provision.process_agent.agent.fake_agent import FakeAgent
# from rpd.provision.testing.fake_interface_agent import InterfaceStatus
from rpd.provision.testing.fake_ipsec_agent import IPSEC
from rpd.provision.testing.fake_gcp_agent import GCP
from rpd.provision.process_agent.agent.agent import ProcessAgent


class TestFakeAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging("fake_agent", filename="fake_agent.log")
        time.sleep(3)

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')
        os.system('rm -rf /tmp/fake_*')

    def test_fake_agent_init(self):
        agent = FakeAgent(ProcessAgent.AGENTTYPE_DHCP)
        self.assertNotEqual(agent, None)

    def test_prepare_para(self):
        print 'test prepare parameter func'
        interface_agent = IPSEC()
        interface_agent.prepare_agent_parameters('1234567890', "lo")
        self.assertEqual(interface_agent.DHCP_parameter['initiated_by'], '1234567890')

        gcp = GCP()
        gcp.prepare_agent_parameters('1234567891', "eth0;")
        self.assertTrue('eth0' in gcp.Fake_Parameter[ProcessAgent.AGENTTYPE_INTERFACE_STATUS])

    def test_fake_agent_period_status_check_no_interface(self):
        print 'test fake_agent_period_status_check func'
        interface_agent = IPSEC()
        interface_agent.fake_agent_period_status_check(None)
        self.assertEqual(interface_agent.agent_status, interface_agent.UP)

    def test_fake_agent_period_status_check_interface_started(self):
        interface_agent = IPSEC()
        # interface started
        interface_agent.input_parameter['eth1'] = {
            "requester": ['1234567892', ],
            "lastChangeTime": time.time(),
        }
        interface_agent.fake_agent_period_status_check(None)
        self.assertEqual(interface_agent.agent_status, interface_agent.UP)

    def test_fake_agent_period_status_check_without_ccap_coreid(self):
        interface_agent = IPSEC()
        # interface started, core id not in self.ccap_cores
        interface_agent.input_parameter['eth1'] = {
            "requester": ['1234567892', ],
            "lastChangeTime": time.time(),
        }
        os.system("rm -rf " + interface_agent.FakeAgent_Descriptor[interface_agent.id])
        interface_agent.fake_agent_period_status_check(None)
        self.assertEqual(interface_agent.agent_status, interface_agent.DOWN)

    def test_fake_agent_period_status_check_with_ccap_coreid(self):
        interface_agent = IPSEC()
        # interface started, core id in self.ccap_cores
        interface_agent.ccap_cores['1234567892'] = None
        interface_agent.input_parameter['eth1'] = {
            "requester": ['1234567892', ],
            "lastChangeTime": time.time(),
        }
        os.system("touch " + interface_agent.FakeAgent_Descriptor[interface_agent.id])
        try:
            interface_agent.fake_agent_period_status_check(None)
        except Exception as e:
            self.assertEqual(type(e), TypeError)


if __name__ == "__main__":
    unittest.main()
