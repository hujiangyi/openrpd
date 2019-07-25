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
import zmq
import os
import time

import rpd.provision.proto.provision_pb2 as ppb2
import rpd.provision.proto.process_agent_pb2 as pb2
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.process_agent.macsec.macsec_agent import MacsecAgent
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.proto import MacsecMsgType


class TestMacsecAgentFunc(unittest.TestCase):

    def setUp(self):
        self.agent = MacsecAgent()

    def tearDown(self):
        self.agent = None
        os.system("rm /tmp/ProcessAgent_AGENTTYPE_*")

    def test_get_get_mac_address(self):
        self.agent.get_mac_address()

    def test_process_cli_action(self):
        self.agent.status_8021x['eth0'] = {
            "status": self.agent.DOWN,
            "lastChangeTime": time.time(),
            "ccap_core_id": ['CORE-1234567890'],
            "count": 0,
            "eap_received": False,
        }

        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = MacsecMsgType.Show8021xSummary
        self.agent.process_cli_action(msg)

        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = MacsecMsgType.Show8021xDetail
        self.agent.process_cli_action(msg)

        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = 3
        self.agent.process_cli_action(msg)

    def test_check_status_8021x_callback(self):
        self.agent.status_8021x['eth0'] = {
            "status": self.agent.DOWN,
            "lastChangeTime": time.time(),
            "ccap_core_id": ['CORE-1234567890'],
            "count": 0,
            "eap_received": False,
        }
        self.agent._check_status_8021x_callback(None)


@unittest.skip("skip the test temperately")
class TestProcessAgent(unittest.TestCase):

    @unittest.skip('skip register test')
    def test_register(self):
        # process_agent = ProcessAgent("ipc:///tmp/p1sock", "ipc:///tmp/p3sock")
        context = zmq.Context()
        sock = context.socket(zmq.REQ)
        sock.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['api'])

        # Fail case
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()
        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['push']
        event_request.reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        # unregister
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.UNREG
        reg.path_info = ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['push']
        event_request.reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

    def runTest(self):
        pass

    #@unittest.skip("skip tod check")
    def test_ike_event(self):
        context = zmq.Context()
        sock1 = context.socket(zmq.PUSH)
        sock1.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_8021X]['pull'])

        sock = context.socket(zmq.REQ)
        sock.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_8021X]['api'])

        sock2 = context.socket(zmq.PULL)
        sock2.bind("ipc:///tmp/sock4.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        # reg.path_info = "ipc:///tmp/sock4.sock"
        reg.path_info = ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_8021X]['api']
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        # core register
        register_request = pb2.api_request()
        reg = pb2.msg_core_register()
        reg.ccap_core_id = 'abcd'
        reg.mgr_id = 'abcd'
        reg.action = pb2.msg_core_register.REG

        register_request.core_reg.CopyFrom(reg)
        data = register_request.SerializeToString()
        sock.send(data)
        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.ccap_core_id = "abcd"
        event_request.action.event_id = ppb2.AGENTTYPE_8021X
        # msg = t_TodMessage()
        # msg.TimeServers.extend(['127.0.0.1', ])
        # msg.TimeOffset = 0
        # parameter = msg.SerializeToString()
        parameter = "enp0s3"
        event_request.action.parameter = parameter

        event_request.action.action = pb2.msg_event.START

        sock1.send(event_request.SerializeToString())

        data = sock2.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.event_id = ppb2.AGENTTYPE_8021X
        event_request.action.parameter = parameter

        event_request.action.action = pb2.msg_event.STOP

        # sock1.send(event_request.SerializeToString())

        while True:
            data = sock2.recv()
            rsp = pb2.msg_event_notification()
            rsp.ParseFromString(data)
            print rsp


if __name__ == '__main__':
    unittest.main()
