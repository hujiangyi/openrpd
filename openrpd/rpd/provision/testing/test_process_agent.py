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

import rpd.provision.proto.process_agent_pb2 as pb2
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.process_agent.rcp.rcp_agent import RcpOverGcp
from rpd.provision.process_agent.dhcp.dhcp_agent import DhcpAgent
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.gpb.dhcp_pb2 import t_DhcpMessage


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
        event_request.mgr_reg.CopyFrom(reg)
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
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

    @unittest.skip("skip interface check")
    def test_interface_status_event(self):
        context = zmq.Context()
        sock1 = context.socket(zmq.PUSH)
        sock1.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['pull'])

        sock = context.socket(zmq.REQ)
        sock.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['api'])

        sock2 = context.socket(zmq.PULL)
        sock2.bind("ipc:///tmp/sock4.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = "ipc:///tmp/sock4.sock"
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.event_id = 1
        event_request.action.parameter = "eth0"

        event_request.action.action = pb2.msg_event.START

        sock1.send(event_request.SerializeToString())

        data = sock2.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.event_id = 1
        event_request.action.parameter = "eth0"

        event_request.action.action = pb2.msg_event.STOP

        # sock1.send(event_request.SerializeToString())

        while True:
            data = sock2.recv()
            rsp = pb2.msg_event_notification()
            rsp.ParseFromString(data)
            print rsp

    @unittest.skip("skip tod check")
    def test_tod_event(self):
        context = zmq.Context()
        sock1 = context.socket(zmq.PUSH)
        sock1.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_TOD]['pull'])

        sock = context.socket(zmq.REQ)
        sock.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_TOD]['api'])

        sock2 = context.socket(zmq.PULL)
        sock2.bind("ipc:///tmp/sock4.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        # reg.path_info = "ipc:///tmp/sock4.sock"
        reg.path_info = ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_TOD]['api']
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
        event_request.action.event_id = pb2.AGENTTYPE_TOD
        # msg = t_TodMessage()
        # msg.TimeServers.extend(['127.0.0.1', ])
        # msg.TimeOffset = 0
        # parameter = msg.SerializeToString()
        parameter = "127.0.0.1/0|127.0.0.1"
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
        event_request.action.event_id = pb2.AGENTTYPE_TOD
        event_request.action.parameter = parameter

        event_request.action.action = pb2.msg_event.STOP

        # sock1.send(event_request.SerializeToString())

        while True:
            data = sock2.recv()
            rsp = pb2.msg_event_notification()
            rsp.ParseFromString(data)
            print rsp

    @unittest.skip("skip rcp check")
    def test_rcp_event(self):
        context = zmq.Context()
        sock1 = context.socket(zmq.PUSH)
        sock1.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_GCP]['pull'])

        sock = context.socket(zmq.REQ)
        sock.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_GCP]['api'])

        sock2 = context.socket(zmq.PULL)
        sock2.bind("ipc:///tmp/sock4.sock")

        rcp_sock = context.socket(zmq.PAIR)
        rcp_sock.connect(RcpOverGcp.SOCK_ADDRESS)

        mgr_sock = context.socket(zmq.REP)
        mgr_sock.bind("ipc:///tmp/rpd_provision_manager_api.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = "ipc:///tmp/sock4.sock"
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
        event_request.action.event_id = pb2.AGENTTYPE_GCP
        event_request.action.parameter = '127.0.0.1'

        event_request.action.action = pb2.msg_event.START

        sock1.send(event_request.SerializeToString())

        data = sock2.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.ccap_core_id = "abcd"
        event_request.action.event_id = pb2.AGENTTYPE_GCP
        event_request.action.parameter = '127.0.0.1'

        event_request.action.action = pb2.msg_event.STOP

        # sock1.send(event_request.SerializeToString())

        # send rcp message
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.REDIRECT_NOTIFICATION
        rcp_msg.RedirectCCAPAddresses.extend(['1.1.1.1'])
        rcp_sock.send(rcp_msg.SerializeToString())

        data = mgr_sock.recv()
        red_rsp = pb2.msg_magager_api()
        red_rsp.ParseFromString(data)
        print red_rsp

        while True:
            data = sock2.recv()
            rsp = pb2.msg_event_notification()
            rsp.ParseFromString(data)
            print rsp

    # @unittest.skip("skip dhcp check")
    def test_dhcp_event(self):
        context = zmq.Context()
        sock1 = context.socket(zmq.PUSH)
        sock1.connect(
            ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_DHCP]['pull'])

        sock = context.socket(zmq.REQ)
        sock.connect(
            ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_DHCP]['api'])

        sock2 = context.socket(zmq.PULL)
        # sock2.bind("ipc:///tmp/sock4.sock")
        sock2.bind(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_DHCP]['push'])

        dhcp_sock = context.socket(zmq.PUSH)
        dhcp_sock.connect(DhcpAgent.SOCK_ADDRESS)

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "abcd"
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_DHCP]['push']
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print 'mgr reg:', reg_rsp

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
        print 'core reg:', reg_rsp

        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.ccap_core_id = "abcd"
        event_request.action.event_id = pb2.AGENTTYPE_DHCP
        event_request.action.parameter = 'eth1'

        event_request.action.action = pb2.msg_event.START

        sock1.send(event_request.SerializeToString())

        data = sock2.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "abcd"
        event_request.action.ccap_core_id = "abcd"
        event_request.action.event_id = pb2.AGENTTYPE_DHCP
        event_request.action.parameter = 'eth1'

        event_request.action.action = pb2.msg_event.STOP

        # sock1.send(event_request.SerializeToString())
        # data = sock2.recv()
        # red_rsp = pb2.msg_event_notification()
        # red_rsp.ParseFromString(data)
        # print red_rsp

        # send dhcp failed message
        hostip = '127.0.0.1'

        dhcp_msg = t_DhcpMessage()
        dhcp_msg.InterfaceName = "eth1"
        dhcp_msg.Status = dhcp_msg.FAILED
        # dhcp_sock.send(dhcp_msg.SerializeToString())

        # send dhcp success message
        dhcp_msg.Status = dhcp_msg.UPDATED
        dhcp_data = dhcp_msg.DHCPData
        dhcp_data.TimeServers.extend([hostip, '1.1.1.1'])
        dhcp_data.LogServers.extend([hostip, '1.1.1.1'])
        dhcp_data.CCAPCores.extend([hostip, ])
        dhcp_data.TimeOffset = 0

        # dhcp_sock.send(dhcp_msg.SerializeToString())

        while True:
            data = sock2.recv()
            rsp = pb2.msg_event_notification()
            rsp.ParseFromString(data)
            print rsp


if __name__ == '__main__':
    unittest.main()
