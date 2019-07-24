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
import zmq
import rpd.provision.proto.process_agent_pb2 as pb2
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.process_agent.dhcp.dhcp_agent import DhcpAgent
from rpd.gpb.dhcp_pb2 import t_DhcpMessage, t_DhcpData
from rpd.provision.transport.transport import Transport
from rpd.common.rpd_logging import setup_logging
import subprocess
import signal
import json


class TestDhcpAgent(unittest.TestCase):

    def setUp(self):
        # try to find the dhcp agent
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing")-2
        self.rootpath = "/".join(dirs[:rpd_index])
        self.pid = subprocess.Popen("coverage run --parallel-mode --rcfile="+self.rootpath+"/.coverage.rc " 
                                    + "/".join(dirs[:rpd_index]) +
                                    "/rpd/provision/process_agent/dhcp/dhcp_agent.py -s",
                                    executable='bash', shell=True)

        self.dhcp_client_transport = Transport(DhcpAgent.SOCK_ADDRESS,
                                               Transport.PUSHSOCK, mode=Transport.TRANSPORT_CLIENT)

    def tearDown(self):
        self.pid.send_signal(signal.SIGINT)
        self.pid.wait()
        self.pid = None
        self.dhcp_client_transport.sock.close()
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')

    def test_dhcp_start_checkStatus_stop(self):
        print 'test dhcp start and stop action'
        context = zmq.Context()
        sock_push = context.socket(zmq.PUSH)
        sock_push.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_DHCP]['pull'])

        sock_api = context.socket(zmq.REQ)
        sock_api.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_DHCP]['api'])

        sock_pull = context.socket(zmq.PULL)
        sock_pull.bind("ipc:///tmp/test_dhcp_agent.scok")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "test_mgr" # use a fake ccap id
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = "ipc:///tmp/test_dhcp_agent.scok"
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_core_register()
        reg.mgr_id = "test_mgr" # use a fake ccap id
        reg.ccap_core_id = "test_ccap_core"
        reg.action = pb2.msg_core_register.REG
        event_request.core_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)

        event_request = pb2.msg_event_request()
        event_request.action.id = "test_ccap_core"
        event_request.action.ccap_core_id = "test_ccap_core"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_DHCP
        event_request.action.parameter = "lo"
        event_request.action.action = pb2.msg_event.START

        sock_push.send(event_request.SerializeToString())

        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # start a second core request in the same interface
        event_request = pb2.api_request()
        reg = pb2.msg_core_register()
        reg.mgr_id = "test_mgr" # use a fake ccap id
        reg.ccap_core_id = "test_ccap_core_2"
        reg.action = pb2.msg_core_register.REG
        event_request.core_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        event_request = pb2.msg_event_request()
        event_request.action.id = "test_ccap_core"
        event_request.action.ccap_core_id = "test_ccap_core_2"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_DHCP
        event_request.action.parameter = "lo"
        event_request.action.action = pb2.msg_event.START

        sock_push.send(event_request.SerializeToString())

        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # test dhcp client send message to the agent
        print 'DHCP client send the dhcp message to agent'
        dhcp_msg = t_DhcpMessage()
        dhcp_msg.InterfaceName = 'lo'
        dhcp_msg.Status = dhcp_msg.UPDATED
        dhcp_msg.Client = dhcp_msg.DHCPV4
        dhcp_data = dhcp_msg.DHCPData
        dhcp_data.TimeServers.extend(['2.2.2.2', '1.1.1.1'])
        dhcp_data.LogServers.extend(['2.2.2.2', '1.1.1.1'])
        dhcp_data.CCAPCores.extend(['2.2.2.2',])
        dhcp_data.TimeOffset = 0
        self.dhcp_client_transport.sock.send(dhcp_msg.SerializeToString())
        time.sleep(5)

        dhcp_msg.InterfaceName = 'eth0'
        dhcp_msg.Status = dhcp_msg.UPDATED
        self.dhcp_client_transport.sock.send(dhcp_msg.SerializeToString())
        time.sleep(5)

        dhcp_msg.Status = dhcp_msg.FAILED
        self.dhcp_client_transport.sock.send(dhcp_msg.SerializeToString())
        time.sleep(5)

        dhcp_msg.Status = dhcp_msg.INITIATED
        self.dhcp_client_transport.sock.send(dhcp_msg.SerializeToString())
        time.sleep(5)

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "test_ccap_core"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_DHCP
        event_request.action.parameter = "lo"
        event_request.action.ccap_core_id = "test_ccap_core"
        event_request.action.action = pb2.msg_event.STOP
        sock_push.send(event_request.SerializeToString())

        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print rsp

        # unregister the ccapcore
        event_request = pb2.api_request()
        reg = pb2.msg_core_register()
        reg.mgr_id = "test_mgr" # use a fake ccap id
        reg.ccap_core_id = "test_ccap_core"
        reg.action = pb2.msg_core_register.UNREG
        event_request.core_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)

        # unregister the mgr
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "test_mgr" # use a fake ccap id
        reg.action = pb2.msg_manager_register.UNREG
        reg.path_info = "ipc:///tmp/test_dhcp_agent.scok"
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)


class TestDhcpAgentFunc(unittest.TestCase):

    def setUp(self):
        setup_logging(("PROVISION", "DHCP"), filename="provision_dhcp.log")
        self.agent = DhcpAgent(simulate_mode=True)
        self.agent.ccap_cores['CORE-1234567890'] = {"mgr": "MGR-1234567890", }
        self.agent.dhcp['eth0'] = {
            "status": self.agent.DOWN,
            "requester": ['CORE-1234567890', ],
            "lastChangeTime": 1,
            "transport": self.agent.process_transport,
            "initiated_by": None,
        }

        path = "ipc:///tmp/rcp.scok"
        transport = Transport(
            path, Transport.PUSHSOCK, Transport.TRANSPORT_CLIENT)

        # Add the fsm to our internal database
        self.agent.mgrs["MGR-1234567890"] = {
            "transport": transport,
            "name": "DHCP",
            "para": {},
            "path": path,
        }

        # init agent dhcpv6 process
        self.agent.start_dhcpv6('eth0')

    def tearDown(self):
        self.agent.mgrs["MGR-1234567890"]['transport'].sock.close()
        self.agent.process_transport.sock.close()
        self.agent = None
        os.system("rm /tmp/ProcessAgent_AGENTTYPE_DHCP")

    def test_start_dhcpv4(self):
        try:
            self.agent.start_dhcpv4('eth0')
        except Exception as e:
            self.assertEqual(OSError, type(e))

    def test_interrupt_handler(self):
        try:
            # interface not in processes
            self.agent._dhcp_no_lease('eth1')
            # interface in processes
            self.agent._dhcp_timeout_cb('eth0')
        except Exception as e:
            self.assertEqual(OSError, type(e))

        self.agent.delete_dhcp_data()

    def test_cleanup_db(self):
        self.agent.cleanup_db('CORE-1234567890')


    def test_process_event_action(self):
        print '############test process_event_action error case#############'
        req = pb2.msg_event_request()

        # core id not exist
        req.action.ccap_core_id = "CORE-0"
        self.agent.process_event_action(req.action)

        # no parameter field
        req.action.ccap_core_id = "CORE-1234567890"
        self.agent.process_event_action(req.action)

        # unknown action
        req.action.event_id = self.agent.id
        req.action.action = pb2.msg_event.UNKNOWN
        req.action.parameter = json.dumps("UNKNOWN")
        self.agent.process_event_action(req.action)

        # start
        self.agent.ccap_cores['CORE-1234567891'] = {"mgr": "MGR-1234567890",}
        req.action.ccap_core_id = "CORE-1234567891"
        req.action.parameter = "eth0"
        req.action.action = pb2.msg_event.START
        self.agent.process_event_action(req.action)

        # the same start
        self.agent.dhcp = dict()
        self.agent.process_event_action(req.action)

        # stop
        req.action.action = pb2.msg_event.STOP
        self.agent.process_event_action(req.action)

    def test_dhcp_msg_cb_error(self):
        # mask is 0
        self.agent.dhcp_msg_cb(self.agent.process_transport.sock, 0)

        # mask is self.dispatcher.EV_FD_ERR
        self.agent.dhcp_msg_cb(self.agent.process_transport.sock, self.agent.dispatcher.EV_FD_ERR)


if __name__ == "__main__":
    unittest.main()
