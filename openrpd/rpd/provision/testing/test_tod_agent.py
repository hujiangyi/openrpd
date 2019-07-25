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
import zmq
import time
import rpd.provision.proto.process_agent_pb2 as pb2
from rpd.gpb.tpc_pb2 import t_TpcMessage
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.process_agent.tod.tod_agent import TimeOfDay
from subprocess import call, Popen
import signal


class TestTodAgent(unittest.TestCase):

    def setUp(self):
        # try to find the tod agent
        currentPath = os.path.split(os.path.realpath(__file__))[0]
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") - 2
        self.rootpath = "/".join(dirs[:rpd_index])
        self.pid = Popen("coverage run --parallel-mode --rcfile=" + self.rootpath + "/.coverage.rc "
                         + "/".join(dirs[:rpd_index]) +
                         "/rpd/provision/process_agent/tod/tod_agent.py",
                         executable='bash', shell=True)

    def tearDown(self):
        self.pid.send_signal(signal.SIGINT)
        self.pid.wait()
        self.pid = None
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')
        call(["killall", "python"])

    def test_tod_start_checkStatus_stop(self):
        context = zmq.Context()
        sock_push = context.socket(zmq.PUSH)
        sock_push.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_TOD]['pull'])

        sock_api = context.socket(zmq.REQ)
        sock_api.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_TOD]['api'])

        sock_pull = context.socket(zmq.PULL)
        sock_pull.bind("ipc:///tmp/test_tod_agent.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "test_mgr"  # use a fake ccap id
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = "ipc:///tmp/test_tod_agent.sock"
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
        reg.mgr_id = "test_mgr"  # use a fake ccap id
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
        event_request.action.event_id = ProcessAgent.AGENTTYPE_TOD
        event_request.action.parameter = "127.0.0.1/10|127.0.0.1"
        event_request.action.action = pb2.msg_event.START

        sock_push.send(event_request.SerializeToString())

        # we want to receive 2 notifications, 1 for check status initial, 2 for the status update
        # but it's waste time if there is no time server, as tpc client will
        # retry
        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)

        # same parameter resend
        # event_request.action.ccap_core_id = "test_ccap_core"
        sock_push.send(event_request.SerializeToString())
        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "test_ccap_core"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_TOD
        event_request.action.parameter = "127.0.0.1/10|127.0.0.1"
        event_request.action.ccap_core_id = "test_ccap_core"
        event_request.action.action = pb2.msg_event.STOP
        sock_push.send(event_request.SerializeToString())
        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)

        # test wrong ccap core id
        event_request = pb2.msg_event_request()
        event_request.action.id = "test_wrong_ccap_id"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_TOD
        event_request.action.parameter = "0.0.0.1/10|0.0.0.1"
        event_request.action.ccap_core_id = "test_wrong_ccap_id"
        event_request.action.action = pb2.msg_event.START
        sock_push.send(event_request.SerializeToString())

        # test no parameter
        event_request = pb2.msg_event_request()
        event_request.action.id = "test_ccap_core"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_TOD
        event_request.action.ccap_core_id = "test_ccap_core"
        event_request.action.action = pb2.msg_event.STOP
        sock_push.send(event_request.SerializeToString())
        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)

        # test no timeoffset and no log server
        event_request.action.parameter = "10.0.0.1/|"
        sock_push.send(event_request.SerializeToString())
        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print(rsp)

        # test illegal parameter
        event_request.action.parameter = "hahaha"
        sock_push.send(event_request.SerializeToString())
        data = sock_pull.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print(rsp)

        # test ipc_msg_call back
        # simulate tpc send to tod_agent
        kill_cmd = "kill -9 `pgrep -f tpc.py`"
        call(kill_cmd, shell=True)
        tod_sock_push = context.socket(zmq.PUSH)
        tod_sock_push.connect(TimeOfDay.SOCK_ADDRESS)
        tpc_msg = t_TpcMessage()
        tpc_msg.Status = tpc_msg.INITIATED
        msg_str = tpc_msg.SerializeToString()
        tod_sock_push.send(msg_str)
        time.sleep(2)
        tpc_msg.Status = tpc_msg.SUCCESS
        msg_str = tpc_msg.SerializeToString()
        tod_sock_push.send(msg_str)
        time.sleep(2)
        tpc_msg.Timestamp = 500
        msg_str = tpc_msg.SerializeToString()
        tod_sock_push.send(msg_str)
        time.sleep(2)
        tpc_msg.Timestamp = 500
        msg_str = tpc_msg.SerializeToString()
        tod_sock_push.send(msg_str)
        time.sleep(2)
        tpc_msg.Status = tpc_msg.FIRST_ATTEMPT_FAILED
        msg_str = tpc_msg.SerializeToString()
        tod_sock_push.send(msg_str)
        time.sleep(2)
        tpc_msg.Status = tpc_msg.ALL_ATTEMPTS_FAILED
        msg_str = tpc_msg.SerializeToString()
        tod_sock_push.send(msg_str)
        time.sleep(2)
        tod_sock_push.close()

        # unregister the ccapcore
        event_request = pb2.api_request()
        reg = pb2.msg_core_register()
        reg.mgr_id = "test_mgr"  # use a fake ccap id
        reg.ccap_core_id = "test_ccap_core"
        reg.action = pb2.msg_core_register.UNREG
        event_request.core_reg.CopyFrom(reg)
        data = event_request.SerializeToString()
        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print(reg_rsp)

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)

        # unregister the mgr
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "test_mgr"  # use a fake ccap id
        reg.action = pb2.msg_manager_register.UNREG
        reg.path_info = "ipc:///tmp/test_tod_agent.sock"
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print(reg_rsp)

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)


if __name__ == "__main__":
    unittest.main()
