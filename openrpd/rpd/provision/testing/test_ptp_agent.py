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
import subprocess
import signal
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification
from rpd.hal.src.HalConfigMsg import MsgTypeGeneralNtf, MsgTypeRoutePtpStatus, \
    MsgTypePtpClockStatus, MsgTypeRpdState
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.provision.process_agent.ptp1588.ptp_agent import HalPtpClient


class TestPtpAgent(unittest.TestCase):

    def setUp(self):
        print "PTP setup"
        # try to find the ptp agent
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") - 2
        self.rootpath = "/".join(dirs[:rpd_index])
        self.start_hal()
        # HAL need some time to work
        time.sleep(5)
        self.mastersim_pid = None
        self.pid = subprocess.Popen("coverage run --parallel-mode --rcfile=" + self.rootpath + "/.coverage.rc "
                                    + self.rootpath +
                                    "/rpd/provision/process_agent/ptp1588/ptp_agent.py",
                                    executable='bash', shell=True)

    def tearDown(self):
        print "tearDown PTP"
        self.pid.send_signal(signal.SIGINT)
        print "INT"
        self.pid.wait()
        self.pid = None
        self.stop_mastersim()
        self.stop_hal()
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')

    def setup_db(self):
        cmd = "redis-server --version"
        output = subprocess.check_output(cmd.split(" "))
        if output.find("Redis") < 0:
            raise Exception("Cannot find redis installation")

        # start a redis server
        configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
                               "/tmp/redis.sock" + " \nunixsocketperm 700\n"
        filename = "./test_ptp.conf"
        with open(filename, "w") as f:
            f.write(configurefileContent)

        self.redis_pid = subprocess.Popen("redis-server " + filename,
                                          executable='bash',
                                          shell=True)

        timeOut = time.time() + 5
        while time.time() < timeOut:
            if os.path.exists("/tmp/redis.sock"):
                break
            time.sleep(1)

        if time.time() > timeOut:
            raise Exception("Cannot setup the redis")

    def start_hal(self):
        self.setup_db()
        self.hal_pid = \
            subprocess.Popen("coverage run --parallel-mode --rcfile=" + self.rootpath + "/.coverage.rc "
                             + self.rootpath + "/rpd/hal/src/HalMain.py"
                             + " --conf=" + self.rootpath + "/rpd/hal/conf/hal.conf",
                             executable='bash', shell=True
                             )

    def stop_hal(self):
        if getattr(self, 'hal_pid', None) is None:
            pass
        else:
            print "Int hal"
            # self.hal_pid.kill()
            self.hal_pid.send_signal(signal.SIGINT)
            self.hal_pid.wait()
            self.hal_pid = None
        if getattr(self, 'redis_pid', None) is None:
            pass
        else:
            print "Int redis"
            # self.redis_pid.kill()
            self.redis_pid.send_signal(signal.SIGINT)
            self.redis_pid.wait()
            self.redis_pid = None

    def start_mastersim(self):
        # try to find the l2tp agent
        self.mastersim_pid = subprocess.Popen("coverage run --parallel-mode --rcfile=" + self.rootpath + "/.coverage.rc "
                                              + self.rootpath +
                                              "/rpd/hal/lib/drivers/HalPtpDriver.py -s",
                                              executable='bash', shell=True
                                              )

    def stop_mastersim(self):
        if getattr(self, 'mastersim_pid', None) is None:
            pass
        else:
            self.mastersim_pid.send_signal(signal.SIGINT)
            self.mastersim_pid.wait()
            self.mastersim_pid = None

    def test_ptp_start_checkStatus_stop(self):
        context = zmq.Context()
        sock_push = context.socket(zmq.PUSH)
        sock_push.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_PTP]['pull'])

        sock_api = context.socket(zmq.REQ)
        sock_api.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_PTP]['api'])

        sock_pull = context.socket(zmq.PULL)
        sock_pull.bind("ipc:///tmp/test_ptp_agent.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "test_mgr"  # use a fake ccap id
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = "ipc:///tmp/test_ptp_agent.sock"
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
        event_request.action.event_id = ProcessAgent.AGENTTYPE_PTP
        event_request.action.parameter = ''
        event_request.action.action = pb2.msg_event.START

        sock_push.send(event_request.SerializeToString())
        if self.mastersim_pid is None:
            self.start_mastersim()
        # we want to receive 2 notifications, 1 for check status initial, 2 for
        # the status update
        timeout = time.time() + 60
        i = 2
        while i > 0 and time.time() < timeout:
            try:
                data = sock_pull.recv(flags=zmq.NOBLOCK)
            except Exception as e:
                print "Got exception: %s" % (str(e))
                time.sleep(1)
                continue
            else:
                rsp = pb2.msg_event_notification()
                rsp.ParseFromString(data)
                print rsp
            i -= 1

        self.assertEqual(i, 0)

        # test stop
        event_request = pb2.msg_event_request()
        event_request.action.id = "test_ccap_core"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_PTP
        event_request.action.parameter = ''
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
        reg.mgr_id = "test_mgr"  # use a fake ccap id
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
        reg.id = "test_mgr"  # use a fake ccap id
        reg.action = pb2.msg_manager_register.UNREG
        reg.path_info = "ipc:///tmp/test_ptp_agent.sock"
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock_api.send(data)

        data = sock_api.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print reg_rsp

        self.assertEqual(reg_rsp.reg_rsp.status, reg_rsp.reg_rsp.OK)


class TestPtpAgentMulti(TestPtpAgent):

    def setUp(self):
        self.instance_id = "0"
        os.environ['INSTANCE_ID'] = str(self.instance_id)
        super(TestPtpAgentMulti, self).setUp()

    def tearDown(self):
        super(TestPtpAgentMulti, self).tearDown()
        del os.environ['INSTANCE_ID']


class TestPtpHalPtpClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global_dispatcher = Dispatcher()
        cls.hal_client =\
            HalPtpClient("PTPClient", "This is a PTP application", "1.9.0",
                         [MsgTypeRoutePtpStatus, MsgTypeGeneralNtf, ],
                         [MsgTypePtpClockStatus, MsgTypeRpdState, ],
                         global_dispatcher, None)

        cls.hal_client.pushSock = HalTransport(
            HalTransport.HalTransportClientAgentPull,
            HalTransport.HalClientMode, index=19,
            socketMode=HalTransport.HalSocketPushMode,
            disconnectHandlerCb=None)

    @classmethod
    def tearDownClass(cls):
        if cls.hal_client.pushSock:
            cls.hal_client.pushSock.close()

    def test_readRpdState(self):
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_READ
        cfg_payload = rcp_msg.SerializeToString()

        queryPtpMsg = HalMessage("HalConfig", SrcClientID="testMsgTypeRpdState",
                                 SeqNum=325,
                                 CfgMsgType=HalConfigMsg.MsgTypeRpdState,
                                 CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(queryPtpMsg)
        self.assertTrue(self.hal_client.ptp_result == t_GeneralNotification.PTPACQUIRE)


if __name__ == "__main__":
    unittest.main()
