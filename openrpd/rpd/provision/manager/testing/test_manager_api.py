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
import rpd.provision.proto.provision_pb2 as provision_pb2
import time
import json
import os
import threading
from rpd.provision.manager.src.manager_process import ManagerProcess
from rpd.provision.manager.src.manager_ccap_core import CCAPCore
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.statistics.provision_stat import ProvisionStateMachineRecord
from rpd.provision.manager.src.manager_api import ManagerApi
from rpd.confdb.rpd_redis_db import RCPDB
from rpd.confdb.testing.test_rpd_redis_db import create_db_conf,\
    start_redis, stop_redis

uTMgrProcess = None
uTMgrApiDispatch = None
CONF_FILE = '/tmp/rcp_db.conf'
SOCKET_PATH = '/tmp/testRedis.sock'


def demoMgrProcess():
    global uTMgrProcess
    global uTMgrApiDispatch
    print "demoMgrProcess thread start!"
    uTMgrProcess = ManagerProcess(test_flag=True)
    uTMgrApiDispatch = uTMgrProcess.dispatcher
    uTMgrProcess.start()
    print "demoMgrProcess thread done!"


def stop_dispatcher_loop(disp):
    disp.end_loop()
    start_time = time.time()
    time_elapsed = 0
    while (not disp.loop_stopped) and time_elapsed < disp.max_timeout_sec:
        time.sleep(0.1)
        time_elapsed = time.time() - start_time


class TestClassManagerApi(ManagerApi):
    API_SOCK_PATH = "ipc:///tmp/_tmp_ut_rpd_provision_manager_api.sock"


class TestManagerAPI(unittest.TestCase):
    """test CLI or other external module request to provision.

    1. add a new ccap core
    2. delete exist ccap core

    """

    @classmethod
    def setUpClass(cls):
        global uTMgrProcess
        create_db_conf()
        start_redis()
        RCPDB.DB_CFG_FILE = CONF_FILE
        t = threading.Thread(target=demoMgrProcess)
        t.start()
        time.sleep(2)
        cls.mgr = uTMgrProcess
        cls.api = TestClassManagerApi(uTMgrProcess, uTMgrProcess.dispatcher)

    @classmethod
    def tearDownClass(cls):
        global uTMgrApiDispatch
        global uTMgrProcess
        stop_redis()
        os.remove(CONF_FILE)
        if uTMgrApiDispatch is not None:
            print "end loop here"
            stop_dispatcher_loop(uTMgrApiDispatch)
        if cls.api:
            uTMgrProcess.dispatcher.fd_unregister(cls.api.manager_api_sock.sock)
            time.sleep(1)
            cls.api.manager_api_sock.sock.close()
        if uTMgrProcess is not None:
            uTMgrProcess.dispatcher.fd_unregister(uTMgrProcess.mgr_api.manager_api_sock.sock)
            time.sleep(1)
            uTMgrProcess.mgr_api.manager_api_sock.sock.close()

    def setUp(self):
        time.sleep(1)
        context = zmq.Context()
        self.sock = context.socket(zmq.REQ)
        self.sock.connect(TestClassManagerApi.API_SOCK_PATH)

    def tearDown(self):
        self.sock.close()
        while len(CCAPCore.ccap_core_db):
            core_id = CCAPCore.ccap_core_db.keys()[0]
            if isinstance(CCAPCore.ccap_core_db[core_id], CCAPCore):
                CCAPCore.ccap_core_db[core_id].del_ccap_core()
            else:
                CCAPCore.ccap_core_db.pop(core_id)
        pass

    def test_manager_ctrl(self):
        global uTMgrApiDispatch
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SET_PROVISION_LOG_LEVEL
        msg.parameter = str(1)
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SET_PROVISION_LOG_LEVEL
        msg.parameter = str(100)
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SET_PROVISION_LOG_LEVEL
        msg.parameter = str(100)
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SET_PC_REBOOT_HOLD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SET_PC_REBOOT_HOLD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.REBOOT
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PC_REBOOT_HOLD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.CLEAR_PC_REBOOT_HOLD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PC_REBOOT_HOLD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.REBOOT
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.REBOOT
        msg.parameter = 'force'
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        uTMgrApiDispatch._tm._timers.clear()

    def test_manager_agent_info(self):
        self.mgr.dhcp_parameter['lo'] = "dummy dhcp info"
        interface = 'lo;127.0.0.1'
        para_set = []

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        para.parameter = interface
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_TOD
        para.parameter = "127.0.0.1/10|127.0.0.1"
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_DHCP
        para.parameter = "lo"
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_GCP
        para.parameter = interface
        para_set.append(para)

        core, reason = CCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)

        print core.ccap_core_id
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_INTERFACE_STATUS
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_DHCP
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_TOD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_GCP
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        # branch cover
        interface = 'dummy;127.0.0.1'
        para_set = []

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        para.parameter = interface
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_TOD
        para.parameter = "127.0.0.1/10|127.0.0.1"
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_DHCP
        para.parameter = "lo"
        para_set.append(para)

        core, reason = CCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)

        print core.ccap_core_id
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_INTERFACE_STATUS
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_DHCP
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_TOD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_GCP
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        # tod time offset cover
        para_set = []
        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_TOD
        para.parameter = "127.0.0.2/|127.0.0.2"
        para_set.append(para)
        core, reason = CCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)

        print core.ccap_core_id
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_TOD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        # tod branch cover
        para_set = []
        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_TOD
        para.parameter = "dummy tod para"
        para_set.append(para)
        core, reason = CCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)

        print core.ccap_core_id
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_TOD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        # use None core to cover exception
        CCAPCore.ccap_core_db['none'] = None
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_INTERFACE_STATUS
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_DHCP
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_TOD
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_GCP
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        CCAPCore.ccap_core_db.pop('none')

    def test_manager_ssd(self):
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SSD_GET_AF_TYPE
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        # ctrl_rsp = provision_pb2.msg_magager_api_rsp()
        parameter = json.loads(msg.parameter)
        # ctrl_rsp.ParseFromString(parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SSD_START
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        # ctrl_rsp = provision_pb2.msg_magager_api_rsp()
        parameter = json.loads(msg.parameter)
        # ctrl_rsp.ParseFromString(parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SSD_END
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        # ctrl_rsp = provision_pb2.msg_magager_api_rsp()
        parameter = json.loads(msg.parameter)
        # ctrl_rsp.ParseFromString(parameter)
        print msg, parameter

    def test_manager_cnt(self):
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_STATE_HISTORY
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter
        seek_core = None
        for i, d in parameter.items():
            for core, sta in d.items():
                seek_core = core
                print seek_core
                break
            if seek_core:
                print '*' * 80
                msg = provision_pb2.t_Provision()
                msg.MsgType = msg.SHOW_PROVISION_CORE_STATISTIC
                msg.parameter = str(seek_core)
                self.sock.send(msg.SerializeToString())

                data = self.sock.recv()
                msg = provision_pb2.t_Provision()
                msg.ParseFromString(data)
                parameter = str(json.loads(msg.parameter))
                print msg, parameter
                break

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_CORE_STATISTIC
        msg.parameter = '1234567'
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = str(json.loads(msg.parameter))
        print msg, parameter

        # exception case
        self.mgr.manager_statistics = None
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_MANAGER_STATE_HISTORY
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.CLEAR_PROVISION_STATE_HISTORY
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = str(json.loads(msg.parameter))
        print msg, parameter

        # exception case
        CCAPCore.core_statistics = None
        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.SHOW_PROVISION_STATE_HISTORY
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter

        print '*' * 80
        msg = provision_pb2.t_Provision()
        msg.MsgType = msg.CLEAR_PROVISION_STATE_HISTORY
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = str(json.loads(msg.parameter))
        print msg, parameter
        CCAPCore.core_statistics = ProvisionStateMachineRecord()

    def test_manager_core(self):
        # get_provision_all
        interface = 'lo;127.0.0.1'
        para_set = []
        for agent_id in range(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, ProcessAgent.AGENTTYPE_L2TP + 1):
            para = provision_pb2.msg_agent_parameter()
            para.agent_id = agent_id
            para.parameter = interface
            para_set.append(para)
        core, reason = CCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)
        print core.ccap_core_id
        interface = "default"
        para_set = []
        for agent_id in range(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, ProcessAgent.AGENTTYPE_L2TP + 1):
            para = provision_pb2.msg_agent_parameter()
            para.agent_id = agent_id
            para.parameter = interface
            para_set.append(para)
        core, reason = CCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)
        print core.ccap_core_id

        CCAPCore.ccap_core_db['none'] = None

        # self.api = TestClassManagerApi(self.mgr, self.mgr.dispatcher)

        print '*' * 80
        print 'Simulate show provision all from external module'
        msg = provision_pb2.t_Provision()
        msg.MsgType = provision_pb2.t_Provision.SHOW_PROVISION_ALL
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter, len(parameter)
        print '*' * 80

        CCAPCore.ccap_core_db.pop('none')

        print '*' * 80
        print 'Simulate show provision all from external module'
        msg = provision_pb2.t_Provision()
        msg.MsgType = provision_pb2.t_Provision.SHOW_PROVISION_ALL
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter, len(parameter)
        print '*' * 80

        print '*' * 80
        print 'Simulate show provision core from external module'
        msg = provision_pb2.t_Provision()
        msg.MsgType = provision_pb2.t_Provision.SHOW_PROVISION_CCAP_CORE_ALL
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter, len(parameter)
        print '*' * 80

        # get_provision_ccap_core_info
        core, reason = CCAPCore.add_ccap_core(
            self.mgr, [],
            initiated_by="DHCP",
            interface="default",
            test_flag=True)
        print core.ccap_core_id
        print '*' * 80
        print 'Simulate show provision ccap core information from external module'
        msg = provision_pb2.t_Provision()
        msg.MsgType = provision_pb2.t_Provision.SHOW_PROVISION_CCAP_CORE
        msg.parameter = core.ccap_core_id
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter
        print '*' * 80

        print '*' * 80
        print 'Simulate show provision unknown ccap core information from external module'
        msg = provision_pb2.t_Provision()
        msg.MsgType = provision_pb2.t_Provision.SHOW_PROVISION_CCAP_CORE
        msg.parameter = "12345678"
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter
        print '*' * 80

        # unsupported msg type
        print '*' * 80
        print 'Simulate req unsupported msg type from external module'
        msg = provision_pb2.t_Provision()
        msg.MsgType = provision_pb2.t_Provision.TEST_PROVISION_CCAP_CORE_REMOVE_CORE
        msg.parameter = "12345678"
        self.sock.send(msg.SerializeToString())

        data = self.sock.recv()
        msg = provision_pb2.t_Provision()
        msg.ParseFromString(data)
        parameter = json.loads(msg.parameter)
        print msg, parameter
        print '*' * 80

    def test_manager_handle(self):
        print '-' * 80
        print 'test_manager_handle'
        self.api._handle_manager_api(self.api.manager_api_sock.sock, 0)
        self.api._handle_manager_api("dummy sock", self.mgr.dispatcher.EV_FD_ERR)
        self.api._handle_manager_api(self.api.manager_api_sock.sock, self.mgr.dispatcher.EV_FD_ERR)
        self.api._handle_manager_api(self.api.manager_api_sock.sock, self.mgr.dispatcher.EV_FD_IN)

        tmp_api_sock = self.api.manager_api_sock
        self.api.manager_api_sock = None
        self.api._handle_manager_api("dummy sock", self.mgr.dispatcher.EV_FD_ERR)
        self.api.manager_api_sock = tmp_api_sock


if __name__ == '__main__':
    unittest.main()
