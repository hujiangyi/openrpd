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
import threading
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.provision.manager.src.manager_process import ManagerProcess
from rpd.provision.manager.src.manager_ccap_core import CoreDescription, CCAPCore, ManagerCoreError
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.transport.transport import Transport
from rpd.statistics.provision_stat import ProvisionStateMachineRecord
from rpd.provision.manager.src.manager_api import ManagerApi
from rpd.gpb.CcapCoreIdentification_pb2 import t_CcapCoreIdentification

uTMgrProcess = None
uTMgrApiDispatch = None


class TestCCAPCore(CCAPCore):
    TIMEOUT_CHECK_CORE_REG = 20

    @staticmethod
    def set_fsm_state():
        #cls.mgr.dhcp_parameter['lo'] = "dummy dhcp info"
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

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_IPSEC
        para.parameter = "success"
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_8021X
        para.parameter = "success"
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_PTP
        para.parameter = "success"
        para_set.append(para)

        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_L2TP
        para.parameter = "success"
        para_set.append(para)
        return para_set


def demoMgrProcess():
    global uTMgrProcess
    global uTMgrApiDispatch
    print "demoMgrProcess thread start!"
    uTMgrProcess = ManagerProcess(test_flag=True)
    uTMgrApiDispatch = uTMgrProcess.dispatcher
    uTMgrProcess.start()
    print "demoMgrProcess thread done!"

class TestCoreDescription(unittest.TestCase):
    def test_core_desc(self):
        fault_flag = False
        try:
            CoreDescription(999, 999)
        except ValueError:
            fault_flag = True
        self.assertTrue(fault_flag)

        desc = CoreDescription(CoreDescription.CORE_ROLE_AUXILIARY,
                               CoreDescription.CORE_MODE_STANDBY)
        self.assertEqual(desc.role,
                         CoreDescription.CORE_ROLE_AUXILIARY)
        self.assertEqual(desc.mode,
                         CoreDescription.CORE_MODE_STANDBY)

        self.assertEqual(CoreDescription.role_str(999), '')
        self.assertEqual(CoreDescription.mode_str(999), '')
        self.assertEqual(CoreDescription.role_str(CoreDescription.CORE_ROLE_AUXILIARY),
                         CoreDescription.role_mapping[CoreDescription.CORE_ROLE_AUXILIARY])
        self.assertEqual(CoreDescription.mode_str(CoreDescription.CORE_MODE_STANDBY),
                         CoreDescription.mode_mapping[CoreDescription.CORE_MODE_STANDBY])


class TestManagerCore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global uTMgrProcess
        t = threading.Thread(target=demoMgrProcess)
        t.start()
        time.sleep(2)
        cls.mgr = uTMgrProcess

    @classmethod
    def tearDownClass(cls):
        global uTMgrApiDispatch
        global uTMgrProcess
        if uTMgrProcess is not None:
            uTMgrProcess.dispatcher.fd_unregister(uTMgrProcess.mgr_api.manager_api_sock.sock)
            time.sleep(1)
            uTMgrProcess.mgr_api.manager_api_sock.sock.close()
        if uTMgrApiDispatch is not None:
            print "end loop here"
            uTMgrApiDispatch.end_loop()
            time.sleep(2)

    def setUp(self):
        pass

    def fake_cb(self):
        pass

    def tearDown(self):
        while len(TestCCAPCore.ccap_core_db):
            core_id = TestCCAPCore.ccap_core_db.keys()[0]
            if isinstance(TestCCAPCore.ccap_core_db[core_id], TestCCAPCore):
                TestCCAPCore.ccap_core_db[core_id].del_ccap_core()
            else:
                TestCCAPCore.ccap_core_db.pop(core_id)
        pass

    def test_core_info(self):
        fault_flag = False
        try:
            TestCCAPCore("dummy")
        except ManagerCoreError:
            fault_flag = True
        self.assertTrue(fault_flag)

        while len(TestCCAPCore.ccap_core_db):
            core_id = TestCCAPCore.ccap_core_db.keys()[0]
            if isinstance(TestCCAPCore.ccap_core_db[core_id], TestCCAPCore):
                TestCCAPCore.ccap_core_db[core_id].del_ccap_core()
            else:
                TestCCAPCore.ccap_core_db.pop(core_id)
        self.assertTrue(TestCCAPCore.is_empty())

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

        # should return None because we didn't start any agent
        tmp_sock = Transport("ipc:///tmp/_tmp_api_socket", Transport.REQSOCK, Transport.TRANSPORT_CLIENT)
        self.mgr.process_agent_db[ProcessAgent.AGENTTYPE_INTERFACE_STATUS] = {
            "status": self.mgr.REGISTER_INITIATED_STATUS,
            "apiSock": tmp_sock,
            "sendSock": "/tmp/_tmp_api_send_socket",
            "recvSock": "/tmp/_tmp_api_recv_socket",
            "ka_stat": 3,
        }
        core, reason = TestCCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=False)
        self.mgr.process_agent_db.pop(ProcessAgent.AGENTTYPE_INTERFACE_STATUS)
        tmp_sock.sock.close()
        self.assertIsNone(core)

        core, reason = TestCCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)
        print core.ccap_core_id

        self.assertFalse(TestCCAPCore.is_empty())
        self.assertTrue(TestCCAPCore.is_ccap_core_existed(interface, None))
        self.assertFalse(TestCCAPCore.is_ccap_core_existed("nosuchif", None))

        para_set = []
        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_L2TP
        para.parameter = "dummy"
        para_set.append(para)
        ret, value = core.update_ccap_core_parameter(para_set)
        self.assertFalse(ret)

        self.mgr.process_agent_db[ProcessAgent.AGENTTYPE_TOD] = {
            "status": self.mgr.REGISTER_INITIATED_STATUS,
            "apiSock": "/tmp/_tmp_api_socket",
            "sendSock": "/tmp/_tmp_api_send_socket",
            "recvSock": "/tmp/_tmp_api_recv_socket",
            "ka_stat": 3,
        }

        para_set = []
        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_TOD
        para.parameter = "127.0.0.1/10|127.0.0.1"
        para_set.append(para)
        ret, value = core.update_ccap_core_parameter(para_set)
        self.assertTrue(ret)

        info_update = protoDef.msg_agent_info_update()
        info_update.ccap_core_id = core.ccap_core_id
        info_update.ccap_core_identification.CoreId = core.ccap_core_id
        info_update.ccap_core_identification.CoreIpAddress = "127.0.0.1"
        info_update.ccap_core_identification.IsPrincipal = 1
        info_update.ccap_core_identification.CoreName = "dummy_name"
        info_update.ccap_core_identification.VendorId = 9
        info_update.ccap_core_identification.CoreMode = t_CcapCoreIdentification.COREMODEACTIVE
        info_update.ccap_core_identification.Index = 0
        TestCCAPCore.handle_agent_info_update(info_update, ProcessAgent.AGENTTYPE_GCP)

        info_update = protoDef.msg_agent_info_update()
        info_update.ccap_core_id = core.ccap_core_id
        info_update.ccap_core_identification.CoreIpAddress = "127.0.0.1"
        info_update.ccap_core_identification.IsPrincipal = 1
        info_update.ccap_core_identification.CoreMode = t_CcapCoreIdentification.COREMODEACTIVE
        TestCCAPCore.handle_agent_info_update(info_update, ProcessAgent.AGENTTYPE_GCP)

        info_update = protoDef.msg_agent_info_update()
        info_update.ccap_core_id = "dummy_id"
        TestCCAPCore.handle_agent_info_update(info_update, ProcessAgent.AGENTTYPE_GCP)

        tmp_id = core.ccap_core_id
        core.ccap_core_id = "nosuchcoreidindb"
        ret, val = core.del_ccap_core()
        self.assertFalse(ret)
        self.assertIn("Cannot find the ccap core id", val)
        core.ccap_core_id = tmp_id

        core.register_status[ProcessAgent.AGENTTYPE_INTERFACE_STATUS] = TestCCAPCore.CCAP_CORE_REGISTERED
        core.del_ccap_core()
        core.register_status[ProcessAgent.AGENTTYPE_INTERFACE_STATUS] = None


    def test_core_handle(self):
        self.mgr.dhcp_parameter['lo'] = "dummy dhcp info"
        interface = 'lo;127.0.0.1'
        para_set = TestCCAPCore.set_fsm_state()

        core, reason = TestCCAPCore.add_ccap_core(
            self.mgr, para_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)
        print core.ccap_core_id

        core.fsm.TRIGGER_Startup()
        # handle_core_event_notification normal case
        for event_id in range(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, ProcessAgent.AGENTTYPE_L2TP + 1):
            core_event = protoDef.msg_core_event_notification()
            core_event.id = core.ccap_core_id
            core_event.ccap_core_id = core.ccap_core_id
            core_event.status = core_event.OK
            core_event.reason = reason
            core_event.event_id = event_id
            core_event.result = "UP"
            TestCCAPCore.handle_core_event_notification(core_event, event_id)
            self.assertTrue(core.agent_status[event_id])

        for event_id in range(ProcessAgent.AGENTTYPE_L2TP, ProcessAgent.AGENTTYPE_INTERFACE_STATUS - 1, -1):
            core_event = protoDef.msg_core_event_notification()
            core_event.id = core.ccap_core_id
            core_event.ccap_core_id = core.ccap_core_id
            core_event.status = core_event.OK
            core_event.reason = reason
            core_event.event_id = event_id
            core_event.result = "Down"
            TestCCAPCore.handle_core_event_notification(core_event, event_id)
            self.assertFalse(core.agent_status[event_id])

        # fm change fail timer exits

        for event_id in range(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, ProcessAgent.AGENTTYPE_L2TP + 1):
            timer = core.dispatcher.timer_register(
                10, self.fake_cb)
            core.registered_timers[event_id] = timer

            core_event = protoDef.msg_core_event_notification()
            core_event.id = core.ccap_core_id
            core_event.ccap_core_id = core.ccap_core_id
            core_event.status = core_event.OK
            core_event.reason = reason
            core_event.event_id = event_id
            core_event.result = "UP"
            TestCCAPCore.handle_core_event_notification(core_event, event_id)
            self.assertIsNone(core.registered_timers[event_id])

        # can not find the core id
        core_event = protoDef.msg_core_event_notification()
        core_event.id = "dummy_id"
        core_event.ccap_core_id = "dummy_id"
        core_event.status = core_event.OK
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        core_event.result = "success"
        TestCCAPCore.handle_core_event_notification(core_event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

        # status is Fail
        core_event = protoDef.msg_core_event_notification()
        core_event.id = core.ccap_core_id
        core_event.ccap_core_id = core.ccap_core_id
        core_event.status = core_event.FAIL
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        core_event.result = "success"
        TestCCAPCore.handle_core_event_notification(core_event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

        # without result
        core_event = protoDef.msg_core_event_notification()
        core_event.id = core.ccap_core_id
        core_event.ccap_core_id = core.ccap_core_id
        core_event.status = core_event.OK
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        TestCCAPCore.handle_core_event_notification(core_event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)


    def test_gcp_optional_handle(self):
        self.mgr.dhcp_parameter['lo'] = "dummy dhcp info"
        interface = 'lo;127.0.0.1'
        param_set = TestCCAPCore.set_fsm_state()
        core, reason = TestCCAPCore.add_ccap_core(
            self.mgr, param_set,
            initiated_by="DHCP",
            interface=interface,
            test_flag=True)
        print core.ccap_core_id

        core.fsm.TRIGGER_Startup()
        # handle_core_event_notification normal case
        for event_id in range(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, ProcessAgent.AGENTTYPE_L2TP - 1):
            core_event = protoDef.msg_core_event_notification()
            core_event.id = core.ccap_core_id
            core_event.ccap_core_id = core.ccap_core_id
            core_event.status = core_event.OK
            core_event.reason = reason
            core_event.event_id = event_id
            core_event.result = "UP"
            TestCCAPCore.handle_core_event_notification(core_event, event_id)
            self.assertTrue(core.agent_status[event_id])

        core_event = protoDef.msg_core_event_notification()
        core_event.id = core.ccap_core_id
        core_event.ccap_core_id = core.ccap_core_id
        core_event.status = core_event.OK
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_GCP
        core_event.result = "OPERATIONAL"
        TestCCAPCore.handle_core_event_notification(core_event, event_id)
        self.assertTrue(core.agent_status[core_event.event_id])

        core_event = protoDef.msg_core_event_notification()
        core_event.id = core.ccap_core_id
        core_event.ccap_core_id = core.ccap_core_id
        core_event.status = core_event.OK
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_L2TP
        core_event.result = "UP"
        TestCCAPCore.handle_core_event_notification(core_event, event_id)
        self.assertFalse(core.agent_status[core_event.event_id])
        self.assertTrue(core.agent_status[ProcessAgent.AGENTTYPE_GCP])

        # can not find the core id
        core_event = protoDef.msg_core_event_notification()
        core_event.id = "dummy_id"
        core_event.ccap_core_id = "dummy_id"
        core_event.status = core_event.OK
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        core_event.result = "success"
        TestCCAPCore.handle_core_event_notification(core_event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

        # status is Fail
        core_event = protoDef.msg_core_event_notification()
        core_event.id = core.ccap_core_id
        core_event.ccap_core_id = core.ccap_core_id
        core_event.status = core_event.FAIL
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        core_event.result = "success"
        TestCCAPCore.handle_core_event_notification(core_event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

        # without result
        core_event = protoDef.msg_core_event_notification()
        core_event.id = core.ccap_core_id
        core_event.ccap_core_id = core.ccap_core_id
        core_event.status = core_event.OK
        core_event.reason = reason
        core_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        TestCCAPCore.handle_core_event_notification(core_event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

if __name__ == '__main__':
    unittest.main()
