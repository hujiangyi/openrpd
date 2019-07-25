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
import rpd.provision.proto.provision_pb2 as provision_pb2
import time
import json
import os
import threading
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.provision.manager.src.manager_process import ManagerProcess
from rpd.provision.manager.src.manager_ccap_core import CoreDescription, ManagerCoreError, CCAPCore
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.transport.transport import Transport
from rpd.statistics.provision_stat import ProvisionStateMachineRecord
from rpd.provision.manager.src.manager_api import ManagerApi
from rpd.gpb.CcapCoreIdentification_pb2 import t_CcapCoreIdentification
from rpd.provision.manager.src.manager_fsm import CCAPFsm, CCAPFsmStartup
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.provision.proto import process_agent_pb2
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.confdb.rpd_redis_db import RCPDB
from rpd.confdb.testing.test_rpd_redis_db import create_db_conf,\
    start_redis, stop_redis

uTMgrProcess = None
uTMgrApiDispatch = None
CONF_FILE = '/tmp/rcp_db.conf'
SOCKET_PATH = '/tmp/testRedis.sock'


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


def stop_dispatcher_loop(disp):
    disp.end_loop()
    start_time = time.time()
    time_elapsed = 0
    while (not disp.loop_stopped) and time_elapsed < disp.max_timeout_sec:
        time.sleep(0.1)
        time_elapsed = time.time() - start_time


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
        create_db_conf()
        start_redis()
        RCPDB.DB_CFG_FILE = CONF_FILE
        t = threading.Thread(target=demoMgrProcess)
        t.start()
        time.sleep(2)
        cls.mgr = uTMgrProcess

    @classmethod
    def tearDownClass(cls):
        global uTMgrApiDispatch
        global uTMgrProcess
        stop_redis()
        os.remove(CONF_FILE)
        if uTMgrApiDispatch is not None:
            print "end loop here"
            stop_dispatcher_loop(uTMgrApiDispatch)
        if uTMgrProcess is not None:
            uTMgrProcess.dispatcher.fd_unregister(uTMgrProcess.mgr_api.manager_api_sock.sock)
            time.sleep(1)
            uTMgrProcess.mgr_api.manager_api_sock.sock.close()

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
        for event_id in range(ProcessAgent.AGENTTYPE_IPSEC, ProcessAgent.AGENTTYPE_L2TP + 1):
            core_event = protoDef.msg_core_event_notification()
            core_event.id = core.ccap_core_id
            core_event.ccap_core_id = core.ccap_core_id
            core_event.status = core_event.OK
            core_event.reason = reason
            core_event.event_id = event_id
            core_event.result = "UP"
            TestCCAPCore.handle_core_event_notification(core_event, event_id)
            self.assertTrue(core.agent_status[event_id])

        for event_id in range(ProcessAgent.AGENTTYPE_L2TP, ProcessAgent.AGENTTYPE_IPSEC - 1, -1):
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

        for event_id in range(ProcessAgent.AGENTTYPE_IPSEC, ProcessAgent.AGENTTYPE_L2TP + 1):
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
        for event_id in range(ProcessAgent.AGENTTYPE_IPSEC, ProcessAgent.AGENTTYPE_L2TP - 1):
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


class TestCCAPCoreClass(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("PROVISION", "test.log")
        cls.mgr = ManagerProcess(simulator=True, test_flag=True)

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.startup_core = CCAPCore(ccap_core_id="test_startup", is_principal=CoreDescription.CORE_ROLE_NONE,
                                     is_active=CoreDescription.CORE_MODE_NONE,
                                     initiated="Startup",
                                     para=None, mgr=self.mgr, ccap_core_interface=None,
                                     ccap_core_network_address=None, added="Startup")
        self.startup_core.fsm.TRIGGER_Startup()

        self.gcp_core = CCAPCore(ccap_core_id="test_gcp_core", is_principal=CoreDescription.CORE_ROLE_NONE,
                                 is_active=CoreDescription.CORE_MODE_NONE,
                                 initiated="DHCP",
                                 para=None, mgr=self.mgr, ccap_core_interface=None,
                                 ccap_core_network_address=None, added="DHCP")
        self.gcp_core.fsm.TRIGGER_Startup()

    def tearDown(self):
        self.startup_core.del_ccap_core()
        self.gcp_core.del_ccap_core()

    def test_init(self):
        self.assertIsInstance(self.startup_core.fsm, CCAPFsmStartup)
        self.assertIsInstance(self.gcp_core.fsm, CCAPFsm)

    def test_startup_core_statechange(self):
        self.startup_core.fsm.TRIGGER_INTERFACE_UP()
        self.assertEqual(self.startup_core.fsm.current, CCAPFsmStartup.STATE_INTERFACE_UP)

    @staticmethod
    def build_event_notification(ccap_id, status, reason, result, agentid):
        """This is a private function, used to send the event notification.

        :param ccap_id: ccap core ID
        :param status: FAIL/OK
        :param reason: The fail reason
        :param result: The success result.
        :return: Node

        """
        msg_event_notification = process_agent_pb2.msg_event_notification()
        msg_event_notification.core_event.id = ccap_id
        msg_event_notification.core_event.ccap_core_id = ccap_id
        msg_event_notification.core_event.status = status
        msg_event_notification.core_event.reason = reason
        msg_event_notification.core_event.event_id = agentid
        msg_event_notification.core_event.result = result
        return msg_event_notification.core_event

    def test_handle_core_interface_up_event(self):
        msg = self.build_event_notification(ccap_id=self.startup_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="UP",
                                            agentid=provision_pb2.AGENTTYPE_INTERFACE_STATUS
                                            )
        self.startup_core._handle_core_interface_event(msg)
        self.assertEqual(self.startup_core.fsm.current, CCAPFsmStartup.STATE_INTERFACE_UP)

    def test_handle_core_8021x_event(self):
        self.startup_core.fsm.TRIGGER_INTERFACE_UP()
        msg = self.build_event_notification(ccap_id=self.startup_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="UP",
                                            agentid=provision_pb2.AGENTTYPE_8021X
                                            )
        self.startup_core._handle_core_8021x_event(msg)
        self.assertEqual(self.startup_core.fsm.current, CCAPFsmStartup.STATE_8021X_OK)

    def test_handle_core_dhcp_event(self):
        self.startup_core.fsm.TRIGGER_INTERFACE_UP()
        self.startup_core.fsm.TRIGGER_MAC_8021X_OK()
        msg = self.build_event_notification(ccap_id=self.startup_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="UP",
                                            agentid=provision_pb2.AGENTTYPE_DHCP
                                            )
        self.startup_core._handle_core_dhcp_event(msg)
        self.assertEqual(self.startup_core.fsm.current, CCAPFsmStartup.STATE_DHCP_OK)

    def test_handle_core_tod_event(self):
        self.startup_core.fsm.TRIGGER_INTERFACE_UP()
        self.startup_core.fsm.TRIGGER_MAC_8021X_OK()
        self.startup_core.fsm.TRIGGER_DHCP_OK()
        msg = self.build_event_notification(ccap_id=self.startup_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="UP",
                                            agentid=provision_pb2.AGENTTYPE_DHCP
                                            )

        self.startup_core._handle_core_tod_event(msg)
        self.assertEqual(self.startup_core.fsm.current, CCAPFsmStartup.STATE_TOD_OK)

    def test_handle_core_ipsec_event(self):
        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="UP",
                                            agentid=provision_pb2.AGENTTYPE_IPSEC
                                            )
        self.gcp_core._handle_core_ipsec_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_TCP)

    def test_handle_core_gcp_event(self):
        self.gcp_core.fsm.TRIGGER_IPSEC_OK()
        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="TCP_OK",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )
        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_GCP_IRA)
        self.assertIsNotNone(self.gcp_core.state_timer[self.gcp_core.fsm.current])

        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="GCP_IRA",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )

        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG)
        self.assertIsNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_IRA])
        self.assertIsNotNone(self.gcp_core.state_timer[self.gcp_core.fsm.current])

        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="GCP_CFG",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )

        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG_CPL)
        self.assertIsNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_CFG])
        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="GCP_CFG_CPL",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )

        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_GCP_OP)
        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="OPERATIONAL",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )
        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_ONLINE)
        self.gcp_core.fsm.TRIGGER_TCP_FAIL()
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_REINIT_IPSEC)
        self.gcp_core.fsm.TRIGGER_IPSEC_OK()
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_REINIT_TCP)
        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="TCP_OK",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )

        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_REINIT_GCP_IRA)

        msg = self.build_event_notification(ccap_id=self.gcp_core.ccap_core_id,
                                            status=process_agent_pb2.msg_core_event_notification.OK,
                                            reason="test",
                                            result="GCP_IRA",
                                            agentid=provision_pb2.AGENTTYPE_GCP
                                            )
        self.gcp_core._handle_core_gcp_event(msg)
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_ONLINE)

    def test_init_ipsec_backoff_reach_max(self):
        self.gcp_core.fsm.TRIGGER_IPSEC_OK()
        self.gcp_core.state_retried_times[CCAPFsm.STATE_INIT_IPSEC] = \
            self.gcp_core.CoreStateFailureRetry[CCAPFsm.STATE_INIT_IPSEC] + 1
        self.gcp_core.fsm.TRIGGER_TCP_FAIL()
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_FAIL)

    def test_gcp_core_timeout(self):
        self.gcp_core.fsm.TRIGGER_IPSEC_OK()
        self.gcp_core.CoreStateTimeoutSeconds[CCAPFsm.STATE_INIT_GCP_IRA] = 1
        self.assertIsNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_IRA])
        self.gcp_core.fsm.TRIGGER_TCP_OK()
        time.sleep(1.1)
        self.gcp_core.dispatcher.handle_one_event()
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_IPSEC)
        self.gcp_core.fsm.TRIGGER_IPSEC_OK()
        self.gcp_core.fsm.TRIGGER_TCP_OK()
        self.gcp_core.CoreStateTimeoutSeconds[CCAPFsm.STATE_INIT_GCP_CFG] = 1
        self.assertIsNotNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_IRA])
        self.assertIsNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_CFG])
        self.gcp_core.fsm.TRIGGER_GCP_IRA()
        self.assertIsNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_IRA])
        self.assertIsNotNone(self.gcp_core.state_timer[CCAPFsm.STATE_INIT_GCP_CFG])
        time.sleep(1.1)
        self.gcp_core.dispatcher.handle_one_event()
        self.assertEqual(self.gcp_core.fsm.current, CCAPFsm.STATE_INIT_IPSEC)


if __name__ == '__main__':
    unittest.main()
