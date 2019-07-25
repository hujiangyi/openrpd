#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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

import unittest
import time
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.provision.manager.src.manager_process import ManagerProcess, CCAPCoreOrchestrator
from rpd.gpb.tpc_pb2 import t_TpcMessage
from rpd.provision.manager.src.manager_ccap_core import CCAPCore, CoreDescription
from rpd.provision.manager.src.manager_fsm import CCAPFsm, ManagerFsm, CCAPFsmStartup
from test_manager_core import TestCCAPCoreClass
import rpd.provision.proto.provision_pb2 as provision_pb2
from rpd.provision.proto import process_agent_pb2
import json
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, stop_test_redis


class testManagerProcess(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("PROVISION", "test_mgr_process.log")
        cls.fake_cb_cnt = 0

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()
        CCAPCoreOrchestrator.NO_PRINCIPAL_CORE_FOUND_TIMEOUT = 60
        CCAPCore.ccap_core_db = {}
        self.fake_cb_cnt = 0
        self.mgr = ManagerProcess(simulator=True, test_flag=True)
        ManagerProcess.SYSTEM_TIME_CONFIRM = "None"

    def tearDown(self):
        CCAPCoreOrchestrator.NO_PRINCIPAL_CORE_FOUND_TIMEOUT = 60
        CCAPCore.ccap_core_db = {}
        ManagerProcess.SYSTEM_TIME_CONFIRM = "None"
        stop_test_redis()

    def fake_cb(self, _):
        self.fake_cb_cnt += 1
        return

    def test_is_system_time_confirmed(self):
        backup = ManagerProcess.SYSTEM_TIME_CONFIRM
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.INITIATED
        result = ManagerProcess.is_system_time_confirmed()
        self.assertFalse(result)
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.SUCCESS
        result = ManagerProcess.is_system_time_confirmed()
        self.assertTrue(result)
        ManagerProcess.SYSTEM_TIME_CONFIRM = backup
        self.assertEquals(ManagerProcess.SYSTEM_TIME_CONFIRM, "None")

    def test_system_time_confirmed(self):
        backup = ManagerProcess.SYSTEM_TIME_CONFIRM
        ManagerProcess._system_time_confirmed(step=t_TpcMessage.SUCCESS)
        result = ManagerProcess.is_system_time_confirmed()
        self.assertTrue(result)
        ManagerProcess.SYSTEM_TIME_CONFIRM = backup
        self.assertEquals(ManagerProcess.SYSTEM_TIME_CONFIRM, "None")

    def test_set_time(self):
        try:
            self.mgr.set_time(timestamp=112314)

        except Exception as e:
            self.fail("Exception happened : %s" % e)

    def test_system_operational_timeout(self):
        self.mgr._system_operational_timeout("unittest")
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_FAIL)

    def test_start_principal_core_seek_timer(self):
        old_timeout = ManagerProcess.SEEK_PRINCIPAL_CORE_TIMEOUT
        self.assertIsNone(self.mgr.principal_core_seek_timer)
        ManagerProcess.SEEK_PRINCIPAL_CORE_TIMEOUT = 100
        self.mgr.start_principal_core_seek_timer(self.fake_cb)
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)
        ManagerProcess.SEEK_PRINCIPAL_CORE_TIMEOUT = 1
        self.mgr.start_principal_core_seek_timer(self.fake_cb)
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)
        time.sleep(1)
        self.mgr.dispatcher.handle_one_event()
        self.assertEqual(self.fake_cb_cnt, 1)
        ManagerProcess.SEEK_PRINCIPAL_CORE_TIMEOUT = old_timeout
        self.assertEquals(ManagerProcess.SEEK_PRINCIPAL_CORE_TIMEOUT, old_timeout)

    def test_create_original_core(self):
        self.mgr.create_original_core(interface="eth0")
        self.assertEquals(len(CCAPCore.ccap_core_db), 1)
        for core in CCAPCore.ccap_core_db.values():
            self.assertIsInstance(core, CCAPCore)
            self.assertIsInstance(core.fsm, CCAPFsmStartup)
            self.assertEquals(core.initiated_by, "Startup")

    def test_fsm_provision_interface_scan(self):
        try:
            self.mgr.fsm.INTERFACE_SCAN(interface="eth0")
            self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_INTERFACE_PROVISION)
        except Exception as e:
            self.fail("Exception happened : %s" % e)

    def test_principal_core_seek_failure(self):
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_INIT)
        self.mgr.fsm.INTERFACE_SCAN(interface="eth0")
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_INTERFACE_PROVISION)

        self.mgr.fsm.STARTUP_DHCP_OK()
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_PROVISION)

        self.mgr.principal_core_seek_failure("unittest")
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_FIRST)

    def test_fsm_provision_state_retry(self):
        self.mgr.fsm.fsm.current = self.mgr.fsm.STATE_PRINCIPLE_RETRY_FIRST
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_FIRST)
        print "Start test fsm_provision_state_retry"
        print "Check equal state"
        self.mgr.fsm.ENTER_CURRENT_STATE()
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_FIRST)

        print "Check Principal present"
        self.mgr.principal_core = "unittest"
        self.mgr.core_orchestrator.active_list.append('1.1.1.1')
        self.mgr.principal_core_seek_failure("unittest")
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_SECOND)
        self.assertEquals(len(self.mgr.core_orchestrator.active_list), 1)

        print "Check reset active list and failed list"
        self.mgr.principal_core = None
        self.mgr.principal_core_seek_failure("unittest")
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_THIRD)
        self.assertEquals(len(self.mgr.core_orchestrator.active_list), 0)
        self.assertEquals(len(self.mgr.core_orchestrator.failed_list), 0)

    def test_principal_core_seek_failure_before_tod(self):
        print "Check system first failed "
        self.assertIsNone(self.mgr.principal_core_seek_timer)
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.FIRST_ATTEMPT_FAILED
        self.mgr._principal_core_seek_failure_before_tod("unittest")
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)

        print "Check system tod initiated "
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.INITIATED
        self.mgr._principal_core_seek_failure_before_tod("unittest")
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)

        print "Check system time is confirmed"
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.SUCCESS
        self.mgr._principal_core_seek_failure_before_tod("unittest")
        self.assertIsNone(self.mgr.principal_core_seek_timer)

        print "Check system tod failed "
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.FIRST_ATTEMPT_FAILED
        self.mgr._principal_core_seek_failure_before_tod("unittest")
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)
        ManagerProcess.SYSTEM_TIME_CONFIRM = t_TpcMessage.ALL_ATTEMPTS_FAILED
        self.mgr._principal_core_seek_failure_before_tod("unittest")
        self.assertIsNone(self.mgr.principal_core_seek_timer)

    def test_fsm_provision_startup(self):
        self.assertIsNotNone(self.mgr.interface_scan_timer)

    def test_fsm_provision_user_mgmt(self):
        try:
            self.mgr.fsm.USER_MGMT()
        except Exception as e:
            self.fail("Exception happened : %s" % e)

    def test_fsm_provision_gcp_mgmt(self):
        try:
            self.mgr.fsm.GCP_MGMT()
        except Exception as e:
            self.fail("Exception happened : %s" % e)

    def test_fsm_provision_dhcp(self):
        try:
            self.mgr.fsm.DHCP()
        except Exception as e:
            self.fail("Exception happened : %s" % e)

    def test_fsm_provision_principal_core_found(self):
        print "Check state no change"
        old = self.mgr.fsm.current
        self.mgr.fsm.SEEK_PRINCIPAL_OK()
        self.assertEquals(self.mgr.fsm.current, old)

        print "Check state change to principal found"
        self.mgr.fsm.fsm.current = self.mgr.fsm.STATE_PRINCIPLE_PROVISION
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_PROVISION)
        self.mgr.principal_core_seek_timer = self.mgr.dispatcher.timer_register(self.mgr.SEEK_PRINCIPAL_CORE_TIMEOUT,
                                                                                self.fake_cb)
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)

        self.mgr.fsm.SEEK_PRINCIPAL_OK()
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPAL_FOUND)
        self.assertIsNone(self.mgr.principal_core_seek_timer)

    def set_mgr_ready_for_8021x(self):
        print "Interface UP"
        self.mgr.interface_up_handler(up_interface_lists=['eth0', 'eth1'])
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_INTERFACE_PROVISION)
        self.assertIsNone(self.mgr.interface_scan_timer)
        self.assertEquals(len(CCAPCore.ccap_core_db), 1)
        for startupcore in CCAPCore.ccap_core_db.values():
            self.assertIsInstance(startupcore, CCAPCore)
            self.assertIsInstance(startupcore.fsm, CCAPFsmStartup)
            self.assertEquals(startupcore.initiated_by, "Startup")
            self.assertEquals(startupcore.fsm.current, "none")
            break
        startupcore.fsm.TRIGGER_Startup()
        self.assertEquals(startupcore.fsm.current, startupcore.fsm.STATE_INIT)
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=startupcore.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_INTERFACE_STATUS
                                                         )
        startupcore._handle_core_interface_event(msg)
        self.assertEquals(startupcore.fsm.current, startupcore.fsm.STATE_INTERFACE_UP)
        return True

    def set_mgr_ready_for_dhcp(self):
        self.assertTrue(self.set_mgr_ready_for_8021x())
        startupcore = self.get_startup_core()
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=startupcore.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_8021X
                                                         )

        startupcore._handle_core_8021x_event(msg)
        self.assertEqual(startupcore.fsm.current, CCAPFsmStartup.STATE_8021X_OK)
        return True

    def set_mgr_ready_for_tod(self):
        self.assertTrue(self.set_mgr_ready_for_dhcp())
        startupcore = self.get_startup_core()
        print "Manager DHCP OK"
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=startupcore.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_DHCP
                                                         )

        startupcore._handle_core_dhcp_event(msg)
        self.assertEqual(startupcore.fsm.current, CCAPFsmStartup.STATE_DHCP_OK)

        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
        event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_DHCP
        event_request_rsp.mgr_event.data = \
            json.dumps(
                {'CCAPCores': ['1.1.1.1', '2.2.2.2'],
                 'TimeServers': ['1.1.1.1', '2.2.2.2'],
                 'TimeOffset': 12800,
                 'CreatedTime': 22222,
                 'LogServers': ['1.1.1.1', '2.2.2.2'],
                 'initiated_by': startupcore.ccap_core_id,
                 'Interface': startupcore.interface})
        self.mgr._handle_mgr_dhcp_event(msg=event_request_rsp.mgr_event)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_PROVISION)
        return True

    def set_mgr_ready_for_ipsec(self, tod_server="1.1.1.1", timestamp="15234215315"):
        self.assertTrue(self.set_mgr_ready_for_tod())
        print "Manager and startup core TOD OK"
        startupcore = self.get_startup_core()
        startupcore.fsm.TRIGGER_TOD_OK()
        self.assertEquals(startupcore.fsm.current, startupcore.fsm.STATE_TOD_OK)

        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
        event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_TOD
        event_request_rsp.mgr_event.data = 'success/' + timestamp + \
                                           '|' + tod_server
        self.mgr._handle_mgr_tod_event(msg=event_request_rsp.mgr_event)
        self.assertTrue(self.mgr.is_system_time_confirmed())
        self.assertIsNotNone(self.mgr.operational_timer)
        self.assertIsNotNone(self.mgr.core_orchestrator.orchestrator_timer)
        self.assertIsNone(self.mgr.principal_core_seek_timer)
        self.assertEquals(len(CCAPCore.ccap_core_db), 2)
        for gcpcore in CCAPCore.ccap_core_db.values():
            if isinstance(gcpcore, CCAPCore) and isinstance(gcpcore.fsm, CCAPFsm):
                break
        self.assertIsInstance(gcpcore, CCAPCore)
        print "GCP core startup OK"
        gcpcore.fsm.TRIGGER_Startup()
        self.assertEquals(gcpcore.fsm.current, gcpcore.fsm.STATE_INIT_IPSEC)
        return True

    def set_core_ready_for_tcp(self, coreid):
        print "GCP core IPsec OK"
        gcpcore = CCAPCore.ccap_core_db[coreid]
        self.assertEquals(gcpcore.fsm.current, gcpcore.fsm.STATE_INIT_IPSEC)
        self.receive_ipsec_ok(gcpcore.ccap_core_id)
        self.assertEquals(gcpcore.fsm.current, gcpcore.fsm.STATE_INIT_TCP)
        return True

    def set_mgr_principal_found(self, core_ip='1.1.1.1'):
        self.assertTrue(self.set_mgr_ready_for_ipsec())
        for gcpcore in CCAPCore.ccap_core_db.values():
            if isinstance(gcpcore, CCAPCore) and isinstance(gcpcore.fsm, CCAPFsm) \
                    and (gcpcore.ccap_core_network_address == core_ip):
                break
        try:
            self.set_core_ready_for_tcp(coreid=gcpcore.ccap_core_id)
            print "Manager receive core identification"
            caps = {
                "index": 1,
                "is_active": True,
                "ccap_core": gcpcore.ccap_core_network_address,
                'interface': gcpcore.interface,
                "is_principal": True}
            event_request_rsp = process_agent_pb2.msg_event_notification()
            event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
            event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_GCP
            event_request_rsp.mgr_event.data = json.dumps("role/" + json.dumps(caps))
            self.mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
            self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPAL_FOUND)
            self.assertIsNone(self.mgr.principal_core_seek_timer)
            self.assertIsNotNone(self.mgr.principal_core)
            return True
        except Exception as e:
            raise e

    def recv_gcp_msg(self, coreid, msg):
        gcpcore = CCAPCore.ccap_core_db[coreid]
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=gcpcore.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result=msg,
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )

        gcpcore._handle_core_gcp_event(msg)
        return True

    def receive_ipsec_ok(self, coreid):
        gcpcore = CCAPCore.ccap_core_db[coreid]
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=coreid,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_IPSEC
                                                         )

        gcpcore._handle_core_ipsec_event(msg)
        return True

    def set_core_op(self, coreid):
        gcpcore = CCAPCore.ccap_core_db[coreid]
        print "Gcp core receive msg"
        self.assertTrue(self.recv_gcp_msg(coreid, "TCP_OK"))
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_INIT_GCP_IRA)
        self.assertTrue(self.recv_gcp_msg(coreid, "GCP_IRA"))
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG)
        self.assertTrue(self.recv_gcp_msg(coreid, "GCP_CFG"))
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG_CPL)
        self.assertTrue(self.recv_gcp_msg(coreid, "GCP_CFG_CPL"))
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_INIT_GCP_OP)
        self.assertTrue(self.recv_gcp_msg(coreid, "OPERATIONAL"))
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_ONLINE)
        return True

    def set_mgr_operational(self):
        self.assertTrue(self.set_mgr_principal_found())
        self.set_core_op(self.mgr.principal_core.ccap_core_id)
        self.assertEqual(self.mgr.fsm.current, self.mgr.fsm.STATE_OPERATIONAL)
        self.assertIsNone(self.mgr.operational_timer)
        # trigger gcp core to startup
        gcpcore = self.get_core("eth0", '2.2.2.2')
        self.assertIsNotNone(gcpcore)
        gcpcore.fsm.TRIGGER_Startup()
        self.assertEqual(gcpcore.fsm.current, gcpcore.fsm.STATE_INIT_IPSEC)
        return True

    def get_startup_core(self):
        return self.mgr.startup_core

    def test_scenario_from_init_to_operational(self):
        self.assertTrue(self.set_mgr_operational())

    def test_scenario_from_init_to_todfail(self):
        self.assertTrue(self.set_mgr_ready_for_tod())
        startupcore = self.get_startup_core()

        print "First tod fail"
        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
        event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_TOD
        event_request_rsp.mgr_event.data = 'tod_first_failed/0' + '|' + '1.1.1.1'
        self.mgr._handle_mgr_tod_event(msg=event_request_rsp.mgr_event)
        self.assertEquals(ManagerProcess.SYSTEM_TIME_CONFIRM, t_TpcMessage.FIRST_ATTEMPT_FAILED)

        print "All tod fail"
        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
        event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_TOD
        event_request_rsp.mgr_event.data = 'tod_failed/' + '' + '|' + '1.1.1.1'
        self.mgr._handle_mgr_tod_event(msg=event_request_rsp.mgr_event)
        self.assertEquals(self.mgr.tod_retry, 1)
        self.assertEquals(ManagerProcess.SYSTEM_TIME_CONFIRM, t_TpcMessage.ALL_ATTEMPTS_FAILED)

        print "Second tod fail"
        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
        event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_TOD
        event_request_rsp.mgr_event.data = 'tod_failed/' + '' + '|' + '1.1.1.1'
        self.mgr._handle_mgr_tod_event(msg=event_request_rsp.mgr_event)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_FAIL)

    def set_mgr_all_core_fail(self):
        for gcpcore in CCAPCore.ccap_core_db.values():
            if isinstance(gcpcore, CCAPCore) and isinstance(gcpcore.fsm, CCAPFsm):
                break
        gcpcore.fsm.TRIGGER_Error()
        self.assertEquals(len(self.mgr.core_orchestrator.failed_list), 1)
        self.assertEquals(len(CCAPCore.ccap_core_db), 2)
        for gcpcore in CCAPCore.ccap_core_db.values():
            if isinstance(gcpcore, CCAPCore) and isinstance(gcpcore.fsm, CCAPFsm):
                break
        self.assertEquals(gcpcore.ccap_core_network_address, '2.2.2.2')
        CCAPCoreOrchestrator.NO_PRINCIPAL_CORE_FOUND_TIMEOUT = 1
        gcpcore.fsm.TRIGGER_Error()
        self.assertEquals(len(self.mgr.core_orchestrator.failed_list), 2)
        self.assertIsNotNone(self.mgr.principal_core_seek_timer)
        time.sleep(1)
        self.mgr.dispatcher.handle_one_event()
        return True

    def test_scenario_from_init_to_principal_not_found(self):
        self.assertTrue(self.set_mgr_ready_for_ipsec())
        for gcpcore in CCAPCore.ccap_core_db.values():
            if isinstance(gcpcore, CCAPCore) and isinstance(gcpcore.fsm, CCAPFsm):
                break
        try:
            print "Core fail"
            self.assertTrue(self.set_mgr_all_core_fail())
            self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_FIRST)

            print "First retry"
            self.assertTrue(self.set_mgr_all_core_fail())
            self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_SECOND)

            print "Second retry"
            self.assertTrue(self.set_mgr_all_core_fail())
            self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPLE_RETRY_THIRD)

            print "Third retry"
            self.assertTrue(self.set_mgr_all_core_fail())
            self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_FAIL)

        except Exception as e:
            self.fail("Exception happened : %s" % e)

    def test_scenario_from_op_to_principal_gcp_reconnect_ok(self):
        self.assertTrue(self.set_mgr_operational())
        principal_core = self.mgr.principal_core
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="TCP_FAIL",
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )
        principal_core._handle_core_gcp_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
        self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 1)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPAL_FOUND)
        self.assertFalse(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])

        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_IPSEC
                                                         )
        principal_core._handle_core_ipsec_event(msg)
        self.assertTrue(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_TCP)
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="TCP_FAIL",
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )

        principal_core._handle_core_gcp_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
        self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 2)
        self.assertFalse(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])

        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_IPSEC
                                                         )

        principal_core._handle_core_ipsec_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_TCP)

        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="TCP_OK",
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )

        principal_core._handle_core_gcp_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_GCP_IRA)
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 2)
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="GCP_IRA",
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )
        principal_core._handle_core_gcp_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_ONLINE)
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 0)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_OPERATIONAL)

    def test_scenario_from_op_to_principal_gcp_reconnect_fail(self):
        self.assertTrue(self.set_mgr_operational())
        principal_core = self.mgr.principal_core
        self.assertEqual(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 0)
        self.assertTrue(self.recv_gcp_msg(principal_core.ccap_core_id, "TCP_FAIL"))
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
        self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 1)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPAL_FOUND)
        self.assertFalse(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])
        self.assertTrue(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])

        for i in range(1, principal_core.CoreStateFailureRetry[principal_core.fsm.STATE_REINIT_IPSEC] + 1):
            self.assertTrue(self.receive_ipsec_ok(principal_core.ccap_core_id))
            self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_TCP)
            self.assertTrue(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])
            self.assertTrue(self.recv_gcp_msg(principal_core.ccap_core_id, "TCP_FAIL"))
            if i == principal_core.CoreStateFailureRetry[principal_core.fsm.STATE_REINIT_IPSEC]:
                break
            self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
            self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
            self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], i + 1)
            self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
            self.assertFalse(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])

        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_DEL)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_FAIL)
        self.assertIsNotNone(self.mgr.reboot_timer)

    def test_scenario_from_op_to_dhcp_fail(self):
        self.assertTrue(self.set_mgr_operational())

        print "Principal tcp fail"
        principal_core = self.mgr.principal_core
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="TCP_FAIL",
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )
        principal_core._handle_core_gcp_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
        self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 1)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPAL_FOUND)
        self.assertFalse(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])

        print "Principal ipsec up"
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="UP",
                                                         agentid=provision_pb2.AGENTTYPE_IPSEC
                                                         )
        principal_core._handle_core_ipsec_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_TCP)
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=principal_core.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="TCP_FAIL",
                                                         agentid=provision_pb2.AGENTTYPE_GCP
                                                         )

        principal_core._handle_core_gcp_event(msg)
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
        self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_REINIT_IPSEC], 2)
        self.assertFalse(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])

        startupcore = self.get_startup_core()
        startupcore.CoreAgentTimeout[provision_pb2.AGENTTYPE_DHCP] = 1
        print "startup core dhcp fail"
        startupcore.fsm.TRIGGER_DHCP_FAIL()
        self.assertIsNotNone(startupcore.registered_timers[provision_pb2.AGENTTYPE_DHCP])
        self.assertEqual(startupcore.fsm.current, startupcore.fsm.STATE_8021X_OK)
        for state in principal_core.state_retried_times:
            self.assertEquals(principal_core.state_retried_times[state], 0)
        for agent_id in principal_core.agent_timeout:
            self.assertEquals(principal_core.agent_timeout[agent_id], 0)

        startupcore.agent_timeout[provision_pb2.AGENTTYPE_DHCP] = startupcore.INIT_DHCP_MAX_TIMES - 1
        print "Startup core dhcp fail reach max retries"
        startupcore.fsm.TRIGGER_DHCP_FAIL()
        self.assertEqual(startupcore.fsm.current, startupcore.fsm.STATE_8021X_OK)
        self.assertIsNotNone(startupcore.registered_timers[provision_pb2.AGENTTYPE_DHCP])
        time.sleep(1)
        self.mgr.dispatcher.handle_one_event()
        print "system enter failure state"
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_FAIL)
        self.assertIsNotNone(self.mgr.reboot_timer)

    def test_scenario_from_op_to_recover_ok(self):
        self.assertTrue(self.set_mgr_operational())
        startupcore = self.get_startup_core()
        print "startup core dhcp fail"
        startupcore.fsm.TRIGGER_DHCP_FAIL()
        principal_core = self.mgr.principal_core
        print "check principal hold at ipsec"
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_REINIT_IPSEC)
        for state in principal_core.state_retried_times:
            self.assertEquals(principal_core.state_retried_times[state], 0)
        for agent_id in principal_core.agent_timeout:
            self.assertEquals(principal_core.agent_timeout[agent_id], 0)
        self.assertFalse(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])
        startupcore.fsm.TRIGGER_DHCP_OK()
        startupcore.fsm.TRIGGER_TOD_OK()
        self.assertTrue(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])

    @staticmethod
    def build_mgr_event(mgrid, agentid, msg_str, data):
        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgrid
        event_request_rsp.mgr_event.event_id = agentid
        event_request_rsp.mgr_event.data = json.dumps(msg_str + "/" + json.dumps(data))
        return event_request_rsp.mgr_event

    @staticmethod
    def get_core(interface, ip):
        for ccap_core in CCAPCore.ccap_core_db.values():
            if ccap_core.interface == interface and ccap_core.ccap_core_network_address == ip:
                return ccap_core
        return None

    def test_scenario_from_op_to_add_lcha_core(self):
        self.assertTrue(self.set_mgr_operational())
        print "Test 3.3.3.3 is not in DB, ignore this message"
        caps = {
            "index": 3,
            "is_active": False,
            "ccap_core": "3.3.3.3",
            "interface": 'eth0',
            "is_principal": True}
        msg = self.build_mgr_event(mgrid=self.mgr.mgr_id,
                                   agentid=provision_pb2.AGENTTYPE_GCP,
                                   msg_str='role',
                                   data=caps)
        try:
            self.mgr._handle_mgr_event_notification(msg=msg, agent_id=provision_pb2.AGENTTYPE_GCP)
        except Exception as e:
            self.fail("Exception happened : %s" % e)

        print "start try 2.2.2.2, set it to aux active"
        self.assertEquals(len(CCAPCore.ccap_core_db), 3)
        caps = {
            "index": 2,
            "is_active": True,
            "ccap_core": "2.2.2.2",
            "interface": 'eth0',
            "is_principal": False}
        msg = self.build_mgr_event(mgrid=self.mgr.mgr_id,
                                   agentid=provision_pb2.AGENTTYPE_GCP,
                                   msg_str='role',
                                   data=caps)
        try:
            self.mgr._handle_mgr_event_notification(msg=msg, agent_id=provision_pb2.AGENTTYPE_GCP)
        except Exception as e:
            self.fail("Exception happened : %s" % e)

        aux_active = self.get_core("eth0", '2.2.2.2')
        self.assertIsNotNone(aux_active)
        self.assertIsInstance(aux_active, CCAPCore)
        self.assertTrue(self.set_core_ready_for_tcp(coreid=aux_active.ccap_core_id))
        self.assertTrue(self.set_core_op(aux_active.ccap_core_id))

        print "Add 3.3.3.3 as standby core"
        ha_info = {"ActiveCoreIpAddress": "2.2.2.2",
                   "StandbyCoreIpAddress": "3.3.3.3",
                   "interface": "eth0",
                   "operation": self.mgr.OPERATION_ADD}
        msg = self.build_mgr_event(mgrid=self.mgr.mgr_id,
                                   agentid=provision_pb2.AGENTTYPE_GCP,
                                   msg_str='Ha',
                                   data=ha_info)
        self.mgr._handle_mgr_event_notification(msg=msg, agent_id=provision_pb2.AGENTTYPE_GCP)
        self.assertEquals(len(CCAPCore.ccap_core_db), 4)
        caps = {
            "index": 3,
            "is_active": False,
            "ccap_core": "3.3.3.3",
            "interface": 'eth0',
            "is_principal": True}
        msg = self.build_mgr_event(mgrid=self.mgr.mgr_id,
                                   agentid=provision_pb2.AGENTTYPE_GCP,
                                   msg_str='role',
                                   data=caps)
        try:
            self.mgr._handle_mgr_event_notification(msg=msg, agent_id=provision_pb2.AGENTTYPE_GCP)
        except Exception as e:
            self.fail("Exception happened : %s" % e)
        aux_standby = self.get_core("eth0", '3.3.3.3')
        self.assertIsNotNone(aux_standby)
        self.assertIsInstance(aux_standby, CCAPCore)
        aux_standby.fsm.TRIGGER_Startup()
        self.assertTrue(self.set_core_ready_for_tcp(coreid=aux_standby.ccap_core_id))
        self.assertTrue(self.set_core_op(aux_standby.ccap_core_id))

    def test_lcha_change_failed(self):
        # this case is operations based on core added
        self.test_scenario_from_op_to_add_lcha_core()

        print "Wrong change information, nothing changed"
        ha_info = {"ActiveCoreIpAddress": "3.3.3.3",
                   "StandbyCoreIpAddress": "2.2.2.2",
                   "interface": "eth0",
                   "operation": self.mgr.OPERATION_CHANGE}

        msg = self.build_mgr_event(mgrid=self.mgr.mgr_id,
                                   agentid=provision_pb2.AGENTTYPE_GCP,
                                   msg_str='Ha',
                                   data=ha_info)
        self.mgr._handle_mgr_event_notification(msg=msg, agent_id=provision_pb2.AGENTTYPE_GCP)
        self.assertIsNotNone(self.get_core('eth0', '2.2.2.2'))
        self.assertIsNotNone(self.get_core('eth0', '3.3.3.3'))

    def test_lcha_change_success(self):
            # this case is operations based on core added
        self.test_scenario_from_op_to_add_lcha_core()

        print "Receive correct lcha change information, do the change."
        ha_info = {"ActiveCoreIpAddress": "2.2.2.2",
                   "StandbyCoreIpAddress": "3.3.3.3",
                   "interface": "eth0",
                   "operation": self.mgr.OPERATION_CHANGE}

        msg = self.build_mgr_event(mgrid=self.mgr.mgr_id,
                                   agentid=provision_pb2.AGENTTYPE_GCP,
                                   msg_str='Ha',
                                   data=ha_info)
        self.mgr._handle_mgr_event_notification(msg=msg, agent_id=provision_pb2.AGENTTYPE_GCP)
        self.assertIsNone(self.get_core('eth0', '2.2.2.2'))
        self.assertIsNotNone(self.get_core('eth0', '3.3.3.3'))
        self.mgr.core_orchestrator.orchestrator_cb(None)
        self.mgr.core_orchestrator.orchestrator_cb(None)
        self.assertIsNotNone(self.get_core('eth0', '2.2.2.2'))

    def test_remove_principal_from_operational(self):
        self.assertTrue(self.set_mgr_operational())
        print "Manager receive core identification"
        caps = {
            "index": 1,
            "is_active": True,
            "ccap_core": self.mgr.principal_core.ccap_core_network_address,
            'interface': self.mgr.principal_core.interface,
            "is_principal": False}
        event_request_rsp = process_agent_pb2.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = self.mgr.mgr_id
        event_request_rsp.mgr_event.event_id = provision_pb2.AGENTTYPE_GCP
        event_request_rsp.mgr_event.data = json.dumps("role/" + json.dumps(caps))
        self.mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        self.assertIsNone(self.mgr.principal_core)

    def test_scenario_startup_exit_online(self):
        # test startup core exit online state, with gcp cores in [init(ipsec), online]
        self.assertTrue(self.set_mgr_operational())
        gcpcore = self.get_core("eth0", '2.2.2.2')
        self.assertEqual(gcpcore.fsm.current, gcpcore.fsm.STATE_INIT_IPSEC)

        # startup exit online because of dhcp failed
        startupcore = self.get_startup_core()
        print "Manager DHCP OK"
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=startupcore.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="DOWN",
                                                         agentid=provision_pb2.AGENTTYPE_DHCP
                                                         )
        startupcore._handle_core_dhcp_event(msg)
        self.assertEqual(startupcore.fsm.current, CCAPFsmStartup.STATE_8021X_OK)
        self.assertEqual(self.mgr.principal_core.fsm.current, CCAPFsm.STATE_REINIT_IPSEC)
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_INIT_IPSEC)

        # startup core receive an INTERFACE DOWN
        msg = TestCCAPCoreClass.build_event_notification(ccap_id=startupcore.ccap_core_id,
                                                         status=process_agent_pb2.msg_core_event_notification.OK,
                                                         reason="test",
                                                         result="DOWN",
                                                         agentid=provision_pb2.AGENTTYPE_INTERFACE_STATUS
                                                         )
        startupcore._handle_core_interface_event(msg)
        self.assertEquals(startupcore.fsm.current, CCAPFsmStartup.STATE_INIT)
        self.assertEqual(self.mgr.principal_core.fsm.current, CCAPFsm.STATE_REINIT_IPSEC)
        self.assertEqual(gcpcore.fsm.current, CCAPFsm.STATE_INIT_IPSEC)

    def test_scenario_gcp_close(self):
        self.assertTrue(self.set_mgr_principal_found())
        coreid = self.mgr.principal_core.ccap_core_id
        principal_core = self.mgr.principal_core
        self.assertTrue(self.recv_gcp_msg(coreid, "TCP_OK"))
        self.assertEqual(principal_core.fsm.current, CCAPFsm.STATE_INIT_GCP_IRA)
        self.assertTrue(self.recv_gcp_msg(coreid, "GCP_IRA"))
        self.assertEqual(principal_core.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG)
        self.assertTrue(self.recv_gcp_msg(coreid, "GCP_CFG"))
        self.assertEqual(principal_core.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG_CPL)

        self.assertEqual(principal_core.state_retried_times[principal_core.fsm.STATE_INIT_IPSEC], 0)
        self.assertTrue(self.recv_gcp_msg(principal_core.ccap_core_id, "TCP_FAIL"))
        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_INIT_IPSEC)
        self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
        self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_INIT_IPSEC], 1)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_PRINCIPAL_FOUND)
        self.assertFalse(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])
        self.assertTrue(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])

        for i in range(1, principal_core.CoreStateFailureRetry[principal_core.fsm.STATE_INIT_IPSEC] + 1):
            self.assertTrue(self.receive_ipsec_ok(principal_core.ccap_core_id))
            self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_INIT_TCP)
            self.assertTrue(principal_core.agent_status[provision_pb2.AGENTTYPE_IPSEC])
            self.assertTrue(self.recv_gcp_msg(coreid, "TCP_OK"))
            self.assertEqual(principal_core.fsm.current, CCAPFsm.STATE_INIT_GCP_IRA)
            self.assertTrue(self.recv_gcp_msg(coreid, "GCP_IRA"))
            self.assertEqual(principal_core.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG)
            self.assertTrue(self.recv_gcp_msg(coreid, "GCP_CFG"))
            self.assertEqual(principal_core.fsm.current, CCAPFsm.STATE_INIT_GCP_CFG_CPL)
            self.assertTrue(self.recv_gcp_msg(principal_core.ccap_core_id, "TCP_FAIL"))
            if i == principal_core.CoreStateFailureRetry[principal_core.fsm.STATE_INIT_IPSEC]:
                break
            self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_INIT_IPSEC)
            self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
            self.assertEquals(principal_core.state_retried_times[principal_core.fsm.STATE_INIT_IPSEC], i + 1)
            self.assertIsNotNone(principal_core.registered_timers[provision_pb2.AGENTTYPE_IPSEC])
            self.assertFalse(principal_core.action_status[provision_pb2.AGENTTYPE_IPSEC])

        self.assertEquals(principal_core.fsm.current, principal_core.fsm.STATE_DEL)
        self.assertEquals(self.mgr.fsm.current, self.mgr.fsm.STATE_FAIL)
        self.assertIsNotNone(self.mgr.reboot_timer)


if __name__ == '__main__':
    unittest.main()
