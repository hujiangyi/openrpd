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
from rpd.provision.manager.src.manager_process import ManagerProcess
from rpd.provision.manager.src.manager_main import AgentsStarter
import subprocess
import time
import os
import json
from rpd.common.rpd_logging import setup_logging
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.provision.manager.src.manager_ccap_core import CCAPCore, CoreDescription
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.gpb.tpc_pb2 import t_TpcMessage


class _e_obj(object):
    pass

@unittest.skip("skip")
class TestCcapCoreOrchestrator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging("PROVISION", filename="provision_mgr_process.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.starter = AgentsStarter(simulator=True)
        self.agent_process = {}
        for agent_id in self.starter.agent_dict:
            self.agent_process[agent_id] = self.starter.start_process(self.starter.agent_dict[agent_id])
        time.sleep(3)

    def tearDown(self):
        for idx in self.agent_process:
            self.agent_process[idx].terminate()

        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')
        os.system('rm -rf /tmp/zmq_*')
        subprocess.call(["killall", "python"])

    def test_seek_principal_core(self):
        print '*'*80
        print "start to test orchestrator seek_principal_core"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.interface_candidate.append('eth0')

        ccap_core = CCAPCore.ccap_core_db.values()

        # principal core is none
        mgr.core_orchestrator.seek_principal_core()

        # ccap_core_id not in db
        mgr.core_orchestrator.active_list.append(('eth0', '1.1.1.1', 'test'))
        mgr.core_orchestrator.seek_principal_core()

        # ccap_core_id in db
        mgr.core_orchestrator.active_list.append(('eth0', '1.1.1.1', ccap_core[0].ccap_core_id))
        mgr.core_orchestrator.seek_principal_core()

        # no principal active
        ccap_core[0].agent_status[ProcessAgent.AGENTTYPE_IPSEC] = True
        ccap_core[0].is_principal = CoreDescription.CORE_ROLE_NONE
        mgr.core_orchestrator.seek_principal_core()

        # principal active
        ccap_core[0].is_principal = CoreDescription.CORE_ROLE_PRINCIPAL
        mgr.core_orchestrator.seek_principal_core()

        second_core = CCAPCore('CORE-1234567890', CoreDescription.CORE_ROLE_PRINCIPAL,
                               CoreDescription.CORE_MODE_ACTIVE, mgr=mgr,
                               ccap_core_interface='eth0', ccap_core_network_address='1.1.1.6')
        CCAPCore.ccap_core_db[second_core.ccap_core_id] = second_core
        mgr.core_orchestrator.active_list.append(('eth0', '1.1.1.1', second_core.ccap_core_id))
        second_core.agent_status[ProcessAgent.AGENTTYPE_IPSEC] = True
        mgr.core_orchestrator.seek_principal_core()

        # principal core not none
        mgr.principal_core = ccap_core[0]
        mgr.core_orchestrator.seek_principal_core()

        mgr.fsm.Error(msg='test fsm error')

@unittest.skip("skip")
class TestManagerProcess(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging("PROVISION", filename="provision_mgr_process.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.starter = AgentsStarter(simulator=True)
        self.agent_process = {}
        for agent_id in self.starter.agent_dict:
            self.agent_process[agent_id] = self.starter.start_process(self.starter.agent_dict[agent_id])
        time.sleep(3)

    def tearDown(self):
        for idx in self.agent_process:
            self.agent_process[idx].terminate()

        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')
        os.system('rm -rf /tmp/zmq_*')
        subprocess.call(["killall", "python"])

    def end_manager(self, mgr):
        """Stop manager main loop.

        :param mgr:

        """
        print 'end the test of provision manager'
        print '*'*80
        if mgr:
            mgr.dispatcher.end_loop()
            mgr.fsm.Error(msg='test fsm error')

    def test_start_fake_process(self):
        """Start provision process with fake agent."""
        print '*'*80
        print "start to test provision manager with fake agent"
        mgr = ManagerProcess(simulator=True)
        mgr.dispatcher.timer_register(10, self.end_manager, arg=mgr)
        mgr.start()

    def test_seek_principal_failure_1(self):
        print '*'*80
        print "start to test seek_principal_failure 1"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        mgr.principal_core_seek_failure(None)
        mgr.fsm.Error(msg='test fsm error')

    def test_seek_principal_failure_2(self):
        print '*' * 80
        print "start to test seek_principal_failure 2"
        mgr2 = ManagerProcess(simulator=False)
        mgr2.fsm.INTERFACE_SCAN(interface='eth0')
        mgr2.fsm.INTERFACE_SCAN(interface='eth0')
        mgr2.fsm.STARTUP_DHCP_OK(interface='eth0')
        mgr2._principal_core_seek_failure_before_tod(None)
        mgr2.fsm.Error(msg='test fsm error')

    def test_seek_principal_failure_3(self):
        print '*' * 80
        print "start to test seek_principal_failure 3"
        mgr3 = ManagerProcess(simulator=False)
        mgr3.fsm.INTERFACE_SCAN(interface='eth0')
        mgr3.fsm.INTERFACE_SCAN(interface='eth0')
        mgr3.fsm.STARTUP_DHCP_OK(interface='eth0')
        mgr3.set_time(time.time(), step=t_TpcMessage.SUCCESS)
        mgr3._principal_core_seek_failure_before_tod(None)

        mgr3.set_time(time.time(), step=t_TpcMessage.FIRST_ATTEMPT_FAILED)
        mgr3._principal_core_seek_failure_before_tod(None)

        # .principal_core_seek_timer not none
        mgr3.set_time(time.time(), step=t_TpcMessage.FIRST_ATTEMPT_FAILED)
        mgr3._principal_core_seek_failure_before_tod(None)
        mgr3.fsm.Error(msg='test fsm error')

    def test_core_map(self):
        print '*'*80
        print "start to test interface fail"
        mgr = ManagerProcess(simulator=False)
        mgr.is_ip_in_core_map('eth0', '1.1.1.1')
        mgr.remove_ip_in_core_map('eth0', '1.1.1.1')
        mgr.add_ip_to_core_map('eth0', ('1.1.1.1', '', 4))
        mgr.get_core_map('eth0', '1.1.1.1')
        mgr.get_core_map('eth0', '1.1.1.1')
        mgr.is_valid_ip('1.1')

    def test_interface_fail(self):
        print '*'*80
        print "start to test interface fail"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.PROVISION_INTERFACE_FAIL(msg='test interface fail')
        mgr.fsm.Error(msg='test fsm error')

    def test_core_fail(self):
        print '*'*80
        print "start to test interface fail"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.interface_candidate.append('eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        mgr.fsm.CORE_FAIL(interface='eth0', core_ip='1.1.1.1', msg='test')
        mgr.fsm.Error(msg='test fsm error')

        # provisioning, time not confirmed
        mgr1 = ManagerProcess(simulator=False)
        mgr1.fsm.INTERFACE_SCAN(interface='eth0')
        mgr1.interface_candidate.append('eth0')
        mgr1.fsm.STARTUP_DHCP_OK(interface='eth0')
        mgr1.fsm.CORE_FAIL(interface='eth0', core_ip='1.1.1.1', msg='test')
        mgr1.fsm.Error(msg='test fsm error')

    def test_basic_fun(self):
        print '*'*80
        print "start to test basic function"
        mgr = ManagerProcess(simulator=False)

        # fd, event mask
        mgr._handle_agent_event(0, 0)
        mgr._handle_agent_event(mgr.process_agent_db[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['recvSock'].sock,
                                mgr.dispatcher.EV_FD_ERR)   # error

        mgr._handle_agent_event(mgr.process_agent_db[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]['recvSock'].sock,
                                10)

    def test_start_process(self):
        """Start provision process with real agent."""
        print '*'*80
        print "start to test provision manager with real agent"
        mgr = ManagerProcess(simulator=False)
        mgr.dhcp_parameter['eth0'] = {
            'TimeServers': ['1.1.1.1', ],
            'TimeOffset': 100,
            'CCAPCores': ['1.1.1.1', ],
            'LogServers': ['1.1.1.1', ]
        }

        # no core
        mgr.core_orchestrator.orchestrator_cb(None)

        # startup
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.add_ip_to_core_map('eth0', ('1.1.1.1', '', mgr.HA_CORE_TRIGGER))
        mgr.core_orchestrator.orchestrator_cb(None)
        mgr.remove_ip_in_core_map('eth0', ('1.1.1.1', '', mgr.HA_CORE_TRIGGER))

        # cb w/o candidate list
        mgr.core_orchestrator.orchestrator_cb(None)

        mgr.add_ip_to_core_map('eth0', ('1.1.1.1', '', mgr.HA_CORE_TRIGGER))
        mgr.interface_list.append({
                        "interface": 'eth0',
                        "status": mgr.INTERFACE_UP,
                    })
        mgr.core_orchestrator.orchestrator_cb(None)

        # is system time confirmed.
        mgr.set_time(time.time())
        mgr.is_system_time_confirmed()

        # mgr state transmit
        mgr.fsm.STARTUP_DHCP_OK()
        mgr.core_orchestrator.orchestrator_cb(None)

        # operational
        mgr.fsm.OPERATIONAL_OK()
        print mgr.fsm.current, mgr.core_orchestrator.active_list
        mgr.core_orchestrator.orchestrator_cb(None)

        # check ka
        mgr.check_ka_status(None)
        mgr.check_ka_status(None)
        mgr.check_ka_status(None)
        keys = CCAPCore.ccap_core_db.keys()
        for key in keys:
            CCAPCore.ccap_core_db.pop(key)
        mgr.process_agent_db[ProcessAgent.AGENTTYPE_INTERFACE_STATUS]["status"] = mgr.MGR_UNREGISTERED
        mgr.check_ka_status(None)

        # fail
        mgr.core_orchestrator.orchestrator_cb(None)
        mgr.fsm.Error(msg='test fsm error')

    def test_fsm_provision_startup_core_fail_1(self):
        print '*'*80
        print "start to test fsm_provision_startup_core_fail 1"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.interface_candidate.append('eth0')

        keys = CCAPCore.ccap_core_db.keys()
        for key in keys:
            CCAPCore.ccap_core_db.pop(key)
        e = _e_obj()
        event = {"name": 'core_fail', "src": "dhcp", "dst": 'core_fail'}
        e.fsm, e.event, e.src, e.dst, e.msg, e.interface = mgr.fsm, event, \
                                                           'dhcp', 'core_fail', 'test core fail', 'eth0'
        # eth0 in candidate
        mgr._fsm_provision_startup_core_fail(e)
        mgr.fsm.Error(msg='test fsm error')

    def test_fsm_provision_startup_core_fail_2(self):
        print '*'*80
        print "start to test fsm_provision_startup_core_fail 2"
        # second scenario, eth1 not in candidate
        mgr1 = ManagerProcess(simulator=False)
        mgr1.fsm.INTERFACE_SCAN(interface='eth0')
        mgr1.interface_candidate.append('eth0')

        e = _e_obj()
        event = {"name": 'core_fail', "src": "dhcp", "dst": 'core_fail'}
        e.fsm, e.event, e.src, e.dst, e.msg, e.interface = mgr1.fsm, event, \
                                                           'dhcp', 'core_fail', 'test core fail', 'eth1'

        keys = CCAPCore.ccap_core_db.keys()
        for key in keys:
            CCAPCore.ccap_core_db.pop(key)
        mgr1._fsm_provision_startup_core_fail(e)
        mgr1.fsm.Error(msg='test fsm error')

    def test_fsm_provision_startup_core_fail_3(self):
        print '*' * 80
        print "start to test fsm_provision_startup_core_fail 3"
        # eth0 in candidate, but there are more candidates
        mgr2 = ManagerProcess(simulator=False)
        mgr2.fsm.INTERFACE_SCAN(interface='eth0')
        mgr2.interface_candidate.append('eth0')
        mgr2.interface_candidate.append('eth1')

        e = _e_obj()
        event = {"name": 'core_fail', "src": "dhcp", "dst": 'core_fail'}
        e.fsm, e.event, e.src, e.dst, e.msg, e.interface = mgr2.fsm, event, \
                                                           'dhcp', 'core_fail', 'test core fail', 'eth0'
        keys = CCAPCore.ccap_core_db.keys()
        for key in keys:
            CCAPCore.ccap_core_db.pop(key)
        mgr2._fsm_provision_startup_core_fail(e)
        mgr2.fsm.Error(msg='test fsm error')

    def test_fsm_provision_core_fail(self):
        print '*'*80
        print "start to test _fsm_provision_core_fail"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.interface_candidate.append('eth0')
        e = _e_obj()
        event = {"name": 'core_fail', "src": "dhcp", "dst": 'core_fail'}
        e.fsm, e.event, e.src, e.dst, e.msg, e.interface = mgr.fsm, event, \
                                                           'dhcp', 'core_fail', 'test core fail', 'eth0'
        mgr._fsm_provision_core_fail(e)
        mgr.fsm.Error(msg='test fsm error')

        mgr1 = ManagerProcess(simulator=False)
        mgr1.fsm.INTERFACE_SCAN(interface='eth0')
        mgr1.interface_candidate.append('eth0')
        e = _e_obj()
        event = {"name": 'core_fail', "src": "dhcp", "dst": 'core_fail'}
        e.fsm, e.event, e.src, e.dst, e.msg, e.interface = mgr1.fsm, event, \
                                                           'dhcp', 'core_fail', 'test core fail', 'eth0'
        mgr1.set_time(time.time(), step=t_TpcMessage.SUCCESS)
        mgr1._fsm_provision_core_fail(e)

        mgr1.fsm.Error(msg='test fsm error')

    @unittest.skip('skip test_interface_scan_timeout_callback')
    def test_interface_scan_timeout_callback(self):
        print '*' * 80
        print "start to test _interface_scan_timeout_callback"
        mgr = ManagerProcess(simulator=False)
        try:
            mgr._interface_scan_timeout_callback(None)
        except Exception as e:
            self.assertEqual(type(e), IOError)
        mgr.fsm.Error(msg='test fsm error')

    def test_handle_rcp_request_msg(self):
        print '*' * 80
        print "start to test _handle_rcp_request_msg"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')

        # msg is not string
        mgr._handle_rcp_request_msg('test', 1)

        # msg is unknown
        mgr._handle_rcp_request_msg('test', 'msg')

        # l2tp not ready
        ccap_core = CCAPCore.ccap_core_db.values()
        ccap_core[0].interface = 'eth0'
        ccap_core[0].ccap_core_network_address = '1.1.1.5'
        ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE
        ccap_core[0].is_principal = CoreDescription.CORE_ROLE_PRINCIPAL
        mgr._handle_rcp_request_msg('get_active_principal', 'msg')

        # l2tp ready
        ccap_core[0].agent_status[ProcessAgent.AGENTTYPE_L2TP] = True
        mgr._handle_rcp_request_msg('get_active_principal', 'msg')

        mgr.fsm.Error(msg='test fsm error')

    def test_interface_up_handler(self):
        print '*' * 80
        print "start to test interface_up_handler"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')

        mgr.interface_list.append(
            {
                "interface": 'eth0',
                "status": mgr.INTERFACE_UP,
            }
        )
        mgr.interface_up_handler(['eth1', 'eth2'])
        mgr.fsm.Error(msg='test fsm error')

    def test_handle_mgr_interface_up_event(self):
        print '*' * 80
        print "start to test _handle_mgr_interface_up_event"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS

        mgr._handle_mgr_interface_up_event(event_request_rsp.mgr_event)
        mgr.fsm.Error(msg='test fsm error')

    def test_handle_mgr_8021x_event(self):
        print '*' * 80
        print "start to test _handle_mgr_8021x_event"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_8021X

        mgr._handle_mgr_8021x_event(event_request_rsp.mgr_event)
        mgr.fsm.Error(msg='test fsm error')

    def test_handle_mgr_dhcp_event(self):
        print '*' * 80
        print "start to test _handle_mgr_dhcp_event"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_DHCP

        ccap_core = CCAPCore.ccap_core_db.values()
        ccap_core[0].interface = 'eth0'

        # no data field
        mgr._handle_mgr_dhcp_event(event_request_rsp.mgr_event)

        # with core list
        event_request_rsp.mgr_event.data = json.dumps(
            {'CCAPCores': ['1.1.1.1', ],
             'TimeServers': ['1.1.1.1', ],
             'TimeOffset': 100,
             'LogServers': ['1.1.1.1', ],
             'initiated_by': None,
             'Interface': 'eth0'})
        mgr._handle_mgr_dhcp_event(event_request_rsp.mgr_event)

        # eth0 already in dhcp_parameters, update it
        event_request_rsp.mgr_event.data = json.dumps(
            {'CCAPCores': ['1.1.1.1', '1.1.1.7'],
             'TimeServers': ['1.1.1.1', ],
             'TimeOffset': 100,
             'LogServers': ['1.1.1.1', ],
             'initiated_by': None,
             'Interface': 'eth0'})
        mgr._handle_mgr_dhcp_event(event_request_rsp.mgr_event)

        # no update
        event_request_rsp.mgr_event.data = json.dumps(
            {'CCAPCores': ['1.1.1.1', '1.1.1.7'],
             'TimeServers': ['1.1.1.1', ],
             'TimeOffset': 100,
             'LogServers': ['1.1.1.1', ],
             'initiated_by': None,
             'Interface': 'eth0'})
        mgr._handle_mgr_dhcp_event(event_request_rsp.mgr_event)

        # no core list
        event_request_rsp.mgr_event.data = json.dumps(
            {'CCAPCores': [],
             'TimeServers': ['1.1.1.1', ],
             'TimeOffset': 100,
             'LogServers': ['1.1.1.1', ],
             'initiated_by': None,
             'Interface': 'eth0'})
        mgr._handle_mgr_dhcp_event(event_request_rsp.mgr_event)

        mgr.fsm.Error(msg='test fsm error')

    def test_handle_mgr_tod_event(self):
        print '*' * 80
        print "start to test _handle_mgr_tod_event"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_TOD

        event_request_rsp.mgr_event.data = 'tod_first_failed/0'
        mgr._handle_mgr_tod_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = 'tod_failed/'
        mgr._handle_mgr_tod_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = 'tod_failed/'
        mgr.tod_retry = mgr.TOD_RETRY_CNT
        mgr._handle_mgr_tod_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = 'else/'
        mgr._handle_mgr_tod_event(event_request_rsp.mgr_event)
        mgr.fsm.Error(msg='test fsm error')

    def test_handle_mgr_ipsec_event(self):
        print '*'*80
        print "start to test _handle_mgr_ipsec_event"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_IPSEC
        mgr._handle_mgr_ipsec_event(event_request_rsp.mgr_event)

        keys = CCAPCore.ccap_core_db.keys()
        for key in keys:
            CCAPCore.ccap_core_db.pop(key)
        mgr.fsm.Error(msg='test fsm error')

    def test_handle_mgr_gcp_event(self):
        print '*'*80
        print "start to test _handle_mgr_gcp_event"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_GCP

        # interface set to ''
        event_request_rsp.mgr_event.data = json.dumps("reboot/;1.1.1.1;info")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = json.dumps("connect_closed/;1.1.1.1;" + str(True))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = json.dumps("gcp_flapping/;1.1.1.1/recovering")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = json.dumps("redirect/1.1.1.3;/;1.1.1.1/")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # interface and ip valid
        ccap_core = CCAPCore.ccap_core_db.values()
        ccap_core[0].interface = 'eth0'
        ccap_core[0].ccap_core_network_address = '1.1.1.5'
        mgr.add_ip_to_core_map('eth0', ('1.1.1.5', '', 4))
        mgr.principal_core = ccap_core[0]

        second_core = CCAPCore('CORE-1234567890', CoreDescription.CORE_ROLE_PRINCIPAL,
                               CoreDescription.CORE_MODE_ACTIVE, mgr=mgr,
                               ccap_core_interface='eth0', ccap_core_network_address='1.1.1.6')
        CCAPCore.ccap_core_db[second_core.ccap_core_id] = second_core

        event_request_rsp.mgr_event.data = json.dumps("reboot/eth0;1.1.1.5;info")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        ccap_core = CCAPCore('CORE-1234567890', CoreDescription.CORE_ROLE_PRINCIPAL,
                             CoreDescription.CORE_MODE_ACTIVE, mgr=mgr,
                             ccap_core_interface='eth0', ccap_core_network_address='1.1.1.5')
        CCAPCore.ccap_core_db[ccap_core.ccap_core_id] = ccap_core
        event_request_rsp.mgr_event.data = json.dumps("connect_closed/eth0;1.1.1.5;" + str(True))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        event_request_rsp.mgr_event.data = json.dumps("gcp_flapping/eth0;1.1.1.5/recovering")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        event_request_rsp.mgr_event.data = json.dumps("gcp_flapping/eth0;1.1.1.5/done")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        mgr.add_ip_to_core_map('eth0', ('1.1.1.5', '', 4))
        event_request_rsp.mgr_event.data = json.dumps("redirect/1.1.1.3;/eth0;1.1.1.5")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        mgr.add_ip_to_core_map('eth0', ('1.1.1.5', '', 4))
        event_request_rsp.mgr_event.data = json.dumps("get_active_principal/3,1.1.1.1/")
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

    def test_gcp_retry_negative_case(self):
        print '*' * 80
        print "start to test_gcp_retry_negative_case"
        mgr = ManagerProcess(simulator=False)
        core_a = CCAPCore('CORE-1000000001', CoreDescription.CORE_ROLE_PRINCIPAL,
                          CoreDescription.CORE_MODE_ACTIVE, mgr=mgr,
                          ccap_core_interface='eth0', ccap_core_network_address='1.1.1.2')

        core_b = CCAPCore('CORE-1000000002', CoreDescription.CORE_ROLE_AUXILIARY,
                          CoreDescription.CORE_MODE_ACTIVE, mgr=mgr,
                          ccap_core_interface='eth0', ccap_core_network_address='1.1.1.3')
        CCAPCore.ccap_core_db[core_a.ccap_core_id] = core_a
        CCAPCore.ccap_core_db[core_b.ccap_core_id] = core_b

        core_a.fsm.TRIGGER_Startup()
        core_a.fsm.TRIGGER_INTERFACE_UP()
        core_a.fsm.TRIGGER_MAC_8021X_OK()
        core_a.fsm.TRIGGER_DHCP_OK()
        core_a.fsm.TRIGGER_IPSEC_OK()

        core_a.del_ccap_core()
        core_b.del_ccap_core()
        core_a.fsm.TRIGGER_IPSEC_FAIL()

    def test_config_table(self):
        print '*'*80
        print "start to test _handle_mgr_gcp_event config_table"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_GCP

        # invalid ip
        caps = {"ccap_core": '0.0.0.0', 'interface': 'eth0',
                "operation": 0}
        event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # add existed ip
        ccap_core = CCAPCore.ccap_core_db.values()
        ccap_core[0].interface = 'eth0'
        ccap_core[0].ccap_core_network_address = '1.1.1.5'
        ccap_core[0].is_principal = CoreDescription.CORE_ROLE_PRINCIPAL
        ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE
        # CCAPCore('CORE-1234567890', CoreDescription.CORE_ROLE_PRINCIPAL,
        #          CoreDescription.CORE_MODE_ACTIVE, mgr=mgr,
        #          ccap_core_interface='etho0', ccap_core_network_address='1.1.1.5')
        caps = {"ccap_core": '1.1.1.5', 'interface': 'eth0',
                "operation": 0} # add
        event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # add a new one
        caps = {"ccap_core": '1.1.1.6', 'interface': 'eth0',
                "operation": 0}     # add
        event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        caps = {"ccap_core": '1.1.1.5', 'interface': 'eth0',
                "operation": 2}     # change
        event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        mgr.add_ip_to_core_map('eth0', ('1.1.1.5', '', 4))
        caps = {"ccap_core": '1.1.1.5', 'interface': 'eth0',
                "operation": 1}     # delete
        event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        mgr.fsm.Error(msg='test fsm error')

    def test_gcp_roel(self):
        print '*' * 80
        print "start to test _handle_mgr_gcp_event role"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_GCP

        ccap_core = CCAPCore.ccap_core_db.values()
        ccap_core[0].interface = 'eth0'
        ccap_core[0].ccap_core_network_address = '1.1.1.5'
        # ccap_core[0].is_principal = CoreDescription.CORE_ROLE_PRINCIPAL
        # ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE

        # not exist core
        caps = {"is_active": False, "ccap_core": '1.1.1.10', 'interface': 'eth0', "is_principal": False}
        event_request_rsp.mgr_event.data = json.dumps("role/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # principal active
        caps = {"is_active": True, "ccap_core": '1.1.1.5', 'interface': 'eth0', "is_principal": True}
        event_request_rsp.mgr_event.data = json.dumps("role/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # auxiliary standby
        caps = {"is_active": False, "ccap_core": '1.1.1.5', 'interface': 'eth0', "is_principal": False}
        event_request_rsp.mgr_event.data = json.dumps("role/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        mgr.fsm.Error(msg='test fsm error')

    def test_gcp_Ha(self):
        print '*' * 80
        print "start to test _handle_mgr_gcp_event HA"
        mgr = ManagerProcess(simulator=False)
        mgr.fsm.INTERFACE_SCAN(interface='eth0')
        mgr.fsm.STARTUP_DHCP_OK(interface='eth0')
        event_request_rsp = protoDef.msg_event_notification()
        event_request_rsp.mgr_event.mgr_id = mgr.mgr_id
        event_request_rsp.mgr_event.event_id = ProcessAgent.AGENTTYPE_GCP

        ccap_core = CCAPCore.ccap_core_db.values()
        ccap_core[0].interface = 'eth0'
        ccap_core[0].ccap_core_network_address = '1.1.1.5'

        print 'Redundant core Add'
        # invalid ip
        caps = {"ActiveCoreIpAddress": '0.0.0.0', "StandbyCoreIpAddress": '1.1.1.10',
                'interface': 'eth0', "operation": 0}
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # not exist core
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.11',
                'interface': 'eth0', "operation": 0}
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # active core mode active
        caps = {"ActiveCoreIpAddress": '1.1.1.5', "StandbyCoreIpAddress": '1.1.1.11',
                'interface': 'eth0', "operation": 0}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        # active core mode standby
        caps = {"ActiveCoreIpAddress": '1.1.1.5', "StandbyCoreIpAddress": '1.1.1.11',
                'interface': 'eth0', "operation": 0}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_STANDBY
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        # standby core mode active
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.5',
                'interface': 'eth0', "operation": 0}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        # standby core mode standby
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.5',
                'interface': 'eth0', "operation": 0}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_STANDBY
        mgr.add_ip_to_core_map('eth0', ('1.1.1.5', '', 0))
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        print 'Redundant core Change'
        ccap_core[0].is_principal = CoreDescription.CORE_ROLE_PRINCIPAL

        # standby core mode active
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.5',
                'interface': 'eth0', "operation": 2}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        # standby core mode standby
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.5',
                'interface': 'eth0', "operation": 2}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_STANDBY
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        print 'Redundant core Delete'
        # standby core mode active
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.5',
                'interface': 'eth0', "operation": 1}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_ACTIVE
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)
        # standby core mode standby
        caps = {"ActiveCoreIpAddress": '1.1.1.10', "StandbyCoreIpAddress": '1.1.1.5',
                'interface': 'eth0', "operation": 1}
        ccap_core[0].is_active = CoreDescription.CORE_MODE_STANDBY
        event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
        mgr._handle_mgr_gcp_event(event_request_rsp.mgr_event)

        mgr.fsm.Error(msg='test fsm error')

if __name__ == '__main__':
    unittest.main()
    setup_logging("PROVISION", "test.log")
