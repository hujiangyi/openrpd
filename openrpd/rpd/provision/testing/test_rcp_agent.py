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
import json
import zmq
import time
import socket
import signal
from threading import Timer
import rpd.provision.proto.process_agent_pb2 as pb2
from rpd.provision.process_agent.agent.agent import ProcessAgent
import subprocess
from rpd.provision.process_agent.rcp.rcp_agent import RcpOverGcp
from rpd.provision.transport.transport import Transport
from rpd.common.rpd_logging import setup_logging
from rpd.rcp.rcp_lib.rcp import RCPSequence
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.rcp.rcp_sessions import RCPSlaveSession
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor
from rpd.provision.manager.src.manager_process import ManagerProcess
from rpd.rcp.rcp_orchestrator import RCPMasterCapabilities


timeStampSock = "/tmp/redis.sock"


def setupDB():
    """Create and start the redis server, then set up the DB.

    :parameter: None
    :return: None

    """
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    filename = "/tmp/test_rcpagent.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(timeStampSock):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")


class TestRcpAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupDB()

    @classmethod
    def tearDownClass(cls):
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)

    def setUp(self):
        # try to find the rcp agent
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") - 2
        self.rootpath = "/".join(dirs[:rpd_index])
        print "python " + self.rootpath + "/rpd/hal/src/HalMain.py --conf " + self.rootpath + "/rpd/hal/conf/hal.conf"
        self.hal_pid = subprocess.Popen("coverage run --parallel-mode --rcfile="+self.rootpath+"/.coverage.rc "
                                        + self.rootpath +
                                        "/rpd/hal/src/HalMain.py --conf " +
                                        self.rootpath + "/rpd/hal/conf/hal.conf",
                                        executable='bash', shell=True)
        self.rcp_pid = subprocess.Popen("coverage run --parallel-mode --rcfile="+self.rootpath+"/.coverage.rc " 
                                        + self.rootpath +
                                        "/rpd/provision/process_agent/rcp/rcp_agent.py",
                                        executable='bash', shell=True)
        time.sleep(2)
        self.timer = None
        self.running = True
        self.tryCnt = 4

    def tearDown(self):
        if getattr(self, 'hal_pid', None) is None:
            pass
        else:
            self.hal_pid.send_signal(signal.SIGINT)
            self.hal_pid.wait()
            self.hal_pid = None
        if getattr(self, 'rcp_pid', None) is None:
            pass
        else:
            self.rcp_pid.send_signal(signal.SIGINT)
            self.rcp_pid.wait()
            self.rcp_pid = None
        self.stop_mastersim()
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')


    def start_mastersim(self):
        print "*" * 40 + 'start_mastersim' + "*" * 40
        self.mastersim_pid = subprocess.Popen("coverage run --parallel-mode --rcfile="+self.rootpath+"/.coverage.rc "
                                              + self.rootpath +
                                              "/rpd/rcp/simulator/rcp_master_sim.py" +
                                              " --use_interface 127.0.0.1",
                                              executable='bash',
                                              shell=True)

    def stop_mastersim(self):
        print "*" * 40 + 'stop_mastersim' + "*" * 40
        if getattr(self, 'mastersim_pid', None) is None:
            pass
        else:
            self.mastersim_pid.send_signal(signal.SIGINT)
            self.mastersim_pid.wait()
            self.mastersim_pid = None

    def timer_cb(self):
        print "*" * 40 + 'timer callback' + str(time.localtime(time.time())) + "*" * 40
        if self.running:
            if self.tryCnt:
                if self.tryCnt % 2:
                    self.stop_mastersim()
                    t = 2
                else:
                    self.start_mastersim()
                    t = 5
                self.timer = Timer(t, self.timer_cb)
                self.timer.start()
                self.tryCnt -= 1
            else:
                self.running = False

    @unittest.skip("MAX_RECONNECT_CNT set to 0, so skip this case")
    def test_rcp_event(self):
        context = zmq.Context()
        sock1 = context.socket(zmq.PUSH)
        sock1.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_GCP]['pull'])

        sock = context.socket(zmq.REQ)
        sock.connect(ProcessAgent.SockPathMapping[ProcessAgent.AGENTTYPE_GCP]['api'])

        sock2 = context.socket(zmq.PULL)
        sock2.bind("ipc:///tmp/sock4.scok")

        mgr_scok = context.socket(zmq.REP)
        mgr_scok.bind("ipc:///tmp/rpd_provision_manager_api.sock")

        # test the successfully register
        event_request = pb2.api_request()
        reg = pb2.msg_manager_register()
        reg.id = "test_rcp"
        reg.action = pb2.msg_manager_register.REG
        reg.path_info = "ipc:///tmp/sock4.scok"
        event_request.mgr_reg.CopyFrom(reg)
        data = event_request.SerializeToString()

        sock.send(data)

        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print "=" * 40 + "MGR REG" + "=" * 40
        print reg_rsp

        # core register
        register_request = pb2.api_request()
        reg = pb2.msg_core_register()
        reg.ccap_core_id = 'test_rcp'
        reg.mgr_id = 'test_rcp'
        reg.action = pb2.msg_core_register.REG

        register_request.core_reg.CopyFrom(reg)
        data = register_request.SerializeToString()
        sock.send(data)
        data = sock.recv()
        reg_rsp = pb2.api_rsp()
        reg_rsp.ParseFromString(data)
        print "=" * 40 + "CORE REG" + "=" * 40
        print reg_rsp

        event_request = pb2.msg_event_request()
        event_request.action.id = "test_rcp"
        event_request.action.ccap_core_id = "test_rcp"
        event_request.action.event_id = ProcessAgent.AGENTTYPE_GCP
        event_request.action.parameter = 'lo;127.0.0.1'

        event_request.action.action = pb2.msg_event.START

        sock1.send(event_request.SerializeToString())

        data = sock2.recv()
        rsp = pb2.msg_event_notification()
        rsp.ParseFromString(data)
        print "=" * 40 + "START" + "=" * 40
        print rsp

        result = False
        print "*" * 40 + 'start timer' + str(time.localtime(time.time())) + "*" * 40
        self.timer = Timer(1, self.timer_cb)
        self.timer.start()
        while self.running:
            try:
                data = sock2.recv(flags=zmq.NOBLOCK)
                if len(data) > 0:
                    rsp = pb2.msg_event_notification()
                    rsp.ParseFromString(data)
                    print "=" * 40 + "NTF" + "=" * 40
                    print rsp
                    if rsp.core_event.result == "DOWN":
                        event_request = pb2.msg_event_request()
                        event_request.action.id = "test_rcp"
                        event_request.action.ccap_core_id = "test_rcp"
                        event_request.action.event_id = ProcessAgent.AGENTTYPE_GCP
                        event_request.action.parameter = 'lo;127.0.0.1'

                        event_request.action.action = pb2.msg_event.STOP

                        sock1.send(event_request.SerializeToString())
                        data = sock2.recv()
                        rsp = pb2.msg_event_notification()
                        rsp.ParseFromString(data)
                        print "=" * 40 + "STOP" + "=" * 40
                        print rsp
                        result = False
                        self.running = False
                    elif rsp.core_event.result == "UP":
                        result = True
            except zmq.Again:
                pass
            except Exception as e:
                print "exception:%s" % str(e)
        if self.timer:
            self.timer.cancel()
        self.assertEqual(result, True)
        time.sleep(5)
        try:
            data = sock2.recv(flags=zmq.NOBLOCK)
            if len(data) > 0:
                rsp = pb2.msg_event_notification()
                rsp.ParseFromString(data)
                print "=" * 40 + "TIMEOUT" + "=" * 40
                print rsp
                self.assertEqual(rsp.core_event.result, "DOWN")
        except Exception as e:
            print "exception:%s" % str(e)


class TestRcpAgentFunc(unittest.TestCase):

    def setUp(self):
        setup_logging(("PROVISION", "GCP"), filename="provision_rcp.log")
        self.agent = RcpOverGcp()
        self.agent.ccap_cores['CORE-1234567890'] = {"mgr": "MGR-1234567890",}
        self.agent.rcp[('eth0', '1.1.1.1')] = {
            "status": self.agent.DOWN,
            "requester": ['CORE-1234567890', ],
            "lastChangeTime": 1,
        }

        path = "ipc:///tmp/rcp.scok"
        transport = Transport(
            path, Transport.PUSHSOCK, Transport.TRANSPORT_CLIENT)

        # Add the fsm to our internal database
        self.agent.mgrs["MGR-1234567890"] = {
            "transport": transport,
            "name": "RCP",
            "para": {},
            "path": path,
        }

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          1,
                          rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                          unittest=True)
        self.agent.rcp_req_group[(1, '1.1.1.1')] = (seq, None, 'transaction_identifier', 'trans_id', time.time() - 5)

        self.agent.gcp_flapping_list[('eth0', '1.1.1.1')] = None

    def tearDown(self):
        self.agent.mgrs["MGR-1234567890"]['transport'].sock.close()
        self.agent = None
        os.system("rm /tmp/ProcessAgent_AGENTTYPE_GCP")

    def test_timeout(self):
        print '############test timeout case#############'
        self.agent._timeout_check_cb(None)

        self.agent.rcp[('eth0', '1.1.1.5')] = {
            "status": self.agent.DOWN,
            "requester": ['CORE-1234567895', ],
            "lastChangeTime": 1,
        }
        self.agent.gcp_flapping_list[('eth0', '1.1.1.5')] = None
        self.agent.gcp_flap_timeout(('eth0', '1.1.1.5'))

        self.agent.ccap_cores['CORE-1234567895'] = {"mgr": "MGR-1234567890",}
        self.agent.rcp[('eth0', '1.1.1.5')]['status'] = self.agent.UP
        self.agent.gcp_flap_timeout(('eth0', '1.1.1.5'))
        self.agent.ccap_cores.pop('CORE-1234567895')

        self.agent.rcp[('eth0', '1.1.1.5')]['status'] = self.agent.UP
        self.agent.gcp_flap_timeout(('eth0', '1.1.1.5'))

    def test_mgr_rcp_rsp_not_exist(self):
        print '############test not exist case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.READ
        rcp_rsp.action.parameter = json.dumps("get_active_principal/1, 2.1.1.1/2.2.2.2")
        self.agent.mgr_rcp_rsp(rcp_rsp.action)

    def test_mgr_rcp_rsp_fail(self):
        print '############test req return fail case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.READ
        rcp_rsp.action.parameter = json.dumps("get_active_principal/1,1.1.1.1/fail")
        self.agent.mgr_rcp_rsp(rcp_rsp.action)

    def test_mgr_rcp_rsp_exception(self):
        print '############test exception case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.READ
        rcp_rsp.action.parameter = json.dumps("get_active_principal/1,1.1.1.1/fail")
        self.agent.rcp_req_group[(1, '1.1.1.1')] = (None, None, 'transaction_identifier', 'trans_id', 1)
        self.agent.mgr_rcp_rsp(rcp_rsp.action)

    def test_mgr_rcp_rsp(self):
        print '############test normal case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.READ
        rcp_rsp.action.parameter = json.dumps("get_active_principal/1,1.1.1.1/2.2.2.2")
        self.agent.mgr_rcp_rsp(rcp_rsp.action)

    def test_mgr_write_request_true(self):
        print '############test led light case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.WRITE
        rcp_rsp.action.parameter = json.dumps("light_led/True")
        self.agent.mgr_write_request(rcp_rsp.action)

    def test_mgr_write_request_false(self):
        print '############test led dark case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.WRITE
        rcp_rsp.action.parameter = json.dumps("light_led/Faslse")
        self.agent.mgr_write_request(rcp_rsp.action)

    def test_mgr_write_request_set_principal(self):
        print '############test set principal case#############'
        rcp_rsp = pb2.msg_event_request()
        rcp_rsp.action.id = "MGR-1234567890"
        rcp_rsp.action.event_id = self.agent.id
        rcp_rsp.action.action = pb2.msg_event.WRITE
        rcp_rsp.action.parameter = json.dumps("set_active_principal/eth0, 1.1.1.1")
        self.agent.mgr_write_request(rcp_rsp.action)

    def test_rcp_msg_cb_basic(self):
        print '############test rcp_msg_cb basic case#############'
        # seq==None
        self.agent.rcp_msg_cb(None)

        seq = t_RcpMessage()
        self.agent.rcp_msg_cb(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          1,
                          rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                          unittest=True)
        desc = GCPSlaveDescriptor(
            '1.1.1.1', port_master='8190', addr_local='1.1.1.2',
            interface_local='eth0',
            addr_family=socket.AF_INET)
        orch = self.agent.process.orchestrator
        session = RCPSlaveSession(desc, self.agent.process.dispatcher,
                                  orch.session_initiate_cb,
                                  orch.session_timeout_cb,
                                  orch.session_connecting_timeout_cb)
        self.agent.rcp_msg_cb(seq,  (session, 'transaction_identifier', 'trans_id'))

    def test_rcp_msg_cb_event(self):
        print '############test rcp_msg_cb event case#############'

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          1,
                          rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                          unittest=True)
        desc = GCPSlaveDescriptor(
            '1.1.1.1', port_master='8190', addr_local='1.1.1.2',
            interface_local='eth0',
            addr_family=socket.AF_INET)
        orch = self.agent.process.orchestrator
        session = RCPSlaveSession(desc, self.agent.process.dispatcher,
                                  orch.session_initiate_cb,
                                  orch.session_timeout_cb,
                                  orch.session_connecting_timeout_cb)
        # reboot
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_REBOOT

        ccap_core_para = {'addr_remote': '1.1.1.1', 'interface_local': 'eth1', 'info': "test"}
        rcp_msg.parameter = json.dumps(ccap_core_para)
        self.agent.rcp_msg_cb(rcp_msg)

        # redirect
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.REDIRECT_NOTIFICATION
        ccap_core_para = {'addr_remote': '1.1.1.1', 'interface_local': 'eth0', 'info': "test"}
        rcp_msg.parameter = json.dumps(ccap_core_para)
        rcp_msg.RedirectCCAPAddresses.append('3.3.3.3')
        self.agent.rcp[('eth0', '1.1.1.1')]['status'] = self.agent.UP
        self.agent.rcp_msg_cb(rcp_msg)

        # configuration
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_CONFIGURATION
        cfg = rcp_msg.RpdDataMessage.RpdData
        rcp_msg.parameter = 'eth0'
        capability = cfg.CcapCoreIdentification.add()
        capability.Index = 1
        capability.CoreId = 'CoreId'
        capability.CoreIpAddress = '1.1.1.1'
        capability.IsPrincipal = True
        capability.CoreMode = 1
        capability.CoreName = "CiscoRPD"
        capability.VendorId = 1
        capability.InitialConfigurationComplete = True
        capability.MoveToOperational = True
        capability.CoreFunction = 1
        capability.ResourceSetIndex = 2
        self.agent.rcp[('eth0', '1.1.1.1')]['status'] = self.agent.DOWN
        self.agent.rcp_msg_cb(rcp_msg)

        # RedundantCoreIpAddress
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_CONFIGURATION
        cfg = rcp_msg.RpdDataMessage.RpdData
        rcp_msg.parameter = 'eth0'
        red = cfg.RedundantCoreIpAddress.add()
        red.ActiveCoreIpAddress = '1.1.1.1'
        red.StandbyCoreIpAddress = '1.1.1.3'
        self.agent.rcp_msg_cb(rcp_msg) # no must field

        desc1 = GCPSlaveDescriptor(
            '1.1.1.1', port_master='8190', addr_local='1.1.1.2',
            interface_local='eth0',
            addr_family=socket.AF_INET)
        orch = self.agent.process.orchestrator
        session_1 = RCPSlaveSession(desc1, self.agent.process.dispatcher,
                                  orch.session_initiate_cb,
                                  orch.session_timeout_cb,
                                  orch.session_connecting_timeout_cb)
        self.agent.process.orchestrator.sessions_active[desc1.get_uniq_id()] = session_1
        caps1 = RCPMasterCapabilities(index=1,
                                      core_id="CoreId-1",
                                      core_ip_addr='1.1.1.1',
                                      is_principal=True,
                                      core_name="SIM_GCPP",
                                      vendor_id=0,
                                      is_active=True,
                                      initial_configuration_complete=True,
                                      move_to_operational=True,
                                      core_function=1,
                                      resource_set_index=2)
        session_1.ccap_capabilities = caps1

        desc2 = GCPSlaveDescriptor(
            '1.1.1.3', port_master='8190', addr_local='1.1.1.2',
            interface_local='eth0',
            addr_family=socket.AF_INET)
        orch = self.agent.process.orchestrator
        session_2 = RCPSlaveSession(desc2, self.agent.process.dispatcher,
                                  orch.session_initiate_cb,
                                  orch.session_timeout_cb,
                                  orch.session_connecting_timeout_cb)
        # self.agent.process.orchestrator.add_sessions([desc2])
        self.agent.process.orchestrator.sessions_active[desc2.get_uniq_id()] = session_2
        caps2 = RCPMasterCapabilities(index=1,
                                      core_id="CoreId-2",
                                      core_ip_addr='1.1.1.1',
                                      is_principal=True,
                                      core_name="SIM_GCPP",
                                      vendor_id=0,
                                      is_active=True,
                                      initial_configuration_complete=True,
                                      move_to_operational=True,
                                      core_function=1,
                                      resource_set_index=2)
        session_2.ccap_capabilities = caps2


        caps1.is_active = False
        caps2.is_active = True
        red.Operation = ManagerProcess.OPERATION_ADD
        self.agent.rcp_msg_cb(rcp_msg)

        caps1.is_active = True
        caps2.is_active = False
        red.Operation = ManagerProcess.OPERATION_CHANGE
        self.agent.rcp_msg_cb(rcp_msg)

        # ConfiguredCoreTable
        # miss operation field
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_CONFIGURATION
        cfg = rcp_msg.RpdDataMessage.RpdData
        cfg_core = cfg.ConfiguredCoreTable.add()
        cfg_core.ConfiguredCoreIp = '1.1.1.1'
        self.agent.rcp_msg_cb(rcp_msg)

        cfg_core.Operation = 0
        self.agent.rcp_msg_cb(rcp_msg)

        # ActivePrincipalCore
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_CONFIGURATION
        cfg = rcp_msg.RpdDataMessage.RpdData
        cfg.ActivePrincipalCore = '1.1.1.1'
        seq.ipc_msg = rcp_msg
        self.agent.rcp_msg_cb(seq, (session, 'transaction_identifier', 'trans_id'))

        # RPD_CONFIGURATION else
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_CONFIGURATION
        cfg = rcp_msg.RpdDataMessage.RpdData
        cfg_core = cfg.Ssd
        cfg_core.SsdServerAddress = '1.1.1.1'
        self.agent.rcp_msg_cb(rcp_msg)

        # configuration done
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.RPD_CONFIGURATION_DONE
        rcp_msg.parameter = ';'.join(['eth0', '1.1.1.1'])
        self.agent.principal_core_interface = 'eth0'
        self.agent.principal_core = '1.1.1.1'
        self.agent.rcp_msg_cb(rcp_msg, (session, 'transaction_identifier', 'trans_id'))

        # CONNECT_CLOSE_NOTIFICATION
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.CONNECT_CLOSE_NOTIFICATION
        ccap_core_para = {'addr_remote': '1.1.1.1', 'interface_local': 'eth0', "reconnect": True}
        rcp_msg.parameter = json.dumps(ccap_core_para)
        self.agent.ccap_cores.pop('CORE-1234567890')
        self.agent.rcp_msg_cb(rcp_msg)

        ccap_core_para = {'addr_remote': '1.1.1.1', 'interface_local': 'eth0', "reconnect": False}
        rcp_msg.parameter = json.dumps(ccap_core_para)
        self.agent.rcp_msg_cb(rcp_msg)

    def test_process_event_action_error(self):
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

        # value error
        req.action.parameter = json.dumps("eth0/1.1.1.1")
        req.action.action = pb2.msg_event.START
        self.agent.process_event_action(req.action)

        self.agent.ccap_cores['CORE-1234567891'] = {"mgr": "MGR-1234567890",}
        req.action.ccap_core_id = "CORE-1234567891"
        req.action.parameter = "eth0;1.1.1.1"
        req.action.action = pb2.msg_event.START
        self.agent.process_event_action(req.action)
        self.agent.ccap_cores.pop('CORE-1234567891')

    def test_process_event_action(self):
        print '############test process_event_action case#############'
        req = pb2.msg_event_request()

        # write
        req.action.ccap_core_id = "CORE-1234567890"
        req.action.parameter = json.dumps("light_led/True")
        req.action.event_id = self.agent.id
        req.action.action = pb2.msg_event.WRITE
        self.agent.process_event_action(req.action)

        # read
        req.action.action = pb2.msg_event.READ
        self.agent.process_event_action(req.action)

        # start
        req.action.parameter = "eth0;1.1.1.1"
        req.action.action = pb2.msg_event.START
        self.agent.process_event_action(req.action)

        # stop
        req.action.parameter = "eth0;1.1.1.1"
        req.action.action = pb2.msg_event.STOP
        self.agent.process_event_action(req.action)

        # stop not exist core
        req.action.parameter = "eth0;1.1.1.3"
        req.action.action = pb2.msg_event.STOP
        self.agent.process_event_action(req.action)

        # start
        req.action.parameter = "eth0;1.1.1.3"
        req.action.action = pb2.msg_event.START
        self.agent.process_event_action(req.action)

    def test_cleanup_db(self):
        self.agent.cleanup_db('CORE-1234567890')

if __name__ == "__main__":
    unittest.main()
