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

"""
This file will provide the following features
1. the interface between the manager and the process agent.
2. send the event trigger and get the status report to/from the process agent.
"""
import ast
import json
import time
import traceback
from random import randint
import zmq
from psutil import net_if_stats
from rpd.gpb.tpc_pb2 import t_TpcMessage

import rpd.provision.proto.process_agent_pb2 as agent_pb2
import rpd.provision.proto.provision_pb2 as provision_pb2
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.dispatcher.timer import DpTimerManager
from rpd.provision.manager.src.manager_api import ManagerApi
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.transport.transport import Transport
from rpd.provision.manager.src.manager_ccap_core import CCAPCore, CoreDescription
from rpd.common.utils import SysTools, Convert
from rpd.provision.manager.src.dhcpinfoDb import DhcpInfoRecord
from rpd.provision.manager.src.manager_fsm import ManagerFsm, CCAPFsm
from rpd.provision.manager.src.manager_hal import ProvMgrHalDriver
from fysom import FysomError
from rpd.common import rpd_event_def
from rpd.common.rpd_event_def import RPD_EVENT_CONNECTIVITY_REBOOT
from rpd.statistics.manager_provision_stat import ManagerProvisionStateMachineRecord


class ManagerError(Exception):
    pass


class CCAPCoreOrchestrator(object):
    """"orchestrate the ccap core list, seeking for principal."""

    __metaclass__ = AddLoggerToClass

    __ORCHESTRATION_TIME = 60
    # this timer is used as hold time before retry after all list candidate cores are failed
    NO_PRINCIPAL_CORE_FOUND_TIMEOUT = 60

    def __init__(self, mgr, fsm, dispatcher, candidate, parameters):
        """initiate the Core orchestrator.

        :param mgr: ManagerProcess instance
        :param fsm: ManagerProcess state machine instance
        :param dispatcher: dispatcher
        :param candidate: ccap core candidate, fmt is {"eth1"[(core ip, mode, trigger),]}
        :param parameters: all agent needed parameter to startup, fmt is {"eth":{"TimeServer":ip}}

        """
        self.dispatcher = dispatcher

        # ccap core info about connection
        self.ccap_core_candidate = candidate
        self.core_parameters = parameters
        self.mgr = mgr
        self.fsm = fsm

        self.active_list = []
        self.failed_list = []

        self.orchestrator_timer = None
        self.no_principal_timer = None

    def orchestrator(self):
        """start orchestrator"""
        if self.orchestrator_timer:
            self.dispatcher.timer_unregister(self.orchestrator_timer)
            self.orchestrator_timer = None
        self.orchestrator_timer = self.dispatcher.timer_register(self.__ORCHESTRATION_TIME,
                                                                 self.orchestrator_cb)

    def generate_parameter(self, interface, core_address):
        core_para = []
        try:
            # set the interface, 802.1X, DHCP agent parameters.
            for agent_id in (ProcessAgent.AGENTTYPE_INTERFACE_STATUS,
                             ProcessAgent.AGENTTYPE_8021X,
                             ProcessAgent.AGENTTYPE_DHCP,
                             ProcessAgent.AGENTTYPE_PTP,
                             ProcessAgent.AGENTTYPE_IPSEC):
                para = provision_pb2.msg_agent_parameter()
                para.agent_id = agent_id
                para.parameter = interface
                core_para.append(para)

            # TOD
            para = provision_pb2.msg_agent_parameter()
            para.agent_id = ProcessAgent.AGENTTYPE_TOD
            para.parameter = ';'.join(self.core_parameters[interface]['TimeServers'])
            para.parameter += '/' + str(self.core_parameters[interface]['TimeOffset'])
            para.parameter += '|' + ';'.join(self.core_parameters[interface]['LogServers'])
            core_para.append(para)

            for agent_id in (ProcessAgent.AGENTTYPE_GCP,
                             ProcessAgent.AGENTTYPE_L2TP):
                para = provision_pb2.msg_agent_parameter()
                para.agent_id = agent_id
                para.parameter = interface + ";" + core_address
                core_para.append(para)
            return core_para
        except Exception as e:
            self.logger.error("Got error when generate ccap core parameters, %s", str(e))
            return []

    def get_next_core(self):
        """create core"""
        initiated = ManagerProcess.CORE_INITIAL_TRIGGER[ManagerProcess.DEFAULT_CORE_TRIGGER]

        if self.candidate_core_cnt() == len(self.active_list) + len(self.failed_list):
            if None is self.mgr.principal_core:
                if None is self.mgr.principal_core_seek_timer:
                    self.mgr.principal_core_seek_timer = self.dispatcher.timer_register(
                        self.NO_PRINCIPAL_CORE_FOUND_TIMEOUT, self.mgr.principal_core_seek_failure)
                    self.logger.info("no principal, register timer to reboot")

                else:
                    self.logger.info("principal is none, but seek timer is not none")
            else:
                self.logger.info("principal core(" + str(self.mgr.principal_core) +
                                 ") is set, try to orchestrate other cores")
                # give failure core more chances
                self.failed_list = []
            return

        for interface in self.ccap_core_candidate:
            if not self.mgr.is_interface_up(interface):
                self.logger.info("Interface %s not up, skipped.", interface)
                continue
            core_info = self.ccap_core_candidate[interface]
            create_flag = False
            for core_ip, mode, trigger in core_info:
                if (interface, core_ip) not in self.failed_list and \
                        not CCAPCore.is_ccap_core_existed(interface, core_ip):
                    # prepare for CCAP core's parameter
                    para = self.generate_parameter(interface, core_ip)
                    if not len(para):
                        continue

                    # set trigger reason
                    if self.fsm.is_provisioning():
                        initiated = ManagerProcess.CORE_INITIAL_TRIGGER[trigger]
                    elif self.fsm.is_provision_retry():
                        initiated = ManagerProcess.CORE_INITIAL_TRIGGER[ManagerProcess.PROVISION_RETRY_TRIGGER]
                    elif self.fsm.is_operational():
                        initiated = ManagerProcess.CORE_INITIAL_TRIGGER[ManagerProcess.PROVISION_OPERATIONAL_TRIGGER]

                    # create CCAP core
                    ccap_core, reason = CCAPCore.add_ccap_core(self.mgr, para, active=mode,
                                                               initiated_by=initiated,
                                                               interface=interface,
                                                               network_address=core_ip,
                                                               added_by=ManagerProcess.CORE_INITIAL_TRIGGER[trigger],
                                                               test_flag=self.mgr.test_flag)
                    if None is not ccap_core:
                        create_flag = True
                        self.logger.info("Candidate core[%s, %s] created successfully.",
                                         ccap_core.interface, ccap_core.ccap_core_network_address)
                        self.active_list.append((interface, core_ip, ccap_core.ccap_core_id))
                        break
                else:
                    self.logger.info("core already created %s, but principal core is %s",
                                     interface + core_ip,
                                     None if self.mgr.principal_core is None
                                     else self.mgr.principal_core.ccap_core_network_address)

            if create_flag:
                break

    # TODO restructrue of this function make it readable
    def sync_delete_ccap_core(self):
        """sync delete ccap core to fail list,
        and remove the core has been deleted from candidate."""

        remove_list = []
        for interface, core_ip, ccap_core_id in self.active_list:
            if ccap_core_id not in CCAPCore.ccap_core_db:
                remove_list.append((interface, core_ip, ccap_core_id))

        for interface, core_ip, ccap_core_id in remove_list:
            if (interface, core_ip, ccap_core_id) in self.active_list:
                self.active_list.remove((interface, core_ip, ccap_core_id))
            if (interface, core_ip) not in self.failed_list:
                self.failed_list.append((interface, core_ip))

        remove_list = []
        for interface, core_ip in self.failed_list:
            core_info = self.ccap_core_candidate[interface]
            deleted_flag = True
            for core_address, _, _ in core_info:
                if Convert.is_ip_address_equal(core_ip, core_address):
                    deleted_flag = False
                    break
            if deleted_flag:
                remove_list.append((interface, core_ip))
        for info in remove_list:
            self.failed_list.remove(info)

    def candidate_core_cnt(self):
        """calculate the CCAP core count."""
        total_cnt = 0
        for interface in self.ccap_core_candidate:
            total_cnt += len(self.ccap_core_candidate[interface])

        return total_cnt

    def seek_principal_core(self):
        """seeking for principal core."""

        if None is not self.mgr.principal_core:
            return
        principal_found = False
        remove_list = []
        for interface, core_ip, ccap_core_id in self.active_list:
            if ccap_core_id in CCAPCore.ccap_core_db:
                ccap_core = CCAPCore.ccap_core_db[ccap_core_id]
                if not ccap_core.agent_status[ProcessAgent.AGENTTYPE_IPSEC]:
                    return

                if ccap_core.is_principal == CoreDescription.CORE_ROLE_NONE:
                    return
                if ccap_core.is_principal == CoreDescription.CORE_ROLE_PRINCIPAL and \
                        ccap_core.is_active == CoreDescription.CORE_MODE_ACTIVE:
                    principal_found = True
                else:
                    ccap_core.del_ccap_core()
                    remove_list.append((interface, core_ip, ccap_core_id))
            else:
                remove_list.append((interface, core_ip, ccap_core_id))

        for interface, core_ip, ccap_core_id in remove_list:
            if (interface, core_ip) not in self.failed_list:
                self.failed_list.append((interface, core_ip))
            if (interface, core_ip, ccap_core_id) in self.active_list:
                self.active_list.remove((interface, core_ip, ccap_core_id))

        if principal_found:
            return

        self.get_next_core()

    def orchestrator_cb(self, _):
        """Implements the method from the CCAPCoreOrchestrator interface."""

        self.logger.debug("Core candidate list %s, active list %s, fail list %s",
                          self.ccap_core_candidate, self.active_list, self.failed_list)

        # restart the orchestrator
        self.orchestrator()

        if not len(self.ccap_core_candidate):
            self.logger.debug("No CCAP core information")
            return
        self.sync_delete_ccap_core()

        if self.fsm.is_fail():
            self.logger.debug("System failure status")

        elif self.fsm.is_startup():
            self.logger.debug("System startup status")

        elif self.fsm.is_provisioning() or self.fsm.is_provision_retry():
            self.logger.debug("System is in provisioning status")
            self.seek_principal_core()

        elif self.fsm.is_operational():
            self.logger.debug("System has principal core")
            # check CCAP core enter operational or not
            for interface, core_ip, ccap_core_id in self.active_list:
                if ccap_core_id not in CCAPCore.ccap_core_db:
                    continue
                ccap_core = CCAPCore.ccap_core_db[ccap_core_id]
                if not ccap_core.agent_status[ProcessAgent.AGENTTYPE_L2TP]:
                    break

            self.get_next_core()

    def clear_list(self):
        """clear active, fail list"""
        self.active_list = []
        self.failed_list = []


class ManagerProcess(object):
    """This class implements the following features:

    1. Register manager process agents.
    2. Receive the interface scan results. DHCP results, GCP redirect
       messages and drive the manager FSM.
    3. Init the manager API for external module, such as CLI, web and etc...

    """
    __metaclass__ = AddLoggerToClass

    MGR_UNREGISTERED = "unregistered"
    MGR_UNREGISTERED_FAIL = "unregistered-fail"
    MGR_REGISTERED = "registered"
    MGR_REGISTER_FAIL = "register-fail"
    REGISTER_INITIATED_STATUS = "register-initiated"

    INTERFACE_UP = 'up'
    INTERFACE_DOWN = 'down'

    AGENT_STATUS_TIMEOUT = 3
    KA_TIMEOUT = 60
    MGR_REGISTER_TIMEOUT = 10
    INTERFACE_SCAN_TIMEOUT = 120
    # to align with I07 6.11 definition
    # CIN_LINK_TIMEOUT 120 second

    # core initial trigger
    DEFAULT_CORE_TRIGGER = 0
    DHCP_CORE_TRIGGER = 1
    GCP_REDIRECT_CORE_TRIGGER = 2
    STARTUP_CORE_TRIGGER = 3
    HA_CORE_TRIGGER = 4
    PROVISION_RETRY_TRIGGER = 5
    PROVISION_OPERATIONAL_TRIGGER = 6
    CONFIGURED_CORE_TABLE_TRIGGER = 7

    PC_BACKOFF_MIN = 60
    PC_BACKOFF_MAX = 300
    NO_PRINCIPAL_CORE_FOUND_TIMEOUT = 60
    PRINCIPAL_CORE_RETRY_COUNT = 3

    SEEK_PRINCIPAL_CORE_TIMEOUT = 300

    RPD_OPERATIONAL_TIMEOUT = 1200

    CORE_INITIAL_TRIGGER = {
        DEFAULT_CORE_TRIGGER: "Default",
        DHCP_CORE_TRIGGER: "DHCP",
        GCP_REDIRECT_CORE_TRIGGER: "GCP_Redirect",
        STARTUP_CORE_TRIGGER: "Startup",
        HA_CORE_TRIGGER: "HA",
        PROVISION_RETRY_TRIGGER: "Provision_core_retry",
        PROVISION_OPERATIONAL_TRIGGER: "Provision_operational",
        CONFIGURED_CORE_TABLE_TRIGGER: "Multiple_Core_Operation"
    }

    MGR_TO_RCP_ACTION_LIGHT_LED = 1
    MGR_TO_RCP_ACTION_SET_ACTIVE_PRINCIPAL = 2
    RcpOperation = {
        MGR_TO_RCP_ACTION_LIGHT_LED: 'light_led',
        MGR_TO_RCP_ACTION_SET_ACTIVE_PRINCIPAL: 'set_active_principal',
    }

    OPERATION_ADD = 0
    OPERATION_DELETE = 1
    OPERATION_CHANGE = 2

    WAITING_PERIOD = 10

    DHCP_LIST_LIMIT = 6

    TOD_RETRY_CNT = 1

    SYSTEM_TIME_CONFIRM = "None"
    SYSTEM_TIME_CONFIM_DICT = {
        t_TpcMessage.INITIATED: "INIT",
        t_TpcMessage.SUCCESS: "SUCCESS",
        t_TpcMessage.FIRST_ATTEMPT_FAILED: "First Attempt Failed",
        t_TpcMessage.ALL_ATTEMPTS_FAILED: "All Attempt Failed",

    }

    # for statistics
    manager_statistics = ManagerProvisionStateMachineRecord()

    def __init__(self, simulator=False, test_flag=False):
        """Initiate the ccap core db, manager api and the definition of
        fsm callback.

        :param simulator: if this flag is set to true, we will use some
         simulate env to run provision. On real RPD, we should set this
         flag to Fasle.

        """
        # DB to hold all the process agent, the key is the agent id
        self.process_agent_db = {}

        # the unique id
        self.mgr_id = 'MGR-' + str(randint(1, 0xFFFFFFFF))

        # the dispatcher
        self.dispatcher = Dispatcher()

        # process the manager API
        self.mgr_api = ManagerApi(self, self.dispatcher)

        callbacks = [
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_STARTUP,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_startup,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_INTERFACE_SCAN,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_interface_scan,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_USER_MGMT,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_user_mgmt,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_GCP_MGMT,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_gcp_mgmt,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_DHCP,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_dhcp,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_STARTUP_DHCP_OK,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_startup_dhcp_ok,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_PROVISION_INTERFACE_FAIL,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_interface_fail,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_OPERATIONAL,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_core_status_operational_ok,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_OPERATIONAL,
                "TrackPoint": "leave",
                "Handler": self._fsm_provision_core_status_operational_fail,
            },
            {
                "Type": "event",
                "Name": ManagerFsm.EVENT_CORE_FAIL,
                "TrackPoint": "on",
                "Handler": self._fsm_provision_core_fail,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_FAIL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_provision_state_fail,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_PRINCIPLE_RETRY_FIRST,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_provision_state_retry,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_PRINCIPLE_RETRY_SECOND,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_provision_state_retry,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_PRINCIPLE_RETRY_THIRD,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_provision_state_retry,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_CHANGE,
                "TrackPoint": ("on",),
                "Handler": self._fsm_state_change,
            },
            {
                "Type": "state",
                "Name": ManagerFsm.STATE_PRINCIPAL_FOUND,
                "TrackPoint": ("on", "reenter"),
                "Handler": self._fsm_provision_principal_core_found,
            },
        ]
        self.fsm = ManagerFsm(callbacks=callbacks)

        self.process_mgr_event_handlers = {
            ProcessAgent.AGENTTYPE_INTERFACE_STATUS: self._handle_mgr_interface_up_event,
            ProcessAgent.AGENTTYPE_8021X: self._handle_mgr_8021x_event,
            ProcessAgent.AGENTTYPE_DHCP: self._handle_mgr_dhcp_event,
            ProcessAgent.AGENTTYPE_TOD: self._handle_mgr_tod_event,
            ProcessAgent.AGENTTYPE_IPSEC: self._handle_mgr_ipsec_event,
            ProcessAgent.AGENTTYPE_GCP: self._handle_mgr_gcp_event,
            ProcessAgent.AGENTTYPE_PTP: self._handle_mgr_ptp_event,
            ProcessAgent.AGENTTYPE_L2TP: self._handle_mgr_l2tp_event,
        }

        # the global parameter settings
        self.dhcp_parameter = {}
        self.tod_parameter = ''
        self.timeserver = ''
        self.timeoffset = ''
        self.createdTime = ''
        self.logserver = ''
        self.tod_status = ''

        self.interface_list = list()

        self.simulator_flag = simulator

        self.principal_core = None
        self.startup_core = None

        self.principal_core_seek_timer = None

        # timer for check interface scan results, if we don't receive valid result in timeout time, will reboot.
        self.interface_scan_timer = None
        self.interface_core_map = {}
        self.interface_candidate = []

        self.reboot_timer = None
        self.operational_timer = None

        self.core_orchestrator = CCAPCoreOrchestrator(self, self.fsm, self.dispatcher,
                                                      self.interface_core_map, self.dhcp_parameter)
        self.tod_retry = 0

        self.mgr_hal = None
        self.test_flag = test_flag

        if not test_flag:
            # process the manager HAL
            self.mgr_hal = ProvMgrHalDriver(drvName="ProvMgr_HAL_CLIENT",
                                            drvDesc="This is provision manager hal driver",
                                            drvVer="1.0.0",
                                            supportedMsgType=ProvMgrHalDriver.cfgmsg_list,
                                            supportedNotificationMsgs=ProvMgrHalDriver.ntfmsg_list,
                                            interestedNotification=ProvMgrHalDriver.ntfmsg_list,
                                            dispatcher=self.dispatcher,
                                            mgr=self
                                            )
            # register to events
            for agent_id in ProcessAgent.AgentName:
                if not self._register_mgr_to_agent(agent_id):
                    SysTools.reboot_blocked("Cannot register mgr %s to agent %s." %
                                            (self.mgr_id, agent_id))
            # start a timer to check the agent status, alive or dead
            self.dispatcher.timer_register(self.KA_TIMEOUT, self.check_ka_status,
                                           timer_type=DpTimerManager.TIMER_REPEATED)
        self.fsm.Startup()

    @classmethod
    def is_system_time_confirmed(cls):
        """system time confirmed judgement"""
        return cls.SYSTEM_TIME_CONFIRM == t_TpcMessage.SUCCESS

    @classmethod
    def _system_time_confirmed(cls, step):
        """system time confirmed api"""
        cls.logger.debug("System time confirmed[%s]", cls.SYSTEM_TIME_CONFIM_DICT[step])
        cls.SYSTEM_TIME_CONFIRM = step

    def set_time(self, timestamp, step=t_TpcMessage.INITIATED):
        """system time set api"""
        self._system_time_confirmed(step)
        SysTools.set_system_time(self.dispatcher, timestamp)

    def _system_operational_timeout(self, _):
        """system can not enter operational mode, exceed the expect time"""
        if not self.fsm.is_operational():
            self.fsm.Error(msg="System can not enter the operational mode.")

    # this is the region to process the agent interface
    def _register_mgr_to_agent(self, agent_id):
        """Register manager to a agent ID, defined in proto file.

        :param agent_id:
        :return:

        """
        if agent_id not in ProcessAgent.AgentName:
            self.logger.error("Cannot find the agent ID [%d], fail to register to the agent." % agent_id)
            return False

        # agent connections
        try:
            api = Transport(
                ProcessAgent.SockPathMapping[agent_id]["api"], Transport.REQSOCK,
                Transport.TRANSPORT_CLIENT)
        except zmq.ZMQError as e:
            self.logger.error(
                "Cannot connect to %s, reason: "
                "%s" % (ProcessAgent.SockPathMapping[agent_id]["api"], str(e)))
            return False

        try:
            event_send_sock = Transport(
                ProcessAgent.SockPathMapping[agent_id]["pull"],
                Transport.PUSHSOCK, Transport.TRANSPORT_CLIENT)
        except zmq.ZMQError as e:
            api.sock.close()
            self.logger.error(
                "Cannot connect to %s, "
                "reason:%s" % (ProcessAgent.SockPathMapping[agent_id]["pull"], str(e)))
            return False

        try:
            event_recv_sock = Transport(
                ProcessAgent.SockPathMapping[agent_id]["push"],
                Transport.PULLSOCK, Transport.TRANSPORT_SERVER)
        except zmq.ZMQError as e:
            api.sock.close()
            event_send_sock.sock.close()
            self.logger.error(
                "Cannot connect to %s, "
                "reason:%s" % (ProcessAgent.SockPathMapping[agent_id]["push"], str(e)))
            return False

        try:
            # create the API connection and register it to the agent
            register_request = agent_pb2.api_request()
            reg = agent_pb2.msg_manager_register()
            reg.id = self.mgr_id
            reg.action = agent_pb2.msg_manager_register.REG
            reg.path_info = ProcessAgent.SockPathMapping[agent_id]["push"]
            register_request.mgr_reg.CopyFrom(reg)
            data = register_request.SerializeToString()
            api.sock.send(data)

            self.dispatcher.fd_register(
                event_recv_sock.sock, Dispatcher.EV_FD_IN | Dispatcher.EV_FD_ERR,
                self._handle_agent_event)

            self.process_agent_db[agent_id] = {
                "status": self.REGISTER_INITIATED_STATUS,
                "apiSock": api,
                "sendSock": event_send_sock,
                "recvSock": event_recv_sock,
                "ka_stat": 3,  # 3 retries
            }
            # wait and check the register status
            handled = False
            for i in range(self.MGR_REGISTER_TIMEOUT * 10):  # multiply 10 for fine granularity
                time.sleep(0.1)
                if self._check_mgr_register_status(agent_id):
                    handled = True
                    break
            if not handled:
                return False

            return True
        except Exception as e:
            self.logger.error(
                "Got an exception when registering mgr to agent %s, reason: %s", agent_id, str(e))
            return False

    def _check_mgr_register_status(self, agent_id):
        """Call back functions, the subclass should implement this function.

        :param agent_id: passed from the register, the agent id information.
        :return: None

        """
        ret = True
        api = self.process_agent_db[agent_id]['apiSock']
        try:
            data = api.sock.recv(flags=zmq.NOBLOCK)
            if data is None:
                return False

            msg = agent_pb2.api_rsp()
            msg.ParseFromString(data)

            self.logger.debug(
                "Receive an event message from the agent[%d]:%s", agent_id, msg)

            # check the fields, we only processing the register fields
            fields = msg.ListFields()

            for field in fields:
                desc, value = field
                if desc.name == "reg_rsp":
                    rsp = value
                    if rsp.status == rsp.OK:
                        self.process_agent_db[agent_id]['status'] = self.MGR_REGISTERED
                        return True
                    else:
                        self.process_agent_db[agent_id]['status'] = self.MGR_REGISTER_FAIL
                        return False
        except zmq.Again:
            return False
        except Exception as e:
            self.logger.error("Cannot process the event, reason:%s" % str(e))
            return False

        return ret

    def _handle_agent_event(self, fd, eventmask):
        """Handle event send from agents when status changed.

        :param fd: sock description
        :param eventmask: event mask
        :return:

        """
        recv = None
        agent_id = 0
        for agent in self.process_agent_db:
            if self.process_agent_db[agent]['recvSock'].sock == fd:
                recv = self.process_agent_db[agent]['recvSock']
                agent_id = agent
                break

        # Receive the msg from the remote
        if eventmask == 0 or agent_id == 0:
            self.logger.warn("Got a fake process event, ignore it")
            return
        # FixMe: may need more action
        if eventmask & self.dispatcher.EV_FD_ERR:
            self.logger.error(
                "Got an error event, fd:%s, eventmask:%d", fd, eventmask)
            return

        if recv.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.debug("Got a fake event, no data will be received!")
            return

        # sanity check
        if agent_id not in self.process_agent_db:
            self.logger.error(
                "Cannot handle msg, reason: agent id %d is not in exist in db", agent_id)
            return
        elif self.process_agent_db[agent_id]['status'] != self.MGR_REGISTERED:
            self.logger.error(
                "Cannot handle msg, reason: agent id %d is not ready for operating, status is %s",
                agent_id, self.process_agent_db[agent_id]['status'])
            return
        try:
            data = recv.sock.recv(flags=zmq.NOBLOCK)

            msg = agent_pb2.msg_event_notification()
            msg.ParseFromString(data)

            self.logger.debug(
                "Receive a event message from the agent:%s" % str(msg))

            # check the fields, we only processing the register fields
            fields = msg.ListFields()

            for field in fields:
                desc, value = field

                if desc.name == "core_event":
                    CCAPCore.handle_core_event_notification(value, agent_id)
                elif desc.name == "mgr_event":
                    self._handle_mgr_event_notification(value, agent_id)
                elif desc.name == "agent_info_update":
                    CCAPCore.handle_agent_info_update(value, agent_id)
                elif desc.name == "ka_rsp":
                    if value.status == value.OK:
                        self.process_agent_db[agent_id]['ka_stat'] = 3
                    else:
                        self.process_agent_db[agent_id]['ka_stat'] -= 1
        except zmq.Again:
            pass
        except Exception as e:
            self.logger.error(traceback.format_exc())
            self.logger.error("Cannot process the event, reason:%s" % str(e))

    def _handle_mgr_event_notification(self, msg, agent_id):
        """Dispatch the messages to corresponding FSM.

        :param msg: the event rsp message.
        :param agent_id: the agent id.
        :return:

        """
        self.logger.debug(
            "Got a manager notification msg:%s from %s, "
            "send it to corresponding handler." % (msg, ProcessAgent.AgentName[agent_id]))
        handler = self.process_mgr_event_handlers[agent_id]
        handler(msg)
        return

    def check_ka_status(self, _):
        """Check link between manager and agent, to assure agent is working."""
        try:
            for agent_id in self.process_agent_db:
                if self.process_agent_db[agent_id]["status"] != self.MGR_REGISTERED:
                    continue
                else:
                    if self.process_agent_db[agent_id]['ka_stat'] <= 0:
                        self.logger.error("process agent %s, keep alive timeout" % ProcessAgent.AgentName[agent_id])
                        self.fsm.Error(
                            msg='Keep alive fail between provision manager process and %s process' %
                            ProcessAgent.AgentName[agent_id])
                    else:
                        # reset ka stat to -1
                        self.process_agent_db[agent_id]['ka_stat'] -= 1

                    # send the request to all registered agent
                    sock = self.process_agent_db[agent_id]['sendSock']
                    register_request = agent_pb2.msg_event_request()
                    ka_req = agent_pb2.msg_manager_ka()
                    ka_req.id = self.mgr_id
                    ka_req.action = agent_pb2.msg_manager_ka.KA
                    register_request.ka_msg.CopyFrom(ka_req)
                    data = register_request.SerializeToString()
                    sock.sock.send(data, flags=zmq.NOBLOCK)
                    self.logger.debug(
                        "Manager sends KA message to process agent %d successfully." % agent_id)

        except Exception as e:
            self.logger.error(
                "Got an exception when check ka status, reason:%s" % str(e))

    def start_principal_core_seek_timer(self, timeout_cb):
        """Register seek principal core timer.

        :param timeout_cb: call back function

        """
        if None is self.principal_core:
            if None is self.principal_core_seek_timer:
                self.principal_core_seek_timer = self.dispatcher.timer_register(self.SEEK_PRINCIPAL_CORE_TIMEOUT,
                                                                                timeout_cb)
            else:
                self.dispatcher.timer_unregister(self.principal_core_seek_timer)
                self.principal_core_seek_timer = None
                self.principal_core_seek_timer = self.dispatcher.timer_register(self.SEEK_PRINCIPAL_CORE_TIMEOUT,
                                                                                timeout_cb)

    def principal_core_seek_failure(self, _):
        """Does not found any principal core for now, enter error state.

        :param _:

        """
        self.logger.warn('Principal core seeking failure.')

        self.principal_core_seek_timer = None
        self.fsm.SEEK_PRINCIPAL_FAIL(msg='No principal core found.')

    def _principal_core_seek_failure_before_tod(self, _):
        """Found no principal core before TOD done, enter error state.

        :param _:

        """
        if self.is_system_time_confirmed():
            if None is not self.principal_core_seek_timer:
                self.dispatcher.timer_unregister(self.principal_core_seek_timer)
                self.principal_core_seek_timer = None
            self.core_orchestrator.orchestrator()
        elif self.SYSTEM_TIME_CONFIRM == t_TpcMessage.FIRST_ATTEMPT_FAILED or \
                self.SYSTEM_TIME_CONFIRM == t_TpcMessage.INITIATED:
            # restart timer when tod agent still retrying
            self.start_principal_core_seek_timer(self._principal_core_seek_failure_before_tod)
        else:
            self.logger.info("%s seek principal core failure before tod.", self.mgr_id)
            self.principal_core_seek_failure(None)

    def _interface_scan_timeout_callback(self, _):
        """Called for failure to receive any interface scan result, or
        receive error result."""
        interface_up = list()
        stats = net_if_stats()
        for interface in stats.keys():
            if interface != 'lo':
                if SysTools.is_if_oper_up(interface):
                    interface_up.append(interface)
        reason = "Current system up interface:{}, Cannot get any valid interfaces, reboot system".format(interface_up)
        self.notify.error(rpd_event_def.RPD_EVENT_PROVISION_NO_INTERFACE_UP[0], "")
        SysTools.reboot_blocked(reason)

    def start(self):
        """Process the manager register, timer register."""
        if not self.test_flag:
            self.mgr_hal.start()
        self.dispatcher.loop()

    def _handle_rcp_request_msg(self, action, msg):
        """Handle the up interface.

        :param action: request type
        :param action: request message sequence number

        """
        agent_id = ProcessAgent.AGENTTYPE_GCP
        rcp_rsp = agent_pb2.msg_event_request()
        rcp_rsp.action.id = self.mgr_id  # Mgr id
        rcp_rsp.action.event_id = agent_id

        if not isinstance(msg, basestring):
            self.logger.error('Got wrong message type %s, expected is string', type(msg))
            return

        if action == 'get_active_principal':
            self.logger.debug('get_active_principal message %s', msg)
            rcp_rsp.action.action = agent_pb2.msg_event.READ
            ret_value = 'get_active_principal/' + msg + '/'
            for ccap_core in CCAPCore.ccap_core_db.values():
                self.logger.info(
                    "Core(%s, %s, %s, %s)", ccap_core.interface,
                    ccap_core.ccap_core_network_address,
                    CoreDescription.role_str(ccap_core.is_principal),
                    CoreDescription.mode_str(ccap_core.is_active))
                if ccap_core.is_active == CoreDescription.CORE_MODE_ACTIVE and \
                   ccap_core.is_principal == CoreDescription.CORE_ROLE_PRINCIPAL:
                    rcp_rsp.action.ccap_core_id = ccap_core.ccap_core_id
                    if ccap_core.fsm.current in CCAPFsm.STATE_ALL_OPERATIONAL:
                        ret_value += ccap_core.ccap_core_network_address
                    else:
                        ret_value += 'fail, active principal core[%s, %s]' % (ccap_core.ccap_core_network_address,
                                                                              ccap_core.fsm.current)
                    break
            else:
                rcp_rsp.action.ccap_core_id = 'None'
                ret_value += 'fail, can not find any active principal'

            rcp_rsp.action.parameter = json.dumps(ret_value)
        else:
            rcp_rsp.action.action = agent_pb2.msg_event.UNKNOWN
            rcp_rsp.action.ccap_core_id = 'None'
            rcp_rsp.action.parameter = json.dumps('%s/' + msg +
                                                  '/fail, unsupported request', action)

        try:
            sock = self.process_agent_db[agent_id]['sendSock']
            sock.sock.send(rcp_rsp.SerializePartialToString(), flags=zmq.NOBLOCK)
        except Exception as e:
            self.logger.error(
                "Got an exception when sending msg to agent %d, reason: %s",
                ProcessAgent.AGENTTYPE_GCP, str(e))

    def _mgr_to_rcp_operational(self, ccap_core_id, action, info):
        """
        :param ccap_core_id: the CCAP core's id
        :param action: operation send to rcp
        :param info: information to carry

        """
        try:
            agent_id = ProcessAgent.AGENTTYPE_GCP
            rcp_rsp = agent_pb2.msg_event_request()
            rcp_rsp.action.id = self.mgr_id  # Mgr id
            rcp_rsp.action.event_id = agent_id
            rcp_rsp.action.action = agent_pb2.msg_event.WRITE
            rcp_rsp.action.ccap_core_id = ccap_core_id
            if action in self.RcpOperation:
                rcp_rsp.action.parameter = json.dumps('%s/%s' % (self.RcpOperation[action], info))
            else:
                raise ManagerError('Unexpected action %s and info %s', action, info)

            sock = self.process_agent_db[agent_id]['sendSock']
            sock.sock.send(
                rcp_rsp.SerializePartialToString(), flags=zmq.NOBLOCK)
        except Exception as e:
            self.logger.error(
                "Got an exception when sending set led message to agent %d, reason: %s",
                ProcessAgent.AGENTTYPE_GCP, str(e))

    def is_interface_up(self, interface):
        """return True if interface is up else False."""

        for interface_dict in self.interface_list:
            if interface == interface_dict['interface']:
                if interface_dict['status'] != self.INTERFACE_DOWN:
                    return True
        return False

    def interface_up_handler(self, up_interface_lists):
        """Handle interface up notified by agent.

        :param up_interface_lists: list of up interface
        :return:

        """
        try:
            for interface_dict in self.interface_list:
                interface = interface_dict['interface']
                if interface not in up_interface_lists and interface_dict['status'] != self.INTERFACE_DOWN:
                    self.logger.debug("Interface[%s] changed to Down state", interface)
                    self.notify.error(rpd_event_def.RPD_EVENT_CONNECTIVITY_ETH_DOWN[0], interface, '')
                    interface_dict['status'] = self.INTERFACE_DOWN
                    # fixme do we need any action?
                    # we need to check cores ints
                elif interface in up_interface_lists and interface_dict['status'] == self.INTERFACE_UP:
                    up_interface_lists.remove(interface)

            for interface in up_interface_lists:
                self.interface_list.append(
                    {
                        "interface": interface,
                        "status": self.INTERFACE_UP,
                    }
                )
                self.notify.info(rpd_event_def.RPD_EVENT_CONNECTIVITY_ETH_UP[0], interface, '')
                if interface not in self.interface_candidate:
                    self.interface_candidate.append(interface)

            if len(self.interface_candidate) and self.interface_candidate[0] not in self.interface_core_map:
                self.fsm.INTERFACE_SCAN(interface=self.interface_candidate[0])

            # Process the timers
            for interface_dict in self.interface_list:
                if interface_dict['status'] == self.INTERFACE_UP:
                    # stop the interface timer
                    if self.interface_scan_timer:
                        self.dispatcher.timer_unregister(
                            self.interface_scan_timer)
                        self.interface_scan_timer = None
                    break
            else:
                if self.interface_scan_timer is None:
                    self.interface_scan_timer = self.dispatcher.timer_register(self.INTERFACE_SCAN_TIMEOUT,
                                                                               self._interface_scan_timeout_callback,
                                                                               timer_type=DpTimerManager.TIMER_ONESHOT)
        except FysomError as e:
            self.logger.error(
                "Got an exception about manager fsm: %s", str(e))

    def update_core_dhcp_parameter(self, interface, parameter):
        """
        update the core dhcp parameters
        :param interface: interface name
        :param parameter: dhcp parameters
        :return:
        """

        core_para = []
        para = provision_pb2.msg_agent_parameter()
        para.agent_id = ProcessAgent.AGENTTYPE_TOD
        para.parameter = ';'.join(parameter['TimeServers'])
        para.parameter += '/' + str(parameter['TimeOffset'])
        para.parameter += '|' + ';'.join(parameter['LogServers'])
        core_para.append(para)
        for core in CCAPCore.ccap_core_db.values():
            if core.interface and core.interface == interface:
                core.update_ccap_core_parameter(parameters=core_para)

    def is_dhcp_para_renewed(self, interface, para):
        """
        is interface dhcp parameters renewed?
        :param interface: interface name
        :param para: dhcp parameters
        :return: True if changed, otherwise False
        """
        if interface not in self.dhcp_parameter:
            self.dhcp_parameter[interface] = para
            return False

        old = self.dhcp_parameter[interface]
        if len(para["CCAPCores"]) != len(old["CCAPCores"]) \
                or len(para["TimeServers"]) != len(old["TimeServers"]) \
                or len(para["LogServers"]) != len(old["LogServers"]):
            return True
        for core_ip in para["CCAPCores"]:
            if core_ip not in old["CCAPCores"]:
                return True
        for ts in para["TimeServers"]:
            if ts not in old["TimeServers"]:
                return True
        for ls in para["LogServers"]:
            if ls not in old["LogServers"]:
                return True
        if old["TimeOffset"] != para["TimeOffset"]:
            return True

        return False

    def is_ip_in_core_map(self, interface, core):
        """return True if interface, core ip pair
        in interface core map else False."""

        if interface not in self.interface_core_map:
            return False

        core_list = self.interface_core_map[interface]
        for core_info in core_list:
            if Convert.is_ip_address_equal(core, core_info[0]):
                return True

        return False

    def remove_ip_in_core_map(self, interface, core):
        """remove ip from interface core map."""

        self.logger.info("Remove interface %s and core [%s] from local map",
                         interface, core)
        if interface not in self.interface_core_map:
            return

        core_list = self.interface_core_map[interface]
        for core_info in core_list:
            if Convert.is_ip_address_equal(core, core_info[0]):
                core_list.remove(core_info)
                return

    def add_ip_to_core_map(self, interface, core):
        """add ip and interface to core map.

        :param interface: eth interface
        :param core: (core ip, core role, triggered)

        """

        self.logger.info("Add interface %s and core [%s] into local map",
                         interface, core)
        if interface not in self.interface_core_map:
            return

        if self.is_ip_in_core_map(interface, core[0]):
            return
        else:
            core_list = self.interface_core_map[interface]
            core_list.append(core)

    def get_core_map(self, interface, core_ip):
        """get core ip and mode from map"""
        if interface not in self.interface_core_map:
            return None

        core_list = self.interface_core_map[interface]
        for core_info in core_list:
            if Convert.is_ip_address_equal(core_ip, core_info[0]):
                return core_info

        return None

    def is_valid_ip(self, ip):
        """filter invailid ip address, such as 0.0.0.0.
        :param ip: ip address
        :return False is invalid.
        """

        if Convert.is_valid_ip_address(ip):
            if ip == "0.0.0.0" or ip == "255.255.255.0":
                return False
            return True
        else:
            return False

    def _handle_mgr_interface_up_event(self, msg):
        """Handle the up interface.

        :param msg:
        :return:

        """
        try:
            if not msg.HasField("data"):
                self.logger.warn(
                    "Interface status agent send notification without parameters")
                return
            up_interface_lists = json.loads(msg.data)
            self.interface_up_handler(up_interface_lists)
        except Exception as e:
            self.logger.error("Got a general exception: %s", str(e))

    def _handle_mgr_8021x_event(self, msg):
        pass

    def _handle_mgr_dhcp_event(self, msg):
        """DHCP event handler.

        # the DHCP data is a list, the schema is as following:
        # {
        #    CCAPCores: [1.1.1.1, 2.2.2.2],
        #    TimeServers ...
        #    LogServers
        #    TimeOffset
        #    CreatedTime
        #    Interface
        #    initiated_by: core_xxxx
        # }
        # fixme cannot handle the renew info

        """
        try:
            if msg.HasField("data"):
                dhcp_parameter = json.loads(msg.data)
                interface = dhcp_parameter['Interface']
                # delete this original core if DHCP cannot get core ip list
                if not len(dhcp_parameter['CCAPCores']):
                    self.notify.critical(rpd_event_def.RPD_EVENT_DHCP_CORE_LIST_MISSING[0], interface)
                    for ccap_core in CCAPCore.ccap_core_db.values():
                        if ccap_core.interface and ccap_core.interface == interface:
                            self.logger.info("Deleting core (%s, %s)...", ccap_core.interface,
                                             ccap_core.ccap_core_network_address)
                            ccap_core.del_ccap_core()
                            if CCAPCore.is_empty():
                                self.fsm.CORE_FAIL(interface=interface, msg='No core list received from DHCP.')
                    return
                dhcp_parameter['CCAPCores'] = \
                    dhcp_parameter['CCAPCores'][:self.DHCP_LIST_LIMIT]
                dhcprec = DhcpInfoRecord()
                dhcprec.updateDhcpInfoKey(interface)
                if interface not in self.dhcp_parameter:
                    # touch the interface firstly
                    self.dhcp_parameter[interface] = \
                        dhcp_parameter
                    dhcprec.updateDhcpInfoRecordData(
                        CreatedTime=dhcp_parameter['CreatedTime'])
                    dhcprec.write()
                    time = dhcprec.getDhcpInfoCreatedTime()
                else:
                    if self.is_dhcp_para_renewed(interface, dhcp_parameter):
                        self.notify.info(rpd_event_def.RPD_EVENT_DHCP_RENEW_PARA_MODIFIED[0],
                                         "{}".format(dhcp_parameter), "")
                        self.dhcp_parameter[interface] = dhcp_parameter
                        dhcprec.updateDhcpInfoRecordData(
                            CreatedTime=dhcp_parameter['CreatedTime'])
                        dhcprec.write()
                        self.update_core_dhcp_parameter(interface, dhcp_parameter)
                    else:
                        return
            else:
                return

            if 'initiated_by' in self.dhcp_parameter[interface]:
                initiated_core_id = self.dhcp_parameter[interface]['initiated_by']
                if None is not initiated_core_id and initiated_core_id in CCAPCore.ccap_core_db:
                    initiated_core = CCAPCore.ccap_core_db[initiated_core_id]
                    core_para = []
                    para = provision_pb2.msg_agent_parameter()
                    para.agent_id = ProcessAgent.AGENTTYPE_TOD
                    para.parameter = ';'.join(self.dhcp_parameter[interface]['TimeServers'])
                    para.parameter += '/' + str(self.dhcp_parameter[interface]['TimeOffset'])
                    para.parameter += '|' + ';'.join(self.dhcp_parameter[interface]['LogServers'])
                    self.timeoffset = \
                        str(self.dhcp_parameter[interface]['TimeOffset'])
                    self.createdtime = \
                        str(self.dhcp_parameter[interface]['CreatedTime'])
                    self.logserver = \
                        ';'.join(self.dhcp_parameter[interface]['LogServers'])
                    self.tod_parameter = para.parameter + '!' + self.tod_status
                    core_para.append(para)
                    initiated_core.update_ccap_core_parameter(core_para)
            else:
                self.logger.warn(
                    "Did not get initiated CCAP core info from DHCP client, "
                    "only got {}".format(dhcp_parameter))
                return
            # Sees there is not case that interface is not in interface_core_map.
            if interface not in self.interface_core_map:
                self.logger.warn(
                    "Cannot find the interface %s in interface core map, DHCP is not interface scan "
                    "initiated?", interface)
                return

            if 'CCAPCores' in self.dhcp_parameter[interface]:

                core_ip_needed_to_create = list()

                # save the interface/core_ip configuration into core map
                for core_ip in self.dhcp_parameter[interface]['CCAPCores']:
                    self.add_ip_to_core_map(interface, (core_ip, CoreDescription.CORE_MODE_NONE,
                                                        self.DHCP_CORE_TRIGGER))

                    if not CCAPCore.is_ccap_core_existed(interface, core_ip):
                        ret = self.get_core_map(interface, core_ip)
                        if None is not ret:
                            core_ip_needed_to_create.append(ret)

                # manager process get DHCP event
                if self.fsm.current == self.fsm.STATE_INTERFACE_PROVISION:
                    self.fsm.STARTUP_DHCP_OK(inteface=interface)
                else:
                    self.fsm.DHCP(inteface=interface)
            else:
                self.logger.error(
                    "Cannot start GCP as doesn't get CCAP-Cores IP address on %s" % interface)
        except FysomError as e:
            self.logger.error("Fsm got an exception: %s", str(e))
        except Exception as e:
            self.logger.error("Got an exception: %s", str(e))

    def _handle_mgr_tod_event(self, msg):
        """
        Process TOD event: TOD success or fail
        as this will impact the system time, and the registered timer.

        self.tod_parameter = time_server1;time_server2/time_offset|logserver1;logserver2!status

        """
        data, timestamp = msg.data.split("/")
        timestamp, valid_timeserver = timestamp.split("|")
        self.logger.info("Manager receive the status(%s) from TOD", data)
        self.timeserver = valid_timeserver
        if data == 'success':
            self.tod_status = 'True'
            self.notify.info(rpd_event_def.RPD_EVENT_PROVISION_TOD_DONE[0], "")
            self.set_time(int(timestamp), step=t_TpcMessage.SUCCESS)

            # to check system is operational or not when system time established
            if None is self.operational_timer:
                self.operational_timer = self.dispatcher.timer_register(self.RPD_OPERATIONAL_TIMEOUT,
                                                                        self._system_operational_timeout)
            if self.principal_core_seek_timer:
                self.dispatcher.timer_unregister(self.principal_core_seek_timer)
                self.principal_core_seek_timer = None
            self.core_orchestrator.orchestrator_cb(None)
        elif data == "tod_first_failed":
            self.set_time(int(timestamp), step=t_TpcMessage.FIRST_ATTEMPT_FAILED)
        elif data == 'tod_failed':
            if self.tod_retry >= self.TOD_RETRY_CNT:
                self.fsm.Error(msg="Tod Fail")
            else:
                self.tod_retry += 1
            # stop dhcp if tod fail
            self._system_time_confirmed(step=t_TpcMessage.ALL_ATTEMPTS_FAILED)
            for ccap_core in CCAPCore.ccap_core_db.values():
                for agent in [ProcessAgent.AGENTTYPE_TOD, ProcessAgent.AGENTTYPE_DHCP]:
                    self.logger.info(
                        "Core[%s] current state is %s, Stop the %s, reason: %s,",
                        ccap_core.ccap_core_id, ccap_core.fsm.current,
                        ProcessAgent.AgentName[agent], data)
                    ccap_core.kick_agent(agent, action='Stop')
        else:
            self.logger.warn(
                "Manager receive the unknown status(%s) from TOD agent", data)
        self.tod_parameter = self.timeserver + '/' + self.timeoffset + '|' + \
            self.logserver + '!' + self.tod_status

    def _handle_mgr_ipsec_event(self, msg):
        pass

    def _handle_mgr_gcp_event(self, msg):
        """Process rcp event rcp CCAP core identification about role info,
        rcp request to reboot, redirect message.

        """
        try:
            data = json.loads(msg.data).split('/')
            action = data[0]
            parameter = data[1]
            self.logger.debug(
                'MGR recv GCP event, action {} and parameter {}'.format(action, parameter))

            if action == 'reboot':
                local_interface, core_ip, info = parameter.split(';')
                if local_interface == '' or core_ip == '' or info == '':
                    self.logger.warn(
                        'GCP GDM cold reset request: interface[%s] or core address[%s] was wrong',
                        local_interface, core_ip)
                    return
                for ccap_core in CCAPCore.ccap_core_db.values():
                    if ccap_core.interface and ccap_core.interface == local_interface and \
                       ccap_core.ccap_core_network_address and \
                        Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, core_ip) and \
                            self.principal_core is ccap_core:
                        # set the node to non-operational status
                        try:
                            self.mgr_hal.sendOperationalStatusNtf(operational=False)
                        except Exception as e:
                            self.logger.warn("Exception happened when send operational status to Hal: %s", str(e))
                        ccap_core.del_ccap_core()
                        SysTools.notify.info(RPD_EVENT_CONNECTIVITY_REBOOT[0], info, "by " + "GDM", "")
                        self.dispatcher.timer_register(
                            self.WAITING_PERIOD, SysTools.external_reboot, arg=(info, "GDM"))
                        break
                else:
                    return
                for ccap_core in CCAPCore.ccap_core_db.values():
                    ccap_core.del_ccap_core()
            elif action == 'connect_closed':
                local_interface, core_ip, reconnect = parameter.split(';')
                if local_interface == '' or core_ip == '':
                    self.logger.warn(
                        'GCP connect timeout: interface[%s] or core address[%s] was wrong',
                        local_interface, core_ip)
                    return
                for ccap_core in CCAPCore.ccap_core_db.values():
                    if ccap_core.interface and ccap_core.interface == local_interface and \
                            ccap_core.ccap_core_network_address and \
                            Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, core_ip):

                        # only log this information to notify CCAP Core
                        if self.principal_core is ccap_core:
                            self.notify.critical(rpd_event_def.RPD_EVENT_CONNECTIVITY_PRINCIPAL_LOST[0],
                                                 rpd_event_def.RpdEventTag.ccap_ip(core_ip))
                        elif ccap_core.is_principal == CoreDescription.CORE_ROLE_PRINCIPAL:
                            self.notify.critical(rpd_event_def.RPD_EVENT_CONNECTIVITY_PRINCIPAL_LOST[0],
                                                 rpd_event_def.RpdEventTag.ccap_ip(core_ip))
                        elif ccap_core.is_principal == CoreDescription.CORE_ROLE_AUXILIARY:
                            self.notify.error(rpd_event_def.RPD_EVENT_CONNECTIVITY_AUXILIARY_LOST[0],
                                              rpd_event_def.RpdEventTag.ccap_ip(core_ip))

                        ccap_core.is_principal = CoreDescription.CORE_ROLE_NONE
                        # delete the core when no principal core found
                        if None is self.principal_core and not ast.literal_eval(reconnect):
                            ccap_core.del_ccap_core()
            elif action == "role":
                parameter = json.loads(parameter)
                ccap_core_network_address = parameter['ccap_core']
                is_principal = parameter['is_principal']
                is_active = parameter['is_active']
                interface = parameter['interface']
                index = parameter['index']

                for ccap_core in CCAPCore.ccap_core_db.values():
                    self.logger.debug("%s", ccap_core)
                    if ProcessAgent.AGENTTYPE_GCP not in ccap_core.parameters:
                        continue

                    if ccap_core.interface == interface and \
                            Convert.is_ip_address_equal(ccap_core_network_address, ccap_core.ccap_core_network_address):
                        self.logger.info(
                            "Core(%s, %s, %s, %s) original role",
                            interface, ccap_core_network_address,
                            CoreDescription.role_str(ccap_core.is_principal),
                            CoreDescription.mode_str(ccap_core.is_active))
                        if is_principal:
                            ccap_core.is_principal = CoreDescription.CORE_ROLE_PRINCIPAL
                        else:
                            ccap_core.is_principal = CoreDescription.CORE_ROLE_AUXILIARY
                            # changed the principal core to None if it modified to aux
                            if ccap_core is self.principal_core:
                                self.principal_core = None
                                self.logger.info("set principal core to None by role change to aux")

                        # core role is either active or standby
                        if is_active:
                            ccap_core.is_active = CoreDescription.CORE_MODE_ACTIVE
                        else:
                            ccap_core.is_active = CoreDescription.CORE_MODE_STANDBY
                            if ccap_core is self.principal_core:
                                self.principal_core = None
                                self.logger.info("set principal core to None by mode change to standby")
                        ccap_core.index = index

                        self.logger.info("Core(%s, %s, %s, %s, %d) role identified",
                                         interface, ccap_core_network_address,
                                         CoreDescription.role_str(ccap_core.is_principal),
                                         CoreDescription.mode_str(ccap_core.is_active),
                                         ccap_core.index)
                        if ccap_core.is_principal == CoreDescription.CORE_ROLE_PRINCIPAL and \
                                ccap_core.is_active == CoreDescription.CORE_MODE_ACTIVE:
                            if self.principal_core is None:
                                self.principal_core = ccap_core
                                active_principal = ccap_core.interface + ";" + ccap_core.ccap_core_network_address
                                self._mgr_to_rcp_operational(ccap_core.ccap_core_id,
                                                             self.MGR_TO_RCP_ACTION_SET_ACTIVE_PRINCIPAL,
                                                             active_principal)
                                self.logger.info("set principal core to %s by role change", active_principal)

                            elif self.principal_core != ccap_core:
                                self.notify.warn(
                                    rpd_event_def.RPD_EVENT_CONNECTIVITY_MUL_ACTIVE_PRINCIPAL[0],
                                    rpd_event_def.RpdEventTag.ccap_ip(ccap_core.ccap_core_network_address))
                                ccap_core.del_ccap_core()
                        else:
                            if self.fsm.is_principal_found():
                                self.logger.info("System is in principal found state...")
                            elif not self.fsm.is_operational():
                                self.logger.info(
                                    "Deleting core (%s, %s)...",
                                    ccap_core.interface,
                                    ccap_core.ccap_core_network_address)
                                if self.principal_core == ccap_core:
                                    self.logger.info("delete principal core %s and set principal to None",
                                                     self.principal_core.ccap_core_network_address)
                                    self.principal_core = None
                                ccap_core.del_ccap_core()
                            else:
                                pass
                        # to accelerate the process time
                        self._principal_updated()
                        self.core_orchestrator.orchestrator_cb(None)
                        return
                self.logger.warn(
                    "Cannot find the CCAP Core[%s, %s] in DB",
                    interface, ccap_core_network_address)

            elif action == 'redirect':
                # try delete redirected core info, both from CCAPCore and interface_core_map
                local_interface, core_ip = data[2].split(';')
                if local_interface == '' or core_ip == '':
                    self.logger.error(
                        'Redirect interface[%s] or core address[%s] was wrong',
                        local_interface, core_ip)
                    return
                for ccap_core in CCAPCore.ccap_core_db.values():
                    if ccap_core.interface and ccap_core.interface == local_interface and \
                            ccap_core.ccap_core_network_address and \
                            Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, core_ip):
                        # delete the core
                        self.logger.info(
                            "Deleting core redirected(%s, %s)...",
                            ccap_core.interface,
                            ccap_core.ccap_core_network_address)
                        ccap_core.del_ccap_core()
                        # update interface to core mapping
                        if self.is_ip_in_core_map(local_interface, core_ip):
                            self.remove_ip_in_core_map(local_interface, core_ip)

                ccap_cores = parameter.split(";")
                for core in ccap_cores:
                    if CCAPCore.is_ccap_core_existed(local_interface, core):
                        continue
                    self.add_ip_to_core_map(local_interface, (core, CoreDescription.CORE_MODE_NONE,
                                                              self.GCP_REDIRECT_CORE_TRIGGER))
                self.core_orchestrator.orchestrator_cb(None)
            elif action == 'Ha':
                parameter = json.loads(parameter)
                active_core = parameter['ActiveCoreIpAddress']
                standby_core = parameter['StandbyCoreIpAddress']
                interface = parameter['interface']
                op = parameter['operation']

                if not self.is_valid_ip(active_core) or not self.is_valid_ip(standby_core):
                    self.logger.warn("Ha operation get invalid IP: %s %s",
                                     active_core, standby_core)
                    return
                active_flag = standby_flag = False
                if op == self.OPERATION_ADD:
                    for ccap_core in CCAPCore.ccap_core_db.values():
                        if ccap_core.interface == interface:
                            if Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, active_core):
                                if ccap_core.is_active == CoreDescription.CORE_MODE_STANDBY:
                                    self.logger.warn(
                                        "RPD has got core(%s, %s, %s, %s), ignore add %s core, mode mismatch",
                                        interface, active_core,
                                        CoreDescription.role_str(ccap_core.is_principal),
                                        CoreDescription.mode_str(ccap_core.is_active),
                                        CoreDescription.mode_str(CoreDescription.CORE_MODE_ACTIVE))
                                    return
                                active_flag = True
                            elif Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, standby_core):
                                if ccap_core.is_active == CoreDescription.CORE_MODE_ACTIVE:
                                    self.logger.warn(
                                        "RPD has got core(%s, %s, %s, %s), ignore add %s core, mode mismatch",
                                        interface, standby_core,
                                        CoreDescription.role_str(ccap_core.is_principal),
                                        CoreDescription.mode_str(ccap_core.is_active),
                                        CoreDescription.mode_str(CoreDescription.CORE_MODE_STANDBY))
                                    return

                                standby_flag = True
                                self.logger.warn(
                                    "RPD has got core(%s, %s, %s, %s), ignore add %s core request by HA",
                                    interface, standby_core,
                                    CoreDescription.role_str(ccap_core.is_principal),
                                    CoreDescription.mode_str(ccap_core.is_active),
                                    CoreDescription.mode_str(CoreDescription.CORE_MODE_STANDBY))
                                # HA standby core maybe include in DHCP list, need to update mode
                                ret = self.get_core_map(interface, standby_core)
                                if None is not ret and ret[-1] != self.HA_CORE_TRIGGER:
                                    self.logger.warn("RPD core(%s, %s) initiated by %s, will be updated",
                                                     interface, standby_core, ret[-1])
                                    self.remove_ip_in_core_map(interface, standby_core)
                                    self.add_ip_to_core_map(interface, (standby_core, CoreDescription.CORE_MODE_STANDBY,
                                                                        self.HA_CORE_TRIGGER))
                                    continue

                    if not active_flag:
                        self.add_ip_to_core_map(interface, (active_core, CoreDescription.CORE_MODE_ACTIVE,
                                                            self.HA_CORE_TRIGGER))
                    if not standby_flag:
                        self.add_ip_to_core_map(interface, (standby_core, CoreDescription.CORE_MODE_STANDBY,
                                                            self.HA_CORE_TRIGGER))
                    # there maybe some new ip added, trigger the orchestrator here
                    self.core_orchestrator.orchestrator_cb(None)
                elif op == self.OPERATION_DELETE:
                    # delete operation only valid for standby core
                    for ccap_core in CCAPCore.ccap_core_db.values():
                        if ccap_core.interface == interface and \
                           Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, standby_core):
                            if CoreDescription.CORE_MODE_STANDBY == ccap_core.is_active:
                                self.logger.info(
                                    'Deleting core(%s, %s, %s, %s), as HA delete occurred',
                                    interface, standby_core,
                                    CoreDescription.role_str(ccap_core.is_principal),
                                    CoreDescription.mode_str(ccap_core.is_active))
                                ccap_core.del_ccap_core()
                                if self.is_ip_in_core_map(interface, standby_core):
                                    self.remove_ip_in_core_map(interface, standby_core)
                            else:
                                self.logger.info(
                                    "Core(%s, %s, %s, %s) by HA deleted, mode(%s) mismatch ignored",
                                    interface, standby_core,
                                    CoreDescription.role_str(ccap_core.is_principal),
                                    CoreDescription.mode_str(ccap_core.is_active),
                                    CoreDescription.mode_str(CoreDescription.CORE_MODE_STANDBY))
                            break
                elif op == self.OPERATION_CHANGE:  # change
                    active_core_p = None
                    standby_core_p = None
                    for ccap_core in CCAPCore.ccap_core_db.values():
                        if ccap_core.interface == interface and \
                           Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, standby_core):
                            standby_core_p = ccap_core
                        if ccap_core.interface == interface and \
                           Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, active_core):
                            active_core_p = ccap_core
                        if standby_core_p and active_core_p:
                            break
                    if not standby_core_p:
                        self.logger.warn("Ha change operation can not be performed, %s %s, standby core is not in DB ",
                                         active_core, standby_core)
                        return

                    if not active_core_p:
                        self.logger.warn("Ha change operation can not be performed, : %s %s, active core is not in DB",
                                         active_core, standby_core)
                        return

                    if CoreDescription.CORE_MODE_STANDBY != standby_core_p.is_active:
                        self.logger.info(
                            "Core(%s, %s, %s, %s), mode(%s) mismatch when HA change operation",
                            standby_core_p.interface, standby_core_p.ccap_core_network_address,
                            CoreDescription.role_str(standby_core_p.is_principal),
                            CoreDescription.mode_str(standby_core_p.is_active),
                            CoreDescription.mode_str(CoreDescription.CORE_MODE_STANDBY))
                        return
                    else:
                        self.logger.info(
                            "Core(%s, %s, %s, %s) changed to %s by HA change operation",
                            interface, standby_core,
                            CoreDescription.role_str(standby_core_p.is_principal),
                            CoreDescription.mode_str(standby_core_p.is_active),
                            CoreDescription.mode_str(CoreDescription.CORE_MODE_ACTIVE))
                        standby_core_p.is_active = CoreDescription.CORE_MODE_ACTIVE
                        # send fault management HA notify
                        self.notify.warn(rpd_event_def.RPD_EVENT_CONNECTIVITY_FAILOVER_STANDBY[0],
                                         rpd_event_def.RpdEventTag.ccap_ip(standby_core))
                        if active_core_p.is_principal == CoreDescription.CORE_ROLE_PRINCIPAL or \
                           active_core_p == self.principal_core:
                            # may exist standby principal cores
                            if None is self.principal_core:
                                self.principal_core = standby_core_p
                                self.logger.info("set principal core to %s by ha change from none",
                                                 standby_core_p.interface + standby_core_p.ccap_core_network_address)

                            elif self.principal_core is not standby_core_p:
                                principal_ip = self.principal_core.ccap_core_network_address
                                if principal_ip != active_core:
                                    self.logger.warn(
                                        "Core(%s, %s, %s, %s) changed to %s backup(%s) is mismatch, real(%s)",
                                        interface, standby_core,
                                        CoreDescription.role_str(standby_core_p.is_principal),
                                        CoreDescription.mode_str(standby_core_p.is_active),
                                        CoreDescription.mode_str(CoreDescription.CORE_MODE_ACTIVE),
                                        active_core, self.principal_core.ccap_core_network_address)
                                    return
                                # change the standby core to active
                                self.principal_core = standby_core_p
                                self.logger.info("set principal core to %s by ha change from standby",
                                                 standby_core_p.interface +
                                                 " " + standby_core_p.ccap_core_network_address)

                            # move recovering state to operation if the principal active core is online
                            self._principal_updated()
                            active_principal = standby_core_p.interface + ";" + standby_core_p.ccap_core_network_address
                            self._mgr_to_rcp_operational(standby_core_p.ccap_core_id,
                                                         self.MGR_TO_RCP_ACTION_SET_ACTIVE_PRINCIPAL,
                                                         active_principal)
                            # ensure there is no seek timer here
                            if self.principal_core_seek_timer:
                                self.dispatcher.timer_unregister(
                                    self.principal_core_seek_timer)
                                self.principal_core_seek_timer = None

                    # to delete active core
                    active_core_p.del_ccap_core()

            elif action == 'get_active_principal':
                self._handle_rcp_request_msg(action, parameter)
            elif action == 'config_table':
                parameter = json.loads(parameter)
                ccap_core_network_address = parameter['ccap_core']
                op = parameter['operation']
                interface = parameter['interface']
                if not self.is_valid_ip(ccap_core_network_address):
                    self.logger.warn("Multiple core operation get invalid IP: %s",
                                     ccap_core_network_address)
                    return
                if op == self.OPERATION_ADD:
                    for ccap_core in CCAPCore.ccap_core_db.values():
                        if ccap_core.interface == interface and \
                           Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, ccap_core_network_address):
                            self.logger.warn(
                                "RPD has core(%s, %s), ignore add core request by ConfiguredCoreTable",
                                interface, ccap_core_network_address)
                            break
                    else:
                        self.add_ip_to_core_map(interface,
                                                (ccap_core_network_address, CoreDescription.CORE_MODE_NONE,
                                                 self.CONFIGURED_CORE_TABLE_TRIGGER))
                elif op == self.OPERATION_DELETE:
                    for ccap_core in CCAPCore.ccap_core_db.values():
                        if ccap_core.interface == interface and \
                           Convert.is_ip_address_equal(ccap_core.ccap_core_network_address, ccap_core_network_address):
                            self.logger.info(
                                'Deleting core(%s, %s, %s, %s), ConfiguredCoreTable del occurred',
                                interface, ccap_core_network_address,
                                CoreDescription.role_str(ccap_core.is_principal),
                                CoreDescription.mode_str(ccap_core.is_active))
                            if ccap_core.is_principal == CoreDescription.CORE_ROLE_PRINCIPAL and \
                               ccap_core.is_active == CoreDescription.CORE_MODE_ACTIVE:
                                self.principal_core = None
                                self._principal_updated()
                                self.logger.info("set principal core to None by config_table delete")

                            ccap_core.del_ccap_core()
                            if self.is_ip_in_core_map(interface, ccap_core_network_address):
                                self.remove_ip_in_core_map(interface, ccap_core_network_address)
                            break
                elif op == self.OPERATION_CHANGE:
                    pass

        except (KeyError, ValueError) as e:
            self.logger.error(
                'Got an error when handling mgr event, reason:%s', str(e))
        except FysomError as e:
            self.logger.error("Fsm got an exception: %s", str(e))

    def _handle_mgr_ptp_event(self, msg):
        pass

    def _handle_mgr_l2tp_event(self, msg):
        pass

    def _fsm_provision_startup(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (
                self.mgr_id, event.fsm.current, event.src, event.event))
        if self.interface_scan_timer is None:
            self.interface_scan_timer = self.dispatcher.timer_register(
                self.INTERFACE_SCAN_TIMEOUT,
                self._interface_scan_timeout_callback,
                timer_type=DpTimerManager.TIMER_ONESHOT)

    def _fsm_provision_user_mgmt(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))

    def _fsm_provision_gcp_mgmt(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))

    def create_original_core(self, interface):
        """create a new core on this interface."""

        para_set = []
        for agent_id in range(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, ProcessAgent.AGENTTYPE_L2TP + 1):
            para = provision_pb2.msg_agent_parameter()
            para.agent_id = agent_id
            para.parameter = interface
            para_set.append(para)

        core, reason = CCAPCore.add_ccap_core(
            self, para_set,
            initiated_by=self.CORE_INITIAL_TRIGGER[self.STARTUP_CORE_TRIGGER],
            interface=interface, test_flag=self.test_flag)

        if not core:
            self.logger.error(
                "Cannot create core on interface %s, reason:%s ", interface, reason)
            return

        # Record the core
        if interface in self.interface_core_map:
            self.logger.warn(
                "Interface %s core configuration should be NULL in this state.", interface)
        else:
            self.interface_core_map[interface] = list()

    def _fsm_provision_interface_scan(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        # get the interface from event args, passed from the interface_event_notification
        self.create_original_core(event.interface)

    def _fsm_provision_dhcp(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))

    def _fsm_provision_state_retry(self, event):
        """No principal core found, try again."""
        # record No principal core found log
        self.notify.error(rpd_event_def.RPD_EVENT_CONNECTIVITY_NO_PRINCIPAL[0], '')

        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s" % (self.mgr_id, event.fsm.current,
                                                                           event.src, event.event))
        if event.src == event.fsm.current:
            self.logger.debug("Reenter this state, ignore it")
            return

        if self.principal_core:
            self.logger.error(
                "Entering an error state, we have found the principal.")
            return

        # unregistered the timer
        if self.principal_core_seek_timer:
            self.dispatcher.timer_unregister(self.principal_core_seek_timer)
            self.principal_core_seek_timer = None

        # del all the cores in interface core map
        self.logger.info("Delete all the cores, reason: %s.", event.msg)
        for core in CCAPCore.ccap_core_db.values():
            if isinstance(core.fsm, CCAPFsm):
                self.logger.info(
                    "Deleting core (%s, %s)...",
                    core.interface, core.ccap_core_network_address)
                core.del_ccap_core()

        self.core_orchestrator.clear_list()
        if self.is_system_time_confirmed():
            self.core_orchestrator.orchestrator_cb(None)
        else:
            for interface_dict in self.interface_list:
                interface = interface_dict['interface']
                if interface_dict['status'] == self.INTERFACE_UP:
                    self.create_original_core(interface)

            self.start_principal_core_seek_timer(self._principal_core_seek_failure_before_tod)

    def _fsm_provision_principal_core_found(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        if self.principal_core_seek_timer:
            self.dispatcher.timer_unregister(self.principal_core_seek_timer)
            self.principal_core_seek_timer = None

    def _fsm_provision_core_status_operational_ok(self, event):
        """Triggered by OPERATIONAL_OK.

        :param event: fsm event info
        :return:

        """
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        if event.src == event.fsm.current:
            self.logger.debug("Reenter this state, ignore it")
            return

        if None is self.principal_core:
            self.logger.error(
                'Entering an unexpected state, expect:operational, but principal is None')
            return

        self.notify.info(rpd_event_def.RPD_EVENT_PROVISION_ENTER_OPERATIONAL[0], '')

        if self.operational_timer:
            self.dispatcher.timer_unregister(self.operational_timer)
            self.operational_timer = None

        for core in CCAPCore.ccap_core_db.values():
            if core is self.principal_core:
                try:
                    self.mgr_hal.sendOperationalStatusNtf(operational=True)
                except Exception as e:
                    self.logger.warn("Exception happened when send operational status to Hal: %s", str(e))
                break
        self.core_orchestrator.orchestrator_cb(None)

    def _fsm_provision_core_status_operational_fail(self, event):
        """Triggered by OPERATIONAL_FAIL.

        :param event: fsm event info
        :return:

        """
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))

        self.notify.error(rpd_event_def.RPD_EVENT_PROVISION_EXIT_OPERATIONAL[0], '')

        try:
            self.mgr_hal.sendOperationalStatusNtf(operational=False)
        except Exception as e:
            self.logger.warn("Exception happened when send operational status to Hal: %s", str(e))

    def _fsm_provision_core_fail(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        self.logger.info("Event message: %s", event.msg)

        if self.fsm.current == self.fsm.STATE_INTERFACE_PROVISION:
            self._fsm_provision_startup_core_fail(event)
            return
        try:
            if not self.is_system_time_confirmed():
                self.fsm.Error(msg='Tod Fail')
                return

            # for startup core, the core_ip is None
            if not event.core_ip:
                self.fsm.Error(msg=event.msg)
                return

            if None is self.principal_core:
                self.core_orchestrator.orchestrator_cb(None)
                return
            elif not self.fsm.is_operational():
                return

            # clear timer
            if self.principal_core_seek_timer:
                self.dispatcher.timer_unregister(self.principal_core_seek_timer)
                self.principal_core_seek_timer = None

        except Exception as e:
            self.logger.error('Got exception when handle core fail event, reason:%s', str(e))

    def _fsm_provision_state_fail(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        self.principal_core = None
        self.logger.info("set principal core to None by provision fail")

        try:
            for ccap_core in CCAPCore.ccap_core_db.values():
                ccap_core.del_ccap_core()
            if self.reboot_timer:
                return
            if event.src in [self.fsm.STATE_PRINCIPLE_PROVISION,
                             self.fsm.STATE_PRINCIPLE_RETRY_FIRST,
                             self.fsm.STATE_PRINCIPLE_RETRY_SECOND,
                             self.fsm.STATE_PRINCIPLE_RETRY_THIRD]:
                # delay a few seconds then reboot
                reboot_delay = randint(self.PC_BACKOFF_MIN, self.PC_BACKOFF_MAX)
            else:
                reboot_delay = randint(1, 10)
            self.reboot_timer = self.dispatcher.timer_register(
                reboot_delay, SysTools.sys_failure_reboot, arg=event.msg)
            self.logger.warn(
                "System will rebooting in %d seconds...", reboot_delay)
        except Exception as e:
            self.logger.error(
                'Got an error when handling provision fail event, reason:%s', str(e))

    def _fsm_provision_startup_dhcp_ok(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        # start principal timer
        self.start_principal_core_seek_timer(
            self._principal_core_seek_failure_before_tod)

    def _fsm_provision_startup_core_fail(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))
        try:
            if event.interface in self.interface_candidate:
                self.interface_candidate.remove(event.interface)
                while len(self.interface_candidate):
                    if self.interface_candidate[0] not in self.interface_core_map:
                        self.fsm.INTERFACE_SCAN(interface=self.interface_candidate[0])
                        break
                    else:
                        self.interface_candidate.pop(0)

                if not len(self.interface_candidate):
                    self.fsm.PROVISION_INTERFACE_FAIL(msg=event.msg)
            else:
                self.logger.warn("%s Entering state %s from state %s, triggered by event:%s. Wrong interface: %s"
                                 % (self.mgr_id, event.fsm.current, event.src, event.event, event.interface))
                self.fsm.PROVISION_INTERFACE_FAIL(msg=event.msg)
        except Exception as e:
            self.logger.warn("Exception happened when process startup core fail: %s" % str(e))
            self.fsm.PROVISION_INTERFACE_FAIL(msg=event.msg)

    def startup_core_exit_online(self):
        for core in CCAPCore.ccap_core_db.values():
            if isinstance(core.fsm, CCAPFsm):
                core.hold_in_ipsec_state()
                self.logger.debug("Hold %s in ipsec state for startup core exit online", str(core))

    def startup_core_enter_online(self):
        for core in CCAPCore.ccap_core_db.values():
            if isinstance(core.fsm, CCAPFsm):
                core.restart_hold_state()
                self.logger.debug("Re start %s in ipsec state for startup core enter online", str(core))

    def _fsm_provision_interface_fail(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s." % (self.mgr_id, event.fsm.current,
                                                                            event.src, event.event))

    def _principal_updated(self):
        if self.fsm.is_fail() or self.fsm.is_startup():
            return
        if self.principal_core:
            self.fsm.SEEK_PRINCIPAL_OK()
            if self.principal_core.fsm.current in CCAPFsm.STATE_ALL_OPERATIONAL:
                self.fsm.OPERATIONAL_OK()
            else:
                self.fsm.OPERATIONAL_FAIL()
        else:
            if self.fsm.current in [ManagerFsm.STATE_OPERATIONAL, ManagerFsm.STATE_PRINCIPAL_FOUND]:
                self.fsm.SEEK_PRINCIPAL_FAIL(msg='Principal core has been removed.')

    def _fsm_state_change(self, event):
        """change state callback

        :param event: event instance
        :return:
        """
        self.manager_statistics.update(self, event)


if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(description="Provision manager process")
    # parse the daemon settings.
    parser.add_argument("-s", "--simulator",
                        action="store_true",
                        help="run the program with simulator mode")
    parser.add_argument("-t", "--test_flag",
                        action="store_true",
                        help="run the program with test mode")
    arg = parser.parse_args()
    setup_logging("PROVISION", filename="provision_mgr_process.log")
    starter = ManagerProcess(simulator=arg.simulator, test_flag=arg.test_flag)
    starter.start()
