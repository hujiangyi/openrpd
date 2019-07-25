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

import time
from random import randint

import zmq

import manager_fsm
import rpd.provision.proto.process_agent_pb2 as agent_pb2
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.dispatcher.timer import DpTimerManager
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.statistics.provision_stat import ProvisionStateMachineRecord
from rpd.common.utils import Convert
from rpd.rcp.rcp_sessions import CcapCoreIdentification


class ManagerCoreError(Exception):
    pass


class CoreDescription(object):
    """Ccap core Role and HA Mode description."""
    __metaclass__ = AddLoggerToClass

    CORE_ROLE_NONE = -1
    CORE_ROLE_AUXILIARY = 0
    CORE_ROLE_PRINCIPAL = 1

    CORE_MODE_NONE = -1
    CORE_MODE_STANDBY = 0
    CORE_MODE_ACTIVE = 1

    role_mapping = {
        CORE_ROLE_NONE: '',
        CORE_ROLE_AUXILIARY: 'Auxiliary',
        CORE_ROLE_PRINCIPAL: 'Principal',
    }
    mode_mapping = {
        CORE_MODE_NONE: '',
        CORE_MODE_STANDBY: 'Standby',
        CORE_MODE_ACTIVE: 'Active',
    }

    def __init__(self, core_role=CORE_ROLE_NONE, core_mode=CORE_MODE_NONE):
        """Init ccap core role and HA-mode.

        :param core_role: principal or Auxiliary
        :param core_mode: active or standby

        """
        if core_role not in self.role_mapping or core_mode not in self.mode_mapping:
            raise ValueError("{} or {} value error, suppose to be 0-2".format(core_role, core_mode))

        self.role = core_role
        self.mode = core_mode

    @staticmethod
    def role_str(core_role):
        if core_role not in CoreDescription.role_mapping:
            return ''
        return CoreDescription.role_mapping[core_role]

    @staticmethod
    def mode_str(core_mode):
        if core_mode not in CoreDescription.mode_mapping:
            return ''
        return CoreDescription.mode_mapping[core_mode]


class CCAPCore(object):
    """Create ccap core info, store principal, active and etc.."""
    __metaclass__ = AddLoggerToClass

    TIMEOUT_CHECK_CORE_REG = 200

    ccap_core_db = {}

    CCAP_CORE_REGISTERED = "registered"
    CCAP_CORE_REGISTER_FAIL = "registered-fail"
    CCAP_CORE_UNREGISTERED = "unregistered"
    CCAP_CORE_UNREGISTER_FAIL = "unregistered-fail"
    # for statistics
    core_statistics = ProvisionStateMachineRecord()
    INIT_INTERFACE_MAX_TIMES = 120
    INIT_8021X_MAX_TIMES = 20
    INIT_DHCP_MAX_TIMES = 20
    INIT_TOD_MAX_TIMES = 100
    INIT_IPSEC_MAX_TIMES = 10
    INIT_GCP_MAX_TIMES = 22
    INIT_PTP_MAX_TIMES = 10
    INIT_L2TP_MAX_TIMES = 10

    INIT_INTERFACE_SECONDS = 1
    INIT_8021X_SECONDS = 5
    INIT_DHCP_SECONDS = 5
    INIT_TOD_SECONDS = 5
    INIT_IPSEC_SECONDS = 30
    INIT_GCP_SECONDS = 15
    INIT_PTP_SECONDS = 60
    INIT_L2TP_SECONDS = 60

    def __init__(self, ccap_core_id,
                 is_principal=CoreDescription.CORE_ROLE_NONE, is_active=CoreDescription.CORE_MODE_NONE,
                 initiated="Startup", para=None, mgr=None, ccap_core_interface=None,
                 ccap_core_network_address=None, added="Startup"):
        # We have to have a valid mgr, which contains a dispatcher and agent information
        if mgr is None:
            reason = "Cannot create Core %s since the mgr is none." % ccap_core_id
            self.logger.error(reason)
            raise ManagerCoreError(reason)

        self.CoreAgentRetryMaxTimes = {
            ProcessAgent.AGENTTYPE_INTERFACE_STATUS: self.INIT_INTERFACE_MAX_TIMES,
            ProcessAgent.AGENTTYPE_8021X: self.INIT_8021X_MAX_TIMES,
            ProcessAgent.AGENTTYPE_DHCP: self.INIT_DHCP_MAX_TIMES,
            ProcessAgent.AGENTTYPE_TOD: self.INIT_TOD_MAX_TIMES,
            ProcessAgent.AGENTTYPE_IPSEC: self.INIT_IPSEC_MAX_TIMES,
            ProcessAgent.AGENTTYPE_GCP: self.INIT_GCP_MAX_TIMES,
            ProcessAgent.AGENTTYPE_PTP: self.INIT_PTP_MAX_TIMES,
            ProcessAgent.AGENTTYPE_L2TP: self.INIT_L2TP_MAX_TIMES,
        }
        self.CoreAgentTimeout = {
            ProcessAgent.AGENTTYPE_INTERFACE_STATUS: self.INIT_INTERFACE_SECONDS,
            ProcessAgent.AGENTTYPE_8021X: self.INIT_8021X_SECONDS,
            ProcessAgent.AGENTTYPE_DHCP: self.INIT_DHCP_SECONDS,
            ProcessAgent.AGENTTYPE_TOD: self.INIT_TOD_SECONDS,
            ProcessAgent.AGENTTYPE_IPSEC: self.INIT_IPSEC_SECONDS,
            ProcessAgent.AGENTTYPE_GCP: self.INIT_GCP_SECONDS,
            ProcessAgent.AGENTTYPE_PTP: self.INIT_PTP_SECONDS,
            ProcessAgent.AGENTTYPE_L2TP: self.INIT_L2TP_SECONDS,
        }
        self.CoreStateFailureRetry = {
            manager_fsm.CCAPFsmStartup.STATE_DHCP_OK: 1,
            manager_fsm.CCAPFsm.STATE_INIT_IPSEC: 3,
            manager_fsm.CCAPFsm.STATE_REINIT_IPSEC: 3,
        }
        self.CoreStateTimeoutSeconds = {
            manager_fsm.CCAPFsm.STATE_INIT_GCP_IRA: 90,
            manager_fsm.CCAPFsm.STATE_REINIT_GCP_IRA: 90,
            manager_fsm.CCAPFsm.STATE_INIT_GCP_CFG: 10,
            manager_fsm.CCAPFsm.STATE_INIT_GCP_OP: 60,
        }

        # Fsm Callbacks
        callbacks_startup = [
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_INIT,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_init,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_INIT,
                "TrackPoint": ("leave"),
                "Handler": self._fsm_leave_state_init,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_INTERFACE_UP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_interface_up,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_INTERFACE_UP,
                "TrackPoint": ("leave"),
                "Handler": self._fsm_leave_state_interface_up,
            },

            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_8021X_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_8021x_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_8021X_OK,
                "TrackPoint": ("leave"),
                "Handler": self._fsm_leave_state_8021x_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_DHCP_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_dhcp_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_DHCP_OK,
                "TrackPoint": ("leave"),
                "Handler": self._fsm_leave_state_dhcp_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_TOD_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_tod_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_TOD_OK,
                "TrackPoint": ("leave", ),
                "Handler": self._fsm_leave_state_tod_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_FAIL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_fail,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsmStartup.STATE_CHANGE,
                "TrackPoint": ("on",),
                "Handler": self._fsm_state_change,
            },
            # event callbacks
        ]
        callbacks_gcp = [
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_IPSEC,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_init_ipsec,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_REINIT_IPSEC,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_init_ipsec,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_FAIL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_fail,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_CHANGE,
                "TrackPoint": ("on",),
                "Handler": self._fsm_state_change,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INIT_TCP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_init_tcp,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INIT_GCP_IRA,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_init_gcp_ira,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INIT_GCP_CFG,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_init_gcp_cfg,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INIT_GCP_CFG_CPL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_init_gcp_cfg_cpl,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INIT_GCP_OP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_init_gcp_op,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_REINIT_TCP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_reinit_tcp,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_REINIT_GCP_IRA,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_state_change_reinit_gcp_ira,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_ONLINE,
                "TrackPoint": ("on", ),
                "Handler": self._fsm_state_change_enter_online,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_ONLINE,
                "TrackPoint": ("leave", ),
                "Handler": self._fsm_state_change_leave_online,
            },
        ]

        # the agent event handlers
        self.core_event_handlers = {
            ProcessAgent.AGENTTYPE_INTERFACE_STATUS: self._handle_core_interface_event,
            ProcessAgent.AGENTTYPE_8021X: self._handle_core_8021x_event,
            ProcessAgent.AGENTTYPE_DHCP: self._handle_core_dhcp_event,
            ProcessAgent.AGENTTYPE_TOD: self._handle_core_tod_event,
            ProcessAgent.AGENTTYPE_IPSEC: self._handle_core_ipsec_event,
            ProcessAgent.AGENTTYPE_GCP: self._handle_core_gcp_event,
            ProcessAgent.AGENTTYPE_PTP: self._handle_core_ptp_event,
            ProcessAgent.AGENTTYPE_L2TP: self._handle_core_l2tp_event,
        }
        if initiated == "Startup":
            fsm = manager_fsm.CCAPFsmStartup(callbacks=callbacks_startup)
            if mgr:
                mgr.startup_core = self
        else:
            fsm = manager_fsm.CCAPFsm(callbacks=callbacks_gcp)
        self.ccap_core_id = ccap_core_id
        self.fsm = fsm
        self.is_principal = is_principal
        self.is_active = is_active
        self.initiated_by = initiated
        self.added_by = added
        self.parameters = para
        self.start_time = time.time()

        self.last_change_time = time.time()

        self.register_status = dict([(x, None) for x in self.core_event_handlers.keys()])
        self.agent_timeout = dict([(x, 0) for x in self.core_event_handlers.keys()])
        self.registered_timers = dict([(x, None) for x in self.core_event_handlers.keys()])
        self.agent_status = dict([(x, False) for x in self.core_event_handlers.keys()])
        self.action_status = dict([(x, False) for x in self.core_event_handlers.keys()])

        self.state_timer = dict([(x, None) for x in self.CoreStateTimeoutSeconds.keys()])
        self.state_retried_times = dict([(x, 0) for x in self.CoreStateFailureRetry.keys()])

        # Get some resources from mgr
        self.dispatcher = mgr.dispatcher
        self.process_agent_db = mgr.process_agent_db
        self.mgr_id = mgr.mgr_id
        self.mgr = mgr
        self.mgr_fsm = mgr.fsm

        # Some values to identify the ccap core
        self.interface = ccap_core_interface
        self.ccap_core_network_address = ccap_core_network_address

        # Core identification info
        self.core_id_from_core = None
        self.core_name = None
        self.core_vendor_id = None
        self.index = None

        # ccap core statistic per state
        self.statistics_per_state = {}
        for agent in ProcessAgent.AgentName:
            self.statistics_per_state[agent] = {"tx": 0, 'rx': 0, 'error': 0}

    # the following function is statemachine common functions
    def _fsm_enter_state_fail(self, event):
        """Failure case handler.

        :param event:

        """
        # when fail case, we should send some message to some module.
        self.logger.info("%s Entering state %s from state %s, triggered by event:%s." % (self.ccap_core_id,
                                                                                         event.fsm.current,
                                                                                         event.src, event.event))
        try:
            # call the mgr call back, there is no principal
            state = event.src
            interface = self.interface
            core_ip = self.ccap_core_network_address

            if self.mgr.principal_core is self:
                self.mgr_fsm.Error(msg="Principal Core(%s, %s) %s fail" %
                                       (interface, core_ip, state))
            else:
                self.del_ccap_core()

                # Info mgr that one core has been in down state
                self.mgr_fsm.CORE_FAIL(interface=interface, core_ip=core_ip,
                                       msg="%s %s fail" %
                                           (str(self), state))
        except Exception as ex:
            self.logger.warn("Unexpected event: %s", str(ex))

    def _fsm_state_change(self, event):
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s. " %
            (self.ccap_core_id, event.fsm.current, event.src, event.event))
        self.last_change_time = time.time()
        self.core_statistics.update(self, event)

    def _fsm_state_change_enter_online(self, event):
        self._unreg_state_timer(event.src)
        for state in self.state_retried_times:
            self.state_retried_times[state] = 0
        if self.mgr.principal_core is not self:
            return
        self.mgr_fsm.OPERATIONAL_OK()

    def _fsm_state_change_leave_online(self, event):
        if self.mgr.principal_core is not self:
            return
        self.mgr_fsm.OPERATIONAL_FAIL()

    # the following function is for startup core statemachine callbacks
    def __state_reenter_wrapper(self, args):
        """We may got failure state for a few times once we enter some state,
        this function will count it and retry.

        :param args:
        :return:

        """
        event = args['event']
        fsm = event.fsm
        agent_id = args['agent_id']
        if not (self.registered_timers[agent_id] is None):
            timer = self.registered_timers[agent_id]
            self.dispatcher.timer_unregister(timer)
            self.registered_timers[agent_id] = None

        self.agent_timeout[agent_id] += 1

        if self.agent_timeout[agent_id] >= self.CoreAgentRetryMaxTimes[agent_id]:
            self.logger.warn("Agent %d exhausted all reties, can not get ready at %d seconds",
                             agent_id, self.CoreAgentRetryMaxTimes[agent_id] * self.CoreAgentTimeout[agent_id])
            fsm.TRIGGER_Error()
            return
        fsm.TRIGGER_ENTER_CURRENT_STATE()

    def _send_to_process_agent(self, agent_id, msg):
        """The API for sending message to agent.

        :param agent_id: agent identification
        :param msg:  message need to be send
        :return:

        """
        if agent_id not in self.process_agent_db:
            self.logger.error(
                "Cannot send message[%s] to agent :%d [Cannot find the agent]", msg, agent_id)
            return False, "Cannot find the agent"

        try:
            sock = self.process_agent_db[agent_id]['sendSock']
            sock.sock.send(msg, flags=zmq.NOBLOCK)
        except Exception as e:
            self.logger.error(
                "Got an exception when sending msg to agent %d, reason: %s", agent_id, str(e))
            return False, str(e)

    def _startup_core_online(self):
        return (self.mgr.startup_core and
                isinstance(self.mgr.startup_core.fsm, manager_fsm.CCAPFsmStartup) and
                self.mgr.startup_core.fsm.current == manager_fsm.CCAPFsmStartup.STATE_TOD_OK)

    def _is_startup_core(self):
        return isinstance(self.fsm, manager_fsm.CCAPFsmStartup)

    # this is to define a start of agent
    def __fsm_enter_state_start(self, event, trigger_agent_id):
        """Common api for all state changed procedure.

        :param event: fysom event
        :param trigger_agent_id: the agent will be tiggered
        :return:

        """
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s. agent:%d start" %
            (self.ccap_core_id, event.fsm.current, event.src, event.event, trigger_agent_id))
        # check if we have the parameter for this fsm, if not try to reenter this state later
        if event.event in self.fsm.AGENT_FAIL_EVENTS:
            if self.registered_timers[trigger_agent_id] is None:
                self.logger.warn(
                    "Cannot find the registered-timers for agent %d" % trigger_agent_id)
                timer = self.dispatcher.timer_register(
                    self.CoreAgentTimeout[trigger_agent_id],
                    self.__state_reenter_wrapper,
                    {'event': event,
                     'agent_id': trigger_agent_id,
                     },
                    DpTimerManager.TIMER_ONESHOT)
                self.registered_timers[trigger_agent_id] = timer
            return

        # when we entering this state, we should inform the agent to start
        # hold the start for gcp core when startup core exit the online, and start up is not online
        if self._is_startup_core() or \
           (event.event != manager_fsm.CCAPFsm.EVENT_STARTUP_CORE_EXIT_ONLINE and self._startup_core_online()):
            self.kick_agent(trigger_agent_id, action='Start')

    def __fsm_enter_state_stop(self, event, trigger_agent_id):
        """Common api for all state changed procedure.

        :param event: fysom event
        :param trigger_agent_id: the agent will be tiggered
        :return:

        """
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s, agent %d, stop"
            % (self.ccap_core_id, event.fsm.current, event.src, event.event, trigger_agent_id))

        try:
            # when we entering this state, we should inform the agent to start
            event_request = agent_pb2.msg_event_request()
            event_request.action.id = self.mgr_id  # Mgr id
            event_request.action.ccap_core_id = self.ccap_core_id
            event_request.action.event_id = trigger_agent_id
            event_request.action.parameter = self.parameters[trigger_agent_id]
            event_request.action.action = agent_pb2.msg_event.STOP
            self._send_to_process_agent(
                trigger_agent_id, event_request.SerializeToString())
        except Exception as ex:
            self.logger.warn("Unexpected event: %s", str(ex))

    def _fsm_enter_state_init(self, event):
        """Enter init state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

    def _fsm_leave_state_init(self, event):
        self.agent_timeout[ProcessAgent.AGENTTYPE_INTERFACE_STATUS] = 0

    def _fsm_leave_state_interface_up(self, event):
        self.agent_timeout[ProcessAgent.AGENTTYPE_8021X] = 0

    def _fsm_leave_state_8021x_ok(self, event):
        self.agent_timeout[ProcessAgent.AGENTTYPE_DHCP] = 0

    def _fsm_leave_state_dhcp_ok(self, event):
        self.agent_timeout[ProcessAgent.AGENTTYPE_TOD] = 0

    def _fsm_enter_state_interface_up(self, event):
        """Enter interface up state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_8021X)

    def _fsm_enter_state_8021x_ok(self, event):
        """Enter 8021x ok state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_DHCP)

    def _fsm_enter_state_dhcp_ok(self, event):
        """Enter DHCP ok state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_TOD)

    def _fsm_enter_state_tod_ok(self, event):
        """Enter TOD ok state.

        :param event: fysom event
        :return:

        """
        self.mgr.startup_core_enter_online()

    def _fsm_leave_state_tod_ok(self, event):
        """Leave TOD ok state.

        :param event: fysom event
        :return:

        """
        self.mgr.startup_core_exit_online()

    # the following function is for gcp state machine call back
    def _fsm_enter_state_init_ipsec(self, event):
        if event.src in manager_fsm.CCAPFsm.STATE_GCP_ALL or event.src in manager_fsm.CCAPFsm.STATE_ALL_OPERATIONAL:
            self.kick_agent(ProcessAgent.AGENTTYPE_GCP, action="Stop")
            self.kick_agent(ProcessAgent.AGENTTYPE_PTP, action="Stop")
            self.kick_agent(ProcessAgent.AGENTTYPE_IPSEC, action='Stop')
            if event.dst in self.state_retried_times and not self.state_retried_times[event.dst] and \
                    event.event != manager_fsm.CCAPFsm.EVENT_STARTUP_CORE_EXIT_ONLINE:
                # If it is the first retry case, we reconnect it immediately
                self.kick_agent(ProcessAgent.AGENTTYPE_IPSEC, action='Start')
            if event.dst in self.state_retried_times:
                if self.state_retried_times[event.dst] >= self.CoreStateFailureRetry[event.dst]:
                    self.fsm.TRIGGER_Error()
                    return
                self.state_retried_times[event.dst] += 1
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_IPSEC)

    def _fsm_state_change_init_tcp(self, event):
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_GCP)
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_L2TP)

    def _unreg_state_timer(self, state):
        if state in self.CoreStateTimeoutSeconds and self.state_timer[state]:
            timer = self.state_timer[state]
            self.dispatcher.timer_unregister(timer)
            self.state_timer[state] = None
            self.logger.debug("%s, unreg state timer: %s", str(self), state)

    def _setup_state_timer(self, state, func):
        if state in self.CoreStateTimeoutSeconds and self.state_timer[state] is None:
            timer = self.dispatcher.timer_register(
                self.CoreStateTimeoutSeconds[state],
                func,
                DpTimerManager.TIMER_ONESHOT)
            self.state_timer[state] = timer
            self.logger.debug("%s, setup state timer: %s", str(self), state)

    def _gcp_ira_timeout(self, args):
        self._unreg_state_timer(manager_fsm.CCAPFsm.STATE_INIT_GCP_IRA)
        self.fsm.TRIGGER_GCP_NO_IRA()

    def _gcp_cfg_timeout(self, args):
        self._unreg_state_timer(manager_fsm.CCAPFsm.STATE_INIT_GCP_CFG)
        self.fsm.TRIGGER_GCP_NO_CFG()

    def _reinit_gcp_ira_timeout(self, args):
        self._unreg_state_timer(manager_fsm.CCAPFsm.STATE_REINIT_GCP_IRA)
        self.fsm.TRIGGER_GCP_NO_IRA()

    def _fsm_state_change_init_gcp_ira(self, event):
        self._setup_state_timer(event.dst, self._gcp_ira_timeout)

    def _fsm_state_change_init_gcp_cfg(self, event):
        self._unreg_state_timer(event.src)
        self._setup_state_timer(event.dst, self._gcp_cfg_timeout)

    def _fsm_state_change_init_gcp_cfg_cpl(self, event):
        self._unreg_state_timer(event.src)
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_PTP)

    def _fsm_state_change_init_gcp_op(self, event):
        for state in self.state_retried_times:
            self.state_retried_times[state] = 0

    def _fsm_state_change_reinit_tcp(self, event):
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_GCP)
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_L2TP)

    def _fsm_state_change_reinit_gcp_ira(self, event):
        self._setup_state_timer(event.dst, self._reinit_gcp_ira_timeout)
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_PTP)

    # the following function is agent ipc message
    def _handle_core_interface_event(self, msg):
        """Core interface up handling.

        The detail result stored in result field. The status field just for
        the message itself. For example, if the interface is down, the
        message status is still OK, by the result is down.

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
        if result == "UP":
            fsm.TRIGGER_INTERFACE_UP()
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_INTERFACE_DOWN()

        self.logger.info(
            "Got a interface up event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_8021x_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_8021X
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_MAC_8021X_OK()
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_MAC_8021X_FAIL()

        self.logger.info("Got a 8021x event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_dhcp_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_DHCP
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_DHCP_OK()
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_DHCP_FAIL()

        self.logger.info("Got a DHCP event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_tod_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_TOD
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_TOD_OK()
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_TOD_FAIL()

        self.logger.info(
            "Got a TOD event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_ipsec_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_IPSEC
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_IPSEC_OK()
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_IPSEC_FAIL()

        self.logger.info("Got a IPSEC event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_gcp_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_GCP
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
        elif result == "OPERATIONAL":
            fsm.TRIGGER_GCP_OP()
        elif result == "TCP_OK":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_TCP_OK()
        elif result == "TCP_FAIL":
            self.agent_status[agent_id] = False
            fsm.TRIGGER_TCP_FAIL()
        elif result == "GCP_IRA":
            fsm.TRIGGER_GCP_IRA()
        elif result == "GCP_CFG":
            fsm.TRIGGER_GCP_CFG()
        elif result == "GCP_CFG_CPL":
            fsm.TRIGGER_GCP_CFG_CPL()
        else:
            if self.agent_status[agent_id]:
                self.agent_status[agent_id] = False
            else:
                self.agent_status[agent_id] = False

        self.logger.info(
            "Got a GCP event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_non_statemachine_agents_event(self, agent_id, result):
        agent_id = agent_id
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
        else:
            if not self.registered_timers[agent_id]:
                timer = self.dispatcher.timer_register(
                    self.CoreAgentTimeout[agent_id],
                    self._retry_agent,
                    {'agent_id': agent_id,
                     },
                    DpTimerManager.TIMER_ONESHOT)
                self.registered_timers[agent_id] = timer
            self.agent_status[agent_id] = False

    def _handle_core_ptp_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_PTP
        self._handle_non_statemachine_agents_event(agent_id=agent_id, result=result)
        self.logger.debug(
            "Got a PTP event:%s, fsm status is :%s" % (msg, fsm.current))

    def _retry_agent(self, args):
        """
        :param args:
        :return:

        """
        agent_id = args['agent_id']
        if not (self.registered_timers[agent_id] is None):
            timer = self.registered_timers[agent_id]
            self.dispatcher.timer_unregister(timer)
            self.registered_timers[agent_id] = None

        self.agent_timeout[agent_id] += 1

        if self.agent_timeout[agent_id] >= self.CoreAgentRetryMaxTimes[agent_id]:
            self.logger.warn("Agent %d exhausted all reties, can not get ready at %d seconds",
                             agent_id, self.CoreAgentRetryMaxTimes[agent_id] * self.CoreAgentTimeout[agent_id])
            return
        self.kick_agent(agent_id, action='Start')

    def _handle_core_l2tp_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_L2TP
        self._handle_non_statemachine_agents_event(agent_id=agent_id, result=result)

        self.logger.debug(
            "Got a L2TP event:%s, fsm status is :%s" % (msg, fsm.current))

    def _register_core_to_agent(self, agent_id, reg_or_unreg=True):
        """Register core to the agent via api socket.

        :param agent_id: agent identification
        :param reg_or_unreg: register if True, otherwise unregistered

        """
        try:
            register_request = agent_pb2.api_request()
            reg = agent_pb2.msg_core_register()
            reg.ccap_core_id = self.ccap_core_id
            reg.mgr_id = self.mgr_id
            if reg_or_unreg:
                reg.action = agent_pb2.msg_core_register.REG
            else:
                reg.action = agent_pb2.msg_core_register.UNREG

            register_request.core_reg.CopyFrom(reg)
            data = register_request.SerializeToString()
            api = self.process_agent_db[agent_id]['apiSock']
            api.sock.send(data)

            handled = False
            for i in range(self.TIMEOUT_CHECK_CORE_REG):
                time.sleep(0.1)
                if self._check_ccap_core_register_status(agent_id, reg_or_unreg):
                    handled = True
                    break
            if not handled:
                raise ManagerCoreError("Cannot %s process agent:%d" % (
                                       "register to" if reg_or_unreg else "unregistered from", agent_id))

            return True
        except Exception as e:
            self.logger.error("Got Exception when %s core %s to agent %d, reason: %s",
                              "register" if reg_or_unreg else "unregistered",
                              self.ccap_core_id, agent_id, str(e))
            import traceback

            self.logger.error(traceback.format_stack())
            return False

    def kick_agent(self, trigger_agent_id, action='Start'):
        """Drive agent to start or stop an action.

        :param trigger_agent_id: agent to done the real work
        :param action: START if action is True else STOP

        """
        try:
            if not self.action_status[trigger_agent_id] and action == 'Stop':
                return

            event_request = agent_pb2.msg_event_request()
            event_request.action.id = self.mgr_id  # Mgr id
            event_request.action.ccap_core_id = self.ccap_core_id
            event_request.action.event_id = trigger_agent_id
            event_request.action.parameter = self.parameters[trigger_agent_id]
            if action == 'Start':
                event_request.action.action = agent_pb2.msg_event.START
                self.statistics_per_state[trigger_agent_id]['tx'] += 1
                self.action_status[trigger_agent_id] = True
            elif action == 'Stop':
                event_request.action.action = agent_pb2.msg_event.STOP
                self.action_status[trigger_agent_id] = False
                self.agent_status[trigger_agent_id] = False
            else:
                raise ManagerCoreError(
                    "Got wrong action parameters: expect to be Start or Stop, real is %s", action)
            self._send_to_process_agent(trigger_agent_id, event_request.SerializeToString())
            self.logger.debug(
                "%s send %s action to agent[%s]", self.ccap_core_id, action,
                ProcessAgent.AgentName[trigger_agent_id])
        except Exception as e:
            self.logger.error(
                "Got Exception when driven action about core %s to agent %d, reason: %s",
                self.ccap_core_id, trigger_agent_id, str(e))

    def _check_ccap_core_register_status(self, agent_id, reg_or_unreg):
        """Call back functions, the subclass should implement this function.

        :param agent_id: passed from the register, the agent id information.
        :param reg_or_unreg: register if True, otherwise unregistered
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
                "Receive a event message from the agent[%d]:%s", agent_id, msg)

            # check the fields, we only processing the register fields
            fields = msg.ListFields()

            for field in fields:
                desc, value = field
                if desc.name == "reg_rsp":
                    rsp = value
                    if rsp.status == rsp.OK:
                        if reg_or_unreg:
                            self.register_status[rsp.agent_id] = self.CCAP_CORE_REGISTERED
                        else:
                            self.register_status[rsp.agent_id] = self.CCAP_CORE_UNREGISTERED
                        return True
                    else:
                        if reg_or_unreg:
                            self.register_status[rsp.agent_id] = self.CCAP_CORE_REGISTER_FAIL
                        else:
                            self.register_status[rsp.agent_id] = self.CCAP_CORE_UNREGISTER_FAIL
                        return False
        except zmq.Again:
            return False
        except Exception as e:
            self.logger.error("Cannot process the event, reason:%s" % str(e))
            return False

        return ret

    @classmethod
    def _generate_ccap_core_id(cls):
        """Generate a 8 bytes string uniquely in the system to identify
        managers, cores.

        :return:

        """
        prefix = "CORE"
        while True:
            uid = prefix + '-' + str(randint(1, 0xFFFFFFFF))
            # Check if the uid is used
            if uid in cls.ccap_core_db:
                continue
            else:
                return uid

    # API for external use
    @classmethod
    # this is the region to process the FSM management
    def add_ccap_core(cls, mgr, parameters, principal=CoreDescription.CORE_ROLE_NONE,
                      active=CoreDescription.CORE_MODE_NONE, initiated_by='Default',
                      interface=None, network_address=None, added_by="Default",
                      test_flag=False):
        """Create the ccap core.

        :param mgr: The manager instance.
        :param parameters: every agent has corresponding parameters, RCP need
         ccap core ip to connect to.
        :param principal: flags for principal core or not
        :param active: flags to identify active or standby connection
        :param initiated_by: triggered by DHCP or RCP redirect
        :param interface: Please see the class init doc string
        :param network_address: Please see the class init doc string
        :param added_by: Please see the class init doc string
        :param test_flag: flag indicating whether to add the ccap core in test mode
        :return: CCAP_Core instance if success, otherwise None

        """
        ccap_core_id = cls._generate_ccap_core_id()

        # convert the parameters to the following mode:
        para_dict = {}
        for ctrl_para in parameters:
            para_dict[ctrl_para.agent_id] = ctrl_para.parameter

        ccap_core = cls(ccap_core_id=ccap_core_id,
                        is_principal=principal,
                        is_active=active,
                        initiated=initiated_by,
                        para=para_dict,
                        mgr=mgr,
                        ccap_core_interface=interface,
                        ccap_core_network_address=network_address,
                        added=added_by)
        agent_id = -1
        try:
            if not test_flag:
                # register ccap core to agents
                for agent_id in ProcessAgent.AgentName:
                    ret = ccap_core._register_core_to_agent(agent_id=agent_id)
                    if not ret:
                        raise ManagerCoreError("failed to register core to agent %d" % agent_id)

            cls.logger.info(
                "Add ccap core %s to the ccap core DB." % ccap_core)
            cls.ccap_core_db[ccap_core.ccap_core_id] = ccap_core

            if not test_flag:
                # Start the FSM
                ccap_core.fsm.TRIGGER_Startup()

            return ccap_core, "success create ccap core %s" % ccap_core_id
        except ManagerCoreError as e:
            reason = "Register core %s to agent %d fail, reason: %s" % (ccap_core_id, agent_id, str(e))
            cls.logger.error(reason)

            return None, reason

    def del_ccap_core(self):
        """Delete ccap core created before, maybe triggered by external module.

        :return:

        """
        ccap_core_id = self.ccap_core_id
        self.logger.info(
            "Deleting the ccap core %s from the ccap core db." % ccap_core_id)
        if ccap_core_id not in self.ccap_core_db:
            self.logger.warn("Ccap core[%s] has been deleted." % ccap_core_id)
            return False, "Cannot find the ccap core id."

        for agent_idx in self.registered_timers:
            if None is not self.registered_timers[agent_idx]:
                self.dispatcher.timer_unregister(self.registered_timers[agent_idx])
                self.registered_timers[agent_idx] = None

        for state in self.state_timer:
            self._unreg_state_timer(state)

        for agent_idx in self.register_status:
            self.kick_agent(agent_idx, action='Stop')

        for agent_idx in self.register_status:
            if self.register_status[agent_idx] == self.CCAP_CORE_REGISTERED:
                self._register_core_to_agent(agent_idx, False)

        ccap_core = self.ccap_core_db.pop(ccap_core_id)
        try:
            if self.index:
                ident_record = CcapCoreIdentification()
                ident_record.index = self.index
                ident_record.delete()
        except Exception as e:
            self.logger.warn("Delete redis db failed when remove core %s, Exception: %s", str(ccap_core), str(e))
        ccap_core.fsm.TRIGGER_DEL()
        return True, "success"

    @classmethod
    def is_ccap_core_existed(cls, interface, core_ip_address):
        """To check if the CCAP core has been created.

        :return: True if CCAP core has been created, otherwise Fasle

        """
        for core in cls.ccap_core_db.values():
            if core.interface == interface and \
                    Convert.is_ip_address_equal(core.ccap_core_network_address, core_ip_address):
                return True
        return False

    @classmethod
    def handle_core_event_notification(cls, msg, agent_id):
        """This function dispatches the msg to corresponding FSM.

        :param msg: the event rsp message.
        :param agent_id: the agent id.
        :return:

        """

        if msg.ccap_core_id not in cls.ccap_core_db:
            cls.logger.warn(
                "Cannot handle msg %s, reason: ccap_core_id is not correct" % msg)
            return

        ccap_core = cls.ccap_core_db[msg.ccap_core_id]
        cls.logger.info(
            "Got a core event notification msg:%s from %s, send it to corresponding handler.",
            msg, ccap_core.ccap_core_network_address)

        if msg.status != agent_pb2.msg_core_event_notification.OK:
            ccap_core.statistics_per_state[agent_id]['error'] += 1
            cls.logger.debug(
                "Msg status fail, will ignore this message, msg:%s", msg)
            return

        # Get the result
        if not msg.HasField("result"):
            ccap_core.statistics_per_state[agent_id]['error'] += 1
            cls.logger.warn(
                "Cannot find the result field in returned message, ignore this message:%s." % msg)
            return

        handler = ccap_core.core_event_handlers[agent_id]
        handler(msg)
        ccap_core.statistics_per_state[agent_id]['rx'] += 1
        return

    @classmethod
    def handle_agent_info_update(cls, msg, agent_id):
        """Dispatch the info to core.

        :param msg: msg_agent_info_update msg
        :param agent_id: the agent ID which send the msg
        :return: None

        """

        cls.logger.debug("Got some info:%s from agent %s", msg, str(agent_id))

        if msg.ccap_core_id not in cls.ccap_core_db:
            cls.logger.warn(
                "Cannot handle msg %s, reason: ccap_core_id is not correct", msg)
            return

        ccap_core = cls.ccap_core_db[msg.ccap_core_id]

        # Handle the Core Identification May split out when we have multiple info's
        fields = msg.ListFields()
        for field in fields:
            desc, value = field
            if desc.name == "ccap_core_identification":
                if value.HasField("CoreId"):
                    ccap_core.core_id_from_core = value.CoreId.encode('hex')

                if value.HasField("CoreName"):
                    ccap_core.core_name = value.CoreName

                if value.HasField("VendorId"):
                    ccap_core.core_vendor_id = value.VendorId

                if value.HasField("Index"):
                    ccap_core.index = value.Index

    def update_ccap_core_parameter(self, parameters):
        """Modify the ccap core parameters, such as Tod, GCP agent parameters.

        :param parameters: agents working material
        :return: True or False

        """
        self.logger.info("Update %s parameters: %s", self.ccap_core_id, parameters)
        for ctrl_parameter in parameters:
            agent_id = ctrl_parameter.agent_id
            parameter = ctrl_parameter.parameter
            if agent_id not in self.process_agent_db:
                self.logger.error(
                    "Cannot set the CCAP core %s parameter since can not "
                    "find the agent %d." % (self.ccap_core_id, agent_id))
                return False, "Cannot find the agent"

            self.parameters[agent_id] = parameter

        return True, "Success"

    @classmethod
    def is_empty(cls):
        return len(cls.ccap_core_db) == 0

    def hold_in_ipsec_state(self):
        """For gcp core, it needs take care about the startup core state, if startup core exit online state,
         need move gcp core to ipsec state, and wait for startup core get back online """
        if isinstance(self.fsm, manager_fsm.CCAPFsm):
            self.fsm.TRIGGER_Startup_exit_online()
            self._reset_counters()

    # start current state
    def restart_hold_state(self):
        """For gcp core, need a restart for startup core online """
        self._reset_counters()
        self.fsm.TRIGGER_Startup_online()

    def _reset_counters(self):
        for state in self.CoreStateFailureRetry:
            self.state_retried_times[state] = 0
        for agent_id in self.core_event_handlers.keys():
            self.agent_timeout[agent_id] = 0

    def __str__(self):
        str = "Core(%s, %s, %s, %s) Core_id %s" % (
            self.interface, self.ccap_core_network_address,
            CoreDescription.role_str(self.is_principal),
            CoreDescription.mode_str(self.is_active),
            self.ccap_core_id)
        return str
