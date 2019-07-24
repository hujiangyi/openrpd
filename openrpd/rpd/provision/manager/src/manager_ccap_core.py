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
        """Init cccap core role and HA-mode.

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
    ccap_core_db = {}

    # Some Constant Values

    REGISTER_RET_CHECK_RESULT = 3

    TIMEOUT_ONE_SECOND = 1
    TIMEOUT_TWO_SECONDS = 2
    TIMEOUT_FIVE_SECONDS = 5
    TIMEOUT_TEN_SECONDS = 10
    TIMEOUT_FIFTEEN_SECONDS = 15
    TIMEOUT_CHECK_CORE_REG = 200  # cnt * 0.1s
    RETRY_TIMES_10 = 10
    RETRY_TIMES_18 = 18
    RETRY_TIMES_20 = 20
    RETRY_TIMES_50 = 50
    RETRY_TIMES_54 = 54
    RETRY_TIMES_100 = 100
    CoreAgentRetry = {
        ProcessAgent.AGENTTYPE_INTERFACE_STATUS: RETRY_TIMES_100,
        ProcessAgent.AGENTTYPE_8021X: RETRY_TIMES_20,
        ProcessAgent.AGENTTYPE_DHCP: RETRY_TIMES_20,
        ProcessAgent.AGENTTYPE_TOD: RETRY_TIMES_100,
        ProcessAgent.AGENTTYPE_IPSEC: RETRY_TIMES_10,
        ProcessAgent.AGENTTYPE_GCP: RETRY_TIMES_20,
        ProcessAgent.AGENTTYPE_PTP: RETRY_TIMES_54,
        ProcessAgent.AGENTTYPE_L2TP: RETRY_TIMES_18,
    }
    CoreTimeout = {
        ProcessAgent.AGENTTYPE_INTERFACE_STATUS: TIMEOUT_ONE_SECOND,
        ProcessAgent.AGENTTYPE_8021X: TIMEOUT_FIVE_SECONDS,
        ProcessAgent.AGENTTYPE_DHCP: TIMEOUT_FIVE_SECONDS,
        ProcessAgent.AGENTTYPE_TOD: TIMEOUT_FIVE_SECONDS,
        ProcessAgent.AGENTTYPE_IPSEC: TIMEOUT_TWO_SECONDS,
        ProcessAgent.AGENTTYPE_GCP: TIMEOUT_FIFTEEN_SECONDS,
        ProcessAgent.AGENTTYPE_PTP: TIMEOUT_TEN_SECONDS,
        ProcessAgent.AGENTTYPE_L2TP: TIMEOUT_TEN_SECONDS,
    }

    CCAP_CORE_REGISTERED = "registered"
    CCAP_CORE_REGISTER_FAIL = "registered-fail"
    CCAP_CORE_UNREGISTERED = "unregistered"
    CCAP_CORE_UNREGISTER_FAIL = "unregistered-fail"

    # for statistics
    core_statistics = ProvisionStateMachineRecord()

    def __init__(self, ccap_core_id,
                 is_principal=CoreDescription.CORE_ROLE_NONE, is_active=CoreDescription.CORE_MODE_NONE,
                 initiated="Startup", para=None, mgr=None, ccap_core_interface=None,
                 ccap_core_network_address=None, added="Startup"):
        # We have to have a valid mgr, which contains a dispatcher and agent information
        if mgr is None:
            reason = "Cannot create Core %s since the mgr is none." % ccap_core_id
            self.logger.error(reason)
            raise ManagerCoreError(reason)

        # Fsm Callbacks
        callbacks = [
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INIT,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_init,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_INTERFACE_UP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_interface_up,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_8021X_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_8021x_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_DHCP_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_dhcp_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_TOD_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_tod_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_IPSEC_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_ipsec_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_RCP_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_rcp_ok,
            },
            {
                "Type": "state",
                "Name": manager_fsm.CCAPFsm.STATE_PTP1588_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self._fsm_enter_state_ptp_ok,
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
                "TrackPoint": ("on", ),
                "Handler": self._fsm_state_change,
            },
            # event callbacks
        ]

        # the agent event handlers
        self.core_event_handlers = {
            ProcessAgent.AGENTTYPE_INTERFACE_STATUS: self._handle_core_interface_up_event,
            ProcessAgent.AGENTTYPE_8021X: self._handle_core_8021x_event,
            ProcessAgent.AGENTTYPE_DHCP: self._handle_core_dhcp_event,
            ProcessAgent.AGENTTYPE_TOD: self._handle_core_tod_event,
            ProcessAgent.AGENTTYPE_IPSEC: self._handle_core_ipsec_event,
            ProcessAgent.AGENTTYPE_GCP: self._handle_core_gcp_event,
            ProcessAgent.AGENTTYPE_PTP: self._handle_core_ptp_event,
            ProcessAgent.AGENTTYPE_L2TP: self._handle_core_l2tp_event,
        }

        fsm = manager_fsm.CCAPFsm(
            callbacks=callbacks, is_principal=is_principal)
        self.ccap_core_id = ccap_core_id
        self.fsm = fsm
        self.is_principal = is_principal
        self.is_active = is_active
        self.initiated_by = initiated
        self.added_by = added
        self.parameters = para
        self.start_time = time.time()
        self.register_status = dict([(x, None) for x in fsm.EventSources])
        self.agent_timeout = dict([(x, 0) for x in fsm.EventSources])
        self.registered_timers = dict([(x, None) for x in fsm.EventSources])
        self.agent_status = dict([(x, False) for x in fsm.EventSources])
        self.action_status = dict([(x, False) for x in fsm.EventSources])

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

        # ccap core statistic per state
        self.statistics_per_state = {}
        for agent in ProcessAgent.AgentName:
            self.statistics_per_state[agent] = {"tx": 0, 'rx': 0, 'error': 0}

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

        if self.agent_timeout[agent_id] >= self.CoreAgentRetry[agent_id]:
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

    # this is to define a start of agent
    def __fsm_enter_state_start(self, event, trigger_agent_id):
        """Common api for all state changed procedure.

        :param event: fysom event
        :param trigger_agent_id: the agent will be tiggered
        :return:

        """
        self._fsm_stop_agent_after_state(event)
        self.logger.info(
            "%s Entering state %s from state %s, triggered by event:%s. agent:%d start" %
            (self.ccap_core_id, event.fsm.current, event.src, event.event, trigger_agent_id))
        # check if we have the parameter for this fsm, if not try to reenter this state later
        if event.event in manager_fsm.CCAPFsm.FAIL_EVENTS:
            if self.registered_timers[trigger_agent_id] is None:
                self.logger.warn(
                    "Cannot find the registered-timers for agent %d" % trigger_agent_id)
                timer = self.dispatcher.timer_register(
                    self.CoreTimeout[trigger_agent_id],
                    self.__state_reenter_wrapper,
                    {'event': event,
                     'agent_id': trigger_agent_id,
                    },
                    DpTimerManager.TIMER_ONESHOT)
                self.registered_timers[trigger_agent_id] = timer
            return

        # when we entering this state, we should inform the agent to start
        self.kick_agent(trigger_agent_id, action='Start')

    # this is to define a stop of agent
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

    def _fsm_stop_agent_after_state(self, event):
        if not event.dst or not event.src or \
           event.dst not in manager_fsm.CCAPFsm.STATE_ALL or\
           event.src not in manager_fsm.CCAPFsm.STATE_ALL:
            self.logger.warn(
                "%s Entering state %s from state %s, triggered by event:%s, no need to stop"
                % (self.ccap_core_id, event.fsm.current, event.src, event.event))
            return
        dst_index = manager_fsm.CCAPFsm.STATE_ALL.index(event.dst)
        src_index = manager_fsm.CCAPFsm.STATE_ALL.index(event.src)
        if event.src in manager_fsm.CCAPFsm.STATE_ALL[dst_index + 1:]:
            for agent in range(dst_index + 1, src_index + 1):
                if event.src in manager_fsm.CCAPFsm.STATE_ALL_OPERATIONAL and \
                   event.dst == manager_fsm.CCAPFsm.STATE_RCP_OK and \
                   event.event == manager_fsm.CCAPFsm.EVENT_PTP1588_FAIL and \
                   agent == ProcessAgent.AGENTTYPE_L2TP:
                    continue
                self.__fsm_enter_state_stop(event, agent)
            # clear timer, status and timeout count
            if dst_index != src_index:
                for agent in range(dst_index + 1, ProcessAgent.AGENTTYPE_L2TP + 1):
                    if None is not self.registered_timers[agent]:
                        self.dispatcher.timer_unregister(self.registered_timers[agent])
                        self.registered_timers[agent] = None
                    self.agent_status[agent] = False
                    self.agent_timeout[agent] = 0
        return

    def _fsm_enter_state_init(self, event):
        """Enter init state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_INTERFACE_STATUS)

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
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_IPSEC)

    def _fsm_enter_state_ipsec_ok(self, event):
        """Enter IPSEC ok state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_GCP)
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_L2TP)

    def _fsm_enter_state_rcp_ok(self, event):
        """Enter RCP ok state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_PTP)

    def _fsm_enter_state_ptp_ok(self, event):
        """Enter PTP ok state.

        :param event: fysom event
        :return:

        """
        self.__fsm_enter_state_start(event, ProcessAgent.AGENTTYPE_L2TP)

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
            state_index = manager_fsm.CCAPFsm.STATE_ALL.index(event.src)
            interface = self.interface
            core_ip = self.ccap_core_network_address

            if self.mgr.principal_core is self:
                self.mgr_fsm.Error(msg="Principal Core(%s, %s) %s fail" %
                                       (interface, core_ip, manager_fsm.CCAPFsm.FAIL_EVENTS[state_index][8:-5]))
            else:
                self.del_ccap_core()

                # Info mgr that one core has been in down state
                self.mgr_fsm.CORE_FAIL(interface=interface, core_ip=core_ip,
                                       msg="Core(%s, %s) %s fail" %
                                           (interface, core_ip, manager_fsm.CCAPFsm.FAIL_EVENTS[state_index][8:-5]))
        except Exception as ex:
            self.logger.warn("Unexpected event: %s", str(ex))

    def _fsm_state_change(self, event):
        """change state callback

        :param event: event instance
        :return:
        """
        self.core_statistics.update(self, event)

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
                raise ManagerCoreError("Cannot %s process agent:%d"%(
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
                for agent_id in manager_fsm.CCAPFsm.EventSources:
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

        for agent_idx in self.register_status:
            self.kick_agent(agent_idx, action='Stop')

        for agent_idx in self.register_status:
            if self.register_status[agent_idx] == self.CCAP_CORE_REGISTERED:
                self._register_core_to_agent(agent_idx, False)

        # fixme we should clean up the ccap core

        ccap_core = self.ccap_core_db.pop(ccap_core_id)
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

    # This the region to process the event processing, call corresponding FSM event to trigger the FSM
    def _handle_core_interface_up_event(self, msg):
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
            fsm.TRIGGER_RCP_OK()
        elif result == "OPERATIONAL":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_MOVE_OPERATIONAL()
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_RCP_FAIL()

        self.logger.info(
            "Got a GCP event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_ptp_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_PTP
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
            fsm.TRIGGER_PTPT1588_OK()
        else:
            self.agent_status[agent_id] = False
            fsm.TRIGGER_PTP1588_FAIL()

        self.logger.info(
            "Got a PTP event:%s, status is changed to:%s" % (msg, fsm.current))

    def _handle_core_l2tp_event(self, msg):
        """Handle core status event, trigger fsm enter next stage when "UP",
        otherwise will retry a few times, fallback to previous stage until
        exceed retry times.

        :param msg: message send by agent when status changed

        """
        fsm = self.fsm
        result = msg.result
        agent_id = ProcessAgent.AGENTTYPE_L2TP
        if result == "UP":
            if not (self.registered_timers[agent_id] is None):
                timer = self.registered_timers[agent_id]
                self.dispatcher.timer_unregister(timer)
                self.registered_timers[agent_id] = None
            self.agent_timeout[agent_id] = 0
            self.agent_status[agent_id] = True
        else:
            self.agent_status[agent_id] = False

        self.logger.info(
            "Got a L2TP event:%s, status is changed to:%s" % (msg, fsm.current))

    def operational_mode_transition(self, msg):
        """system operational mode transition.

        :param msg: the event rsp message.
        :return:

        """

        result = msg.result

        if msg.event_id == ProcessAgent.AGENTTYPE_L2TP:
            return

        if self.mgr.principal_core is not self:
            return

        if result in ["UP", "OPERATIONAL"]:
            if self.agent_status[ProcessAgent.AGENTTYPE_GCP]:
                if not self.mgr_fsm.is_operational():
                    self.mgr_fsm.OPERATIONAL_OK()
            elif self.mgr_fsm.is_operational():
                self.mgr_fsm.OPERATIONAL_FAIL()
        else:
            if self.mgr_fsm.is_operational():
                self.mgr_fsm.OPERATIONAL_FAIL()

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

        # system operational mode transition
        ccap_core.operational_mode_transition(msg)
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

                cls.logger.debug(
                    "Update core info: core id:%s, core name:%s, vendor_id:%d",
                    ccap_core.core_id_from_core,
                    ccap_core.core_name,
                    ccap_core.core_vendor_id)

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

    def __str__(self):
        str = "Core(%s, %s, %s, %s) Core_id %s" % (
            self.interface, self.ccap_core_network_address,
            CoreDescription.role_str(self.is_principal),
            CoreDescription.mode_str(self.is_active),
            self.ccap_core_id)
        return str
