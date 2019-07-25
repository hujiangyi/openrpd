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
from copy import copy
from fysom import Fysom
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.common.rpd_logging import AddLoggerToClass


class CCAPFsmError(Exception):
    pass


class FsmBase(object):
    __metaclass__ = AddLoggerToClass

    def __init__(self, states, events, config, callbacks):
        """
        :param callbacks: actions in respond to events
         {
            Type:event/state
            TrackPoint:On/Before/After/ Leave/Enter/reenter
            Name:
            Handler:
         }

        """
        # Get all the Event
        generatedCallbackDict = dict()
        newConfig = copy(config)
        for callback in callbacks:
            if callback["Type"] == 'event':
                if isinstance(callback["TrackPoint"], str):
                    if callback["TrackPoint"] not in ["on", "before", "after"]:
                        raise CCAPFsmError(
                            "Cannot register event callback since Trackpoint type unrecognised")
                elif isinstance(callback["TrackPoint"], tuple) or isinstance(callback["TrackPoint"], list):
                    # for the iter
                    for trackpoint in callback["TrackPoint"]:
                        if trackpoint not in ["on", "before", "after"]:
                            raise CCAPFsmError(
                                "Cannot register event callback since Trackpoint type unrecognised")
                else:
                    raise CCAPFsmError("track point type error.")

                if callback["Name"] not in events:
                    raise CCAPFsmError(
                        "Cannot register event callback since event name is unrecognised")
            elif callback["Type"] == 'state':
                if isinstance(callback["TrackPoint"], str):
                    if callback["TrackPoint"] not in ["on", "leave", "enter", "reenter", "after"]:
                        raise CCAPFsmError(
                            "Cannot register state callback since Trackpoint type unrecognised")
                elif isinstance(callback["TrackPoint"], tuple) or isinstance(callback["TrackPoint"], list):
                    # for the iter
                    for trackpoint in callback["TrackPoint"]:
                        if trackpoint not in ["on", "leave", "enter", "reenter", "after"]:
                            raise CCAPFsmError(
                                "Cannot register state callback since Trackpoint type unrecognised")
                else:
                    raise CCAPFsmError("track point type error.")
                if callback["Name"] not in states:
                    raise CCAPFsmError(
                        "Cannot register event callback since states name is unrecognised")
            else:
                raise CCAPFsmError(
                    "Cannot register state callback since Type unrecognised")

            if not callable(callback['Handler']):
                raise CCAPFsmError(
                    "Cannot register state callback since handler is not callable")

            if isinstance(callback["TrackPoint"], str):
                if callback["TrackPoint"] == "on":
                    callbackTrackpoint = "on"
                else:
                    callbackTrackpoint = "on" + callback["TrackPoint"]
                prefix = callbackTrackpoint + callback['Name']
                self.logger.debug("reigister handler:%s" % prefix)
                generatedCallbackDict[prefix] = callback["Handler"]
            else:
                for trackpoint in callback["TrackPoint"]:
                    if trackpoint == 'on':
                        callbackTrackpoint = "on"
                    else:
                        callbackTrackpoint = "on" + trackpoint
                    prefix = callbackTrackpoint + callback['Name']
                    self.logger.debug("reigster handler:%s" % prefix)
                    generatedCallbackDict[prefix] = callback["Handler"]

        if len(generatedCallbackDict) > 0:
            newConfig["callbacks"] = generatedCallbackDict

        self.fsm = Fysom(newConfig)

    @classmethod
    def getAllState(cls):
        return [cls.__getattribute__(cls, attr) for attr in dir(cls) if attr.startswith('STATE')]

    @classmethod
    def getAllEvents(cls):
        return [cls.__getattribute__(cls, attr) for attr in dir(cls) if attr.startswith('EVENT')]

    def __getattr__(self, item):
        return getattr(self.fsm, item)


class CCAPFsm(FsmBase):
    """
    This FSM defines state machine of ccap-core
    """

    """
    Define all states here
    """
    STATE_FAIL = "FAIL"
    STATE_DEL = "DEL"
    STATE_INIT_IPSEC = 'init(ipsec)'
    STATE_INIT_TCP = 'init(tcp)'
    STATE_INIT_GCP_IRA = 'init(gcp-ira)'
    STATE_INIT_GCP_CFG = 'init(gcp-cfg)'
    STATE_INIT_GCP_CFG_CPL = 'init(gcp-cfg-cpl)'
    STATE_INIT_GCP_OP = 'init(gcp-op)'
    STATE_REINIT_IPSEC = 'reinit(ipsec)'
    STATE_REINIT_TCP = 'reinit(tcp)'
    STATE_REINIT_GCP_IRA = 'reinit(gcp-ira)'
    STATE_ONLINE = 'online'
    STATE_CHANGE = "changestate"

    """
    not the state for a FSM, just for some checkout points
    """
    STATE_ALL = [STATE_FAIL, STATE_DEL, STATE_INIT_IPSEC, STATE_INIT_TCP, STATE_INIT_GCP_IRA, STATE_INIT_GCP_CFG,
                 STATE_INIT_GCP_CFG_CPL, STATE_INIT_GCP_OP,
                 STATE_REINIT_IPSEC, STATE_REINIT_TCP, STATE_REINIT_GCP_IRA, STATE_ONLINE]
    STATE_OPERATIONAL = [STATE_INIT_GCP_OP, STATE_ONLINE]

    STATE_GCP = 'init(gcp)'
    STATE_GCP_ALL = [STATE_INIT_TCP, STATE_INIT_GCP_IRA, STATE_INIT_GCP_CFG, STATE_INIT_GCP_CFG_CPL,
                     STATE_REINIT_TCP, STATE_REINIT_GCP_IRA]

    STATE_IPSEC = 'init(ipsec)'
    STATE_IPSEC_ALL = [STATE_INIT_IPSEC, STATE_REINIT_IPSEC]

    STATE_ALL_INIT = [STATE_INIT_IPSEC, STATE_INIT_TCP, STATE_INIT_GCP_IRA, STATE_INIT_GCP_CFG,
                      STATE_INIT_GCP_CFG_CPL, STATE_INIT_GCP_OP]
    STATE_ALL_REINIT = [STATE_REINIT_IPSEC, STATE_REINIT_TCP, STATE_REINIT_GCP_IRA, STATE_ONLINE]
    STATE_FINAL = [STATE_FAIL, STATE_DEL]
    STATE_ALL_OPERATIONAL = [STATE_ONLINE, STATE_INIT_GCP_OP]

    """
    Define all events here.
    """
    EVENT_IPSEC_OK = 'TRIGGER_IPSEC_OK'
    EVENT_IPSEC_FAIL = 'TRIGGER_IPSEC_FAIL'

    EVENT_TCP_OK = 'TRIGGER_TCP_OK'
    EVENT_TCP_FAIL = 'TRIGGER_TCP_FAIL'
    EVENT_GCP_IRA = 'TRIGGER_GCP_IRA'
    EVENT_GCP_NO_IRA = 'TRIGGER_GCP_NO_IRA'
    EVENT_GCP_CFG = 'TRIGGER_GCP_CFG'
    EVENT_GCP_NO_CFG = 'TRIGGER_GCP_NO_CFG'
    EVENT_GCP_CFG_CPL = 'TRIGGER_GCP_CFG_CPL'
    EVENT_GCP_NO_CFG_CPL = 'TRIGGER_GCP_NO_CFG_CPL'
    EVENT_GCP_OP = 'TRIGGER_GCP_OP'
    EVENT_GCP_NO_OP = 'TRIGGER_GCP_NO_GCP_OP'
    EVENT_STARTUP_CORE_EXIT_ONLINE = "TRIGGER_Startup_exit_online"
    EVENT_STARTUP_CORE_ONLINE = "TRIGGER_Startup_online"

    AGENT_FAIL_EVENTS = [EVENT_IPSEC_FAIL, EVENT_TCP_FAIL, EVENT_GCP_NO_CFG]

    # For the module timeout, the module will report as a fail message,
    # For the retry, the process agent also will handle this.
    # The timeout here means, After retry several times, the process agent always reports as an FAIL message.
    EVENT_ENTER_CURRENT_STATE = 'TRIGGER_ENTER_CURRENT_STATE'
    EVENT_STARTUP = 'TRIGGER_Startup'
    EVENT_ERROR = 'TRIGGER_Error'
    EVENT_DEL = 'TRIGGER_DEL'
    FsmSetupCfg = {
        'initial': None,
        'events': [
            {'name': EVENT_STARTUP, 'src': 'none', 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_ALL_INIT, 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_ALL_REINIT, 'dst': STATE_REINIT_IPSEC},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_IPSEC_ALL, 'dst': '='},

            {'name': EVENT_IPSEC_OK, 'src': STATE_INIT_IPSEC, 'dst': STATE_INIT_TCP},
            {'name': EVENT_IPSEC_OK, 'src': STATE_REINIT_IPSEC, 'dst': STATE_REINIT_TCP},
            {'name': EVENT_IPSEC_OK, 'src': [state for state in STATE_ALL if state not in STATE_IPSEC_ALL], 'dst': '='},

            {'name': EVENT_TCP_OK, 'src': STATE_INIT_TCP, 'dst': STATE_INIT_GCP_IRA},
            {'name': EVENT_TCP_OK, 'src': STATE_REINIT_TCP, 'dst': STATE_REINIT_GCP_IRA},
            {'name': EVENT_TCP_OK,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_TCP, STATE_REINIT_TCP]],
             'dst': '='},

            {'name': EVENT_TCP_FAIL, 'src': STATE_ALL_INIT, 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_TCP_FAIL, 'src': STATE_ALL_REINIT, 'dst': STATE_REINIT_IPSEC},
            {'name': EVENT_TCP_FAIL, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_GCP_IRA, 'src': STATE_INIT_GCP_IRA, 'dst': STATE_INIT_GCP_CFG},
            {'name': EVENT_GCP_IRA, 'src': STATE_REINIT_GCP_IRA, 'dst': STATE_ONLINE},
            {'name': EVENT_GCP_IRA,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_IRA, STATE_REINIT_GCP_IRA]],
             'dst': '='},

            {'name': EVENT_GCP_NO_IRA, 'src': STATE_INIT_GCP_IRA, 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_GCP_NO_IRA, 'src': STATE_REINIT_GCP_IRA, 'dst': STATE_REINIT_IPSEC},
            {'name': EVENT_GCP_NO_IRA,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_IRA, STATE_REINIT_GCP_IRA]],
             'dst': '='},

            {'name': EVENT_GCP_CFG, 'src': STATE_INIT_GCP_CFG, 'dst': STATE_INIT_GCP_CFG_CPL},
            {'name': EVENT_GCP_CFG,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_CFG, ]],
             'dst': '='},

            {'name': EVENT_GCP_NO_CFG, 'src': STATE_INIT_GCP_CFG, 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_GCP_NO_CFG,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_CFG, ]],
             'dst': '='},

            {'name': EVENT_GCP_CFG_CPL, 'src': STATE_INIT_GCP_CFG_CPL, 'dst': STATE_INIT_GCP_OP},
            {'name': EVENT_GCP_CFG_CPL,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_CFG_CPL, ]],
             'dst': '='},

            {'name': EVENT_GCP_NO_CFG_CPL, 'src': STATE_INIT_GCP_CFG_CPL, 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_GCP_NO_CFG_CPL,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_CFG_CPL, ]],
             'dst': '='},

            {'name': EVENT_GCP_OP, 'src': STATE_INIT_GCP_OP, 'dst': STATE_ONLINE},
            {'name': EVENT_GCP_OP,
             'src': [state for state in STATE_ALL if state not in [STATE_INIT_GCP_OP, ]],
             'dst': '='},

            {'name': EVENT_GCP_NO_OP, 'src': '*', 'dst': '='},

            # Receive Fail for several times
            {'name': EVENT_ERROR, 'src': "*", 'dst': STATE_FAIL},

            {'name': EVENT_ENTER_CURRENT_STATE, 'src': '*', 'dst': '='},

            {'name': EVENT_STARTUP_CORE_EXIT_ONLINE, 'src': STATE_ALL_INIT, 'dst': STATE_INIT_IPSEC},
            {'name': EVENT_STARTUP_CORE_EXIT_ONLINE, 'src': STATE_ALL_REINIT, 'dst': STATE_REINIT_IPSEC},
            {'name': EVENT_STARTUP_CORE_EXIT_ONLINE, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_STARTUP_CORE_ONLINE, 'src': '*', 'dst': '='},

            {'name': EVENT_DEL, 'src': '*', 'dst': STATE_DEL}
        ],
    }

    def __init__(self, callbacks):
        states = CCAPFsm.getAllState()
        events = CCAPFsm.getAllEvents()
        super(CCAPFsm, self).__init__(states, events, self.FsmSetupCfg, callbacks)
        self.logger.info("CCAP Fsm has been created.")


class CCAPFsmStartup(FsmBase):
    """
    the ccap core state machine for startup core
    """

    """
    define all states here.
    """
    STATE_FAIL = "FAIL"
    STATE_INIT = 'INIT'
    STATE_DEL = "DEL"
    STATE_INTERFACE_UP = 'init(dot1x)'
    STATE_8021X_OK = 'init(dhcp)'
    STATE_DHCP_OK = 'init(tod)'
    STATE_TOD_OK = 'online(startup)'
    STATE_CHANGE = "changestate"
    """
    STATE for check usage
    """
    STATE_ALL = [STATE_FAIL, STATE_INIT, STATE_DEL, STATE_INTERFACE_UP, STATE_8021X_OK, STATE_DHCP_OK, STATE_TOD_OK]
    STATE_FINAL = [STATE_FAIL, STATE_DEL]
    STATE_AFTER_8021X = [STATE_8021X_OK, STATE_DHCP_OK, STATE_TOD_OK]
    STATE_AFTER_DHCP = [STATE_DHCP_OK, STATE_TOD_OK]
    """
    define all events here.
    """
    EVENT_INTERFACE_UP = 'TRIGGER_INTERFACE_UP'
    EVENT_INTERFACE_DOWN = 'TRIGGER_INTERFACE_DOWN'
    EVENT_8021X_OK = 'TRIGGER_MAC_8021X_OK'
    EVENT_8021X_FAIL = 'TRIGGER_MAC_8021X_FAIL'
    EVENT_DHCP_OK = 'TRIGGER_DHCP_OK'
    EVENT_DHCP_FAIL = 'TRIGGER_DHCP_FAIL'
    EVENT_TOD_OK = 'TRIGGER_TOD_OK'
    EVENT_TOD_FAIL = 'TRIGGER_TOD_FAIL'

    # For the module timeout, the module will report as a fail message,
    # For the retry, the process agent also will handle this.
    # The timeout here means, After retry several times, the process agent always reports as an FAIL message.
    EVENT_TIMEOUT = 'TRIGGER_TIMEOUT'

    EVENT_ENTER_CURRENT_STATE = 'TRIGGER_ENTER_CURRENT_STATE'
    EVENT_STARTUP = 'TRIGGER_Startup'

    EVENT_ERROR = 'TRIGGER_Error'
    EVENT_DEL = 'TRIGGER_DEL'

    AGENT_FAIL_EVENTS = [EVENT_INTERFACE_DOWN, EVENT_8021X_FAIL, EVENT_DHCP_FAIL, EVENT_TOD_FAIL]

    FsmSetupCfg = {
        'initial': None,
        'events': [
            {'name': EVENT_INTERFACE_DOWN,
             'src': [state for state in STATE_ALL if state not in STATE_FINAL], 'dst': STATE_INIT},
            {'name': EVENT_INTERFACE_DOWN,
             'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_INTERFACE_UP, 'src': STATE_INIT, 'dst': STATE_INTERFACE_UP},
            {'name': EVENT_INTERFACE_UP, 'src': [state for state in STATE_ALL if state not in [STATE_INIT, ]],
             'dst': '='},

            {'name': EVENT_8021X_FAIL, 'src': STATE_AFTER_8021X, 'dst': STATE_INTERFACE_UP},
            {'name': EVENT_8021X_FAIL,
             'src': [state for state in STATE_ALL if state not in STATE_AFTER_8021X], 'dst': '='},

            {'name': EVENT_8021X_OK, 'src': STATE_INTERFACE_UP, 'dst': STATE_8021X_OK},
            {'name': EVENT_8021X_OK,
             'src': [state for state in STATE_ALL if state not in STATE_INTERFACE_UP], 'dst': '='},

            {'name': EVENT_DHCP_FAIL, 'src': STATE_AFTER_DHCP, 'dst': STATE_8021X_OK},
            {'name': EVENT_DHCP_FAIL,
             'src': [state for state in STATE_ALL if state not in STATE_AFTER_DHCP], 'dst': '='},

            {'name': EVENT_DHCP_OK, 'src': STATE_8021X_OK, 'dst': STATE_DHCP_OK},
            {'name': EVENT_DHCP_OK, 'src': [state for state in STATE_ALL if state not in STATE_8021X_OK], 'dst': '='},

            {'name': EVENT_TOD_FAIL, 'src': STATE_TOD_OK, 'dst': STATE_DHCP_OK},
            {'name': EVENT_TOD_FAIL, 'src': [state for state in STATE_ALL if state not in STATE_TOD_OK], 'dst': '='},

            {'name': EVENT_TOD_OK, 'src': STATE_DHCP_OK, 'dst': STATE_TOD_OK},
            {'name': EVENT_TOD_OK, 'src': [state for state in STATE_ALL if state not in STATE_DHCP_OK], 'dst': '='},

            # Receive Fail for several times
            {'name': EVENT_TIMEOUT, 'src': "*", 'dst': STATE_FAIL},
            {'name': EVENT_ERROR, 'src': "*", 'dst': STATE_FAIL},

            {'name': EVENT_ENTER_CURRENT_STATE, 'src': '*', 'dst': '='},

            {'name': EVENT_STARTUP, 'src': 'none', 'dst': STATE_INIT},
            {'name': EVENT_DEL, 'src': '*', 'dst': STATE_DEL}
        ],
    }

    def __init__(self, callbacks):
        states = CCAPFsmStartup.getAllState()
        events = CCAPFsmStartup.getAllEvents()
        super(CCAPFsmStartup, self).__init__(states, events, self.FsmSetupCfg, callbacks)
        self.logger.info("Startup CCAP Fsm has been created.")
        self.is_principal = False


class ManagerFsm(FsmBase):
    STATE_FAIL = "FAIL"
    STATE_INIT = 'INIT'
    STATE_INTERFACE_PROVISION = "INTERFACE_PROVISION"
    STATE_PRINCIPLE_PROVISION = 'PRINCIPLE_PROVISION'
    STATE_PRINCIPLE_RETRY_FIRST = 'PRINCIPLE_PROVISION_FIRST'
    STATE_PRINCIPLE_RETRY_SECOND = 'PRINCIPLE_PROVISION_SECOND'
    STATE_PRINCIPLE_RETRY_THIRD = 'PRINCIPLE_PROVISION_THIRD'
    STATE_CHANGE = "changestate"
    """
        After system entered operational state,  if principal core fail, the system will enter into recovering state.
        When old principal core comes back to operational or system received a HA change request to standby core,
         the system will enter into operational state from recovering state.
    """
    STATE_OPERATIONAL = 'OPERATIONAL'
    STATE_PRINCIPAL_FOUND = 'PRINCIPAL_FOUND'

    EVENT_INTERFACE_SCAN = 'INTERFACE_SCAN'
    EVENT_USER_MGMT = 'USER_MGMT'
    EVENT_GCP_MGMT = 'GCP_MGMT'
    EVENT_DHCP = 'DHCP'
    EVENT_STARTUP_DHCP_OK = 'STARTUP_DHCP_OK'
    EVENT_STARTUP_CORE_FAIL = 'STARTUP_CORE_FAIL'
    EVENT_PROVISION_INTERFACE_FAIL = 'PROVISION_INTERFACE_FAIL'
    EVENT_OPERATIONAL_OK = 'OPERATIONAL_OK'
    EVENT_OPERATIONAL_FAIL = 'OPERATIONAL_FAIL'
    EVENT_SEEK_PRINCIPAL_FAIL = 'SEEK_PRINCIPAL_FAIL'
    EVENT_SEEK_PRINCIPAL_OK = 'SEEK_PRINCIPAL_OK'

    EVENT_CORE_FAIL = "CORE_FAIL"
    EVENT_ENTER_CURRENT_STATE = "ENTER_CURRENT_STATE"
    EVENT_STARTUP = "Startup"
    EVENT_ERROR = "Error"

    FsmSetupCfg = {
        'initial': None,
        'events': [
            {'name': EVENT_STARTUP, 'src': 'none', 'dst': STATE_INIT},
            {'name': EVENT_INTERFACE_SCAN, 'src': STATE_INIT, 'dst': STATE_INTERFACE_PROVISION},
            {'name': EVENT_INTERFACE_SCAN, 'src':
                [STATE_INTERFACE_PROVISION, STATE_PRINCIPLE_PROVISION, STATE_OPERATIONAL], 'dst': '='},

            {'name': EVENT_STARTUP_DHCP_OK, 'src': STATE_INTERFACE_PROVISION, 'dst': STATE_PRINCIPLE_PROVISION},
            {'name': EVENT_PROVISION_INTERFACE_FAIL, 'src': STATE_INTERFACE_PROVISION, 'dst': STATE_FAIL},

            {'name': EVENT_USER_MGMT, 'src': '*', 'dst': '='},
            {'name': EVENT_GCP_MGMT, 'src': '*', 'dst': '='},

            {'name': EVENT_DHCP, 'src': '*', 'dst': '='},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': [STATE_OPERATIONAL,
                                                        STATE_PRINCIPAL_FOUND],
                                                'dst': STATE_PRINCIPLE_PROVISION},

            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': [STATE_PRINCIPLE_PROVISION, STATE_OPERATIONAL,
                                                        STATE_PRINCIPAL_FOUND],
                                                'dst': STATE_PRINCIPLE_RETRY_FIRST},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': STATE_PRINCIPLE_RETRY_FIRST,
             'dst': STATE_PRINCIPLE_RETRY_SECOND},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': STATE_PRINCIPLE_RETRY_SECOND,
             'dst': STATE_PRINCIPLE_RETRY_THIRD},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': [STATE_PRINCIPLE_RETRY_THIRD, STATE_FAIL, STATE_INIT],
             'dst': STATE_FAIL},

            {'name': EVENT_CORE_FAIL, 'src': '*', 'dst': '='},
            {'name': EVENT_SEEK_PRINCIPAL_OK, 'src': [STATE_PRINCIPLE_PROVISION,
                                                      STATE_PRINCIPLE_RETRY_FIRST,
                                                      STATE_PRINCIPLE_RETRY_SECOND,
                                                      STATE_PRINCIPLE_RETRY_THIRD], 'dst': STATE_PRINCIPAL_FOUND},
            {'name': EVENT_SEEK_PRINCIPAL_OK, 'src': [STATE_FAIL, STATE_INIT, STATE_OPERATIONAL, STATE_PRINCIPAL_FOUND],
                                              'dst': '='},

            {'name': EVENT_OPERATIONAL_OK, 'src': [STATE_PRINCIPAL_FOUND,
                                                   STATE_OPERATIONAL], 'dst': STATE_OPERATIONAL},
            {'name': EVENT_OPERATIONAL_FAIL, 'src': [STATE_OPERATIONAL, STATE_PRINCIPAL_FOUND], 'dst': STATE_PRINCIPAL_FOUND},

            {'name': EVENT_ERROR, 'src': "*", 'dst': STATE_FAIL},
            {'name': EVENT_ENTER_CURRENT_STATE, 'src': '*', 'dst': '='},
        ],
    }

    def __init__(self, callbacks):
        states = ManagerFsm.getAllState()
        events = ManagerFsm.getAllEvents()
        super(ManagerFsm, self).__init__(states, events, self.FsmSetupCfg, callbacks)

    def is_startup(self):
        return self.fsm.current == self.STATE_INIT or self.fsm.current == self.STATE_INTERFACE_PROVISION

    def is_provisioning(self):
        return self.fsm.current == self.STATE_PRINCIPLE_PROVISION

    def is_provision_retry(self):
        return self.fsm.current == self.STATE_PRINCIPLE_RETRY_FIRST or \
            self.fsm.current == self.STATE_PRINCIPLE_RETRY_SECOND or \
            self.fsm.current == self.STATE_PRINCIPLE_RETRY_THIRD

    def is_operational(self):
        return self.fsm.current == self.STATE_OPERATIONAL

    def is_principal_found(self):
        return self.fsm.current == self.STATE_PRINCIPAL_FOUND

    def is_fail(self):
        return self.fsm.current == self.STATE_FAIL
