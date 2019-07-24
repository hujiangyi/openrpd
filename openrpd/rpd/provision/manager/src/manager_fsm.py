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
                elif isinstance(callback["TrackPoint"], tuple) or isinstance(callback["TrackPoint"], list): # for the iter
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
                elif isinstance(callback["TrackPoint"], tuple) or isinstance(callback["TrackPoint"], list): # for the iter
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
    STATE_FAIL = "FAIL"
    STATE_INIT = 'INIT'
    STATE_DEL = "DEL"
    STATE_INTERFACE_UP = 'init(dot1x)'
    STATE_8021X_OK = 'init(dhcp)'
    STATE_DHCP_OK = 'init(tod)'
    STATE_TOD_OK = 'init(ipsec)'
    STATE_IPSEC_OK = 'init(gcp)'
    STATE_RCP_OK = 'init(clock)'
    STATE_PTP1588_OK = 'online'
    STATE_OPERATIONAL_OK = 'online'
    STATE_CHANGE = "changestate"

    STATE_ALL = [STATE_INIT, STATE_INTERFACE_UP, STATE_8021X_OK, STATE_DHCP_OK, STATE_TOD_OK,
                 STATE_IPSEC_OK, STATE_RCP_OK, STATE_PTP1588_OK, STATE_OPERATIONAL_OK]

    STATE_FINAL = [STATE_FAIL, STATE_DEL]

    STATE_AFTER_INIT = STATE_ALL[1:]

    STATE_AFTER_INTERFACE_UP = STATE_ALL[2:]
    STATE_BEFORE_INTERFACE_UP = STATE_ALL[:1]

    STATE_AFTER_8021X = STATE_ALL[3:]
    STATE_BEFORE_8021X = STATE_ALL[:2]

    STATE_AFTER_DHCP = STATE_ALL[4:]
    STATE_BEFORE_DHCP = STATE_ALL[:3]

    STATE_AFTER_TOD = STATE_ALL[5:]
    STATE_BEFORE_TOD = STATE_ALL[:4]

    STATE_AFTER_IPSEC = STATE_ALL[6:]
    STATE_BEFORE_IPSEC = STATE_ALL[:5]

    STATE_AFTER_RCP = STATE_ALL[7:]
    STATE_BEFORE_RCP = STATE_ALL[:6]

    STATE_AFTER_PTP1588 = STATE_ALL[8:]
    STATE_BEFORE_PTP1588 = STATE_ALL[:7]

    STATE_ALL_OPERATIONAL = [STATE_PTP1588_OK, STATE_OPERATIONAL_OK]

    EVENT_INTERFACE_UP = 'TRIGGER_INTERFACE_UP'
    EVENT_INTERFACE_DOWN = 'TRIGGER_INTERFACE_DOWN'
    EVENT_8021X_OK = 'TRIGGER_MAC_8021X_OK'
    EVENT_8021X_FAIL = 'TRIGGER_MAC_8021X_FAIL'
    EVENT_DHCP_OK = 'TRIGGER_DHCP_OK'
    EVENT_DHCP_FAIL = 'TRIGGER_DHCP_FAIL'
    EVENT_TOD_OK = 'TRIGGER_TOD_OK'
    EVENT_TOD_FAIL = 'TRIGGER_TOD_FAIL'
    EVENT_IPSEC_OK = 'TRIGGER_IPSEC_OK'
    EVENT_IPSEC_FAIL = 'TRIGGER_IPSEC_FAIL'
    EVENT_RCP_OK = 'TRIGGER_RCP_OK'
    EVENT_RCP_FAIL = 'TRIGGER_RCP_FAIL'
    EVENT_PTP1588_OK = 'TRIGGER_PTPT1588_OK'
    EVENT_PTP1588_FAIL = 'TRIGGER_PTP1588_FAIL'
    EVENT_MOVE_OPERATIONAL = 'TRIGGER_MOVE_OPERATIONAL'

    EVENT_REDIRECT = 'TRIGGER_REDIRECT'

    # For the module timeout, the module will report as a fail message,
    # For the retry, the process agent also will handle this.
    # The timeout here means, After retry several times, the process agent always reports as an FAIL message.
    EVENT_TIMEOUT = 'TRIGGER_TIMEOUT'
    EVENT_CANNOT_REACH_AGENT = 'TRIGGER_CANNOT_REACH_AGENT'

    EVENT_ENTER_CURRENT_STATE = 'TRIGGER_ENTER_CURRENT_STATE'
    EVENT_STARTUP = 'TRIGGER_Startup'

    EVENT_ERROR = 'TRIGGER_Error'
    EVENT_DEL = 'TRIGGER_DEL'

    FAIL_EVENTS = (EVENT_INTERFACE_DOWN, EVENT_8021X_FAIL, EVENT_DHCP_FAIL,
                   EVENT_TOD_FAIL, EVENT_IPSEC_FAIL, EVENT_RCP_FAIL, EVENT_PTP1588_FAIL,
                   EVENT_TIMEOUT, EVENT_ERROR)

    FsmSetupCfg = {
        'initial': None,
        'events': [
            {'name': EVENT_INTERFACE_DOWN, 'src': '*', 'dst': STATE_INIT},
            {'name': EVENT_INTERFACE_UP, 'src': STATE_INIT, 'dst': STATE_INTERFACE_UP},
            {'name': EVENT_INTERFACE_UP, 'src': STATE_AFTER_INIT, 'dst': '='},
            {'name': EVENT_INTERFACE_UP, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_8021X_FAIL, 'src': STATE_BEFORE_INTERFACE_UP, 'dst': '='},
            {'name': EVENT_8021X_FAIL, 'src': STATE_INTERFACE_UP, 'dst': '='},
            {'name': EVENT_8021X_FAIL, 'src': STATE_AFTER_INTERFACE_UP, 'dst': STATE_INTERFACE_UP},
            {'name': EVENT_8021X_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_8021X_OK, 'src': STATE_INTERFACE_UP, 'dst': STATE_8021X_OK},
            {'name': EVENT_8021X_OK, 'src': STATE_AFTER_INTERFACE_UP, 'dst': '='},
            {'name': EVENT_8021X_OK, 'src': STATE_BEFORE_INTERFACE_UP, 'dst': '='},
            {'name': EVENT_8021X_OK, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_DHCP_FAIL, 'src': STATE_BEFORE_8021X, 'dst': '='},
            {'name': EVENT_DHCP_FAIL, 'src': STATE_8021X_OK, 'dst': '='},
            {'name': EVENT_DHCP_FAIL, 'src': STATE_AFTER_8021X, 'dst': STATE_8021X_OK},
            {'name': EVENT_DHCP_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_DHCP_OK, 'src': STATE_8021X_OK, 'dst': STATE_DHCP_OK},
            {'name': EVENT_DHCP_OK, 'src': STATE_AFTER_8021X, 'dst': '='},
            {'name': EVENT_DHCP_OK, 'src': STATE_BEFORE_8021X, 'dst': '='},
            {'name': EVENT_DHCP_OK, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_TOD_FAIL, 'src': STATE_BEFORE_DHCP, 'dst': '='},
            {'name': EVENT_TOD_FAIL, 'src': STATE_DHCP_OK, 'dst': '='},
            {'name': EVENT_TOD_FAIL, 'src': STATE_AFTER_DHCP, 'dst': STATE_DHCP_OK},
            {'name': EVENT_TOD_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_TOD_OK, 'src': STATE_DHCP_OK, 'dst': STATE_TOD_OK},
            {'name': EVENT_TOD_OK, 'src': STATE_AFTER_DHCP, 'dst': '='},
            {'name': EVENT_TOD_OK, 'src': STATE_BEFORE_DHCP, 'dst': '='},
            {'name': EVENT_TOD_OK, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_IPSEC_FAIL, 'src': STATE_BEFORE_TOD, 'dst': '='},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_TOD_OK, 'dst': '='},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_AFTER_TOD, 'dst': STATE_TOD_OK},
            {'name': EVENT_IPSEC_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_IPSEC_OK, 'src': STATE_TOD_OK, 'dst': STATE_IPSEC_OK},
            {'name': EVENT_IPSEC_OK, 'src': STATE_AFTER_TOD, 'dst': '='},
            {'name': EVENT_IPSEC_OK, 'src': STATE_BEFORE_TOD, 'dst': '='},
            {'name': EVENT_IPSEC_OK, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_RCP_FAIL, 'src': STATE_BEFORE_IPSEC, 'dst': '='},
            {'name': EVENT_RCP_FAIL, 'src': STATE_IPSEC_OK, 'dst': '='},
            {'name': EVENT_RCP_FAIL, 'src': STATE_AFTER_IPSEC, 'dst': STATE_IPSEC_OK},
            {'name': EVENT_RCP_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_RCP_OK, 'src': STATE_IPSEC_OK, 'dst': STATE_RCP_OK},
            {'name': EVENT_RCP_OK, 'src': STATE_AFTER_IPSEC, 'dst': '='},
            {'name': EVENT_RCP_OK, 'src': STATE_BEFORE_IPSEC, 'dst': '='},
            {'name': EVENT_RCP_OK, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_REDIRECT, 'src':STATE_BEFORE_IPSEC, 'dst': '='},
            {'name': EVENT_REDIRECT, 'src': STATE_AFTER_TOD, 'dst': STATE_TOD_OK},
            {'name': EVENT_REDIRECT, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_PTP1588_FAIL, 'src': STATE_BEFORE_RCP, 'dst': '='},
            {'name': EVENT_PTP1588_FAIL, 'src': STATE_RCP_OK, 'dst': '='},
            {'name': EVENT_PTP1588_FAIL, 'src': STATE_AFTER_RCP, 'dst': STATE_RCP_OK},
            {'name': EVENT_PTP1588_FAIL, 'src': STATE_FINAL, 'dst': '='},
            {'name': EVENT_PTP1588_OK, 'src': STATE_RCP_OK, 'dst': STATE_PTP1588_OK},
            {'name': EVENT_PTP1588_OK, 'src': STATE_AFTER_RCP, 'dst': '='},
            {'name': EVENT_PTP1588_OK, 'src': STATE_BEFORE_RCP, 'dst': '='},
            {'name': EVENT_PTP1588_OK, 'src': STATE_FINAL, 'dst': '='},

            {'name': EVENT_MOVE_OPERATIONAL, 'src': STATE_AFTER_IPSEC, 'dst': STATE_OPERATIONAL_OK},


            # Cannot reach the event
            {'name': EVENT_CANNOT_REACH_AGENT, 'src': "*", 'dst': STATE_FAIL},

            # Receive Fail for several times
            {'name': EVENT_TIMEOUT, 'src': "*", 'dst': STATE_FAIL},
            {'name': EVENT_ERROR, 'src': "*", 'dst': STATE_FAIL},

            {'name': EVENT_ENTER_CURRENT_STATE, 'src':'*', 'dst':'='},

            {'name': EVENT_STARTUP, 'src':'none', 'dst':STATE_INIT},
            {'name': EVENT_DEL, 'src':'*', 'dst':STATE_DEL}
        ],
    }

    EventSources = (
        ProcessAgent.AGENTTYPE_INTERFACE_STATUS,
        ProcessAgent.AGENTTYPE_8021X,
        ProcessAgent.AGENTTYPE_DHCP,
        ProcessAgent.AGENTTYPE_TOD,
        ProcessAgent.AGENTTYPE_IPSEC,
        ProcessAgent.AGENTTYPE_GCP,
        ProcessAgent.AGENTTYPE_PTP,
        ProcessAgent.AGENTTYPE_L2TP,
    )

    def __init__(self, callbacks, is_principal=True):
        states = CCAPFsm.getAllState()
        events = CCAPFsm.getAllEvents()
        super(CCAPFsm, self).__init__(states, events, self.FsmSetupCfg, callbacks)
        if is_principal:
            self.logger.info("Principal CCAP Fsm has been created.")
        else:
            self.logger.info("Auxiliary CCAP Fsm has been created.")

        self.is_principal = is_principal


class PrincipleCCAPFsm(CCAPFsm):
    def __init__(self, callbacks):
        super(PrincipleCCAPFsm, self).__init__(callbacks, is_principal=True)


class AuxiliaryCCAPFsm(CCAPFsm):
    def __init__(self, callbacks):
        super(AuxiliaryCCAPFsm, self).__init__(callbacks, is_principal=False)


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
    STATE_RECOVERING = 'RECOVERING'

    EVENT_INTERFACE_SCAN = 'INTERFACE_SCAN'
    EVENT_USER_MGMT = 'USER_MGMT'
    EVENT_GCP_MGMT = 'GCP_MGMT'
    EVENT_DHCP= 'DHCP'
    EVENT_STARTUP_DHCP_OK = 'STARTUP_DHCP_OK'
    EVENT_STARTUP_CORE_FAIL = 'STARTUP_CORE_FAIL'
    EVENT_PROVISION_INTERFACE_FAIL = 'PROVISION_INTERFACE_FAIL'
    EVENT_OPERATIONAL_OK = 'OPERATIONAL_OK'
    EVENT_OPERATIONAL_FAIL = 'OPERATIONAL_FAIL'
    EVENT_SEEK_PRINCIPAL_FAIL = 'SEEK_PRINCIPAL_FAIL'

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
                [STATE_INTERFACE_PROVISION,STATE_PRINCIPLE_PROVISION, STATE_OPERATIONAL], 'dst': '='},

            {'name': EVENT_STARTUP_DHCP_OK, 'src': STATE_INTERFACE_PROVISION, 'dst': STATE_PRINCIPLE_PROVISION},
            {'name': EVENT_CORE_FAIL, 'src': STATE_INTERFACE_PROVISION, 'dst': '='},
            {'name': EVENT_PROVISION_INTERFACE_FAIL, 'src': STATE_INTERFACE_PROVISION, 'dst': STATE_FAIL},

            {'name': EVENT_USER_MGMT, 'src': STATE_OPERATIONAL, 'dst': '='},
            {'name': EVENT_GCP_MGMT, 'src': STATE_OPERATIONAL, 'dst': '='},

            {'name': EVENT_DHCP, 'src': [STATE_PRINCIPLE_PROVISION,
                                         STATE_PRINCIPLE_RETRY_FIRST,
                                         STATE_PRINCIPLE_RETRY_SECOND,
                                         STATE_PRINCIPLE_RETRY_THIRD,
                                         STATE_OPERATIONAL], 'dst': '='},

            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': [STATE_PRINCIPLE_PROVISION, STATE_OPERATIONAL],
             'dst': STATE_PRINCIPLE_RETRY_FIRST},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': STATE_PRINCIPLE_RETRY_FIRST,
             'dst': STATE_PRINCIPLE_RETRY_SECOND},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': STATE_PRINCIPLE_RETRY_SECOND,
             'dst': STATE_PRINCIPLE_RETRY_THIRD},
            {'name': EVENT_SEEK_PRINCIPAL_FAIL, 'src': [STATE_PRINCIPLE_RETRY_THIRD, STATE_FAIL],
             'dst': STATE_FAIL},

            {'name': EVENT_CORE_FAIL, 'src': [STATE_PRINCIPLE_PROVISION,
                                              STATE_PRINCIPLE_RETRY_FIRST,
                                              STATE_PRINCIPLE_RETRY_SECOND,
                                              STATE_PRINCIPLE_RETRY_THIRD,
                                              STATE_OPERATIONAL,
                                              STATE_RECOVERING,
                                              STATE_FAIL], 'dst': '='},

            {'name': EVENT_OPERATIONAL_OK, 'src': [STATE_PRINCIPLE_PROVISION,
                                                   STATE_PRINCIPLE_RETRY_FIRST,
                                                   STATE_PRINCIPLE_RETRY_SECOND,
                                                   STATE_PRINCIPLE_RETRY_THIRD,
                                                   STATE_RECOVERING,
                                                   STATE_OPERATIONAL], 'dst': STATE_OPERATIONAL},
            {'name': EVENT_OPERATIONAL_FAIL, 'src': STATE_OPERATIONAL, 'dst': STATE_RECOVERING},

            {'name': EVENT_ERROR, 'src': "*", 'dst': STATE_FAIL},
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

    def is_recovering(self):
        return self.fsm.current == self.STATE_RECOVERING

    def is_fail(self):
        return self.fsm.current == self.STATE_FAIL

