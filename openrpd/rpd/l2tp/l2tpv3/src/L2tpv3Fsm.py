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
from rpd.common.rpd_logging import AddLoggerToClass


class l2tpv3FsmParameterError(Exception):
    pass


class L2tpV3Fsm(object):
    """The base class of session FSM and connection FSM."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, states, events, config, callbacks):
        """TODO params dont match
        :param callbacks: it is used to indicate some event happens, we should take some action
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
                if callback["TrackPoint"] not in ["on", "before", "after"]:
                    raise l2tpv3FsmParameterError(
                        "Cannot register event callback since Trackpoint type unrecognised")
                if callback["Name"] not in events:
                    raise l2tpv3FsmParameterError(
                        "Cannot register event callback since event name is unrecognised")
            elif callback["Type"] == 'state':
                if callback["TrackPoint"] not in ["on", "leave", "enter", "reenter", "after"]:
                    raise l2tpv3FsmParameterError(
                        "Cannot register state callback since Trackpoint type unrecognised")
                if callback["Name"] not in states:
                    raise l2tpv3FsmParameterError(
                        "Cannot register event callback since states name is unrecognised")
            else:
                raise l2tpv3FsmParameterError(
                    "Cannot register state callback since Type unrecognised")

            if not callable(callback['Handler']):
                raise l2tpv3FsmParameterError(
                    "Cannot register state callback since handler is not callable")

            if callback["TrackPoint"] == "on":
                callbackTrackpoint = "on"
            else:
                callbackTrackpoint = "on" + callback["TrackPoint"]

            prefix = callbackTrackpoint + callback['Name']
            generatedCallbackDict[prefix] = callback["Handler"]

        if len(generatedCallbackDict) > 0:
            newConfig["callbacks"] = generatedCallbackDict

        self.fsm = Fysom(newConfig)

    @classmethod
    def getAllState(cls):
        return [cls.__getattribute__(cls, attr) for attr in dir(cls) if attr.startswith('State')]

    @classmethod
    def getAllEvents(cls):
        return [cls.__getattribute__(cls, attr) for attr in dir(cls) if attr.startswith('Event')]

    def __getattr__(self, item):
        return getattr(self.fsm, item)


class L2tpv3ConnectionFsm(L2tpV3Fsm):
    """Connection FSM."""
    StateIdle = 'idle'
    StateWaitCtlReply = 'waitCtlReply'
    StateWaitCtlConn = 'waitCtlConn'
    StateEstablished = 'established'

    EventLocalRequest = 'localRequest'
    EventRecvGoodSCCRQ = 'recvGoodSCCRQ'
    EventRecvBadSCCRQ = 'recvBadSCCRQ'
    EventRecvGoodSCCRP = 'recvGoodSCCRP'
    EventRecvBadSCCRP = 'recvBadSCCRP'
    EventRecvSCCRQLoseTieGood = 'recvSCCRQLoseTieGood'
    EventRecvSCCRQLoseTieBad = 'recvSCCRQLoseTieBad'
    EventRecvSCCRQWinSCCRQ = 'recvSCCRQWinSCCRQ'
    EventRecvGoodSCCCN = 'recvGoodSCCCN'
    EventRecvBadSCCCN = 'recvBadSCCCN'
    EventRecvStopCCN = 'recvStopCCN'
    EventCloseRequest = 'closeRequest'
    EventRecvHALError = 'recvHalError'

    FsmSetupCfg = {
        'initial': StateIdle,
        'events': [
            {'name': EventLocalRequest, 'src':
                StateIdle, 'dst': StateWaitCtlReply},
            {'name': EventLocalRequest, 'src':
                StateEstablished, 'dst': StateEstablished},

            {'name': EventRecvGoodSCCRQ, 'src':
                StateIdle, 'dst': StateWaitCtlConn},
            {'name': EventRecvGoodSCCRQ, 'src':
                [StateWaitCtlConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvBadSCCRQ, 'src':
                [StateIdle, StateWaitCtlConn], 'dst': StateIdle},

            {'name': EventRecvGoodSCCRP, 'src':
                [StateWaitCtlConn, StateEstablished, StateIdle], 'dst': StateIdle},
            {'name': EventRecvGoodSCCRP, 'src':
                StateWaitCtlReply, 'dst': StateEstablished},

            {'name': EventRecvBadSCCRP, 'src': [StateIdle, StateWaitCtlReply, StateWaitCtlConn, StateEstablished],
             'dst': StateIdle},

            {'name': EventRecvSCCRQLoseTieGood, 'src':
                StateWaitCtlReply, 'dst': StateWaitCtlConn},
            {'name': EventRecvSCCRQLoseTieBad, 'src':
                StateWaitCtlReply, 'dst': StateIdle},
            {'name': EventRecvSCCRQWinSCCRQ, 'src':
                StateWaitCtlReply, 'dst': StateWaitCtlReply},

            {'name': EventRecvGoodSCCCN, 'src':
                [StateIdle, StateWaitCtlReply, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvGoodSCCCN, 'src':
                StateWaitCtlConn, 'dst': StateEstablished},

            {'name': EventRecvBadSCCCN, 'src': [StateIdle, StateWaitCtlReply, StateWaitCtlConn, StateEstablished],
             'dst': StateIdle},
            {'name': EventRecvStopCCN, 'src': [StateEstablished, StateIdle, StateWaitCtlConn, StateWaitCtlReply],
             'dst': StateIdle},
            {'name': EventCloseRequest, 'src': [StateIdle, StateWaitCtlReply, StateWaitCtlConn, StateEstablished],
             'dst': StateIdle},
            {'name': EventRecvHALError, 'src': [StateWaitCtlConn, StateEstablished],
             'dst': StateIdle},
        ],
    }

    def __init__(self, callbacks):
        """
        :param callbacks: it is used to indicate some event happens, we should take some action
         {
            Type:event/state
            TrackPoint:On/Before/After/ Leave/Enter/reenter
            Name:
            Handler:
         }
        """
        states = L2tpv3ConnectionFsm.getAllState()
        events = L2tpv3ConnectionFsm.getAllEvents()
        super(L2tpv3ConnectionFsm, self).__init__(
            states, events, self.FsmSetupCfg, callbacks)
        self.logger.debug("Connection Fsm has been created.")


class L2tpv3SessionSenderFsm(L2tpV3Fsm):
    """Session FSM."""
    StateIdle = 'idle'
    StateWaitReply = 'waitCtlReply'
    StateEstablished = 'established'

    EventLocalRequest = 'localRequest'
    EventCloseRequest = 'closeRequest'
    EventRecvGoodICRP = 'recvGoodICRP'
    EventRecvBadICRP = 'recvBadICRP'
    EventRecvICRQLoseTie = 'recvICRQLoseTie'
    EventRecvICRQWinTie = 'recvICRQWinTie'
    EventRecvCDN = 'recvCDN'
    EventRecvICCN = 'recvICCN'

    FsmSetupCfg = {
        'initial': StateIdle,
        'events': [
            {'name': EventLocalRequest, 'src':
                StateIdle, 'dst': StateWaitReply},
            {'name': EventLocalRequest, 'src':
                StateEstablished, 'dst': StateEstablished},
            {'name': EventCloseRequest, 'src':
                [StateIdle, StateWaitReply, StateEstablished], 'dst': StateIdle},

            {'name': EventRecvGoodICRP, 'src':
                StateWaitReply, 'dst': StateEstablished},
            {'name': EventRecvGoodICRP, 'src':
                [StateIdle, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvBadICRP, 'src':
                [StateIdle, StateWaitReply, StateEstablished], 'dst': StateIdle},

            {'name': EventRecvICRQLoseTie, 'src':
                StateWaitReply, 'dst': StateIdle},
            {'name': EventRecvICRQWinTie, 'src':
                StateWaitReply, 'dst': StateWaitReply},

            {'name': EventRecvCDN, 'src':
                [StateIdle, StateWaitReply, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvICCN, 'src':
                [StateIdle, StateWaitReply, StateEstablished], 'dst': StateIdle}
        ],
    }

    def __init__(self, callbacks):
        states = L2tpv3SessionSenderFsm.getAllState()
        events = L2tpv3SessionSenderFsm.getAllEvents()
        super(L2tpv3SessionSenderFsm, self).__init__(
            states, events, self.FsmSetupCfg, callbacks)
        self.logger.debug("L2tp session sender Fsm has been created.")


class L2tpv3SessionRecipientFsm(L2tpV3Fsm):
    """Recipient session FSM."""
    StateIdle = 'idle'
    StateWaitConn = 'waitCtlConn'
    StateEstablished = 'established'

    EventLocalRequest = 'localRequest'
    EventCloseRequest = 'closeRequest'
    EventRecvICRP = 'recvICRP'
    EventRecvBadICRQ = 'recvBadICRQ'
    EventRecvGoodICRQ = 'recvGoodICRQ'
    EventRecvBadICCN = 'recvBadICCN'
    EventRecvGoodICCN = 'recvGoodICCN'
    EventRecvCDN = 'recvCDN'
    EventRecvHalStatusChange = 'recvHalStatusChange'

    FsmSetupCfg = {
        'initial': StateIdle,
        'events': [
            {'name': EventCloseRequest, 'src':
                [StateIdle, StateWaitConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvICRP, 'src':
                [StateIdle, StateWaitConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvCDN, 'src':
                [StateIdle, StateWaitConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvBadICRQ, 'src':
                [StateIdle, StateWaitConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvBadICCN, 'src':
                [StateIdle, StateWaitConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvGoodICRQ, 'src':
                [StateWaitConn, StateEstablished], 'dst': StateIdle},
            {'name': EventRecvGoodICRQ, 'src':
                StateIdle, 'dst': StateWaitConn},
            {'name': EventRecvGoodICCN, 'src':
                StateWaitConn, 'dst': StateEstablished},
            {'name': EventRecvGoodICCN, 'src':
                [StateIdle, StateEstablished], 'dst': StateIdle},
        ],
    }

    def __init__(self, callbacks):
        states = L2tpv3SessionRecipientFsm.getAllState()
        events = L2tpv3SessionRecipientFsm.getAllEvents()
        super(L2tpv3SessionRecipientFsm, self).__init__(
            states, events, self.FsmSetupCfg, callbacks)
        self.logger.debug("L2tp session recipient Fsm has been created")
