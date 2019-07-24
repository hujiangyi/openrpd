
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
#
import l2tpv3.src.L2tpv3Fsm as L2tpFsm
import unittest
from rpd.common.rpd_logging import setup_logging


class testL2tpv3Fsm(unittest.TestCase):

    def localrequest(self, event):
        print "onlocalRequest: receive the event:" + event.src + " " + event.dst + "  " + event.event

    def setUp(self):
        self.L2tpv3Fsm = L2tpFsm
        setup_logging('L2TP')

    def tearDown(self):
        pass

    def test_CreateL2TpFsm(self):
        fsm = L2tpFsm.L2tpv3ConnectionFsm([])

        # pass the ut if thers is no exception
        fsm = L2tpFsm.L2tpv3ConnectionFsm(
            [{
                "Type": "event",
                "TrackPoint": "on",
                "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
                "Handler": self.localrequest
            }
            ]
        )

        self.assertRaises(
            L2tpFsm.l2tpv3FsmParameterError, L2tpFsm.L2tpv3ConnectionFsm,
            [{
             "Type": "event1",
             "TrackPoint": "on",
             "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
             "Handler": self.localrequest
             }
             ]
        )

        self.assertRaises(
            L2tpFsm.l2tpv3FsmParameterError, L2tpFsm.L2tpv3ConnectionFsm,
            [{
             "Type": "event",
             "TrackPoint": "test",  # should be some predifined value
             "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
             "Handler": self.localrequest
             }])

        self.assertRaises(
            L2tpFsm.l2tpv3FsmParameterError, L2tpFsm.L2tpv3ConnectionFsm,
            [{
             "Type": "event",
             "TrackPoint": "on",
             "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest + "test",
             "Handler": self.localrequest
             }
             ]
        )
        self.assertRaises(
            L2tpFsm.l2tpv3FsmParameterError, L2tpFsm.L2tpv3ConnectionFsm,
            [{
             "Type": "event",
             "TrackPoint": "on",
             "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
             "Handler": "a"
             }
             ]
        )

    def test_state(self):
        """
        Tes Exception
        Type = state

        """
        try:
            fsm = L2tpFsm.L2tpv3ConnectionFsm(
                [{
                    "Type": "state",
                    "TrackPoint": "on",
                    "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
                    "Handler": self.localrequest
                }
                ]
            )

            fsm.localRequest()
            self.assertEqual(
                L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm.current)
        except Exception as e:
            pass

    def test_L2tpv3ConnectionFsm(self):
        """
        RFC3931-Page-69
        States: idle, wait-ctl-replay, wait-ctl-conn, established
        1.idle->waitConn->established->Idle
        2.wait-ctl-reply --- idle/established/wait-ctl-conn/wait-ctl-reply
        3.wait-ctl-conn --->  established/idle/
        4.idle--->wait-ctl-reply/wait-ctl-conn/idle

        """
        fsm_11 = L2tpFsm.L2tpv3ConnectionFsm(
            [{
                "Type": "event",
                "TrackPoint": "on",
                "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
                "Handler": self.localrequest
            }
            ]
        )

        fsm_11.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_11.current)

        fsm_12 = L2tpFsm.L2tpv3ConnectionFsm(
            [{
                "Type": "event",
                "TrackPoint": "on",
                "Name": L2tpFsm.L2tpv3ConnectionFsm.EventLocalRequest,
                "Handler": self.localrequest
            }
            ]
        )

        # S1:
        # idle->waitConn->established->Idle
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        fsm_12.recvGoodSCCCN()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # S22: wait-ctl-reply ---> idle/established/wait-ctl-conn/wait-ctl-reply
        # RFC3931-Page-70

        # st1:
        # idle->fsm_12.localRequest(StateWaitCtlReply)->recvGoodSCCRP(Established)->
        # recvStopCCN(idle)->idle
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvGoodSCCRP
        fsm_12.recvGoodSCCRP()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st2:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvBadSCCRP
        fsm_12.recvBadSCCRP()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st3:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvSCCRQLoseTieGood
        fsm_12.recvSCCRQLoseTieGood()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st4:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvSCCRQLoseTieBad
        fsm_12.recvSCCRQLoseTieBad()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st5:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvSCCRQWinSCCRQ
        fsm_12.recvSCCRQWinSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st6:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvGoodSCCCN
        fsm_12.recvGoodSCCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st7:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        # recvBadSCCCN
        fsm_12.recvBadSCCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # S33: wait-ctl-conn --->  established/idle/

        # st1:
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        # recvGoodSCCCN
        fsm_12.recvGoodSCCCN()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st2:
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        # recvBadSCCCN
        fsm_12.recvBadSCCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st3:
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        # recvGoodSCCRQ/recvBadSCCRQ
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st4:
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        # recvGoodSCCRP/recvBadSCCRP
        fsm_12.recvGoodSCCRP()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # S44: idle--->wait-ctl-reply/wait-ctl-conn/idle
        # RFC3931-Page-69
        # idle--->wait-ctl-reply/wait-ctl-conn/idle

        # st1:
        # localRequest
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st2:
        # recvGoodSCCRQ
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlConn, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st3:
        # recvBadSCCRQ
        fsm_12.recvBadSCCRQ()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st4:
        # recvGoodSCCRP/recvBadSCCRP
        fsm_12.recvGoodSCCRP()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st5:
        # recvGoodSCCCN/recvBadSCCCN
        fsm_12.recvGoodSCCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # S55: established---> established/idle
        # st1:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        fsm_12.recvGoodSCCRP()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        # Local open request
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st2:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        fsm_12.recvGoodSCCRP()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        # closeRequest
        fsm_12.closeRequest()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

        # st3:
        fsm_12.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateWaitCtlReply, fsm_12.current)
        fsm_12.recvGoodSCCRP()
        self.assertEqual(
            L2tpFsm.L2tpv3ConnectionFsm.StateEstablished, fsm_12.current)
        # recvGoodSCCRQ/recvBaSCCRQ/recvSCCRP/recvSCCCN
        fsm_12.recvGoodSCCRQ()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)
        fsm_12.recvStopCCN()
        self.assertEqual(L2tpFsm.L2tpv3ConnectionFsm.StateIdle, fsm_12.current)

    def test_L2tpv3SessionSenderFsm(self):
        """
        RFC3931-Page-72
        1.idle--->wait-replay--->Established
        2.idle --- idle
        3.idle --- wait-replay
        4.Established --- idle

        """
        # Normal
        fsm = L2tpFsm.L2tpv3SessionSenderFsm(
            [{
                "Type": "event",
                "TrackPoint": "on",
                "Name": L2tpFsm.L2tpv3SessionSenderFsm.EventLocalRequest,
                "Handler": self.localrequest
            }
            ]
        )

        # S1: idle--->wait-replay--->Established
        # idle->(localRequest)StateWaitReply->(recvGoodICRP)StateEstablished->
        # (recvCDN)StateIdle->idle
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        fsm.recvGoodICRP()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateEstablished, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # S2: idle --- idle
        # st1:
        fsm.recvICCN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st2:
        fsm.recvGoodICRP()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st3:
        fsm.recvBadICRP()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # S3: idle --- wait-replay
        # st1:
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        # closeRequest
        fsm.closeRequest()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st2:
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        # recvICCN
        fsm.recvICCN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st3:
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        # recvICRQLoseTie
        fsm.recvICRQLoseTie()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st4:
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        # recvBadICRP
        fsm.recvBadICRP()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st4:
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        # recvCDN
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # S4: Established --- idle
        # st1: --->closeRequest
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        fsm.recvGoodICRP()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateEstablished, fsm.current)
        # closeRequest
        fsm.closeRequest()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st2: --->recvGoodICRP
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        fsm.recvGoodICRP()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateEstablished, fsm.current)
        # recvGoodICRP
        fsm.recvGoodICRP()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st3: --->recvBadICRP
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        fsm.recvGoodICRP()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateEstablished, fsm.current)
        # recvBadICRP
        fsm.recvBadICRP()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

        # st4: --->recvCDN
        fsm.localRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionSenderFsm.StateWaitReply, fsm.current)
        # recvCDN
        fsm.recvCDN()
        self.assertEqual(L2tpFsm.L2tpv3SessionSenderFsm.StateIdle, fsm.current)

    def recvGoodICRQ(self, event):
        print "onlocalRequest: receive the event:" + event.src + " " + event.dst + "  " + event.event

    def test_L2tpv3SessionRecipientFsm(self):
        """
        RFC3931-Page-73
        1.idle->wait-conn->Established
        2.idle --- idle
        3.Established->idle
        4.idle --- wait-conn

        """
        # Normal
        fsm = L2tpFsm.L2tpv3SessionRecipientFsm(
            [{
                "Type": "event",
                "TrackPoint": "on",
                "Name": L2tpFsm.L2tpv3SessionRecipientFsm.EventRecvGoodICRQ,
                "Handler": self.recvGoodICRQ
            }
            ]
        )

        # S1
        # idle->wait-conn->Established
        # idle->recvGoodICRQ(wait-conn)->recvGoodICCN(Established)->recvCDN(idle)->idle
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateWaitConn, fsm.current)
        fsm.recvGoodICCN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateEstablished, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # S2
        # idle --- idle
        # recvBadICRQ
        fsm.recvBadICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # recvGoodICCN
        fsm.recvGoodICCN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # S3
        # Established->idle

        # st1:
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateWaitConn, fsm.current)
        fsm.recvGoodICCN()
        # recvGoodICRQ
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateEstablished, fsm.current)
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # st2:
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateWaitConn, fsm.current)
        fsm.recvGoodICCN()
        # recvGoodICCN
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateEstablished, fsm.current)
        fsm.recvGoodICCN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # st3:
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateWaitConn, fsm.current)
        fsm.recvGoodICCN()
        # closeRequest
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateEstablished, fsm.current)
        fsm.closeRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # S4
        # idle --- wait-conn
        # recvBadICCN
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateWaitConn, fsm.current)
        fsm.recvBadICCN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)

        # closeRequest
        fsm.recvGoodICRQ()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateWaitConn, fsm.current)
        fsm.closeRequest()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)
        fsm.recvCDN()
        self.assertEqual(
            L2tpFsm.L2tpv3SessionRecipientFsm.StateIdle, fsm.current)


if __name__ == "__main__":
    unittest.main()
