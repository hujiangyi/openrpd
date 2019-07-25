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

from rpd.dispatcher.dispatcher import Dispatcher

from l2tpv3.src.L2tpv3Connection import L2tpConnection
from l2tpv3.src.L2tpv3ControlPacket import L2tpv3ControlPacket, L2tpv3StopCCN, L2tpv3ACK
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
from l2tpv3.src.L2tpv3Fsm import L2tpv3ConnectionFsm
from l2tpv3.src.L2tpv3Fsm import L2tpv3SessionRecipientFsm
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP, Hostname, CallSerialNumber, FailoverSessionState
from l2tpv3.src.L2tpv3RFC3931AVPs import LocalSessionID, RemoteSessionID, AssignedControlConnectionID, \
    RouterID, PseudowireCapList, RemoteEndID
from docsisAVPs.src.L2tpv3CableLabsAvps import DepiL2SpecificSublayerSubtype
from l2tpv3.src.L2tpv3Session import L2tpv3Session
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
import struct
import l2tpv3.src.L2tpv3Fsm as L2tpv3Fsm
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis


class fake_hal(object):

    def __init__(self):
        pass

    def send_l2tp_lcce_assignment_msg(self, lcce=None, msg_type=None):
        return


class testL2tpConnection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ircq_buf = struct.pack('!130B',
                                   0xc8, 0x03, 0x0, 130,
                                   0x0, 0x0, 0x0, 0x12,
                                   0x0, 0x3, 0x0, 0x4,
                                   0xc, 8, 0x0, 0x0,
                                   0x0, 0x0, 0x0, 10,
                                   0xc, 10, 0x0, 0x0,
                                   0, 15, 0, 0,
                                   0, 0,
                                   0xc, 10, 0x0, 0x0,
                                   0, 63, 0x40, 0x00,
                                   0x00, 0x01,
                                   0xc, 10, 0x0, 0x0,
                                   0, 64, 0x0, 0x0,
                                   0x0, 0x0,
                                   0xc, 40, 0x0, 0x0,
                                   0x0, 66, 0x0, 0x0,
                                   0x00, 0x03, 0x00, 0x00,
                                   0x00, 0x03, 0x01, 0x01,
                                   0x00, 0x03, 0x02, 0x02,
                                   0x00, 0x03, 0x03, 0x03,
                                   0x00, 0x03, 0x04, 0x04,
                                   0x00, 0x03, 0x05, 0x05,
                                   0x00, 0x03, 0x06, 0x06,
                                   0x00, 0x03, 0x07, 0x07,
                                   0xc, 8, 0, 0,
                                   0, 68, 0, 12,
                                   0xc, 8, 0, 0,
                                   0, 69, 0, 3,
                                   0xc, 8, 0, 0,
                                   0, 71, 0, 2,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 0x2, 0x1, 0x0,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 0x4, 0x7, 0xD0,
                                   )
        setup_test_redis()

    @classmethod
    def tearDownClass(cls):
        for conn in L2tpConnection.ConnectionDb.values():
            conn.CloseConnection()
        stop_test_redis()

    def testConnection_init(self):
        conn_address = '127.11.2.1'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.2'
        # localConnectionID not equal to zero
        conn1 = L2tpConnection(1, 1, conn_address, local_addr)
        session1 = L2tpv3Session(1, 2, 'sender', conn1)
        conn1.addSession(session1)
        self.assertEqual(conn1.sessions.keys(), [1])
        self.assertEqual(conn1.sessionsByRemoteSessionId.keys(), [2])
        self.assertEqual(conn1.localConnID, 1)
        self.assertIsNotNone(conn1.ConnectionDb)

        # localConnectionID equal to zero
        local_addr = '127.11.2.3'
        conn2 = L2tpConnection(0, 2, conn_address, local_addr)
        session2 = L2tpv3Session(1, 2, 'sender', conn2)
        conn2.addSession(session2)
        self.assertEqual(conn2.sessions.keys(), [1])
        self.assertEqual(conn2.sessionsByRemoteSessionId.keys(), [2])
        self.assertIsNotNone(conn2.localConnID)
        self.assertIsNotNone(conn2.ConnectionDb)
        conn1.CloseConnection()
        conn2.CloseConnection()

    def testCloseConnection(self):
        conn_address = '127.11.2.2'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False
        L2tpv3GlobalSettings.l2tp_hal_client = fake_hal()

        local_addr = '127.11.2.4'
        L2tpConnection.ConnectionDb.clear()
        conn = L2tpConnection(3, 3, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)

        conn.ReceiveHalMsg(msg=None)
        msg = L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp()
        msg.result = False
        try:
            conn.ReceiveHalMsg(msg)
        except Exception as e:
            pass
        msg.result = True
        conn.ReceiveHalMsg(msg)
        conn.SendHalMsg(msg_type=L2tpConnection.ADD_LCCE)
        conn.fsmEventrecvBadSCCRP(event=None)
        conn.fsmEventrecvSCCRQLoseTieGood(event=None)
        conn.fsmEventrecvSCCRQLoseTieBad(event=None)
        conn.fsmEventrecvSCCRQWinSCCRQ(event=None)
        conn.fsmEventcloseRequest(event=None)
        conn.fsmEventHalError(event=None)
        # CloseConnection will trigger new session fsm transmit,
        # set fsm.transition is to simulate session fsm is handling event
        # but has not finished case
        session.fsm.fsm.transition = 'test'
        conn.CloseConnection()
        self.assertEqual(len(conn.ConnectionDb), 0)
        self.assertEqual(
            session.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)
        L2tpv3GlobalSettings.l2tp_hal_client = None

    def testReceiveControlPackets(self):
        conn_address = '127.11.2.3'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.5'
        conn = L2tpConnection(4, 4, conn_address, local_addr)

        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)

        self.assertEqual(pkt.connectionID, 4660)
        self.assertEqual(pkt.avps[0].messageType, ControlMessageAVP.SCCRQ)

        conn.ReceiveControlPackets(pkt, ('127.0.0.2', 1))
        conn.CloseConnection()

    def testHandlePkt_FirstAvpIsNotControlAvp(self):
        """Handle control packet: the first avp is not control avp.

        :return:

        """
        conn_address = '127.11.2.4'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.6'
        conn = L2tpConnection(5, 5, conn_address, local_addr)
        avp1 = Hostname("TestAVP")
        avp2 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp3 = RouterID(0)
        avp4 = AssignedControlConnectionID(1)
        avp5 = PseudowireCapList(())
        avps = [avp1, avp2, avp3, avp4, avp5]
        sccrq = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(sccrq)
        self.assertIsNone(ret)
        conn.CloseConnection()
        self.assertIsNone(ret)

    def testHandlePkt_WithoutAvps(self):
        """Handle control packet: without avps.

        :return:

        """
        conn_address = '127.11.2.5'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.7'
        conn = L2tpConnection(6, 6, conn_address, local_addr)
        avps = list()
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(pkt)
        self.assertIsNone(ret)
        conn.CloseConnection()

    def testHandlePkt_WithAvp_WEN(self):
        """Handle control packet: avp message type is WEN, not in
        self.ctlMsgHandle.

        :return:

        """
        conn_address = '127.11.2.6'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.8'
        conn = L2tpConnection(7, 7, conn_address, local_addr)
        avp1 = ControlMessageAVP(ControlMessageAVP.WEN)
        avps = [avp1]
        wen = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(wen)
        self.assertIsNone(ret)
        conn.CloseConnection()

    def testHandlePkt_SCCRQ(self):
        """Handle control packet: SCCRQ.

        Function: recvSCCRQ.

        :return:

        """
        conn_address = '127.11.2.7'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.9'
        conn = L2tpConnection(8, 8, conn_address, local_addr)

        # Receive a good SCCRQ, return SCCRP
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avp3 = RouterID(0)
        avp4 = AssignedControlConnectionID(1)
        avp5 = PseudowireCapList(())
        avps = [avp1, avp2, avp3, avp4, avp5]
        sccrq = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        sccrp = conn.HandlePkt(sccrq)

        self.assertEqual(sccrp.connectionID, 8)
        self.assertEqual(sccrp.length, 28)
        self.assertEqual(sccrp.avps[0].length, 8)
        self.assertEqual(conn.fsm.current,
                         L2tpv3ConnectionFsm.StateWaitCtlConn)
        # self.assertEqual(sccrp.avps[0].messageType, ControlMessageAVP.SCCRP)

        # Receive a bad SCCRQ, return stopCCN
        session = L2tpv3Session(1, 2, 'receiver', conn)
        conn.addSession(session)

        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)
        avps.append(localAvp)
        sccrp = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        stopCCN = conn.HandlePkt(sccrp)
        self.assertEqual(stopCCN.length, 58)
        self.assertEqual(stopCCN.connectionID, 8)
        self.assertEqual(stopCCN.avps[0].length, 8)
        self.assertEqual(
            stopCCN.avps[0].messageType, ControlMessageAVP.StopCCN)

    def testHandlePkt_SCCRP(self):
        """Handle control packet: SCCRP.

        Function: recvSCCRP.

        :return:

        """
        conn_address = '127.11.2.8'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.10'
        conn = L2tpConnection(9, 9, conn_address, local_addr)

        # Receive a good SCCRP, return SCCCN
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRP)
        avp2 = AssignedControlConnectionID(10)
        avps = [avp1, avp2]
        sccrp = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        scccn = conn.HandlePkt(sccrp)
        self.assertEqual(scccn.avps[0].messageType, ControlMessageAVP.SCCCN)
        self.assertEqual(scccn.connectionID, 10)
        self.assertEqual(scccn.avps[0].length, 8)

        # Receive a bad SCCRP, return stopCCN
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)
        avps.append(localAvp)
        sccrp = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        cdn = conn.HandlePkt(sccrp)
        self.assertEqual(cdn.length, 58)
        self.assertEqual(cdn.connectionID, 10)
        self.assertEqual(cdn.avps[0].length, 8)
        self.assertEqual(cdn.avps[0].messageType, ControlMessageAVP.StopCCN)
        conn.CloseConnection()

    def testHandlePkt_SCCCN(self):
        """Handle control packet: SCCCN.

        Function: recvSCCCN.

        :return:

        """
        conn_address = '127.11.2.9'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.11'
        conn = L2tpConnection(10, 10, conn_address, local_addr)

        # Receive a good SCCCN, return NULL
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCCN)
        avp2 = AssignedControlConnectionID(10)
        avps = [avp1, avp2]
        scccn = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(scccn)
        self.assertIsNotNone(ret)
        self.assertIsInstance(ret, L2tpv3ACK)

        # Receive a bad SCCCN, return stopCCN
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)
        avp3 = CallSerialNumber()
        avps.append(localAvp)
        avps.append(avp3)
        scccn = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(scccn)
        self.assertIsNotNone(ret)
        self.assertIsInstance(ret, L2tpv3ACK)

        # Recovery tunnel receive SCCCN
        recover_conn = L2tpConnection(100, 100, conn_address, local_addr)
        recover_conn.isInRecovery = True
        conn.recoverConnection = recover_conn
        conn.isRecoveryTunnel = True
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCCN)
        avp2 = AssignedControlConnectionID(10)
        avps = [avp1, avp2]
        scccn = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(scccn)
        self.assertFalse(recover_conn.isInRecovery)

        conn.CloseConnection()

    def test_recvICRQ_abnormal(self):
        """Handle control packet: ICRQ, remoteSessid is none.

        :return: none

        """
        conn_address = '127.11.2.10'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.12'
        conn = L2tpConnection(11, 11, conn_address, local_addr)

        avp1 = ControlMessageAVP(ControlMessageAVP.ICRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        icrq = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(icrq)
        conn.CloseConnection()
        self.assertIsNone(ret)

    def test_recvICRQ_normal_1(self):
        """Handle control packet: ICRQ, session exist.

        :return: none

        """
        conn_address = '127.11.2.11'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.13'
        conn = L2tpConnection(12, 12, conn_address, local_addr)
        icrq = L2tpv3ControlPacket.decode(self.ircq_buf)
        icrp = conn.HandlePkt(icrq)
        print icrp

        self.assertEqual(icrp.connectionID, 12)
        ret = conn.checkMustAvps(
            L2tpv3ControlPacket.ICRPMandatoryAVPs, icrp.avps)
        self.assertTrue(ret)
        self.assertEqual(icrp.avps[0].messageType, ControlMessageAVP.ICRP)
        session = conn.findSessionByRemoteSessionID(0x40000001)
        self.assertIsNotNone(session)

        conn.CloseConnection()

    def test_recvICCN(self):
        conn_address = '127.11.2.13'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.15'
        conn = L2tpConnection(14, 14, conn_address, local_addr)
        session = L2tpv3Session(3, 4, 'receive', conn)
        conn.addSession(session)

        # localSessionID = session.remoteSessionId
        remoteSessionID = session.localSessionId
        # localAvp = LocalSessionID(localSessionID)
        remoteAvp = RemoteSessionID(remoteSessionID)

        # Normal case, session is not none
        avp = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp]
        avps.append(remoteAvp)
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(iccn.length, 30)
        self.assertEqual(iccn.avps[0].messageType, 12)
        ret = conn.HandlePkt(iccn)
        self.assertIsNotNone(ret)
        self.assertIsInstance(ret, L2tpv3ACK)

        conn.CloseConnection()

    def test_recvCDN(self):
        conn_address = '127.11.2.14'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.16'
        conn = L2tpConnection(15, 15, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)

        avp = ControlMessageAVP(ControlMessageAVP.CDN)
        avps = [avp]
        avps.append(localAvp)
        cdn = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(cdn.length, 30)
        self.assertEqual(cdn.avps[0].messageType, 14)

        conn.HandlePkt(cdn)
        self.assertEqual(conn.fsm.current, 'idle')
        conn.CloseConnection()

    def test_recvICRP(self):
        conn_address = '127.11.2.15'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.17'
        conn = L2tpConnection(16, 16, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)

        avp = ControlMessageAVP(ControlMessageAVP.ICRP)
        avps = [avp]
        avps.append(localAvp)
        icrp = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(icrp.length, 30)
        self.assertEqual(icrp.avps[0].messageType, 11)

        ret = conn.HandlePkt(icrp)
        self.assertIsNone(ret)
        conn.CloseConnection()

    def test_recvHELLO(self):
        conn_address = '127.11.2.16'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.18'
        conn = L2tpConnection(17, 17, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)

        avp = ControlMessageAVP(ControlMessageAVP.HELLO)
        avps = [avp]
        avps.append(localAvp)
        hello = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(hello.length, 30)
        self.assertEqual(hello.avps[0].messageType, 6)

        zlb = conn.HandlePkt(hello)
        self.assertEqual(zlb.length, 12)
        conn.CloseConnection()

    def test_recvSLI(self):
        conn_address = '127.11.2.17'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.19'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)

        avp1 = ControlMessageAVP(ControlMessageAVP.SLI)
        avp2 = CallSerialNumber()
        avps = [avp1, avp2]
        avps.append(localAvp)
        sli = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(sli.length, 40)
        self.assertEqual(sli.avps[0].messageType, ControlMessageAVP.SLI)

        ret = conn.recvSLI(sli)
        self.assertIsNone(ret)
        # Abnormal SLI message
        avps = list()
        sli = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = conn.HandlePkt(sli)
        self.assertIsNone(ret)
        conn.CloseConnection()

    def test_localRequest(self):
        conn_address = '127.11.2.18'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.20'
        conn = L2tpConnection(19, 19, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)

        conn.localRequest('127.0.0.1')
        self.assertEqual(
            conn.fsm.current, L2tpv3ConnectionFsm.StateWaitCtlReply)
        conn.CloseConnection()

    def test_recvStopCCN(self):
        conn_address = '127.11.2.19'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.21'
        conn = L2tpConnection(20, 20, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        # receive sccrq, new state->wait-ctl-conn
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = AssignedControlConnectionID(10)
        avps = [avp1, avp2]
        sccrq = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        sccrp = conn.HandlePkt(sccrq)
        self.assertEqual(
            conn.fsm.current, L2tpv3ConnectionFsm.StateWaitCtlConn)

        # receive SCCCN, new state->established
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCCN)
        avp2 = AssignedControlConnectionID(10)
        avps = [avp1, avp2]
        scccn = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        ret = conn.HandlePkt(scccn)
        self.assertEqual(
            conn.fsm.current, L2tpv3ConnectionFsm.StateEstablished)

        # receive a stopCCN, new state -> idle
        localSessionID = session.remoteSessionId
        localAvp = LocalSessionID(localSessionID)

        avp = ControlMessageAVP(ControlMessageAVP.StopCCN)
        avps = [avp]
        avps.append(localAvp)
        stopCCN = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(stopCCN.length, 30)
        self.assertEqual(stopCCN.avps[0].messageType, 4)

        ret = conn.HandlePkt(stopCCN)
        self.assertEqual(conn.fsm.current, L2tpv3ConnectionFsm.StateIdle)

    def test__findSession(self):
        """Handle control packet: ICRQ, session not exist.

        :return: none

        """
        conn_address = '127.11.2.20'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.22'
        conn = L2tpConnection(21, 21, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)

        # session1 and session2 are None, return none
        localAvp = LocalSessionID(3)
        remoteAvp = RemoteSessionID(4)
        avp = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp, localAvp, remoteAvp]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        self.assertEqual(iccn.length, 40)
        self.assertEqual(iccn.avps[0].messageType, ControlMessageAVP.ICCN)
        self.assertEqual(iccn.avps[1].sessionID, 3)
        ret = conn._findSession(iccn)
        self.assertIsNone(ret)

        # session1 is not none and session2 is None, return session1
        localAvp = LocalSessionID(2)
        remoteAvp = RemoteSessionID(4)
        avp = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp, localAvp, remoteAvp]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        session1 = conn._findSession(iccn)
        self.assertIsNotNone(session1)
        conn.CloseConnection()

    def test_add_remove_find_Session(self):
        conn_address = '127.11.2.21'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.23'
        conn = L2tpConnection(22, 22, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'sender', conn)
        session1 = None
        conn.addSession(session)
        conn.addSession(session1)
        self.assertEqual(conn.sessions.keys(), [1])
        self.assertEqual(conn.sessionsByRemoteSessionId.keys(), [2])
        self.assertIsNotNone(
            conn.findSessionByLocalSessionID(session.localSessionId))
        self.assertIsNotNone(
            conn.findSessionByRemoteSessionID(session.remoteSessionId))

        conn.removeSession(session)
        self.assertEqual(conn.sessions.keys(), [])
        self.assertEqual(conn.sessionsByRemoteSessionId.keys(), [])
        self.assertIsNone(
            conn.findSessionByLocalSessionID(session.localSessionId))
        self.assertIsNone(
            conn.findSessionByRemoteSessionID(session.remoteSessionId))
        conn.CloseConnection()

    def test_allocate_local_session_id(self):
        conn_address = '127.11.2.25'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.24'
        conn = L2tpConnection(12, 12, conn_address, local_addr)
        pkt = L2tpv3ControlPacket()
        ret = conn._findSession(pkt=pkt)
        self.assertIsNone(ret)
        conn.recvICCN(pkt)
        conn.recvCDN(pkt)
        conn.recvICRP(pkt)
        conn.recvSLI(pkt)
        L2tpv3GlobalSettings.MustAvpsCheck = True
        ret = conn.recvSCCRQ(pkt)
        self.assertIsInstance(ret, L2tpv3StopCCN)
        ret = conn.recvSCCRP(pkt)
        ret = conn.recvSCCCN(pkt)
        ret = conn.recvStopCCN(pkt)

        ret = conn.allocate_local_session_id(pkt=pkt)
        self.assertEqual(ret, 0)
        remoteEndId = RemoteEndID()
        localsession = LocalSessionID(0x112)
        pkt.avps.append(remoteEndId)
        pkt.avps.append(localsession)
        ret = conn.allocate_local_session_id(pkt=pkt)
        self.assertEqual(ret, 0)
        sublayer = DepiL2SpecificSublayerSubtype(17)
        pkt.avps.append(sublayer)
        ret = conn.allocate_local_session_id(pkt=pkt)
        self.assertEqual(ret, 0x1100000)

        icrq = L2tpv3ControlPacket.decode(self.ircq_buf)
        ret = conn.allocate_local_session_id(pkt=icrq)
        self.assertEqual(ret, 0x10030000)
        for avp in icrq.avps:
            if isinstance(avp, RemoteSessionID):
                icrq.avps.remove(avp)
        avp_remote = RemoteSessionID(0x80000001)
        icrq.avps.append(avp_remote)
        ret = conn.allocate_local_session_id(pkt=icrq)
        self.assertEqual(ret, 0x80000001)
        conn.CloseConnection()
        conn.CloseConnection()

    def testStopConnection(self):
        conn_address = '127.11.2.26'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False
        L2tpv3GlobalSettings.l2tp_hal_client = fake_hal()

        local_addr = '127.11.2.27'
        L2tpConnection.ConnectionDb.clear()
        conn = L2tpConnection(3, 3, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)

        conn.ReceiveHalMsg(msg=None)
        msg = L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp()
        msg.result = False
        try:
            conn.ReceiveHalMsg(msg)
        except Exception as e:
            pass
        msg.result = True
        conn.ReceiveHalMsg(msg)
        conn.SendHalMsg(msg_type=L2tpConnection.ADD_LCCE)
        conn.fsmEventrecvBadSCCRP(event=None)
        conn.fsmEventrecvSCCRQLoseTieGood(event=None)
        conn.fsmEventrecvSCCRQLoseTieBad(event=None)
        conn.fsmEventrecvSCCRQWinSCCRQ(event=None)
        conn.fsmEventcloseRequest(event=None)
        conn.fsmEventHalError(event=None)
        conn.StopConnection()
        conn.StopConnection()
        self.assertEqual(len(conn.ConnectionDb), 0)
        L2tpv3GlobalSettings.l2tp_hal_client = None

    def test_recvFSQ(self):
        """Handle control packet: FSQ.

        Function: recvFSQ.

        :return:

        """
        conn_address = '127.11.2.28'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = True

        local_addr = '127.11.2.30'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)

        avp1 = ControlMessageAVP(ControlMessageAVP.FSQ)
        avp2 = FailoverSessionState(session.remoteSessionId, session.localSessionId)
        avp3 = FailoverSessionState(4, 5)
        avps = [avp1, avp2, avp3]
        fsq = L2tpv3ControlPacket(0, 0, 1, avps)

        fsr = conn.HandlePkt(fsq)
        self.assertIsNotNone(fsr)
        self.assertEqual(fsr.avps[1].sessionID, 1)
        self.assertEqual(fsr.avps[1].remoteSessionID, 2)
        self.assertEqual(fsr.avps[2].sessionID, 0)
        self.assertEqual(fsr.avps[2].remoteSessionID, 4)
        conn.CloseConnection()

    def test_recvFSR(self):
        """Handle control packet: FSR.

        Function: recvFSR.

        :return:

        """
        conn_address = '127.11.2.29'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.31'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)

        avp1 = ControlMessageAVP(ControlMessageAVP.FSR)
        avp2 = FailoverSessionState(session.remoteSessionId, session.localSessionId)
        avps = [avp1, avp2]
        fsr = L2tpv3ControlPacket(0, 0, 1, avps)

        ret = conn.HandlePkt(fsr)
        self.assertIsNone(ret)
        conn.CloseConnection()

    def test_queryInactSessions(self):
        conn_address = '127.11.2.30'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.32'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        session.local_circuit_status = L2tpv3Session.CIRCUIT_STATUS_DOWN
        conn.addSession(session)
        conn.queryInactSessions()
        conn.CloseConnection()

    def test_queryStaleSessions(self):
        conn_address = '127.11.2.31'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.33'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        session.stale = True
        conn.addSession(session)
        conn.queryStaleSessions()
        conn.CloseConnection()

    def test_closeUnEstSessions(self):
        conn_address = '127.11.2.32'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.34'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        session = L2tpv3Session(1, 2, 'receive', conn)
        conn.addSession(session)
        session.fsm.recvGoodICRQ()
        conn.closeUnEstSessions()
        self.assertFalse(conn.sessions)

        session = L2tpv3Session(3, 4, 'receive', conn)
        conn.addSession(session)
        session.fsm.recvGoodICRQ()
        session.fsm.recvGoodICCN()
        conn.closeUnEstSessions()
        self.assertTrue(conn.sessions)
        self.assertEqual(session.fsm.current, L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateEstablished)
        conn.CloseConnection()

    def test_resetTransport(self):
        conn_address = '127.11.2.33'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.35'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        avp = ControlMessageAVP(ControlMessageAVP.HELLO)
        avps = [avp]
        hello = L2tpv3ControlPacket(0, 0, 1, avps)
        conn.transport.sendList.append({
            "time": 1,
            "pkt": hello,
            "sendTimes": 0,
        })
        conn.transport.receiveWindow.add(hello)
        conn.transport.ackNr = 105
        conn.transport.ns = 56
        conn.resetTransport()
        self.assertFalse(conn.transport.sendList)
        self.assertFalse(conn.transport.receiveWindow)
        self.assertEqual(conn.transport.ackNr, 0)
        self.assertEqual(conn.transport.ackNr, 0)
        conn.CloseConnection()

    def test_recovery_process_failure(self):
        conn_address = '127.11.2.34'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, True, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False

        local_addr = '127.11.2.36'
        conn = L2tpConnection(18, 18, conn_address, local_addr)
        reocverconn = L2tpConnection(2, 1, conn_address, local_addr)
        conn.isRecoveryTunnel = True
        conn.recoverConnection = reocverconn
        conn.isInRecovery = True

        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = AssignedControlConnectionID(10)
        avps = [avp1, avp2]
        sccrq = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        conn.HandlePkt(sccrq)
        self.assertEqual(conn.fsm.current,
                         L2tpv3ConnectionFsm.StateWaitCtlConn)
        conn.StopConnection()
        self.assertNotIn(reocverconn, L2tpConnection.ConnectionDb.values())


if __name__ == "__main__":
    unittest.main()
