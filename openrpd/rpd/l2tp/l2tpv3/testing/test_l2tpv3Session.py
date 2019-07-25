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
import time

from rpd.dispatcher.dispatcher import Dispatcher
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
from l2tpv3.src.L2tpv3Connection import L2tpConnection
from l2tpv3.src.L2tpv3ControlPacket import L2tpv3ControlPacket, L2tpv3CDN, L2tpv3ACK
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
from l2tpv3.src.L2tpv3Fsm import L2tpv3SessionSenderFsm, L2tpv3SessionRecipientFsm
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3RFC3931AVPs import CallSerialNumber
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP
from l2tpv3.src.L2tpv3RFC3931AVPs import LocalSessionID
from l2tpv3.src.L2tpv3RFC3931AVPs import RemoteSessionID
from l2tpv3.src.L2tpv3Session import L2tpv3Session
import struct
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, GeneralL2tpv3AVP
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.mcast.src.mcast import Mcast
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis


class fake_avp(GeneralL2tpv3AVP):

    def handleAvp(self, pkt, retPak):
        return False


class fake_halclient():

    def __init__(self):
        self.called = 0

    def send_l2tp_session_req_msg(self, session, msg_type):
        self.called += 1
        return


class testL2tpv3Session(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        conn_address = '127.0.0.1'

        for key in Mcast.McastDb.keys():
            Mcast.McastDb.pop(key)

        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.MustAvpsCheck = False
        L2tpv3GlobalSettings.LocalIPAddress = '127.0.0.2'
        cls.conn = L2tpConnection(
            1, 1, conn_address, localAddr=L2tpv3GlobalSettings.LocalIPAddress)

        cls.icrq_buf = struct.pack('!206B',
                                   0xc8, 0x03, 0x0, 206,
                                   0x0, 0x0, 0x0, 0x0,
                                   0x0, 0x3, 0x0, 0x4,
                                   0xc, 8, 0x0, 0x0,
                                   0x0, 0x0, 0x0, 10,
                                   0xc, 10, 0x0, 0x0,
                                   0, 15, 0, 0,
                                   0, 0,
                                   0xc, 10, 0x0, 0x0,
                                   0, 63, 0x40, 0x01,
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
                                   0xc, 20, 0x11, 0x8b,
                                   0x0, 15, 0x0, 0x1,
                                   0x0, 0x2, 0x0, 0x3,
                                   0x0, 0x6, 0x0, 0x8,
                                   0x0, 11, 0x0, 13,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 16, 0x0, 0x3,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 17, 0x0, 0x3,
                                   0xc, 40, 0x11, 0x8b,
                                   0x0, 11, 0, 0,
                                   0x5, 0x6, 0x7, 0x8,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   229, 1, 1, 255,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   )
        setup_test_redis()

    @classmethod
    def tearDownClass(cls):
        cls.conn.CloseConnection()
        for key in Mcast.McastDb.keys():
            Mcast.McastDb.pop(key)
        stop_test_redis()

    def testL2tpv3Session_init(self):
        session1 = L2tpv3Session(1, 2, 'sender', self.conn)
        self.assertEqual(session1.localSessionId, 1)
        self.assertEqual(session1.remoteSessionId, 2)

        session2 = L2tpv3Session(1, 2, 'receive', self.conn)
        self.assertEqual(session2.remoteSessionId, 2)

    def test_CloseSession(self):
        session_sender = L2tpv3Session(1, 2, 'sender', self.conn)
        session_sender.CloseSession()
        self.assertEqual(
            session_sender.fsm.current, L2tpv3SessionSenderFsm.StateIdle)

        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        session_receiver.CloseSession()
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)

    def test_ReceiveCDN(self):
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)

        # receive icrq, send icrp, state becomes to waitCtlConn
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        icrq.SetPktConnection(self.conn)
        icrq.SetPktSession(session_receiver)
        icrq.Connection.remoteConnID = 1
        icrp = session_receiver.ReceiveICRQ(icrq)
        print icrp
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateWaitConn)

        # receive iccn, , state becomes to established
        avp1 = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp1]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = session_receiver.ReceiveICCN(iccn)
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateEstablished)

        # receive cdn message, clean up, state becomes to idle
        avp = ControlMessageAVP(ControlMessageAVP.CDN)
        avp_Mcast_leave = L2tpv3CableLabsAvps.DepiRemoteMulticastLeave(
            ("5.6.7.8", "229.1.1.255"))
        avps = [avp, avp_Mcast_leave]
        cdn = L2tpv3ControlPacket(0, 0, 1, avps)
        session_receiver.ReceiveCDN(cdn)
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)

    def test_ReceiveICCN(self):

        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)

        # Abnormal case: receive a bad ICCN, return CDN
        avp1 = ControlMessageAVP(ControlMessageAVP.ICCN)
        avp2 = CallSerialNumber()
        avps = [avp1]
        avps.append(avp2)
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = session_receiver.ReceiveICCN(iccn)
        self.assertIsNotNone(ret)
        self.assertIsInstance(ret, L2tpv3ACK)

        # Normal case: receive a good ICCN, return None
        avp1 = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp1]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = session_receiver.ReceiveICCN(iccn)
        self.assertIsNotNone(ret)
        self.assertIsInstance(ret, L2tpv3ACK)

        # Normal case: receive a good ICCN, return None
        avp1 = ControlMessageAVP(ControlMessageAVP.ICCN)
        avp2 = fake_avp()
        avps = [avp1, avp2]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = session_receiver.ReceiveICCN(iccn)
        self.assertIsInstance(ret, L2tpv3CDN)

        L2tpv3GlobalSettings.MustAvpsCheck = True
        avp1 = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp1]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = session_receiver.ReceiveICCN(iccn)
        L2tpv3GlobalSettings.MustAvpsCheck = False
        self.assertIsInstance(ret, L2tpv3CDN)

    def test_LocalRequest(self):
        # fsm is L2tpv3SessionRecipientFsm
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        session_receiver.LocalRequest()
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)

        # fsm is L2tpv3SessionSenderFsm
        session_sender = L2tpv3Session(1, 2, 'sender', self.conn)
        session_sender.LocalRequest()
        self.assertEqual(
            session_sender.fsm.current, L2tpv3SessionSenderFsm.StateWaitReply)

    def test_ReceiveICRP(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.ICRP)
        avp2 = LocalSessionID(1)
        avps = [avp1, avp2]
        icrp = L2tpv3ControlPacket(0, 0, 1, avps)

        # fsm is L2tpv3SessionRecipientFsm
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        session_receiver.ReceiveICRP(icrp)
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)

        # fsm is L2tpv3SessionSenderFsm, receive a bad icrp, return cdn
        session_sender = L2tpv3Session(1, 2, 'sender', self.conn)
        cdn = session_sender.ReceiveICRP(icrp)
        self.assertEqual(cdn.avps[0].messageType, ControlMessageAVP.CDN)

        # fsm is L2tpv3SessionSenderFsm, receive a good icrp, return iccn
        icrp.SetPktSession(session_sender)
        iccn = session_sender.ReceiveICRP(icrp)
        self.assertEqual(iccn.avps[0].messageType, ControlMessageAVP.ICCN)

        L2tpv3GlobalSettings.MustAvpsCheck = True
        ret = session_sender.ReceiveICRP(icrp)
        L2tpv3GlobalSettings.MustAvpsCheck = False
        self.assertIsInstance(ret, L2tpv3CDN)

        session_sender = L2tpv3Session(1, 0, 'sender', self.conn)
        icrp.SetPktSession(session_sender)
        icrp.avps.remove(avp2)
        iccn = session_sender.ReceiveICRP(icrp)
        self.assertIsInstance(ret, L2tpv3CDN)

    def test_ReceiveICRQ(self):
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        icrq.avps.pop(4)
        icrq.SetPktConnection(self.conn)
        session_receiver = L2tpv3Session(0, 1, 'receiver', self.conn)
        icrq.Connection.remoteConnID = 1

        # ICRQ session is None, receive a bad ICRQ, send a CDN
        cdn = session_receiver.ReceiveICRQ(icrq)
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)
        self.assertEqual(cdn.avps[0].messageType, ControlMessageAVP.CDN)
        self.assertEqual(cdn.avps[1].messageType, ControlMessageAVP.StopCCN)

        # Receive a good ICRQ, send a ICRP
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        print icrq
        icrq.SetPktConnection(self.conn)
        icrq.SetPktSession(session_receiver)
        icrp = session_receiver.ReceiveICRQ(icrq)
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateWaitConn)
        self.assertEqual(icrp.avps[0].messageType, ControlMessageAVP.ICRP)

        L2tpv3GlobalSettings.MustAvpsCheck = True
        ret = session_receiver.ReceiveICRQ(icrp)
        self.assertIsInstance(ret, L2tpv3CDN)
        ret = session_receiver.ReceiveICRQ(icrq)
        L2tpv3GlobalSettings.MustAvpsCheck = False
        self.assertEqual(ret.avps[0].messageType, ControlMessageAVP.ICRP)

    def test_ReceiveSLI(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.SLI)
        avp2 = LocalSessionID(1)
        avp3 = CallSerialNumber(12)

        # Can't handle AVP in SLI , return CDN
        avps = [avp1, avp2, avp3]
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        sli = L2tpv3ControlPacket(0, 0, 1, avps)
        sli.SetPktConnection(self.conn)
        sli.Connection.remoteConnID = 1
        ret = session_receiver.ReceiveSLI(sli)
        self.assertIsNone(ret)

        # AVP length is 1, return None
        avps_none = [avp1]
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        sli = L2tpv3ControlPacket(0, 0, 1, avps_none)
        sli.SetPktConnection(self.conn)
        sli.Connection.remoteConnID = 1
        ret = session_receiver.ReceiveSLI(sli)
        self.assertIsNone(ret)
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateIdle)

        L2tpv3GlobalSettings.MustAvpsCheck = True
        ret = session_receiver.ReceiveSLI(sli)
        sli.avps.append(avp2)
        avp_fake = fake_avp()
        sli.avps.append(avp_fake)
        ret = session_receiver.ReceiveSLI(sli)
        L2tpv3GlobalSettings.MustAvpsCheck = False
        self.assertIsInstance(ret, L2tpv3CDN)
        ret = session_receiver.ReceiveSLI(sli)
        self.assertIsInstance(ret, L2tpv3CDN)

    def test_fsmStateRecipientIdle_1(self):
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        session_receiver.fsm.recvGoodICRQ()
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateWaitConn)
        # receive CDN
        session_receiver.fsm.recvCDN()
        # self.assertIsNone(session_receiver.connection)
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateIdle)
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        session_receiver.fsm.recvGoodICRQ()
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateWaitConn)
        # receive closeRequest
        session_receiver.fsm.closeRequest()
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateIdle)

        # receive other event to idle
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)
        session_receiver.fsm.recvGoodICRQ()
        session_receiver.fsm.recvBadICCN()
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateIdle)

    def test_ICRQ_1(self):
        """ICRQ request:"""
        session_receiver = L2tpv3Session(0, 0x40001111, 'receiver', self.conn)
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        print icrq
        icrq.SetPktConnection(self.conn)
        icrq.SetPktSession(session_receiver)
        icrp = session_receiver.ReceiveICRQ(icrq)
        print icrp
        ret = self.conn.checkMustAvps(
            L2tpv3ControlPacket.ICRPMandatoryAVPs, icrp.avps)
        self.assertTrue(ret)

    def test_mcast_leave(self):
        """ICRQ request:"""
        session_receiver = L2tpv3Session(0, 0x40001111, 'receiver', self.conn)
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        print icrq
        icrq.SetPktConnection(self.conn)
        icrq.SetPktSession(session_receiver)
        icrp = session_receiver.ReceiveICRQ(icrq)
        print icrp
        session_receiver.fsmStateRecipientEnterStateEstablished(session_receiver.fsm.EventRecvGoodICCN)
        time.sleep(1)

        session_receiver_1 = L2tpv3Session(0, 0x40001112, 'receiver', self.conn)
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        avp_Mcast = L2tpv3CableLabsAvps.DepiRemoteMulticastJoin(
            ("5.6.7.8", "1.1.1.255"))
        icrq.avps.append(avp_Mcast)
        icrq.SetPktConnection(self.conn)
        icrq.SetPktSession(session_receiver)
        icrp = session_receiver.ReceiveICRQ(icrq)

        session_receiver.fsmStateRecipientEnterStateEstablished(session_receiver.fsm.EventRecvGoodICCN)
        time.sleep(1)

        session_receiver.fsmStateRecipientLeaveStateEstablished(session_receiver.fsm.EventRecvCDN)
        session_receiver.fsm.recvCDN()
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateIdle)

    def test_ReceiveHalMsg(self):
        session_receiver = L2tpv3Session(0x1098, 0x40001111, 'receiver', self.conn)
        sessionRsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        # fill session_selector
        sessionRsp.session_selector.local_session_id = session_receiver.localSessionId
        sessionRsp.session_selector.remote_session_id = session_receiver.remoteSessionId
        sessionRsp.session_selector.local_ip = self.conn.localAddr
        sessionRsp.session_selector.remote_ip = self.conn.remoteAddr
        sessionRsp.req_data.circuit_status = True
        sessionRsp.result = True
        session_receiver.ReceiveHalMsg(sessionRsp)
        self.assertEqual(session_receiver.local_circuit_status, session_receiver.CIRCUIT_STATUS_UP)
        sessionRsp.req_data.circuit_status = False
        sessionRsp.result = True
        session_receiver.ReceiveHalMsg(sessionRsp)
        self.assertEqual(session_receiver.local_circuit_status, session_receiver.CIRCUIT_STATUS_DOWN)

    def test_fsm(self):
        session_receiver = L2tpv3Session(0x1098, 0x40001111, 'receiver', self.conn)
        session_receiver.fsmEventSenderRecvICRQLoseTie(None)
        session_receiver.fsmEventSenderRecvICRQWinTie(None)
        session_receiver.fsmEventSenderRecvICCN(None)
        session_receiver.fsmEventSenderRecvCDN(None)
        pass

    def test_SendHalMsg(self):
        halclient = fake_halclient()
        L2tpv3GlobalSettings.l2tp_hal_client = halclient
        session_receiver = L2tpv3Session(0x1098, 0x40001111, 'receiver', self.conn)
        session_receiver.SendHalMsg(L2tpv3Session.ADD_SESSION)
        L2tpv3GlobalSettings.l2tp_hal_client = None
        self.assertEqual(halclient.called, 1)

    def test_sendSLI(self):
        session_receiver = L2tpv3Session(1, 2, 'receiver', self.conn)

        # receive icrq, send icrp, state becomes to waitCtlConn
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        icrq.SetPktConnection(self.conn)
        icrq.SetPktSession(session_receiver)
        icrq.Connection.remoteConnID = 1
        icrp = session_receiver.ReceiveICRQ(icrq)
        self.assertEqual(
            session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateWaitConn)

        # receive iccn, , state becomes to established
        avp1 = ControlMessageAVP(ControlMessageAVP.ICCN)
        avps = [avp1]
        iccn = L2tpv3ControlPacket(0, 0, 1, avps)
        ret = session_receiver.ReceiveICCN(iccn)
        self.assertEqual(session_receiver.fsm.current,
                         L2tpv3SessionRecipientFsm.StateEstablished)

        # start test
        msg = L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus()
        msg.status = False
        session_receiver.local_circuit_status = True
        session_receiver.ReceiveHalMsg(msg=msg)

        self.assertFalse(session_receiver.local_circuit_status)
        session_receiver.local_circuit_status = False
        session_receiver.ReceiveHalMsg(msg=msg)
        self.assertFalse(session_receiver.local_circuit_status)

        msg.status = True
        session_receiver.local_circuit_status = True
        session_receiver.ReceiveHalMsg(msg=msg)
        self.assertTrue(session_receiver.local_circuit_status)

        session_receiver.local_circuit_status = False
        session_receiver.ReceiveHalMsg(msg=msg)
        self.assertTrue(session_receiver.local_circuit_status)

        msg = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        session_receiver.local_circuit_status = False
        msg.result = False
        session_receiver.ReceiveHalMsg(msg=msg)
        self.assertFalse(session_receiver.local_circuit_status)

        msg.result = True
        msg.req_data.circuit_status = True
        session_receiver.ReceiveHalMsg(msg=msg)
        self.assertTrue(session_receiver.local_circuit_status)


if __name__ == "__main__":
    unittest.main()
