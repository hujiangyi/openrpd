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
import struct
from rpd.dispatcher.dispatcher import Dispatcher

from l2tpv3.src.L2tpv3Connection import L2tpConnection
from l2tpv3.src.L2tpv3ControlPacket import L2tpv3ControlPacket, L2tpv3ZLB, l2tpV3TerminatePkt, \
    L2tpv3Hello, L2tpv3StopCCN, L2tpv3CDN, _packetEncoder
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3RFC3931AVPs import AssignedControlConnectionID
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP, Hostname, TunnelRecovery, FailoverSessionState
from l2tpv3.src.L2tpv3Session import L2tpv3Session
from l2tpv3.src.L2tpv3Transport import L2tpv3Transport


class testL2tpv3ControlPacket(unittest.TestCase):

    def testCreateControlPacket(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)

        print pkt

    def testGenerateBuffer(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.ZLB)
        avp2 = Hostname("TestAVP")
        avps = []
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)

        print pkt

    def testCreatePacketFromBuf(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)

        buf = pkt.encode()

        pkt1 = L2tpv3ControlPacket.decode(buf)
        print pkt1

    def test_decode(self):
        buf = struct.pack('!118B',
                          0xc8, 0x03, 0x00, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x12, 0x00, 0x00, 0x00, 0x07,
                          0x52, 0x70, 0x68, 0x79, 0x4e, 0x6f, 0x64, 0x65, 0x2d, 0x46, 0x30, 0x38, 0x00, 0x0a, 0x00, 0x00,
                          0x00, 0x3c, 0x5d, 0x0e, 0x01, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x3d, 0xdd, 0x86, 0x69, 0x5e,
                          0x00, 0x0a, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x0c, 0x00, 0x0d, 0x80, 0x32, 0x11, 0x8b, 0x00, 0x0f,
                          0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
                          0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0f, 0x00, 0x10,
                          0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x00, 0x14, 0x00, 0x15, 0x00, 0x16)
        try:
            pkt1 = L2tpv3ControlPacket.decode(buf)
        except Exception as e:
            self.assertRegexpMatches(str(e), "Cannot decode the buffer avp length must larger than 6, got*")


class test_L2tpv3PacketError(unittest.TestCase):

    def test_L2tpv3PacketError(self):
        pass


class test__packetEncoder(unittest.TestCase):
    pkt = _packetEncoder()

    def test___init__(self):
        self.pkt.__init__()


class test_L2tpv3ControlPacket(unittest.TestCase):

    def testL2tpv3ControlPacket_init_list(self):
        """Normal case for initial L2ptv3ControlPacket, avpValueStr is not
        None, avps is List.

        :return: None

        """
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(
            0x1234, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertIsNone(pkt.Session)
        self.assertEqual(pkt.connectionID, 4660)
        self.assertEqual(pkt.nr, 1)
        self.assertEqual(pkt.ns, 0)
        self.assertEqual(pkt.isZlb, False)
        self.assertIsNone(pkt.Connection)
        self.assertIsNone(pkt.transport)
        self.assertEqual(pkt.avpStr, 'testL2tpv3ControlPacket')

    def testL2tpv3ControlPacket_init_tuple(self):
        """Normal case for initial L2ptv3ControlPacket, avpValueStr is None,
        avps is Tuple.

        :return: None

        """
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = (avp1, avp2)
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)

        self.assertEqual(pkt.connectionID, 4660)
        self.assertEqual(pkt.nr, 1)
        self.assertEqual(pkt.ns, 0)
        self.assertEqual(pkt.isZlb, False)
        self.assertIsNone(pkt.Session)
        self.assertIsNone(pkt.Connection)
        self.assertIsNone(pkt.transport)

    def testL2tpv3ControlPacket_init_abnormal(self):
        """Abnormal case for initial L2ptv3ControlPacket, avpValueStr is not
        None, avps is neither List nor Tuple.

        :return: None

        """
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = {avp1, avp2}
        try:
            pkt = L2tpv3ControlPacket(
                0x1234, 0, 1, avps, "testL2tpv3ControlPacket")
        except Exception as e:
            print e

    def test___str__(self):
        self.__str__()

    def test_encode(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(
            0x1234, 0, 1, avps, "testL2tpv3ControlPacket")
        pkt.encode(False)
        pkt.encode(True)

    def test_decode(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        buf = pkt.encode()
        pkt1 = L2tpv3ControlPacket.decode(buf)
        self.assertEqual(pkt1.avps[0].attrType, 0)
        self.assertEqual(pkt1.avps[0].messageType, ControlMessageAVP.SCCRQ)
        self.assertEqual(pkt1.avps[1].attrType, 7)
        self.assertEqual(pkt1.avps[1].avpName, 'Hostname')

        # pkt's avp lenght is zero
        avps = list()
        pkt = L2tpv3ControlPacket(0x1234, 0, 1, avps)
        buf = pkt.encode()
        zlb = L2tpv3ControlPacket.decode(buf)
        self.assertTrue(zlb.isZlb)

    def test_SetPktConnection(self):
        conn_address = '127.13.1.3'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.LocalIPAddress = '127.13.2.3'

        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(
            0x1234, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertIsNone(pkt.Connection)
        conn = L2tpConnection(6, 6, conn_address)
        pkt.SetPktConnection(conn)
        self.assertIsNotNone(pkt.Connection)
        conn.CloseConnection()

    def test_SetPktSession(self):
        conn_address = '127.13.1.4'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.LocalIPAddress = '127.13.2.4'
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(
            0x1234, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertIsNone(pkt.Session)
        conn = L2tpConnection(2, 2, conn_address)
        session = L2tpv3Session(1, 2, 'receiver', conn)
        pkt.SetPktSession(session)
        self.assertIsNotNone(pkt.Session)
        conn.CloseConnection()

    def test_SetPacketTransport(self):
        conn_address = '127.13.3.3'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.LocalIPAddress = '127.13.3.4'
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(
            0x1234, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertIsNone(pkt.transport)
        conn = L2tpConnection(3, 3, conn_address)
        transport = L2tpv3Transport(conn, '127.0.1.1', '127.0.1.2')
        pkt.SetPacketTransport(transport)
        self.assertIsNotNone(pkt.transport)
        conn.CloseConnection()

    def test_GetLocalConnectionID(self):
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        LocalConnectionID = pkt.GetLocalConnectionID()
        self.assertEqual(LocalConnectionID, 1)

    def test_GetRemoteConnectionID(self):

        # Abnormal case: can't get RemoteConnectionID from Avps
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        RemoteConnectionID = pkt.GetRemoteConnectionID()
        self.assertIsNone(RemoteConnectionID[0])
        self.assertFalse(RemoteConnectionID[1])

        # Normal case: get RemoteConnectionID from Avps
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = AssignedControlConnectionID(1)
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        RemoteConnectionID = pkt.GetRemoteConnectionID()
        self.assertEqual(RemoteConnectionID[0], 1)
        self.assertTrue(RemoteConnectionID[1])

    def test_isRecoveryTunnelSCCRQ(self):
        # Normal SCCRQ
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertEqual(pkt.isRecoveryTunnelSCCRQ(), (False, 0, 0))

        # RecoveryTunnelSCCRQ
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avp3 = TunnelRecovery(1, 2)
        avps = [avp1, avp2, avp3]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertTrue(pkt.isRecoveryTunnelSCCRQ())

    def test_isFSR(self):
        # SCCRQ
        avp1 = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        avp2 = Hostname("TestAVP")
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertFalse(pkt.isFSR())

        # FSR
        avp1 = ControlMessageAVP(ControlMessageAVP.FSR)
        avp2 = FailoverSessionState(1, 2)
        avps = [avp1, avp2]
        pkt = L2tpv3ControlPacket(1, 0, 1, avps, "testL2tpv3ControlPacket")
        self.assertTrue(pkt.isFSR())


class testL2tpv3ZLB(unittest.TestCase):

    def testL2tpv3ZLB(self):
        pkt = L2tpv3ZLB(1, 1, 1)
        self.assertTrue(pkt.isZlb)
        self.assertEqual(pkt.length, 12)
        self.assertIsNotNone(pkt.avpStr)
        self.assertIsNone(pkt.Session)
        self.assertIsNone(pkt.Connection)
        self.assertIsNone(pkt.transport)


class testl2tpV3TerminatePkt(unittest.TestCase):

    def testl2tpV3TerminatePkt(self):
        pkt = l2tpV3TerminatePkt(ControlMessageAVP.StopCCN, 1, 0, 0, "CCN")
        self.assertEqual(pkt.avps[0].messageType, ControlMessageAVP.StopCCN)
        self.assertIsNotNone(pkt.avpStr)
        self.assertIsNone(pkt.Session)
        self.assertIsNone(pkt.Connection)
        self.assertIsNone(pkt.transport)


class testL2tpv3StopCCN(unittest.TestCase):

    def testL2tpv3StopCCN(self):
        conn_address = '127.13.3.5'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.LocalIPAddress = '127.13.3.5'
        conn = L2tpConnection(4, 4, conn_address)
        pkt = L2tpv3StopCCN(conn, 0, 0, "CCN")
        self.assertEqual(pkt.avps[0].messageType, ControlMessageAVP.StopCCN)
        self.assertIsNotNone(pkt.avpStr)
        self.assertIsNone(pkt.Session)
        self.assertIsNone(pkt.Connection)
        self.assertIsNone(pkt.transport)
        conn.CloseConnection()


class testL2tpv3CDN(unittest.TestCase):

    def testL2tpv3CDN(self):
        conn_address = '127.13.3.6'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        L2tpv3GlobalSettings.LocalIPAddress = '127.13.3.6'
        conn = L2tpConnection(5, 5, conn_address)

        session = L2tpv3Session(1, 2, 'receiver', conn)
        cdn = L2tpv3CDN(session, 2, 4, "Avp cannot be handled correctly")
        self.assertEqual(cdn.avps[0].messageType, ControlMessageAVP.CDN)
        self.assertEqual(cdn.avps[1].messageType, ControlMessageAVP.StopCCN)
        self.assertEqual(cdn.avps[2].attrType, 63)
        self.assertEqual(cdn.avps[3].attrType, 64)


class testL2tpv3Hello(unittest.TestCase):

    def testL2tpv3Hello(self):
        pkt = L2tpv3Hello(1)
        self.assertEqual(pkt.avps[0].messageType, ControlMessageAVP.HELLO)
        self.assertIsNotNone(pkt.avpStr)
        self.assertIsNone(pkt.Session)
        self.assertIsNone(pkt.Connection)
        self.assertIsNone(pkt.transport)


if __name__ == "__main__":
    unittest.main()
