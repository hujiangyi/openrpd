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
import unittest
from l2tpv3.src.L2tpv3Transport import L2tpv3TransportError
from l2tpv3.src.L2tpv3Transport import TransportEncoder, L2tpv3Network
import l2tpv3.src.L2tpv3Connection as L2tpv3Connection
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3ControlPacket import L2tpv3ControlPacket
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP, Hostname, AssignedControlConnectionID
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging


class Test\
            (unittest.TestCase):
    # open the logger
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        cls.logger.info("start setup...")
        cls.logger.info("************************************************")
        cls.logger.info("***                setUpClass:               ***")
        cls.logger.info("************************************************")
        # open logger
        setup_logging("L2TP")
        # use the localhost as the default IP address
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress,
            create_global_listen=False)
        cls.dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher

        # create the connection
        cls.connection = L2tpv3Connection.L2tpConnection(
            666, 666, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)

        # instance the transport
        cls.transport = cls.connection.transport

    def testReceivePacket(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***           ReceivePacket:normal           ***")
        self.logger.info("************************************************")
        # receive a SCCRQ form remote
        msgAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        assignedAvp = AssignedControlConnectionID(self.connection.localConnID)
        sccrq = L2tpv3ControlPacket(6, avps=(msgAvp, assignedAvp))

        # before receive packet, the nr is not change
        lastNr = self.transport.ackNr
        # before receive packet, the receiveWindow is not change
        lastReceiveWindow = len(self.transport.receiveWindow)

        self.transport.ReceivePacket(
            sccrq, (self.connection.remoteAddr, self.connection.localConnID))
        print self.transport
        # after receive packet, the nr should be +1
        self.assertEqual(self.transport.ackNr, lastNr + 1)
        # after receive packet, the receiveWindow should be same
        self.assertEqual(len(self.transport.receiveWindow), lastReceiveWindow)

    def testReceiveNonePacket(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***            ReceivePacket:none            ***")
        self.logger.info("************************************************")
        # create None L2tpv3ControlPacket type
        try:
            self.transport.ReceivePacket(
                None, (self.connection.remoteAddr, self.connection.localConnID))
        except Exception as e:
            self.assertRegexpMatches(
                str(e), L2tpv3TransportError.ParameterTypeError)

    def testReceiveUnnormalPacket(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***          ReceivePacket:unnormal          ***")
        self.logger.info("************************************************")
        # struct unnormal ns/nr
        msgAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        assignedAvp = AssignedControlConnectionID(self.connection.localConnID)
        sccrq = L2tpv3ControlPacket(
            666, 100000, 100000, avps=(msgAvp, assignedAvp))
        # before ReceivePacket, the nr is not change
        lastNr = self.transport.ackNr
        self.transport.ReceivePacket(
            sccrq, (self.connection.remoteAddr, self.connection.localConnID))
        # after Receive the unnormal packets, the nr did't change
        self.assertEqual(self.transport.ackNr, lastNr)

        # struct duplicated packet
        zlb = ControlMessageAVP(ControlMessageAVP.ZLB)
        hostName = Hostname("TestAVP")
        avps = []
        pkt1 = L2tpv3ControlPacket(self.connection.remoteConnID, 0, 0, avps)
        pkt2 = L2tpv3ControlPacket(self.connection.remoteConnID, 0, 0, avps)
        pkts = [pkt1, pkt2]

        # before ReceivePacket, the nr is not change
        lastNr = self.transport.ackNr
        for pkt in pkts:
            self.transport.ReceivePacket(pkt, None)
        # after Receive the unnormal packets, the nr did't change
        self.assertEqual(self.transport.ackNr, lastNr)

    def testReceiveUnseqPacket(self):
        avps = []
        pkt1 = L2tpv3ControlPacket(self.connection.remoteConnID, 0, 0, avps)
        self.transport.ReceivePacket(pkt1, None)
        pkt2 = L2tpv3ControlPacket(self.connection.remoteConnID, 1, 1, avps)
        self.transport.ReceivePacket(pkt2, None)
        pkt3 = L2tpv3ControlPacket(self.connection.remoteConnID, 2, 1, avps)
        self.transport.ReceivePacket(pkt3, None)
        pkt4 = L2tpv3ControlPacket(self.connection.remoteConnID, 3, 1, avps)
        self.transport.ReceivePacket(pkt4, None)
        pkt5 = L2tpv3ControlPacket(self.connection.remoteConnID, 4, 1, avps)
        self.transport.ReceivePacket(pkt5, None)
        pkt6 = L2tpv3ControlPacket(self.connection.remoteConnID, 5, 1, avps)
        self.transport.ReceivePacket(pkt6, None)
        pkt7 = L2tpv3ControlPacket(self.connection.remoteConnID, 6, 1, avps)
        self.transport.ReceivePacket(pkt7, None)
        pkt8 = L2tpv3ControlPacket(self.connection.remoteConnID, 7, 2, avps)
        self.transport.ReceivePacket(pkt8, None)
        pkt9 = L2tpv3ControlPacket(self.connection.remoteConnID, 9, 4, avps)
        self.transport.ReceivePacket(pkt9, None)
        pkt9a = L2tpv3ControlPacket(self.connection.remoteConnID, 9, 4, avps)
        self.assertEqual(len(self.transport.receiveWindow), 1)
        self.transport.ReceivePacket(pkt9a, None)
        self.assertEqual(len(self.transport.receiveWindow), 1)
        pkt10 = L2tpv3ControlPacket(self.connection.remoteConnID, 10, 5, avps)
        self.transport.ReceivePacket(pkt10, None)
        self.assertEqual(len(self.transport.receiveWindow), 2)
        pkt10a = L2tpv3ControlPacket(self.connection.remoteConnID, 10, 6, avps)
        self.transport.ReceivePacket(pkt10a, None)
        self.assertEqual(len(self.transport.receiveWindow), 2)
        pkt11 = L2tpv3ControlPacket(self.connection.remoteConnID, 11, 6, avps)
        self.transport.ReceivePacket(pkt11, None)
        self.assertEqual(len(self.transport.receiveWindow), 3)
        pkt12 = L2tpv3ControlPacket(self.connection.remoteConnID, 8, 7, avps)
        self.transport.ReceivePacket(pkt12, None)
        self.assertEqual(len(self.transport.receiveWindow), 0)

    def testReceiveZLBPacket(self):
        orig_receiveWindow = self.transport.receiveWindow
        orig_receiveWindowSize = self.transport.receiveWindowSize
        avps = []
        pkt = L2tpv3ControlPacket(self.connection.remoteConnID, 1,2,avps=avps)
        pkt.isZlb = True
        self.transport.ReceivePacket(pkt, None)
        pass
        pkt.isZlb = False
        pkt.ns = 3
        self.transport.receiveWindow.append(pkt)
        self.transport.receiveWindowSize = 1
        self.transport.ReceivePacket(pkt, None)

        self.transport.receiveWindow = orig_receiveWindow
        self.transport.receiveWindowSize = orig_receiveWindowSize
        pass


    def testRegisterTransport(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***            RegisterTransport:            ***")
        self.logger.info("************************************************")
        self.transport.RegisterTransport()
        self.assertEqual(self.dispatcher.socketMapping[
                         self.transport.network.fileno()], self.transport.network)
        self.assertEqual(
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress, self.transport.remoteAddr)
        self.assertIsNotNone(self.connection.localConnID)

    def testSendPacket(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***             SendPacket:normal            ***")
        self.logger.info("************************************************")
        # send a SCCRQ form remote
        msgAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        assignedAvp = AssignedControlConnectionID(self.connection.localConnID)
        sccrq = L2tpv3ControlPacket(666, avps=(msgAvp, assignedAvp))
        # before send packet, the ns is not change
        lastNs = self.transport.ns
        # before send packet, the sendlist is not change
        lastSendList = len(self.transport.sendList)

        self.transport.SendPacket(
            sccrq, (self.connection.remoteAddr, self.connection.localConnID))
        # after send packet, the ns is +1
        self.assertEqual(self.transport.ns, lastNs + 1)
        # after send packet, the sendlist is +1
        self.assertEqual(len(self.transport.sendList), lastSendList + 1)

    def testSendNonePacket(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***              SendPacket:none             ***")
        self.logger.info("************************************************")
        try:
            self.transport.SendPacket(
                None, (self.connection.remoteAddr, self.connection.localConnID))
        except Exception as e:
            self.assertRegexpMatches(
                str(e), L2tpv3TransportError.ParameterTypeError)

    def testSendUnnormalPacket(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***            SendPacket:unnormal           ***")
        self.logger.info("************************************************")
        # strunct unnormal packet
        msgAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        assignedAvp = AssignedControlConnectionID(self.connection.localConnID)
        sccrq = L2tpv3ControlPacket(666, avps=(msgAvp, assignedAvp))
        sccrq.isZlb = True
        # before send packet, the ns is not change
        lastNs = self.transport.ns
        # before send packet, the sendlist is not change
        lastSendList = len(self.transport.sendList)
        self.transport.SendPacket(sccrq, None)
        # after send packet, the ns is not change
        self.assertEqual(self.transport.ns, lastNs)
        # after send packet, the sendList is not change
        self.assertEqual(len(self.transport.sendList), lastSendList)

    def testSetDispatcher(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***            SetDispatcher:normal          ***")
        self.logger.info("************************************************")
        connection = L2tpv3Connection.L2tpConnection(
            888, 888, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
        connection.transport.SetDispatcher(self.dispatcher)
        self.assertEqual(self.dispatcher, connection.transport.dispatcher)
        connection.CloseConnection()

    def testSetNoneDispatcher(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***             SetDispatcher:None           ***")
        self.logger.info("************************************************")
        connection = L2tpv3Connection.L2tpConnection(
            1000, 1000, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
        try:
            connection.transport.SetDispatcher(None)
        except Exception as e:
            self.assertRegexpMatches(
                str(e), L2tpv3TransportError.ParameterTypeError)
        connection.CloseConnection()

    def testSetUnmormalDispatcher(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***           SetDispatcher:unnormal         ***")
        self.logger.info("************************************************")
        connection = L2tpv3Connection.L2tpConnection(
            1222, 1222, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
        try:
            connection.transport.SetDispatcher("test")
        except Exception as e:
            self.assertRegexpMatches(
                str(e), L2tpv3TransportError.ParameterTypeError)
        connection.CloseConnection()

    def testTimetickCallback(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***           TimetickCallback:normal        ***")
        self.logger.info("************************************************")
        connection = L2tpv3Connection.L2tpConnection(
            1666, 1666, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
        # send a SCCRQ form remote
        msgAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        assignedAvp = AssignedControlConnectionID(connection.localConnID)
        sccrq = L2tpv3ControlPacket(1666, avps=(msgAvp, assignedAvp))
        connection.transport.SendPacket(
            sccrq, (connection.remoteAddr, connection.localConnID))
        # before timetick callback, the value nr/ns
        # lastNr = transport.ackNr
        lastNs = connection.transport.ns
        connection.transport.sendTimeout = 0
        connection.transport.resendTimes = 1
        connection.transport.TimetickCallback()
        # after timetick callback, need to send the stopccn, sothe ns +1
        self.assertEqual(lastNs, connection.transport.ns)
        connection.transport.sendTimeout = 0
        connection.transport.resendTimes = 0.5
        connection.transport.TimetickCallback()
        self.assertEqual(
            connection.connection_status, L2tpv3Connection.L2tpConnection.CLOSED)

    def testUnnormalTimetickCallback(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***          TimetickCallback:unnormal       ***")
        self.logger.info("************************************************")
        connection = L2tpv3Connection.L2tpConnection(
            1888, 1888, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
        # send a zlb form remote
        msgAvp = ControlMessageAVP(ControlMessageAVP.ZLB)
        assignedAvp = AssignedControlConnectionID(connection.localConnID)
        zlb = L2tpv3ControlPacket(1888, avps=(msgAvp, assignedAvp))
        connection.transport.SendPacket(
            zlb, (connection.remoteAddr, connection.localConnID))

        # send a ZLB form remote, before timetick callback is True
        lastNeedSendZlb = connection.transport.needSendZlb = True

        connection.transport.sendZlbTimeout = 0
        connection.transport.TimetickCallback()
        # after send ZLB, the needSendZlb change to False
        self.assertNotEqual(connection.transport.needSendZlb, lastNeedSendZlb)
        connection.CloseConnection()

        connection = L2tpv3Connection.L2tpConnection(
            2000, 2000, L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
        # send a zlb form remote
        msgAvp = ControlMessageAVP(ControlMessageAVP.ZLB)
        assignedAvp = AssignedControlConnectionID(connection.localConnID)
        zlb = L2tpv3ControlPacket(2000, avps=(msgAvp, assignedAvp))
        connection.transport.SendPacket(
            zlb, (connection.remoteAddr, connection.localConnID))
        connection.transport.lastTimetick = time.time() - 60
        sendListTime = connection.transport.sendList[0]["time"]
        connection.transport.TimetickCallback()
        # after timetick callback, this time should be updated
        self.assertTrue(
            connection.transport.sendList[0]["time"] > sendListTime)

        """connection.transport.lastTimetick = time.time() + 60
        sendListTime = connection.transport.sendList[0]["time"]
        connection.transport.TimetickCallback()
        # after timetick callback, this time should be updated
        self.assertFalse(connection.transport.sendList[0]["time"] > sendListTime)"""
        connection.CloseConnection()

    def testTransportEncoder(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***          TransportEncoder:normal         ***")
        self.logger.info("************************************************")
        transportEncoder = TransportEncoder()
        originalDict = len(self.transport.__dict__)
        retDict = len(transportEncoder.default(self.transport))
        self.assertNotEqual(retDict, originalDict)

    def testUnmoralTransportEncoder(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***         TransportEncoder:unnormal        ***")
        self.logger.info("************************************************")
        transportEncoder = TransportEncoder()

        class TestDict(object):

            def __init__(self):
                self.test1 = 1
                self.test2 = 2
        testDict = TestDict()
        originalDict = len(testDict.__dict__)
        retDict = len(transportEncoder.default(testDict))
        self.assertEqual(retDict, originalDict)

    def testNoneTransportEncoder(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***           TransportEncoder:none          ***")
        self.logger.info("************************************************")
        transportEncoder = TransportEncoder()
        try:
            transportEncoder.default(None)
        except Exception as e:
            self.assertRegexpMatches(str(e), ".object has no attribute.")

    def testCloseTransport(self):
        self.logger.info("start testing...")
        self.logger.info("************************************************")
        self.logger.info("***              CloseTransport:             ***")
        self.logger.info("************************************************")
        # before requestUnregister, unregisterRequest should don't change
        startLength = len(self.dispatcher.unregisterRequest)
        self.transport.CloseTransport()
        # self.dispatcher.requestUnregister(self.connection.transport)
        # after requestUnregister, unregisterRequest length + 1
        stopLength = len(self.dispatcher.unregisterRequest)
        self.assertIsNotNone(stopLength)
        self.assertEqual(stopLength, startLength + 1)

    @classmethod
    def tearDownClass(cls):
        cls.logger.info("start tearDown...")
        cls.logger.info("************************************************")
        cls.logger.info("***               tearDownClass:             ***")
        cls.logger.info("************************************************")
        cls.connection.CloseConnection()
        cls.dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = None

    def test_recvWinKey(self):
        orig_ackNr = self.transport.ackNr
        orig_wrapCount = self.transport.wrapCount
        pkt = L2tpv3ControlPacket()
        pkt.ns = 1
        self.transport.ackNr = 1
        self.transport.wrapCount = 1
        ret = self.transport._recvWinKey(pkt=pkt)
        self.assertEqual(ret, 0x10001)
        pkt.ns = 30
        self.transport.ackNr = 34
        self.transport.wrapCount = 1
        ret = self.transport._recvWinKey(pkt=pkt)
        self.transport.ackNr = orig_ackNr
        self.transport.wrapCount = orig_wrapCount
        self.assertEqual(ret, 0x2001e)

class TestL2tpv3Network(unittest.TestCase):
    def test_L2tpv3Network(self):
        network = L2tpv3Network(localAddr="127.0.0.1", connID=123134)
        self.assertIsInstance(network, L2tpv3Network)
        network.close()

    def test_L2tpv3Network_ipv6(self):
        network = L2tpv3Network(localAddr="::1", connID=123134)
        self.assertIsInstance(network, L2tpv3Network)
        network.close()

if __name__ == "__main__":
    unittest.main()
