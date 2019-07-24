
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
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP, ProtocolVersion, TieBreaker, FrameCapabilities, \
    Hostname, VendorName, ReceiveWinSize, RouterID, AssignedControlConnectionID, PseudowireCapList, \
    CallSerialNumber, SequencingRequired, LocalSessionID, RemoteSessionID, RemoteEndID, PseudowireType, \
    L2SpecificSublayer, DataSequencing, ResultCode, CircuitStatus

import unittest


class testL2tpv3Rfc3931AVP(unittest.TestCase):

    def testControlMessageAvp(self):
        controlAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        print controlAvp

    def testRetcode(self):
        avp1 = ResultCode(
            ControlMessageAVP.StopCCN, 2, errorCode=3, errMessage="Test")

        buf = avp1.encode()

        avp2 = ResultCode.decodeAll(buf)
        print avp2[0]
        print avp1

    def testProtocolRevisionAvp(self):
        protoAvp = ProtocolVersion(1, 2)

        print protoAvp

    def testTieBraker(self):
        tie = TieBreaker(value="01234567")
        print tie

    def testHostname(self):
        hostname = Hostname("JINJUN", mustAvp=False)

        print hostname

    def testVendorName(self):
        vendor = VendorName("JINJUN", mustAvp=False, hiddenAvp=True)

        print vendor

    def testReceiveWinSize(self):
        recvWinsize = ReceiveWinSize(123, mustAvp=True)

        buf = recvWinsize.encode()

        avp2 = ReceiveWinSize.decodeAll(buf)
        print avp2[0]
        print recvWinsize

    def testRouterID(self):
        avp1 = RouterID(0x12345678, mustAvp=True)

        buf = avp1.encode()

        avp2 = RouterID.decodeAll(buf)
        print avp2[0]
        print avp1

    def testAssignedCOnnectionID(self):
        avp1 = AssignedControlConnectionID(0x12345678, mustAvp=True)

        buf = avp1.encode()

        avp2 = AssignedControlConnectionID.decodeAll(buf)
        print avp2[0]
        print avp1

    def testPseudoWireList(self):
        avp1 = PseudowireCapList((1, 2, 3, 4, 5, 6), mustAvp=True)

        buf = avp1.encode()

        avp2 = PseudowireCapList.decodeAll(buf)
        print avp2[0]
        print avp1

    def testCallSerailNum(self):
        avp1 = CallSerialNumber(12345, hiddenAvp=True)

        buf = avp1.encode()

        avp2 = CallSerialNumber.decodeAll(buf)
        print avp2[0]
        print avp1

    def testSequenceRequired(self):
        avp1 = SequencingRequired()

        buf = avp1.encode()

        avp2 = SequencingRequired.decodeAll(buf)
        print avp2[0]
        print avp1

    def testLocalSessionID(self):
        avp1 = LocalSessionID(0x1234)

        buf = avp1.encode()

        avp2 = LocalSessionID.decodeAll(buf)
        print avp2[0]
        print avp1

    def testRemoteSessionID(self):
        avp1 = RemoteSessionID(0x1234)

        buf = avp1.encode()

        avp2 = RemoteSessionID.decodeAll(buf)
        print avp2[0]
        print avp1

    def testRemoteEndID(self):
        avp1 = RemoteEndID()
        buf = avp1.encode()
        avp2 = RemoteEndID.decodeAll(buf)
        print avp2[0]
        print avp1

    def testPesudowireType(self):
        avp1 = PseudowireType(12)

        buf = avp1.encode()

        avp2 = PseudowireType.decodeAll(buf)
        print avp2[0]
        print avp1

    def testL2sublayer(self):
        avp1 = L2SpecificSublayer(1234)

        buf = avp1.encode()

        avp2 = L2SpecificSublayer.decodeAll(buf)
        print avp2[0]
        print avp1

    def testDataSeqencing(self):
        avp1 = DataSequencing(1)

        buf = avp1.encode()

        avp2 = DataSequencing.decodeAll(buf)
        print avp2[0]
        print avp1

    def testCircuitStatus(self):
        avp1 = CircuitStatus(True, True)

        buf = avp1.encode()

        avp2 = CircuitStatus.decodeAll(buf)
        print avp2[0]
        print avp1
if __name__ == "__main__":
    unittest.main()
