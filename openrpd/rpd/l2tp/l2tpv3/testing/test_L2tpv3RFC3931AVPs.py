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
import unittest
import struct

from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP, ProtocolVersion, TieBreaker, FrameCapabilities, \
    Hostname, VendorName, ReceiveWinSize, RouterID, AssignedControlConnectionID, PseudowireCapList, \
    CallSerialNumber, SequencingRequired, LocalSessionID, RemoteSessionID, RemoteEndID, PseudowireType, \
    L2SpecificSublayer, DataSequencing, ResultCode, CircuitStatus, FirmwareRevision, SbfdDiscriminator, SbfdVccv, \
    FailoverCapability, TunnelRecovery, SuggestedControlSequence, FailoverSessionState
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging

from l2tpv3.src.L2tpv3ControlPacket import L2tpv3ControlPacket


class TestL2tpv3RFC3931AVPs(unittest.TestCase):
    # open the logger
    __metaclass__ = AddLoggerToClass

    def setUp(self):
        self.ControlMessageAVP = ControlMessageAVP(
            messageType=ControlMessageAVP.SCCRQ)

        self.ResultCode = ResultCode(
            msgType=ControlMessageAVP.CDN, resultCode=15, errorCode=760,
            errMessage="zyj", mustAvp=True, attrValue="yong")

        self.ProtocolVersion = ProtocolVersion(
            version=10, revision=20, attrValue=None)

        self.FrameCapabilities = FrameCapabilities(
            bitmask=0, async=False, sync=False, attrValue=None)

        self.TieBreaker = TieBreaker(value="12345678")

        self.FirmwareRevision = FirmwareRevision(
            value=0, hiddenAvp=False, attrValue=None)

        self.Hostname = Hostname(value="value", mustAvp=True)

        self.VendorName = VendorName(
            value="man", mustAvp=True, hiddenAvp=False)

        self.ReceiveWinSize = ReceiveWinSize(
            value=0, mustAvp=False, attrValue=None)

        self.RouterID = RouterID(value=0, mustAvp=False, attrValue=None)

        self.AssignedControlConnectionID = AssignedControlConnectionID(
            value=0, mustAvp=False, hiddenAvp=False,
            attrValue=None)

        self.PseudowireCapList = PseudowireCapList(
            value=(), mustAvp=False, hiddenAvp=False, attrValue=None)

        self.CallSerialNumber = CallSerialNumber(
            value=0, hiddenAvp=False, attrValue=None)

        self.SequencingRequired = SequencingRequired()

        self.LocalSessionID = LocalSessionID(
            value=0, mustAvp=True, hiddenAvp=False, attrValue=None)

        self.RemoteSessionID = RemoteSessionID(
            value=0, mustAvp=True, hiddenAvp=False, attrValue=None)

        self.RemoteEndID = RemoteEndID()

        self.PseudowireType = PseudowireType(
            value=12, mustAvp=False, hiddenAvp=False, attrValue=None)

        self.L2SpecificSublayer = L2SpecificSublayer(
            value=0, mustAvp=False, hiddenAvp=False, attrValue=None)

        self.DataSequencing = DataSequencing(
            value=0, mustAvp=False, hiddenAvp=False, attrValue=None)

        self.CircuitStatus = CircuitStatus(
            active=True, new=True, mustAvp=False, hiddenAvp=False, attrValue=None)
        
        self.SbfdDiscriminator = SbfdDiscriminator(value=0, mustAvp=True, attrValue=None)
        
        self.SbfdVccv = SbfdVccv(value=0, mustAvp=True, attrValue=None)

        self.FailoverCapability = FailoverCapability(
            failoverCapofCC=True, failoverCapofDC=False, recoveryTime=0, hiddenAvp=False, attrValue=None)

        self.TunnelRecovery = TunnelRecovery(
            recoverTunnelID = 1, recoverRemoteTunnelID = 2, attrValue=None)

        self.SuggestedControlSequence = SuggestedControlSequence(
            suggestedNs = 0, suggestedNr = 0, hiddenAvp=False, attrValue=None)

        self.FailoverSessionState = FailoverSessionState(
            sessionID = 1, remoteSessionID = 2, hiddenAvp=False, attrValue=None)

    def tearDown(self):
        pass

    def test_ControlMessageAVP(self):

        # messageType is in ControlMessageAVP.ControlMesagedSet and attrValue
        # is None
        self.controlAvp = ControlMessageAVP(ControlMessageAVP.SCCRQ)
        self.assertEqual(self.controlAvp.messageType, 1)

        # messageType is in ControlMessageAVP.ControlMesagedSet and attrValue
        # is not None
        self.controlAvp = ControlMessageAVP(ControlMessageAVP.SCCRP, "qwer7ss")
        self.assertEqual(self.controlAvp.messageType, 2)

        # messageType is Not in ControlMessageAVP.ControlMesagedSet
        try:
            self.controlAvp = ControlMessageAVP(3303)
        except Exception as e:
            self.assertEqual(str(e), "message type error")

    def test_ControlMessageAVP_SetFlags(self):
        self.ControlMessageAVP.SetFlags(False, True)
        self.assertEqual(self.ControlMessageAVP.mustAvp, False)
        self.assertEqual(self.ControlMessageAVP.hiddenAvp, True)

    def test_ControlMessageAVP_handleAvp(self):
        ret_value = self.ControlMessageAVP.handleAvp("0980", "nofalse")
        self.assertEqual(ret_value, True)

    def test_ControlMessageAVP_decode(self):
        for value in self.ControlMessageAVP.ControlMesagedSet:
            buff0 = struct.pack('!H', value)
            result = self.ControlMessageAVP.decode(buff0)
            print "current control message is : " + self.ControlMessageAVP.ControlMesagedSet[value]
            self.assertEqual(result.messageType, value)
        buff0 = struct.pack('!H', 0xffff)
        try:
            self.ControlMessageAVP.decode(buff0)
        except Exception as e:
            self.assertEqual(str(e), "message type error")

    def test_ControlMessageAVP_ValidateFlags(self):
        self.ControlMessageAVP.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.ControlMessageAVP.ValidateFlags(
            mustAvp=True, hiddenAvp=True), False)

    def test_ResultCode(self):
        # msgType != ControlMessageAVP.StopCCN and msgType !=
        # ControlMessageAVP.CDN
        try:
            self.ResultCode = ResultCode(
                msgType=1, resultCode=2, errorCode=None,
                errMessage=None, mustAvp=True, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "Wrong parameter Type")

        # msgType = ControlMessageAVP.StopCCN or msgType =
        # ControlMessageAVP.CDN
        try:
            self.ResultCode = ResultCode(
                msgType=ControlMessageAVP.StopCCN, resultCode=2, errorCode=None,
                errMessage=None, mustAvp=True, attrValue=None)

        except Exception as e:
            self.assertEqual(str(e), "Wrong parameter Type")

        # msgType == ControlMessageAVP.StopCCN and resultCode not in
        # ResultCode.ResultCodeStopCCN

        # ResultCode.ResultCodeStopCCN = {0: 'Reserved.', 1: 'General request to clear control connection.',
            # 2: 'General error, Error Code indicates the problem.', 3: 'Control connection already exists.',
            # 4: 'Requester is not authorized to establish a control connection.',
            # 5: 'The protocol version of the requester is not supported, Error Code indicates highest
            # version supported.', 6: 'Requester is being shut down.',
            # 7: 'Finite state machine error or timeout'}
        try:
            self.ResultCode = ResultCode(
                msgType=ControlMessageAVP.StopCCN, resultCode=8, errorCode=None,
                errMessage=None, mustAvp=True, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "Wrong parameter Type")

        # msgType == ControlMessageAVP.CDN and resultCode not in
        # ResultCode.ResultCodeCDN
        try:
            self.ResultCode = ResultCode(
                msgType=ControlMessageAVP.CDN, resultCode=8, errorCode=None,
                errMessage=None, mustAvp=True, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "Wrong parameter Type")

        # attrValue is Not None self.errorCode is not None and self.errorMsg is
        # not None
        self.ResultCode = ResultCode(
            msgType=ControlMessageAVP.CDN, resultCode=8, errorCode=2,
            errMessage=1, mustAvp=True, attrValue="Jiang")

        # attrValue is None self.errorCode is Not None or self.errorMsg is Not None
        # msgType == ControlMessageAVP.StopCCN and resultCode not in
        # ResultCode.ResultCodeStopCCN

        # msgType == ControlMessageAVP.CDN and resultCode is in
        # ResultCode.ResultCodeCDN

        # ResultCode.ResultCodeCDN = {0: 'Reserved.',
        # 1: 'Session disconnected due to loss of carrier or circuit disconnect.',
        # 2: 'Session disconnected for the reason indicated in Error Code.',
        # 3: 'Session disconnected for administrative reasons.',
        # 4: 'Session establishment failed due to lack of appropriate facilities being
        # available (temporary condition).',
        # 5: 'Session establishment failed due to lack of appropriate facilities being
        # available (permanent condition).',
        # 16: 'Finite state machine error or timeout.',
        # 13: 'Session not established due to losing tie breaker.',
        # 14: 'Session not established due to unsupported PW type.',
        # 15: 'Session not established, sequencing required without valid
        # L2-Specific Sublayer.'}

        # errorCode = None
        self.ResultCode = ResultCode(
            msgType=ControlMessageAVP.CDN, resultCode=15, errorCode=None,
            errMessage="zyj", mustAvp=True, attrValue=None)
        # errorCode != None
        self.ResultCode = ResultCode(
            msgType=ControlMessageAVP.CDN, resultCode=15, errorCode=760,
            errMessage="zyj", mustAvp=True, attrValue=None)

    def test_ResultCode_SetFlags(self):
        self.ResultCode.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_ResultCode_handleAvp(self):
        self.ResultCode.handleAvp(pkt="10352", retPak="456131")
        self.assertEqual(
            self.ResultCode.handleAvp(pkt="10352", retPak="456131"), True)

    def test_ResultCode_decode(self):
        # len(buf) == 2
        buf1 = "22"
        self.ResultCode.decode(buf=buf1)

        # len(buf) == 4
        buf2 = "4444"
        self.ResultCode.decode(buf=buf2)

        # len(buf) > 4
        buf3 = "12345"
        self.ResultCode.decode(buf=buf3)

        # len(buf) is other
        try:
            buf4 = "1"
            self.ResultCode.decode(buf=buf4)
        except Exception as e:
            self.assertEqual(
                str(e), "Cannot decode the return code AVP since length error.")

    def test_ResultCode_ValidateFlags(self):
        # return hiddenAvp == False
        self.ResultCode.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.ResultCode.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_ProtocolVersion(self):
        # attrValue is Not None
        self.ProtocolVersion = ProtocolVersion(
            version=10, revision=20, attrValue="bce")

    def test_ProtocolVersion_handleAvp(self):
        # retPak is None
        self.ProtocolVersion.handleAvp(pkt="zyjbce", retPak=None)
        self.assertEqual(
            self.ProtocolVersion.handleAvp(pkt="zyjbce", retPak=None), True)

        # retPak is Not None
        try:
            self.ProtocolVersion.handleAvp(pkt="zyjbce", retPak='retPaking')
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_ProtocolVersion_SetFlags(self):
        self.ProtocolVersion.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_ProtocolVersion_decode(self):
        buff0 = "xq"
        self.ProtocolVersion.decode(buff0)

    def test_ProtocolVersion_ValidateFlags(self):
        # return (mustAvp == True) and (hiddenAvp == False)
        self.ProtocolVersion.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.ProtocolVersion.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_FrameCapabilities(self):
        # not isinstance(async, bool) or not isinstance(sync, bool)
        try:
            self.FrameCapabilities = FrameCapabilities(
                bitmask=0, async="sb", sync="bf", attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.FrameCapabilities = FrameCapabilities(
            bitmask=0, async=False, sync=False, attrValue="love")

    def test_FrameCapabilities_handleAvp(self):
        # retPak is Not None
        try:
            self.FrameCapabilities.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

        # retPak is None
        self.FrameCapabilities.handleAvp(pkt="RFC3931", retPak=None)
        self.assertEqual(
            self.FrameCapabilities.handleAvp(pkt="RFC3931", retPak=None), True)

    def test_FrameCapabilities_SetFlags(self):
        self.FrameCapabilities.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_FrameCapabilities_decode(self):
        buff1 = "4444"
        self.FrameCapabilities.decode(buf=buff1)

    def test_FrameCapabilities_ValidateFlags(self):
        # return (mustAvp == True)

        self.FrameCapabilities.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.FrameCapabilities.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_TieBreaker(self):
        # not isinstance(value, str)
        try:
            self.TieBreaker = TieBreaker(value=23)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # len(value) != 8
        try:
            self.TieBreaker = TieBreaker(value="1234567")
        except Exception as e:
            self.assertEqual(str(e), "Tie Breaker value shuold be 8")

    def test_TieBreaker_handleAvp(self):
        self.TieBreaker.handleAvp(pkt="zxcvb", retPak="money")
        self.assertEqual(
            self.TieBreaker.handleAvp(pkt="zxcvb", retPak="money"), True)

    def test_TieBreaker_SetFlags(self):
        self.TieBreaker.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_TieBreaker_decode(self):
        buff2 = "87654321"
        self.TieBreaker.decode(buf=buff2)

    def test_TieBreaker_ValidateFlags(self):
        # return (hiddenAvp == True)
        self.TieBreaker.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.TieBreaker.ValidateFlags(
            mustAvp=True, hiddenAvp=False), False)

    def test_FirmwareRevision(self):
        # not isinstance(hiddenAvp, bool)
        try:
            self.FirmwareRevision = FirmwareRevision(
                value=0, hiddenAvp=666, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is None
        self.FirmwareRevision = FirmwareRevision(
            value=0, hiddenAvp=False, attrValue="girl")

    def test_FirmwareRevision_handleAvp(self):
        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.FirmwareRevision.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

        # retPak is None
        self.FirmwareRevision.handleAvp(pkt="delay", retPak=None)

    def test_FirmwareRevision_SetFlags(self):
        self.FirmwareRevision.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_FirmwareRevision_decode(self):
        buff3 = "22"
        self.FirmwareRevision.decode(buf=buff3)

    def test_FirmwareRevision_ValidateFlags(self):
        # return (mustAvp == False)
        self.FirmwareRevision.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.FirmwareRevision.ValidateFlags(
            mustAvp=True, hiddenAvp=False), False)

    def test_Hostname(self):
        # not isinstance(value, str) or len(value) < 1
        try:
            self.Hostname = Hostname(value="", mustAvp=True)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

    def test_Hostname_handleAvp(self):
        # retPak is None
        self.Hostname.handleAvp(pkt="boy", retPak=None)
        self.assertEqual(self.Hostname.handleAvp(pkt="boy", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.Hostname.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_Hostname_SetFlags(self):
        self.Hostname.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_Hostname_decode(self):
        buff5 = "zxcvrt"
        self.Hostname.decode(buf=buff5)

    def test_Hostname_ValidateFlags(self):
        # return (hiddenAvp == False)
        self.Hostname.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.Hostname.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_VendorName(self):
        # not isinstance(value, str) or len(value) < 1
        try:
            self.VendorName = VendorName(
                value="", mustAvp=True, hiddenAvp=False)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

    def test_VendorName_handleAvp(self):
        # retPak is None
        self.VendorName.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.VendorName.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.VendorName.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_VendorName_SetFlags(self):
        self.VendorName.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_VendorName_decode(self):
        buff6 = "123"
        self.VendorName.decode(buf=buff6)

    def test_VendorName_ValidateFlags(self):

        self.VendorName.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.VendorName.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_ReceiveWinSize(self):
        # not isinstance(mustAvp, bool)
        try:
            self.ReceiveWinSize = ReceiveWinSize(
                value=0, mustAvp=33, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.ReceiveWinSize = ReceiveWinSize(
            value=0, mustAvp=False, attrValue="baby")

    def test_ReceiveWinSize_handleAvp(self):
        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.ReceiveWinSize.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute
            # 'Connection'")

    def test_ReceiveWinSize_SetFlags(self):
        self.ReceiveWinSize.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_ReceiveWinSize_decode(self):
        buff6 = "22"
        self.ReceiveWinSize.decode(buf=buff6)

    def test_ReceiveWinSize_ValidateFlags(self):

        self.ReceiveWinSize.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.ReceiveWinSize.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_RouterID(self):
        # not isinstance(mustAvp, bool)
        try:
            self.RouterID = RouterID(value="", mustAvp=99, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.RouterID = RouterID(value="", mustAvp=True, attrValue="aaa")

    def test_RouterID_handleAvp(self):
        # retPak is None
        self.RouterID.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.RouterID.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.RouterID.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_RouterID_SetFlags(self):
        self.RouterID.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_RouterID_decode(self):
        buff6 = "1234"
        self.RouterID.decode(buf=buff6)

    def test_RouterID_ValidateFlags(self):

        self.RouterID.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.RouterID.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_AssignedControlConnectionID(self):
        # not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool)
        try:
            self.AssignedControlConnectionID = AssignedControlConnectionID(
                value=0, mustAvp=333,
                hiddenAvp=666, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.AssignedControlConnectionID = AssignedControlConnectionID(
            value=0, mustAvp=False,
            hiddenAvp=False, attrValue=None)

    def test_AssignedControlConnectionID_handleAvp(self):
        # retPak is None
        self.AssignedControlConnectionID.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.AssignedControlConnectionID.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.AssignedControlConnectionID.handleAvp(
                pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute
            # 'Connection'")

    def test_AssignedControlConnectionID_SetFlags(self):
        self.AssignedControlConnectionID.SetFlags(
            mustAvp=True, hiddenAvp=False)

    def test_AssignedControlConnectionID_decode(self):
        buff6 = "1234"
        self.AssignedControlConnectionID.decode(buf=buff6)

    def test_AssignedControlConnectionID_ValidateFlags(self):
        self.AssignedControlConnectionID.ValidateFlags(
            mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.AssignedControlConnectionID.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_PseudowireCapList(self):
        # not isinstance(value, tuple) or not isinstance(mustAvp, bool) or not
        # isinstance(hiddenAvp, bool)
        try:
            self.PseudowireCapList = PseudowireCapList(
                value=1, mustAvp=1, hiddenAvp=1, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.PseudowireCapList = PseudowireCapList(
            value=(), mustAvp=False, hiddenAvp=False, attrValue="good")

        self.PseudowireCapList = PseudowireCapList(value=(1, 2, 3, 4))

    def test_PseudowireCapList_handleAvp(self):
        # retPak is None
        self.PseudowireCapList.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.PseudowireCapList.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.PseudowireCapList.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_PseudowireCapList_SetFlags(self):
        self.PseudowireCapList.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_PseudowireCapList_decode(self):
        buff6 = "1234"
        avp = self.PseudowireCapList.decode(buf=buff6)
        print avp

    def test_PseudowireCapList_ValidateFlags(self):

        self.PseudowireCapList.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.PseudowireCapList.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_CallSerialNumber(self):
        # not isinstance(hiddenAvp, bool)
        try:
            self.CallSerialNumber = CallSerialNumber(
                value=0, hiddenAvp=999, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.CallSerialNumber = CallSerialNumber(
            value=0, hiddenAvp=False, attrValue="jjjkkk")

    def test_CallSerialNumber_handleAvp(self):
        # retPak is None
        self.CallSerialNumber.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.CallSerialNumber.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # self.        AssignedControlConnectionID.handleAvp

    def test_CallSerialNumber_SetFlags(self):
        self.CallSerialNumber.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_CallSerialNumber_decode(self):
        buff6 = "1234"
        self.CallSerialNumber.decode(buf=buff6)

    def test_CallSerialNumber_ValidateFlags(self):
        # return (mustAvp == True)
        self.CallSerialNumber.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.CallSerialNumber.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_SequencingRequired_handleAvp(self):
        # retPak is None
        self.SequencingRequired.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.SequencingRequired.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.SequencingRequired.handleAvp(
                pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_SequencingRequired_SetFlags(self):
        self.SequencingRequired.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_SequencingRequired_decode(self):
        buff6 = "1234"
        self.SequencingRequired.decode(buf=buff6)

    def test_SequencingRequired_ValidateFlags(self):
        # return (mustAvp == True)
        self.SequencingRequired.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.SequencingRequired.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_LocalSessionID(self):
        # not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool)
        try:
            self.LocalSessionID = LocalSessionID(
                value=0, mustAvp=7, hiddenAvp=7, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.LocalSessionID = LocalSessionID(
            value=0, mustAvp=True, hiddenAvp=False, attrValue="haha")

    def test_LocalSessionID_handleAvp(self):
        # retPak is None
        self.LocalSessionID.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.LocalSessionID.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.LocalSessionID.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute
            # 'Session'")

    def test_LocalSessionID_SetFlags(self):
        self.LocalSessionID.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_LocalSessionID_decode(self):
        buff6 = "1234"
        self.LocalSessionID.decode(buf=buff6)

    def test_LocalSessionID_ValidateFlags(self):
        # return (mustAvp == True)
        self.LocalSessionID.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.LocalSessionID.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_RemoteSessionID(self):
        # not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool)
        try:
            self.RemoteSessionID = RemoteSessionID(
                value=0, mustAvp=7, hiddenAvp=7, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.RemoteSessionID = RemoteSessionID(
            value=0, mustAvp=True, hiddenAvp=False, attrValue="haha")

    def test_RemoteSessionID_encode(self):
        self.RemoteSessionID.encode()

    def test_RemoteSessionID_handleAvp(self):
        # retPak is None
        self.RemoteSessionID.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.RemoteSessionID.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.RemoteSessionID.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_RemoteSessionID_SetFlags(self):
        self.RemoteSessionID.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_RemoteSessionID_decode(self):
        buff6 = "1234"
        self.RemoteSessionID.decode(buf=buff6)

    def test_RemoteSessionID_ValidateFlags(self):
        # return (mustAvp == True)
        self.RemoteSessionID.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.RemoteSessionID.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_RemoteEndID(self):
        # not isinstance(value, str) or len(value) < 1 or not isinstance(mustAvp, bool)
        # or isinstance(hiddenAvp, bool)
        try:
            self.RemoteEndID = RemoteEndID(value="", mustAvp=3, hiddenAvp=3)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        # self.RemoteEndID = RemoteEndID(value="", mustAvp=True,
        # hiddenAvp=False)

    def test_RemoteEndID_handleAvp(self):
        # retPak is None
        self.RemoteEndID.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.RemoteEndID.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.RemoteEndID.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_RemoteEndID_SetFlags(self):
        self.RemoteEndID.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_RemoteEndID_decode(self):
        buff6 = struct.pack('!34B', 0x0, 0x0,
                            0x00, 0x03, 0x00, 0x00,
                            0x00, 0x03, 0x01, 0x01,
                            0x00, 0x03, 0x02, 0x02,
                            0x00, 0x03, 0x03, 0x03,
                            0x00, 0x03, 0x04, 0x04,
                            0x00, 0x03, 0x05, 0x05,
                            0x00, 0x03, 0x06, 0x06,
                            0x00, 0x03, 0x07, 0x07)
        result = self.RemoteEndID.decode(buff6)
        print str(result)

    def test_RemoteEndID_ValidateFlags(self):
        # return (mustAvp == True)
        self.RemoteEndID.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.RemoteEndID.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_PseudowireType(self):
        # not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool)
        try:
            self.PseudowireType = PseudowireType(
                value=12, mustAvp=5, hiddenAvp=5, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")
        try:
            self.PseudowireType = PseudowireType(value=1234)
        except Exception as e:
            self.assertEqual(str(e), "PseudowireType type is not supported")

        # attrValue is Not None
        self.PseudowireType = PseudowireType(value=12, attrValue="king")
        print str(self.PseudowireType)
        self.assertEqual(self.PseudowireType.attrValue, "king")

    def test_PseudowireType_handleAvp(self):
        # retPak is None
        self.PseudowireType.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.PseudowireType.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        avp = []
        retPak = L2tpv3ControlPacket(0, 0, avps=avp)
        try:
            self.PseudowireType.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")
        avp = []
        pw = PseudowireType(PseudowireType.PSPPW)
        retPak = L2tpv3ControlPacket(avps=avp)
        ret = pw.handleAvp(pkt="RFC3931", retPak=retPak)
        self.assertTrue(ret)
        self.assertEqual(retPak.avps[0].pwType, PseudowireType.PSPPW)

    def test_PseudowireType_SetFlags(self):
        self.PseudowireType.SetFlags(mustAvp=False, hiddenAvp=True)
        self.assertEqual(self.PseudowireType.mustAvp, False)
        self.assertEqual(self.PseudowireType.hiddenAvp, True)

    def test_PseudowireType_decode(self):
        buff6 = struct.pack('!H', 12)
        avp = self.PseudowireType.decode(buf=buff6)
        self.assertEqual(self.PseudowireType.pwType, 12)

    def test_PseudowireType_ValidateFlags(self):
        # return (mustAvp == True)
        ret = self.PseudowireType.ValidateFlags(True, False)
        self.assertEqual(ret, True)
        ret = self.PseudowireType.ValidateFlags(False, False)
        self.assertEqual(ret, False)
        ret = self.PseudowireType.ValidateFlags(True, True)
        self.assertEqual(ret, False)
        ret = self.PseudowireType.ValidateFlags(False, True)
        self.assertEqual(ret, False)

    def test_L2SpecificSublayer(self):
        # not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool)
        try:
            self.L2SpecificSublayer = L2SpecificSublayer(value=3,
                                                         mustAvp=543,
                                                         hiddenAvp=88888)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")
        # attrValue is Not None
        self.L2SpecificSublayer = L2SpecificSublayer(value=3, attrValue="show")
        self.assertEqual(self.L2SpecificSublayer.attrValue, "show")


    def test_L2SpecificSublayer_handleAvp(self):
        # retPak is None
        self.L2SpecificSublayer.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.L2SpecificSublayer.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.L2SpecificSublayer.handleAvp(
                pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_L2SpecificSublayer_SetFlags(self):
        self.L2SpecificSublayer.SetFlags(mustAvp=False, hiddenAvp=True)
        self.assertEqual(self.L2SpecificSublayer.mustAvp, False)
        self.assertEqual(self.L2SpecificSublayer.hiddenAvp, True)

    def test_L2SpecificSublayer_decode(self):
        buff6 = struct.pack('!H', 3)
        avp = self.L2SpecificSublayer.decode(buf=buff6)
        print str(avp)
        self.assertEqual(avp.l2Sublayer, 3)

    def test_L2SpecificSublayer_ValidateFlags(self):
        # return (mustAvp == True)
        self.L2SpecificSublayer.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.L2SpecificSublayer.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_DataSequencing(self):
        # not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool)
        # or value not in (0, 1, 2)
        try:
            self.DataSequencing = DataSequencing(
                value=4, mustAvp=9999, hiddenAvp=53, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

            # attrValue is Not None
            self.DataSequencing = DataSequencing(
                value=0, mustAvp=False, hiddenAvp=False, attrValue="zhang")

    def test_DataSequencing___str__(self):
        self.DataSequencing.__str__()

    def test_DataSequencing_handleAvp(self):
        # retPak is None
        self.DataSequencing.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.DataSequencing.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.DataSequencing.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_DataSequencing_SetFlags(self):
        self.DataSequencing.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_DataSequencing_decode(self):
        # return DataSequencing(value, mustAvp=False, attrValue=buf)
        try:
            buff6 = "00"
            self.DataSequencing.decode(buf=buff6)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

    def test_DataSequencing_ValidateFlags(self):
        # return (mustAvp == True)
        self.DataSequencing.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(
            self.DataSequencing.ValidateFlags(mustAvp=True, hiddenAvp=False), True)

    def test_CircuitStatus(self):
        # not isinstance(active, bool) or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool)
        # or not isinstance(new, bool)
        try:
            self.CircuitStatus = CircuitStatus(active=0, new=0, mustAvp=0,
                                               hiddenAvp=0, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

            # attrValue is Not None
            self.CircuitStatus = CircuitStatus(
                active=True, new=True, mustAvp=False,
                hiddenAvp=False, attrValue="abc")

    def test_CircuitStatus_handleAvp(self):
        # retPak is None
        self.CircuitStatus.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.CircuitStatus.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.CircuitStatus.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_CircuitStatus_SetFlags(self):
        self.CircuitStatus.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_CircuitStatus_decode(self):
        # return DataSequencing(value, mustAvp=False, attrValue=buf)
        try:
            buff6 = "00"
            self.CircuitStatus.decode(buf=buff6)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

    def test_CircuitStatus_ValidateFlags(self):
        # return (mustAvp == True)
        self.CircuitStatus.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.CircuitStatus.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)


    def test_SbfdDiscriminator(self):
        # not isinstance(mustAvp, bool)
        try:
            self.SbfdDiscriminator = SbfdDiscriminator(value="", mustAvp=99, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.SbfdDiscriminator = SbfdDiscriminator(value="", mustAvp=True, attrValue="aaa")

    def test_SbfdDiscriminator_handleAvp(self):
        # retPak is None
        self.SbfdDiscriminator.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.SbfdDiscriminator.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.SbfdDiscriminator.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_SbfdDiscriminator_SetFlags(self):
        self.SbfdDiscriminator.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_SbfdDiscriminator_decode(self):
        buff6 = "1234"
        self.SbfdDiscriminator.decode(buf=buff6)

    def test_SbfdDiscriminator_ValidateFlags(self):

        self.SbfdDiscriminator.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.SbfdDiscriminator.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)


    def test_SbfdVccv(self):
        # not isinstance(mustAvp, bool)
        try:
            self.SbfdVccv = SbfdVccv(value="", mustAvp=99, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.SbfdVccv = SbfdVccv(value="", mustAvp=True, attrValue="aaa")

    def test_SbfdVccv_handleAvp(self):
        # retPak is None
        self.SbfdVccv.handleAvp(pkt="lkjh", retPak=None)
        self.assertEqual(
            self.SbfdVccv.handleAvp(pkt="lkjh", retPak=None), True)

        # retPak is Not None
        # Skip the handleAvp and coverage it
        try:
            self.SbfdVccv.handleAvp(pkt="RFC3931", retPak="beautiful")
        except Exception as e:
            pass
            # self.assertEqual(str(e), "'str' object has no attribute 'avps'")

    def test_SbfdVccv_SetFlags(self):
        self.SbfdVccv.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_SbfdVccv_decode(self):
        buff6 = "34"
        self.SbfdVccv.decode(buf=buff6)

    def test_SbfdVccv_ValidateFlags(self):

        self.SbfdVccv.ValidateFlags(mustAvp=True, hiddenAvp=False)
        self.assertEqual(self.SbfdVccv.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_FailoverCapability(self):
        try:
            self.FailoverCapability = FailoverCapability(failoverCapofCC=123,
                failoverCapofDC=456, recoveryTime=0, hiddenAvp=666, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        try:
            self.FailoverCapability = FailoverCapability(failoverCapofCC=False,
                failoverCapofDC=False, recoveryTime=0, hiddenAvp=False, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "failoverCapofCC and failoverCapofDC can't be false at the same time")

        # attrValue is Not None
        self.FailoverCapability = FailoverCapability(failoverCapofCC=True,
            failoverCapofDC=False, recoveryTime=0, hiddenAvp=False, attrValue="RFC4951")

    def test_FailoverCapability_handleAvp(self):
        self.assertEqual(
            self.FailoverCapability.handleAvp(pkt="RFC4951", retPak=None), True)

        # retPak is Not None
        try:
            self.FailoverCapability.handleAvp(pkt="RFC4951", retPak="wonderful")
        except Exception as e:
            pass

    def test_FailoverCapability_SetFlags(self):
        self.FailoverCapability.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_FailoverCapability_decode(self):
        buff = struct.pack("!HI", 0x1, 0x0)
        self.FailoverCapability.decode(buf=buff)

    def test_FailoverCapability_ValidateFlags(self):
        self.assertEqual(self.FailoverCapability.ValidateFlags(
            mustAvp=False, hiddenAvp=False), True)

    def test_TunnelRecovery(self):
        # attrValue is Not None
        self.TunnelRecovery = TunnelRecovery(
            recoverTunnelID = 1, recoverRemoteTunnelID = 2, attrValue="RFC4951")

    def test_TunnelRecovery_handleAvp(self):
        self.assertEqual(
            self.TunnelRecovery.handleAvp(pkt="RFC4951", retPak="RFC4951"), True)

    def test_TunnelRecovery_SetFlags(self):
        self.TunnelRecovery.SetFlags(mustAvp=True, hiddenAvp=False)

    def test_TunnelRecovery_decode(self):
        buff = struct.pack("!HII", 0x0, 0x1, 0x2)
        self.TunnelRecovery.decode(buf=buff)

    def test_TunnelRecovery_ValidateFlags(self):
        self.assertEqual(self.TunnelRecovery.ValidateFlags(
            mustAvp=True, hiddenAvp=False), True)

    def test_SuggestedControlSequence(self):
        try:
            self.SuggestedControlSequence = SuggestedControlSequence(
                suggestedNs = 0, suggestedNr = 0, hiddenAvp=123, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.SuggestedControlSequence = SuggestedControlSequence(
            suggestedNs = 0, suggestedNr = 0, hiddenAvp=False, attrValue="RFC4951")

    def test_SuggestedControlSequence_handleAvp(self):
        self.assertEqual(
            self.SuggestedControlSequence.handleAvp(pkt="RFC4951", retPak="RFC4951"), True)

    def test_SuggestedControlSequence_SetFlags(self):
        self.SuggestedControlSequence.SetFlags(mustAvp=False, hiddenAvp=False)

    def test_SuggestedControlSequence_decode(self):
        buff = struct.pack("!HII", 0x0, 0x0, 0x0)
        self.SuggestedControlSequence.decode(buf=buff)

    def test_SuggestedControlSequence_ValidateFlags(self):
        self.assertEqual(self.SuggestedControlSequence.ValidateFlags(
            mustAvp=False, hiddenAvp=False), True)

    def test_FailoverSessionState(self):
        try:
            self.FailoverSessionState = FailoverSessionState(
                sessionID = 1, remoteSessionID = 2, hiddenAvp=123, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is Not None
        self.FailoverSessionState = FailoverSessionState(
            sessionID = 1, remoteSessionID = 2, hiddenAvp=False, attrValue="RFC4951")

    def test_FailoverSessionState_handleAvp(self):
        try :
            self.FailoverSessionState.handleAvp(pkt="RFC4951", retPak="RFC4951")
        except Exception as e:
            pass

    def test_FailoverSessionState_SetFlags(self):
        self.FailoverSessionState.SetFlags(mustAvp=False, hiddenAvp=False)

    def test_FailoverSessionState_decode(self):
        buff = struct.pack("!HII", 0x0, 0x1, 0x2)
        self.FailoverSessionState.decode(buf=buff)

    def test_FailoverSessionState_ValidateFlags(self):
        self.assertEqual(self.FailoverSessionState.ValidateFlags(
            mustAvp=False, hiddenAvp=False), True)

if __name__ == "__main__":
    unittest.main()
