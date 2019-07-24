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
"""This file defines the rpd l2Tp supported RFC3991 AVPs, currently, the following AVP wil be supported:

* Control Message AVP
* Protocol Version AVP
* Frame Capability AVP
* Tie Breaker AVP
* Firmware Version AVP
* Hostname AVP
* Vendor Name AVP
* Receive Window Size AVP
* Router ID AVP
* Assigned control Connection ID AVP
* pseudowire Capability AVP
* Local session AVP
* Remote session AVP
* Remote End ID AVP
* Pseudowire Type AVP
* Layer2 Specific Sublayer AVP
* Data Sequence AVP
* SBFD Discriminator AVP
* SBFD VCCV Capability AVP
"""

import struct

from L2tpv3AVP import addDebugLogToHandle
from L2tpv3AVP import AvpEncoder
from L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror
import L2tpv3GlobalSettings as L2tpv3GlobalSettings


class ControlMessageAVP(l2tpv3AVP):
    """The is the control message AVP.

    This AVP will return the message type. Encdoe function will reuse
    the base classes encode function.

    """
    SCCRQ = 1
    SCCRP = 2
    SCCCN = 3
    StopCCN = 4
    HELLO = 6
    ZLB = ACK = 20
    OCRQ = 7
    OCRP = 8
    OCCN = 9
    ICRQ = 10
    ICRP = 11
    ICCN = 12
    CDN = 14
    WEN = 15
    SLI = 16
    #new control messages in RFC4951
    FSQ = 21
    FSR = 22

    ControlMesagedSet = {
        SCCRQ: "SCCRQ",
        SCCRP: "SCCRP",
        SCCCN: "SCCCN",
        StopCCN: "StopCCN",
        HELLO: "HELLO",
        ACK: "ACK",
        OCRQ: "OCRQ",
        OCRP: "OCRP",
        OCCN: "OCCN",
        ICRQ: "ICRQ",
        ICRP: "ICRP",
        ICCN: "ICCN",
        CDN: "CDN",
        WEN: "WEN",
        SLI: "SLI",
        FSQ: "FSQ",
        FSR: "FSR",
    }

    RecoveryTunnelMesagedSet = {
        SCCRQ: "SCCRQ",
        SCCRP: "SCCRP",
        SCCCN: "SCCCN",
        StopCCN: "StopCCN",
        HELLO: "HELLO",
        ACK: "ACK",
    }
    AttrType = l2tpv3AVP.ControlMessage

    def __init__(self, messageType, attrValue=None):
        if messageType not in ControlMessageAVP.ControlMesagedSet:
            self.logger.warn(
                "Cannot construct a Control message AVP with unknown Message type: %d" % messageType)
            raise l2tpv3AVPerror("message type error")
        self.messageType = messageType
        if attrValue is None:
            msgRet = struct.pack("!H", messageType)
        else:
            msgRet = attrValue
        super(ControlMessageAVP, self).__init__(
            AttrType=0, VendorID=0, AttrValue=msgRet, MustAvp=True, HidenAVP=False)

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @addDebugLogToHandle
    def handleAvp(self, pkt, ret_pak):
        return True

    @staticmethod
    def decode(buf):
        msgType, = struct.unpack("!H", buf)
        return ControlMessageAVP(msgType, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, ControlMessageAVP.AttrType)] = ControlMessageAVP

"""::

      +---------------------------------------------------------------+
      |0                   1                   2                   3  |
      |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1|
      +-------------------------------+-------------------------------+
      |          Result Code          |     Error Code (optional)     |
      +-------------------------------+-------------------------------+
      | Error Message ... (optional, arbitrary number of octets)      |
      +---------------------------------------------------------------+
"""


class ResultCode(l2tpv3AVP):
    AttrType = l2tpv3AVP.ResultCode

    ResultCodeStopCCN = {
        0: "Reserved.",
        1: "General request to clear control connection.",
        2: "General error, Error Code indicates the problem.",
        3: "Control connection already exists.",
        4: "Requester is not authorized to establish a control connection.",
        5: "The protocol version of the requester is not supported, Error Code indicates highest version supported.",
        6: "Requester is being shut down.",
        7: "Finite state machine error or timeout",
    }

    ResultCodeCDN = {
        0: "Reserved.",
        1: "Session disconnected due to loss of carrier or circuit disconnect.",
        2: "Session disconnected for the reason indicated in Error Code.",
        3: "Session disconnected for administrative reasons.",
        4: "Session establishment failed due to lack of appropriate facilities being available (temporary condition).",
        5: "Session establishment failed due to lack of appropriate facilities being available (permanent condition).",
        13: "Session not established due to losing tie breaker.",
        14: "Session not established due to unsupported PW type.",
        15: "Session not established, sequencing required without valid L2-Specific Sublayer.",
        16: "Finite state machine error or timeout.",
    }

    ErrorCode = {
        0: "No General Error.",
        1: "No control connection exists yet for this pair of LCCEs.",
        2: "Length is wrong.",
        3: "One of the field values was out of range.",
        4: "Insufficient resources to handle this operation now.",
        5: "Invalid Session ID.",
        6: "A generic vendor-specific error occurred.",
        7: "Try another. If initiator is aware of other possible responder destinations, it should try one of them.  "
           "This can be used to guide an LAC or LNS based on policy.",
        8: "The session or control connection was shut down due to receipt of an unknown AVP with the M bit set.",
        9: "Try another directed.",
    }

    def __init__(self, msgType, resultCode, errorCode=None, errMessage=None, mustAvp=True, attrValue=None):

        if msgType != ControlMessageAVP.StopCCN and msgType != ControlMessageAVP.CDN:
            self.logger.warn(
                "Cannot use a Result code AVP in non stopCCN or non CDN")
            raise l2tpv3AVPerror("Wrong parameter Type")

        if attrValue is None:
            if msgType == ControlMessageAVP.StopCCN and resultCode not in ResultCode.ResultCodeStopCCN:
                self.logger.warn("Cannot find the result code for stopCCN")
                raise l2tpv3AVPerror("Wrong parameter Type")

            if msgType == ControlMessageAVP.CDN and resultCode not in ResultCode.ResultCodeCDN:
                self.logger.warn("Cannot find the result code for CDN")
                raise l2tpv3AVPerror("Wrong parameter Type")

        self.messageType = msgType
        self.resultCode = resultCode
        self.errorCode = errorCode
        self.errorMsg = errMessage

        if attrValue is None:
            msgRet = struct.pack("!H", self.resultCode)

            if self.errorCode is not None:
                msgRet += struct.pack("!H", self.errorCode)
            if self.errorMsg is not None:
                formatStr = "!" + str(len(self.errorMsg)) + "s"
                msgRet += struct.pack(formatStr, self.errorMsg)
        else:
            msgRet = attrValue
        super(
            ResultCode, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=msgRet, MustAvp=mustAvp,
                                       HidenAVP=False)

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    @staticmethod
    def decode(buf):
        errcode = None
        errMsg = None
        retcode = 0

        if len(buf) == 2:
            retcode, = struct.unpack("!H", buf)
        elif len(buf) == 4:
            retcode, errcode = struct.unpack("!HH", buf)
        elif len(buf) > 4:
            formatStr = "!HH" + str(len(buf) - 4) + "s"
            retcode, errcode, errMsg = struct.unpack(formatStr, buf)
        else:
            raise l2tpv3AVPerror(
                "Cannot decode the return code AVP since length error.")

        return ResultCode(ControlMessageAVP.StopCCN, retcode, errcode, errMsg, True, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, ResultCode.AttrType)] = ResultCode


class ProtocolVersion(l2tpv3AVP):
    """The AVP defined in RFC2661, keep it in RFC3931."""
    AttrType = l2tpv3AVP.ProtocolVersion

    def __init__(self, version, revision, attrValue=None):

        self.version = version
        self.revision = revision
        if attrValue is None:
            retStr = struct.pack("!BB", version, revision)
        else:
            retStr = attrValue
        super(ProtocolVersion, self).__init__(
            AttrType=2, VendorID=0, AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        protocolAvp = ProtocolVersion(1, 0)
        retPak.avps.append(protocolAvp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        version, revision = struct.unpack("!BB", buf)
        return ProtocolVersion(version, revision, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, ProtocolVersion.AttrType)] = ProtocolVersion


class FrameCapabilities(l2tpv3AVP):
    """The AVP defined in RFC2661, keep it in RFC3931."""
    AttrType = l2tpv3AVP.FrameCapabilities

    def __init__(self, bitmask=0, async=False, sync=False, attrValue=None):

        if not isinstance(async, bool) or not isinstance(sync, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.async = async
        self.sync = sync
        self.bitmask = bitmask

        capability = self.bitmask << 2
        capability |= 1 if self.async else 0
        capability |= 2 if self.sync else 0
        if attrValue is None:
            retStr = struct.pack("!I", capability)
        else:
            retStr = attrValue

        super(FrameCapabilities, self).__init__(
            AttrType=3, VendorID=0, AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        frameCapAvp = FrameCapabilities(async=False, sync=False)
        retPak.avps.append(frameCapAvp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        capability, = struct.unpack("!I", buf)

        return FrameCapabilities(capability >> 2,
                                 True if capability & 0x02 else False,
                                 True if capability & 0x01 else False,
                                 attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, FrameCapabilities.AttrType)] = FrameCapabilities


class TieBreaker(l2tpv3AVP):
    AttrType = l2tpv3AVP.TieBreaker

    def __init__(self, value=""):

        if not isinstance(value, str):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        if len(value) != 8:
            msg = "Tie Breaker value shuold be 8"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.tieBreaker = value
        super(
            TieBreaker, self).__init__(AttrType=l2tpv3AVP.TieBreaker, VendorID=0, AttrValue=value, MustAvp=True,
                                       HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!8s", buf)

        return TieBreaker(value)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, TieBreaker.AttrType)] = TieBreaker


class FirmwareRevision(l2tpv3AVP):
    AttrType = l2tpv3AVP.FirmwareRevision

    def __init__(self, value=0, hiddenAvp=False, attrValue=None):

        if not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.firmwareRevision = value
        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            FirmwareRevision, self).__init__(AttrType=l2tpv3AVP.FirmwareRevision, VendorID=0, AttrValue=retStr,
                                             MustAvp=False, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        firmwareAvp = FirmwareRevision(0)
        retPak.avps.append(firmwareAvp)

        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return FirmwareRevision(value, hiddenAvp=False)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return not mustAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, FirmwareRevision.AttrType)] = FirmwareRevision


class Hostname(l2tpv3AVP):
    AttrType = l2tpv3AVP.HostName

    def __init__(self, value="", mustAvp=True):

        if not isinstance(value, str) or len(value) < 1:
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.hostname = value

        super(
            Hostname, self).__init__(AttrType=l2tpv3AVP.HostName, VendorID=0, AttrValue=value,
                                     MustAvp=mustAvp, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        hostName = Hostname("OpenRPD")
        retPak.avps.append(hostName)

        # Save the hostname in the connection info region
        connection = pkt.Connection
        connection.info["hostname"] = self.hostname

        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):

        length = len(buf)
        formatStr = "!" + str(length) + "s"
        value, = struct.unpack(formatStr, buf)

        return Hostname(value, mustAvp=True)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return not hiddenAvp


l2tpv3AVP.SubclassMapping[(l2tpv3AVP.ItefVendor, Hostname.AttrType)] = Hostname


class VendorName(l2tpv3AVP):
    AttrType = l2tpv3AVP.VendorName

    def __init__(self, value="", mustAvp=True, hiddenAvp=False):

        if not isinstance(value, str) or len(value) < 1:
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.VendorName = value

        super(
            VendorName, self).__init__(AttrType=l2tpv3AVP.VendorName, VendorID=0, AttrValue=value,
                                       MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        VnameAvp = VendorName("Cisco")
        retPak.avps.append(VnameAvp)

        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):

        length = len(buf)
        formatStr = "!" + str(length) + "s"
        value, = struct.unpack(formatStr, buf)

        return VendorName(value, mustAvp=True)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, VendorName.AttrType)] = VendorName


class ReceiveWinSize(l2tpv3AVP):
    AttrType = l2tpv3AVP.ReceivedWindowSize

    def __init__(self, value=0, mustAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.receiveWinSize = value

        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            ReceiveWinSize, self).__init__(AttrType=l2tpv3AVP.ReceivedWindowSize, VendorID=0, AttrValue=retStr,
                                           MustAvp=mustAvp, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        connection = pkt.Connection
        transport = connection.transport
        self.logger.debug(
            "Connection[%d, %d] receive window size is changed to:%d" % (connection.localConnID,
                                                                         connection.remoteConnID,
                                                                         self.receiveWinSize))
        transport.remoteWindowSize = self.receiveWinSize

        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return ReceiveWinSize(value, mustAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return (hiddenAvp == False)


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, ReceiveWinSize.AttrType)] = ReceiveWinSize


class RouterID(l2tpv3AVP):
    AttrType = l2tpv3AVP.RouterID

    def __init__(self, value=0, mustAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.routerID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            RouterID, self).__init__(AttrType=l2tpv3AVP.RouterID, VendorID=0, AttrValue=retStr,
                                     MustAvp=mustAvp, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        ridAvp = RouterID(0x7f000001)
        retPak.avps.append(ridAvp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return RouterID(value, mustAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return not hiddenAvp


l2tpv3AVP.SubclassMapping[(l2tpv3AVP.ItefVendor, RouterID.AttrType)] = RouterID


class AssignedControlConnectionID(l2tpv3AVP):
    AttrType = l2tpv3AVP.AssignedControlConnectionID

    def __init__(self, value=0, mustAvp=False, hiddenAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.connectionID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            AssignedControlConnectionID, self).__init__(AttrType=l2tpv3AVP.AssignedControlConnectionID, VendorID=0,
                                                        AttrValue=retStr,
                                                        MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        assignedCtlIDAvp = AssignedControlConnectionID(
            pkt.Connection.localConnID)
        retPak.avps.append(assignedCtlIDAvp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return AssignedControlConnectionID(value, mustAvp=False, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, AssignedControlConnectionID.AttrType)] = AssignedControlConnectionID


class PseudowireCapList(l2tpv3AVP):
    AttrType = l2tpv3AVP.PseudowireCapabilityList

    def __init__(self, value=(), mustAvp=False, hiddenAvp=False, attrValue=None):
        if not isinstance(value, tuple) or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.pseudowireList = value

        if attrValue is None:
            retStr = ""
            for cap in value:
                retStr += struct.pack("!H", cap)
        else:
            retStr = attrValue

        super(
            PseudowireCapList, self).__init__(AttrType=l2tpv3AVP.PseudowireCapabilityList, VendorID=0,
                                              AttrValue=retStr,
                                              MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        intersection_pw_cap_list = self.pseudowireList
        hal_client = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client
        if hal_client:
            pw_cap_list = hal_client.pw_cap_list
            intersection_pw_cap_list = tuple(set(pw_cap_list).intersection(set(self.pseudowireList)))
        pwAvp = PseudowireCapList(value=intersection_pw_cap_list)
        retPak.avps.append(pwAvp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):

        offset = 0
        ret = list()
        while offset < len(buf):
            value, = struct.unpack("!H", buf[offset:offset + 2])
            offset += 2
            ret.append(value)

        return PseudowireCapList(tuple(ret), mustAvp=False, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, PseudowireCapList.AttrType)] = PseudowireCapList


class CallSerialNumber(l2tpv3AVP):
    AttrType = l2tpv3AVP.CallSerialNumber

    def __init__(self, value=0, hiddenAvp=False, attrValue=None):

        if not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.serialNum = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            CallSerialNumber, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                             MustAvp=True, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return CallSerialNumber(value, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, CallSerialNumber.AttrType)] = CallSerialNumber


class SequencingRequired(l2tpv3AVP):
    AttrType = l2tpv3AVP.SequenceRequired

    def __init__(self):
        self.seqRequred = True
        super(
            SequencingRequired, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue="",
                                               MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        avp = SequencingRequired()
        retPak.avps.append(avp)

        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = False

    @staticmethod
    def decode(buf):
        return SequencingRequired()

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, SequencingRequired.AttrType)] = SequencingRequired


class LocalSessionID(l2tpv3AVP):
    AttrType = l2tpv3AVP.LocalSession

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.sessionID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            LocalSessionID, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                           MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        # check if we have a valid session for this packet
        if pkt.Session is None:
            self.logger.warn(
                "We cannot handle this AVP since session is none, pkt:%s", pkt)
            return False
        localSess = LocalSessionID(pkt.Session.localSessionId)
        retPak.avps.append(localSess)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return LocalSessionID(value, mustAvp=True, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, LocalSessionID.AttrType)] = LocalSessionID


class RemoteSessionID(l2tpv3AVP):
    AttrType = l2tpv3AVP.RemoteSession

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.sessionID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            RemoteSessionID, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                            MustAvp=mustAvp, HidenAVP=hiddenAvp)

    def encode(self):
        """Generate a buf which hold all the AVP definitions."""
        self.attrValue = struct.pack("!I", self.sessionID)
        return super(RemoteSessionID, self).encode()

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        # find th local session and put is into the remote session
        for avp in pkt.avps:
            if isinstance(avp, LocalSessionID):
                remoteAvp = RemoteSessionID(avp.sessionID)
                retPak.avps.append(remoteAvp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return RemoteSessionID(value, mustAvp=True, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, RemoteSessionID.AttrType)] = RemoteSessionID


class RemoteEndID(l2tpv3AVP):
    AttrType = l2tpv3AVP.RemoteEndID

    def __init__(self, value=(), mustAvp=True, hiddenAvp=False, attrValue=None):
        if not isinstance(value, tuple) or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)
        self.rpd_mapping = value
        if attrValue is None:
            self.attrValue = self.rpd_mapping_to_value(value)
        else:
            self.attrValue = attrValue

        super(
            RemoteEndID, self).__init__(AttrType=self.AttrType, VendorID=0,
                                        AttrValue=self.attrValue,
                                        MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @staticmethod
    def rpd_mapping_to_value(mapping=()):
        """
        :param mapping: mapping should be {(rfport, channeltype, channelindex):tag}
        :return: the struct buf

        """
        buf = ""
        buf += struct.pack("!H", 0)
        for key, value in mapping:
            rfport, channeltype, channelindex = key
            tag = value
            buf += struct.pack("!4B", rfport, channeltype, channelindex, tag)
        return buf

    def __str__(self):
        ret = AvpEncoder().default(self)
        return str(ret)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        """buf format::

          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |rf port index  |  channel type | channel index | ch id/mpts tag|
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        """
        if not buf:
            return None

        length = len(buf)
        length -= 2
        if length % 4 != 0:
            msg = "can not decode the buffer"
            raise l2tpv3AVPerror(msg)
        i = 0
        value_buf = buf[2:]
        mapping = {}
        while i < length:
            rfport, channeltype, channelindex, tag, = struct.unpack(
                '!BBBB', value_buf[i: i + 4])
            mapping[(rfport, channeltype, channelindex)] = tag
            i += 4
        ret_mapping = [(k, mapping[k]) for k in sorted(mapping.keys())]
        return RemoteEndID(value=tuple(ret_mapping), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, RemoteEndID.AttrType)] = RemoteEndID


class PseudowireType(l2tpv3AVP):
    """PseudowireType AVP."""
    MPTPW = 12
    PSPPW = 13
    pseudowiretypeset = {
        MPTPW: "MPT PseudowireType",
        PSPPW: "PSP PseudowireType",
    }
    AttrType = l2tpv3AVP.PseudowireType

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)
        if value not in PseudowireType.pseudowiretypeset:
            self.logger.warn(
                "PseudowireType type: %d is not supported" % value)
            raise l2tpv3AVPerror("PseudowireType type is not supported")

        self.pwType = value

        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            PseudowireType, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                           MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        """This is a session property, we should save the avp to depi session
        and enable the configuration in HAL."""
        if retPak is None:
            return True

        avp = PseudowireType(self.pwType, True, False)
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)
        return PseudowireType(value, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, PseudowireType.AttrType)] = PseudowireType


class L2SpecificSublayer(l2tpv3AVP):
    AttrType = l2tpv3AVP.Layer2SpecificSublayer
    MPEG_TS = 12
    MPT = 3
    PSP = 4

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.l2Sublayer = value

        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            L2SpecificSublayer, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                               MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        avp = L2SpecificSublayer(self.l2Sublayer)
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)
        return L2SpecificSublayer(value, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, L2SpecificSublayer.AttrType)] = L2SpecificSublayer


class DataSequencing(l2tpv3AVP):
    AttrType = l2tpv3AVP.DataSequence
    NOSeq = 0
    NonIPSeq = 1
    AllSeq = 2
    Explaination = {
        NOSeq: "0 - No incoming data packets require sequencing.",
        NonIPSeq: "1 - Only non-IP data packets require sequencing.",
        AllSeq: "2 - All incoming data packets require sequencing.",
    }

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool) \
                or value not in (0, 1, 2):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.sequenceFlag = value

        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            DataSequencing, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                           MustAvp=mustAvp, HidenAVP=hiddenAvp)

    def __str__(self):
        retStr = super(DataSequencing, self).__str__()
        retStr += "\nExplanation:\n" + self.Explaination[self.sequenceFlag]
        return retStr

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        avp = DataSequencing(DataSequencing.AllSeq)

        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return DataSequencing(value, mustAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, DataSequencing.AttrType)] = DataSequencing


class CircuitStatus(l2tpv3AVP):
    AttrType = l2tpv3AVP.CircuitStatus
    ActiveBit = 0
    NewBit = 1

    def __init__(self, active=True, new=True, mustAvp=False, hiddenAvp=False, attrValue=None):

        if not isinstance(active, bool) or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool) \
                or not isinstance(new, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.active = active
        self.new = new

        if attrValue is None:
            mask = 0
            if active:
                mask |= 1
            if new:
                mask |= 2

            retStr = struct.pack("!H", mask)
        else:
            retStr = attrValue

        super(
            CircuitStatus, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                          MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        avp = CircuitStatus(active=False, new=True)
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        active = True if value & 0x01 else False
        new = True if value & 0x02 else False

        return CircuitStatus(active, new, mustAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, CircuitStatus.AttrType)] = CircuitStatus



class SbfdDiscriminator(l2tpv3AVP):
    AttrType = l2tpv3AVP.SbfdDiscriminator

    def __init__(self, value=0, mustAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.discriminator = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            SbfdDiscriminator, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                           MustAvp=mustAvp, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        sbfddiscri = SbfdDiscriminator(0x11111111)
        retPak.avps.append(sbfddiscri)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return SbfdDiscriminator(value, mustAvp=True, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, SbfdDiscriminator.AttrType)] = SbfdDiscriminator

class SbfdVccv(l2tpv3AVP):
    AttrType = l2tpv3AVP.SbfdVccv
    VccvValue = 384

    def __init__(self, value=0, mustAvp=False, attrValue=None):

        if not isinstance(mustAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.vccv = value

        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            SbfdVccv, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                           MustAvp=mustAvp, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        SbfdVccvCapability = SbfdVccv(384)
        retPak.avps.append(SbfdVccvCapability)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return SbfdVccv(value, mustAvp=True, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, SbfdVccv.AttrType)] = SbfdVccv

class FailoverCapability(l2tpv3AVP):
    AttrType = l2tpv3AVP.FailoverCapability

    def __init__(self, failoverCapofCC=True, failoverCapofDC=False, recoveryTime=0, hiddenAvp=False, attrValue=None):
        if not isinstance(failoverCapofCC, bool) or not isinstance(failoverCapofDC, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        if failoverCapofCC == False and failoverCapofDC == False:
            msg = "failoverCapofCC and failoverCapofDC can't be false at the same time"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.failoverCapofCC = failoverCapofCC
        self.failoverCapofDC = failoverCapofDC
        self.recoveryTime = recoveryTime

        if attrValue == None:
            mask = 0
            if failoverCapofCC:
                mask |= 1
            if failoverCapofDC:
                mask |= 2
            retStr = struct.pack("!HI", mask, recoveryTime)
        else :
            retStr = attrValue

        super(
            FailoverCapability, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                               MustAvp=False, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        if not L2tpv3GlobalSettings.L2tpv3GlobalSettings.failoverCapofCC and not L2tpv3GlobalSettings.L2tpv3GlobalSettings.failoverCapofDC:
            return True

        if self.failoverCapofCC and L2tpv3GlobalSettings.L2tpv3GlobalSettings.failoverCapofCC:
            pkt.Connection.failoverCapofCC = True

        if self.failoverCapofDC and L2tpv3GlobalSettings.L2tpv3GlobalSettings.failoverCapofDC:
            pkt.Connection.failoverCapofDC = True

        pkt.Connection.recoveryTime =  self.recoveryTime

        avp = FailoverCapability(failoverCapofCC=L2tpv3GlobalSettings.L2tpv3GlobalSettings.failoverCapofCC,
                                 failoverCapofDC=L2tpv3GlobalSettings.L2tpv3GlobalSettings.failoverCapofDC,
                                 recoveryTime=L2tpv3GlobalSettings.L2tpv3GlobalSettings.recoveryTime)
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        flag, recoveryTime = struct.unpack("!HI", buf)

        failoverCapofCC = True if flag & 0x01 else False
        failoverCapofDC = True if flag & 0x02 else False

        return FailoverCapability(failoverCapofCC, failoverCapofDC, recoveryTime, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return not mustAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, FailoverCapability.AttrType)] = FailoverCapability

class TunnelRecovery(l2tpv3AVP):
    AttrType = l2tpv3AVP.TunnelRecovery

    def __init__(self, recoverTunnelID, recoverRemoteTunnelID, attrValue=None):
        self.recoverTunnelID = recoverTunnelID
        self.recoverRemoteTunnelID = recoverRemoteTunnelID

        if attrValue == None:
            retStr = struct.pack("!HII", 0, recoverTunnelID, recoverRemoteTunnelID)
        else :
            retStr = attrValue

        super(
            TunnelRecovery, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                               MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        _, recoverTunnelID, recoverRemoteTunnelID = struct.unpack("!HII", buf)

        return TunnelRecovery(recoverTunnelID, recoverRemoteTunnelID, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, TunnelRecovery.AttrType)] = TunnelRecovery

class SuggestedControlSequence(l2tpv3AVP):
    AttrType = l2tpv3AVP.SuggestedControlSequence

    def __init__(self, suggestedNs, suggestedNr, hiddenAvp=False, attrValue=None):
        if not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.suggestedNs = suggestedNs
        self.suggestedNr = suggestedNr

        if attrValue == None:
            retStr = struct.pack("!HII", 0, suggestedNs, suggestedNr)
        else :
            retStr = attrValue

        super(
            SuggestedControlSequence, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                                     MustAvp=False, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        #rpd doesn't support failover, will not receive this avp
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        _, suggestedNs, suggestedNr = struct.unpack("!HII", buf)

        return SuggestedControlSequence(suggestedNs, suggestedNr, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return not mustAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, SuggestedControlSequence.AttrType)] = SuggestedControlSequence

class FailoverSessionState(l2tpv3AVP):
    AttrType = l2tpv3AVP.FailoverSessionState

    def __init__(self, sessionID, remoteSessionID, hiddenAvp=False, attrValue=None):
        if not isinstance(hiddenAvp, bool):
            msg = "parameter type error"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.sessionID = sessionID
        self.remoteSessionID = remoteSessionID

        if attrValue == None:
            retStr = struct.pack("!HII", 0, sessionID, remoteSessionID)
        else :
            retStr = attrValue

        super(
            FailoverSessionState, self).__init__(AttrType=self.AttrType, VendorID=0, AttrValue=retStr,
                                                 MustAvp=False, HidenAVP=hiddenAvp)
    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        remoteSessionID = self.sessionID
        sessionID =self.remoteSessionID
        ses = pkt.Connection.findSessionByLocalSessionID(sessionID)

        if pkt.avps[0].messageType == ControlMessageAVP.FSR:
            if ses is not None:
                if remoteSessionID == 0:
                    ses.silentlyClosed = True
                    ses.CloseSession()
                elif remoteSessionID == ses.remoteSessionId and ses.stale:
                    ses.stale = False

        elif pkt.avps[0].messageType == ControlMessageAVP.FSQ:
            if retPak is None:
                return True

            if ses is None:
                sessionID = 0
            elif ses.remoteSessionId != self.sessionID:
                sessionID = 0
                ses.stale = True

            avp = FailoverSessionState(sessionID, remoteSessionID)
            retPak.avps.append(avp)

        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        _, sessionID, remoteSessionID = struct.unpack("!HII", buf)

        return FailoverSessionState(sessionID, remoteSessionID, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return not mustAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.ItefVendor, FailoverSessionState.AttrType)] = FailoverSessionState
