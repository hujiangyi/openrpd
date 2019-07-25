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

import copy
import struct
from json import JSONEncoder
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import L2tpv3CiscoAVPs
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
import vendorAVPs.src.L2tpv3VspAvps as L2tpv3VspAvps
from sets import Set
from rpd.common.rpd_logging import AddLoggerToClass

"""
   0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |T|L|x|x|S|x|x|x|x|x|x|x|  Ver  |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Control Connection ID                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Ns              |               Nr              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


class L2tpv3PacketError(Exception):
    ParameterError = "Parameter Type Error"
    BufferIsTooLow = "Buffer is too low"


class _packetEncoder(JSONEncoder):
    """Packet encoder will encode the control packet to string using json
    facility.

    The excludedFields is used to tell the encoder that don't encode
    these fields.

    """
    Excludefields = (
        "logger", "avpStr", "transport", "isZlb", "session", "Connection",
        "attrValue", "tieBreaker", "data", "remoteEndID", "ctlMsgHandler")

    def __init__(self):
        super(_packetEncoder, self).__init__(indent=4)

    def default(self, o):
        """Overwrite the original default function."""
        retDict = copy.copy(o.__dict__)

        for field in self.Excludefields:
            if field in retDict:
                retDict.pop(field)

        return retDict


class L2tpv3ControlPacket(object):
    """The l2tp control packet encoding/decoding class."""
    __metaclass__ = AddLoggerToClass
    SCCRQMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.Hostname,
        L2tpv3RFC3931AVPs.RouterID,
        L2tpv3RFC3931AVPs.AssignedControlConnectionID,
        L2tpv3RFC3931AVPs.PseudowireCapList,
    ))

    SCCRPMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.Hostname,
        L2tpv3RFC3931AVPs.RouterID,
        L2tpv3RFC3931AVPs.AssignedControlConnectionID,
        L2tpv3RFC3931AVPs.PseudowireCapList,
    ))

    SCCCNMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
    ))

    StopCCNMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.ResultCode,
    ))

    HELLOMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
    ))

    ICRQMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.LocalSessionID,
        L2tpv3RFC3931AVPs.RemoteSessionID,
        L2tpv3RFC3931AVPs.CallSerialNumber,
        L2tpv3RFC3931AVPs.PseudowireType,
        L2tpv3RFC3931AVPs.RemoteEndID,
        L2tpv3RFC3931AVPs.L2SpecificSublayer,
        L2tpv3RFC3931AVPs.CircuitStatus,
    ))

    ICRPMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.LocalSessionID,
        L2tpv3RFC3931AVPs.RemoteSessionID,
        L2tpv3RFC3931AVPs.CircuitStatus,
        L2tpv3RFC3931AVPs.L2SpecificSublayer,
        L2tpv3RFC3931AVPs.DataSequencing
    ))

    ICCNMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.LocalSessionID,
        L2tpv3RFC3931AVPs.RemoteSessionID,
    ))

    SLIMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.LocalSessionID,
        L2tpv3RFC3931AVPs.RemoteSessionID,
    ))
    CDNMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.LocalSessionID,
        L2tpv3RFC3931AVPs.RemoteSessionID,
        L2tpv3RFC3931AVPs.ResultCode,
    ))

    FSQMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
    ))

    FSRMandatoryAVPs = Set((
        L2tpv3RFC3931AVPs.ControlMessageAVP,
    ))

    def __init__(self, remoteConnID=0, Ns=0, Nr=0, avps=(), avpValueStr=None):
        """Init the basic elem to construct a control packet.

        :param remoteConnID: the remote conneciton ID, it is used to fill the control message header.
        :param Ns: The ns field of the control message, please note that, you can ignore this field, since the transport
         will rewrite this field when sending the packet out.
        :param Nr: The nr field in control message.
        :param avps: the packet supported AVP, all the avp in this tuple will be encoded.
        :param avpValueStr: This is a pre-encoded string, if this field is not None, we will bypass the AVP encoded
         procedure.

        """
        if not isinstance(avps, tuple) and not isinstance(avps, list):
            self.logger.warn(
                L2tpv3PacketError.ParameterError + ", the avp is not a tuple or list.")
            raise L2tpv3PacketError(L2tpv3PacketError.ParameterError)

        # The connection ID here is the remote connection ID
        self.connectionID = remoteConnID
        self.ns = Ns
        self.nr = Nr

        if isinstance(avps, tuple):
            self.avps = list(avps)
        else:
            self.avps = avps

        if avpValueStr is not None:
            avpStr = avpValueStr
        else:
            avpStr = ""
            for avp in avps:
                avpStr += avp.encode()

        self.length = 12 + \
            len(avpStr)  # 12 means the control message header len.
        self.avpStr = avpStr

        # if it is a ZLB control packet
        self.isZlb = False

        self.Session = None
        self.Connection = None
        self.transport = None

    def __str__(self):
        """Encoding this control packet into a json style stirng."""
        return _packetEncoder().encode(self)

    def encode(self, reGenerateAvpStr=False):
        """the control packet encoding function. This function will encode the
        control message header and all the AVPs.

        :param reGenerateAvpStr: we can use the pre-encoded avp str instead of re-generate string.
        :return: encoding str, not including the session ID, the kernel will add it for us.

        """
        flags = 0x8000 | 0x4000 | 0x0800 | 0x03
        if reGenerateAvpStr:
            # Generate the new avpStr
            avpStr = ""
            for avp in self.avps:
                avpStr += avp.encode()

            self.avpStr = avpStr
            self.length = 12 + len(avpStr)
        formatStr = "!HHIHH" + str(self.length - 12) + "s"
        return struct.pack(formatStr, flags, self.length, self.connectionID, self.ns, self.nr, self.avpStr)

    def SetPktConnection(self, connection):
        self.logger.debug("Set packet to connection:[%d, %d]" % (
            connection.localConnID, connection.remoteConnID))
        self.Connection = connection

    def SetPktSession(self, session):
        self.logger.debug("Set packet to session[%d, %d]" % (
            session.localSessionId, session.remoteSessionId))
        self.Session = session

    def SetPacketTransport(self, transport):
        self.transport = transport

    @staticmethod
    def decode(buf):
        """Decode a str to control packet. Also the function will invoke the
        AVp's decode function.After this function, all the AVP will be also
        decoded.

        :param buf: Original packet received from from wire.
        :return: a decoded control packet.

        """
        if len(buf) < 12:
            raise L2tpv3PacketError(L2tpv3PacketError.BufferIsTooLow)
        # Get the header fields

        _, length, conn, ns, nr = struct.unpack("!HHIHH", buf[:12])
        if length > len(buf):
            raise L2tpv3PacketError(L2tpv3PacketError.BufferIsTooLow)

        # decode the avps
        avps = l2tpv3AVP.decodeAll(buf[12:length])

        # Genreate the packets
        pkt = L2tpv3ControlPacket(conn, ns, nr, avps, buf[12:length])

        if len(avps) == 0:
            pkt.isZlb = True

        if len(avps) > 0 and \
                isinstance(avps[0], L2tpv3RFC3931AVPs.ControlMessageAVP) and\
                avps[0].messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.ACK:
            pkt.isZlb = True

        return pkt

    def GetLocalConnectionID(self):
        return self.connectionID

    def GetRemoteConnectionID(self):
        # We should get the connection from the AVP
        for avp in self.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.AssignedControlConnectionID):
                return avp.connectionID, True

        return None, False

    def isRecoveryTunnelSCCRQ(self):
        # to distinguish normal and recovery tunnel
        if self.isZlb or not isinstance(self.avps[0], L2tpv3RFC3931AVPs.ControlMessageAVP):
            return False, 0, 0

        if len(self.avps) > 1:
            if self.avps[0].messageType != L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRQ:
                return False, 0, 0

            for avp in self.avps[1:]:
                if isinstance(avp, L2tpv3RFC3931AVPs.TunnelRecovery):
                    return True, avp.recoverRemoteTunnelID, avp.recoverTunnelID

        return False, 0, 0

    def isFSR(self):
        if self.isZlb or not isinstance(self.avps[0], L2tpv3RFC3931AVPs.ControlMessageAVP):
            return False

        if self.avps[0].messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.FSR:
            return True

        return False


class L2tpv3ZLB(L2tpv3ControlPacket):
    """A wrapper to construct a ZLB packet."""

    def __init__(self, connectionID=0, Ns=0, Nr=0):
        super(L2tpv3ZLB, self).__init__(
            connectionID, Ns, Nr, avps=tuple(), avpValueStr=None)
        self.isZlb = True


class l2tpV3TerminatePkt(L2tpv3ControlPacket):
    """Base class for CDN and StopCCN."""

    def __init__(self, msgType, connID, resultCode, errCode, errMsg):
        stopAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(msgType)
        retcode = L2tpv3RFC3931AVPs.ResultCode(
            L2tpv3RFC3931AVPs.ControlMessageAVP.StopCCN, resultCode, errCode, errMsg)
        super(l2tpV3TerminatePkt, self).__init__(
            remoteConnID=connID, avps=(stopAvp, retcode))


class L2tpv3StopCCN(l2tpV3TerminatePkt):
    """A wrapper to construct a StopCCN packet."""

    def __init__(self, connection, resultCode, errCode, errMsg):
        super(
            L2tpv3StopCCN, self).__init__(L2tpv3RFC3931AVPs.ControlMessageAVP.StopCCN, connection.remoteConnID,
                                          resultCode, errCode, errMsg)
        assignedConnectionAvp = L2tpv3RFC3931AVPs.AssignedControlConnectionID(
            connection.localConnID)
        self.avps.append(assignedConnectionAvp)


class L2tpv3CDN(l2tpV3TerminatePkt):
    """A wrapper to construct a CDN packet."""

    def __init__(self, session, resultCode, errCode, errMsg):
        connection = session.connection
        super(
            L2tpv3CDN, self).__init__(L2tpv3RFC3931AVPs.ControlMessageAVP.CDN, connection.remoteConnID,
                                      resultCode, errCode, errMsg)
        localSessionID = session.localSessionId
        remoteSessionID = session.remoteSessionId

        localAvp = L2tpv3RFC3931AVPs.LocalSessionID(localSessionID)
        remoteAvp = L2tpv3RFC3931AVPs.RemoteSessionID(remoteSessionID)
        self.avps.append(localAvp)
        self.avps.append(remoteAvp)


class L2tpv3Hello(L2tpv3ControlPacket):
    """A wrapper to construct a HELLO packet."""

    def __init__(self, connID):
        helloavp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.HELLO)
        super(L2tpv3Hello, self).__init__(
            remoteConnID=connID, avps=(helloavp,))


class L2tpv3ACK(L2tpv3ControlPacket):
    """A wrapper to construct a ACK packet."""

    def __init__(self, connID):
        ackavp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.ACK)
        super(L2tpv3ACK, self).__init__(
            remoteConnID=connID, avps=(ackavp,))
        self.isZlb = True
