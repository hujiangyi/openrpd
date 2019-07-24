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

"""This file defines the rpd l2Tp supported RFC3991 AVPs, currently, the
following AVP wil be supported:

* Local Session /Cisco
* Remote Session /Cisco
* PesudoWire Type /Cisco
* Session Tie Breaker /Cisco
* Assigned Connection ID AVP / Cisco
* Pseudowire
  Capability List /Cisco
* Draft AVP version /Cisco

"""

import struct

from L2tpv3AVP import addDebugLogToHandle
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror


class SessionTieBreakerCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.SessionTieBreakerCisco

    def __init__(self, value=""):
        if not isinstance(value, str):
            msg = "parameter type error, value type is %s, expected:str" % str(value)
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        if len(value) != 8:
            msg = "Tie Breaker value length should be 8, real length:%d" % len(value)
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.tieBreaker = value
        super(
            SessionTieBreakerCisco, self).__init__(AttrType=self.SessionTieBreakerCisco, VendorID=self.CiscoVendor,
                                                   AttrValue=value, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!8s", buf)

        return SessionTieBreakerCisco(value)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, SessionTieBreakerCisco.AttrType)] = SessionTieBreakerCisco


class AssignedConnectionIDCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.AssignedControlConnectionIDCisco

    def __init__(self, value=0, mustAvp=False, hiddenAvp=False, attrValue=None):

        if (not isinstance(value, int) and not isinstance(value, long))\
                or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error, value type: %s, mustAVP type:%s , hiddenAVP error:%s." %(
                type(value), type(mustAvp), type(hiddenAvp)
            )
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.connectionID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            AssignedConnectionIDCisco, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CiscoVendor,
                                                      AttrValue=retStr, MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        connection = pkt.Connection
        localConnID = connection.localConnID
        avp = AssignedConnectionIDCisco(localConnID)
        retPak.avps.append(avp)

        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return AssignedConnectionIDCisco(value, mustAvp=False, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, AssignedConnectionIDCisco.AttrType)] = AssignedConnectionIDCisco


class PseudowireCapListCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.PseudowireCapabilityListCisco

    def __init__(self, value=(), mustAvp=False, hiddenAvp=False, attrValue=None):

        if not isinstance(value, tuple) or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error, value type: %s, mustAVP type:%s , hiddenAVP error:%s." %(
                type(value), type(mustAvp), type(hiddenAvp)
            )
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
            PseudowireCapListCisco, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CiscoVendor,
                                                   AttrValue=retStr, MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        avp = PseudowireCapListCisco((12,))
        retPak.avps.append(avp)

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

        return PseudowireCapListCisco(tuple(ret), mustAvp=False, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, PseudowireCapListCisco.AttrType)] = PseudowireCapListCisco


class LocalSessionIDCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.LocalSessionCisco

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if (not isinstance(value, int) and not isinstance(value, long)) \
                or not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool):
            msg = "parameter type error, value type: %s, mustAVP type:%s , hiddenAVP error:%s." %(
                type(value), type(mustAvp), type(hiddenAvp)
            )
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.sessionID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            LocalSessionIDCisco, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CiscoVendor,
                                                AttrValue=retStr,
                                                MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        # check if we have a valid session for this packet
        if pkt.Session is None:
            self.logger.warn("We cannot handle this AVP for None session, pkt:%s", str(pkt))
            return False
        localSess = LocalSessionIDCisco(pkt.Session.localSessionId)
        retPak.avps.append(localSess)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return LocalSessionIDCisco(value, mustAvp=True, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, LocalSessionIDCisco.AttrType)] = LocalSessionIDCisco


class RemoteSessionIDCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.RemoteSessionCisco

    def __init__(self, value=0, mustAvp=True, hiddenAvp=False, attrValue=None):

        if (not isinstance(value, int) and not isinstance(value, long))\
                or not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool):
            msg = "parameter type error, value type: %s, mustAVP type:%s , hiddenAVP error:%s." %(
                type(value), type(mustAvp), type(hiddenAvp)
            )
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.sessionID = value

        if attrValue is None:
            retStr = struct.pack("!I", value)
        else:
            retStr = attrValue

        super(
            RemoteSessionIDCisco, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CiscoVendor,
                                                 AttrValue=retStr,
                                                 MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        # find th local session and put is into the remote session
        for avp in pkt.avps:
            if isinstance(avp, LocalSessionIDCisco):
                remoteAvp = RemoteSessionIDCisco(avp.sessionID)
                retPak.avps.append(remoteAvp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!I", buf)

        return RemoteSessionIDCisco(value, mustAvp=True, hiddenAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, RemoteSessionIDCisco.AttrType)] = RemoteSessionIDCisco


class PseudowireTypeCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.PseudowireTypeCisco

    def __init__(self, value=0, mustAvp=False, hiddenAvp=False, attrValue=None):

        if (not isinstance(value, int) and not isinstance(value, long)) \
                or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool):
            msg = "parameter type error, value type: %s, mustAVP type:%s , hiddenAVP error:%s." %(
                type(value), type(mustAvp), type(hiddenAvp)
            )
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.pwType = value

        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            PseudowireTypeCisco, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CiscoVendor,
                                                AttrValue=retStr,
                                                MustAvp=mustAvp, HidenAVP=hiddenAvp)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return PseudowireTypeCisco(value, mustAvp=False, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, PseudowireTypeCisco.AttrType)] = PseudowireTypeCisco


class DraftAVPVersionCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.DraftAvpVersionCisco

    def __init__(self, value=0, attrValue=None):

        if not isinstance(value, int) and not isinstance(value, long):
            msg = "parameter type error, value type: %s" %type(value)
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.firmwareRevision = value
        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            DraftAVPVersionCisco, self).__init__(AttrType=l2tpv3AVP.DraftAvpVersionCisco,
                                                 VendorID=l2tpv3AVP.CiscoVendor,
                                                 AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        avp = DraftAVPVersionCisco(1)
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return DraftAVPVersionCisco(value)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, DraftAVPVersionCisco.AttrType)] = DraftAVPVersionCisco


class DepiMcmtsSimplificationCisco(l2tpv3AVP):
    AttrType = l2tpv3AVP.DepiMcmtsSimplificationCisco

    def __init__(self, typeDef, version, value, attrValue=None):

        if not isinstance(value, str) \
                or (not isinstance(typeDef, int) and not isinstance(typeDef, long))\
                or (not isinstance(version, int) and not isinstance(version, long)):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.type = typeDef
        self.version = version
        self.dataLen = len(value)
        self.data = value

        if attrValue is None:
            formatStr = "!BBB" + str(len(value)) + "s"
            retStr = struct.pack(
                formatStr, typeDef, version, len(value), value)
        else:
            retStr = attrValue

        super(
            DepiMcmtsSimplificationCisco, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CiscoVendor,
                                                         AttrValue=retStr, MustAvp=False, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        avp = DepiMcmtsSimplificationCisco(0, 0, '\x01')
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = False
        self.hiddenAvp = False

    @staticmethod
    def decode(buf):

        formatStr = "!BBB" + str(len(buf) - 3) + "s"
        t, ver, l, value = struct.unpack(formatStr, buf)

        return DepiMcmtsSimplificationCisco(t, ver, value, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return True


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CiscoVendor, DepiMcmtsSimplificationCisco.AttrType)] = DepiMcmtsSimplificationCisco
