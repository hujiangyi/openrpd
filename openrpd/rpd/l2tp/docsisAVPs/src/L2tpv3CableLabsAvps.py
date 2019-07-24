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
"""
This file defines the rpd l2Tp supported cable labs AVP, currently, the following AVP wil be supported:

Please add all your suported AVP here
"""

from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror, addDebugLogToHandle
import struct
import socket
from docsisAVPs.src.L2tpv3CableLabsDef import l2tpV3CablelabsAVPDef
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings


class LocalMTUCableLabs(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.LocalMTU

    def __init__(self, value=0, attrValue=None):

        if not isinstance(value, int) and not isinstance(value, long):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.localMTU = value
        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            LocalMTUCableLabs, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CableLabsVendor,
                                              AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        remote_mtu = self.localMTU
        hal_client = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client
        if hal_client:
            remote_mtu = hal_client.mtu_payload
        avp = RemoteMTUCableLabs(value=remote_mtu)
        retPak.avps.append(avp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return LocalMTUCableLabs(value=value, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, LocalMTUCableLabs.AttrType)] = LocalMTUCableLabs


class RemoteMTUCableLabs(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.RemoteMTU

    def __init__(self, value=0, attrValue=None):

        if not isinstance(value, int) and not isinstance(value, long):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.localMTU = value
        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            RemoteMTUCableLabs, self).__init__(AttrType=self.AttrType, VendorID=l2tpv3AVP.CableLabsVendor,
                                               AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        value, = struct.unpack("!H", buf)

        return RemoteMTUCableLabs(value=value, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, RemoteMTUCableLabs.AttrType)] = RemoteMTUCableLabs


# Will set to zero
class DepiResourceAllocReq(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.ResourceAllocReq

    def __init__(self, value=(), attrValue=None):

        if not isinstance(value, tuple):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.allocas = value  # with PHB, Flow
        if attrValue is None:
            retStr = ""
            for phb, flowid in value:
                retStr += struct.pack("!BB", phb, flowid)
        else:
            retStr = attrValue

        super(DepiResourceAllocReq, self).__init__(AttrType=self.AttrType,
                                                   VendorID=l2tpv3AVP.CableLabsVendor,
                                                   AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, originPkt, retPak):

        if retPak is None:
            return True
        self.logger.debug(
            "Processing the Depi resource allocation request:%s", retPak)
        avps = retPak.avps

        rsp = DepiResourceAllocReplyCableLabs(value=self.allocas)
        avps.append(rsp)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        # skip the reserved
        offset = 0
        if len(buf) % 2 or not len(buf):
            msg = "parameter length error, expect 2xn current is %d" % len(buf)
            raise l2tpv3AVPerror(msg)
        ret = list()
        while offset < len(buf):
            phb, flow = struct.unpack("!BB", buf[offset:offset + 2])
            offset += 2
            phb = phb & 0x3f
            flow = flow & 0x03
            ret.append((phb, flow))
        return DepiResourceAllocReq(value=tuple(ret), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiResourceAllocReq.AttrType)] = DepiResourceAllocReq


class DepiResourceAllocReplyCableLabs(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.ResourceAllocReply

    def __init__(self, value=(), attrValue=None):

        if not isinstance(value, tuple):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.allocas = value  # with PHB, Flow
        if attrValue is None:
            retStr = ""
            for phb, flowid in value:
                retStr += struct.pack("!BB", phb, flowid)
        else:
            retStr = attrValue

        super(
            DepiResourceAllocReplyCableLabs, self).__init__(AttrType=self.AttrType,
                                                            VendorID=l2tpv3AVP.CableLabsVendor,
                                                            AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        offset = 0
        ret = list()
        while offset < len(buf):
            phb, flow = struct.unpack("!BB", buf[offset:offset + 2])
            offset += 2
            phb = phb & 0x3f
            flow = flow & 0x03
            ret.append((phb, flow))
        return DepiResourceAllocReplyCableLabs(value=tuple(ret), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiResourceAllocReplyCableLabs.AttrType)] = DepiResourceAllocReplyCableLabs


class DepiPseudowireSubtypeCapList(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.DEPIPseudowireSubtypeCapList

    def __init__(self, value=(), attrValue=None):

        if not isinstance(value, tuple):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.pw_list = value
        if attrValue is None:
            retStr = ""
            for key in value:
                pw_type = key
                retStr += struct.pack("!H", pw_type)
        else:
            retStr = attrValue

        super(
            DepiPseudowireSubtypeCapList, self).__init__(AttrType=self.AttrType,
                                                         VendorID=l2tpv3AVP.CableLabsVendor,
                                                         AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        intersection_pw_cap_list = self.pw_list
        hal_client = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client
        if hal_client:
            sublayer_pw_cap_list = hal_client.sublayer_pw_cap_list
            intersection_pw_cap_list = tuple(set(sublayer_pw_cap_list).intersection(set(self.pw_list)))
        ret_caplist = DepiPseudowireSubtypeCapList(value=intersection_pw_cap_list)
        retPak.avps.append(ret_caplist)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        ret = list()
        offset = 0
        while offset < len(buf):
            pw_type, = struct.unpack("!H", buf[offset:offset + 2])
            offset += 2
            ret.append(pw_type)
        return DepiPseudowireSubtypeCapList(value=tuple(ret), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiPseudowireSubtypeCapList.AttrType)] = DepiPseudowireSubtypeCapList


class DepiPseudowireSubtype(l2tpv3AVP):
    MAX_SUBTYPE_VALUE = 22
    AttrType = l2tpV3CablelabsAVPDef.DEPIPseudowireSubtype

    def __init__(self, value=0, attrValue=None):

        if value > DepiPseudowireSubtype.MAX_SUBTYPE_VALUE:
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.pw_type = value
        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            DepiPseudowireSubtype, self).__init__(AttrType=self.AttrType,
                                                  VendorID=l2tpv3AVP.CableLabsVendor,
                                                  AttrValue=retStr, MustAvp=False, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        pw_type, = struct.unpack("!H", buf)
        return DepiPseudowireSubtype(value=pw_type, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiPseudowireSubtype.AttrType)] = DepiPseudowireSubtype


class DepiL2SpecificSublayerSubtype(l2tpv3AVP):
    MAX_SUBTYPE_VALUE = 22
    AttrType = l2tpV3CablelabsAVPDef.DEPIL2SpecificSublayerSubtype

    def __init__(self, value=0, attrValue=None):

        if value > DepiL2SpecificSublayerSubtype.MAX_SUBTYPE_VALUE:
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.pw_type = value
        if attrValue is None:
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        super(
            DepiL2SpecificSublayerSubtype, self).__init__(AttrType=self.AttrType,
                                                          VendorID=l2tpv3AVP.CableLabsVendor,
                                                          AttrValue=retStr, MustAvp=False, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        depi_l2_subtype = DepiL2SpecificSublayerSubtype(self.pw_type)
        retPak.avps.append(depi_l2_subtype)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        pw_type, = struct.unpack("!H", buf)
        return DepiL2SpecificSublayerSubtype(value=pw_type, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiL2SpecificSublayerSubtype.AttrType)] = DepiL2SpecificSublayerSubtype


class DepiMulticastCapability(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.DEPIMulticastCapability

    def __init__(self, value=True, attrValue=None):

        if not isinstance(value, bool):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.mcast_capable = value
        if attrValue is None:
            data = 0x8000 if self.mcast_capable else 0
            retStr = struct.pack("!H", data)
        else:
            retStr = attrValue

        super(
            DepiMulticastCapability, self).__init__(AttrType=self.AttrType,
                                                    VendorID=l2tpv3AVP.CableLabsVendor,
                                                    AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True
        mcast_cap = True
        hal_client = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client
        if hal_client:
            mcast_cap = hal_client.mcast_cap
        depi_mcast_cap = DepiMulticastCapability(value=mcast_cap)
        retPak.avps.append(depi_mcast_cap)
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        mcast_cap_char, = struct.unpack("B", buf[0])
        mcast_cap = True if mcast_cap_char & 0x80 else False
        return DepiMulticastCapability(value=mcast_cap, attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiMulticastCapability.AttrType)] = DepiMulticastCapability


class DepiRemoteMulticastJoin(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.DEPIRemoteMulticastJoin

    def __init__(self, value=(), attrValue=None):

        if not isinstance(value, tuple) or len(value) != 2:
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)
        src_ip, group_ip, = value
        grp_addrinfo = socket.getaddrinfo(group_ip, None)[0]
        src_addrinfo = socket.getaddrinfo(src_ip, None)[0]
        family = grp_addrinfo[0]
        self.src_ip = src_addrinfo[4][0]
        self.group_ip = grp_addrinfo[4][0]
        if attrValue is None:
            if family == socket.AF_INET:
                src_ip, = struct.unpack("!L", socket.inet_aton(self.src_ip))
                group_ip, = struct.unpack("!L", socket.inet_aton(self.group_ip))
                retStr = struct.pack(
                    "!H4L4L", 0, src_ip, 0, 0, 0, group_ip, 0, 0, 0)
            else:
                grp_bin = socket.inet_pton(grp_addrinfo[0], grp_addrinfo[4][0])
                src_bin = socket.inet_pton(src_addrinfo[0], src_addrinfo[4][0])
                retStr = struct.pack("!H",0) + src_bin + grp_bin
        else:
            retStr = attrValue

        super(
            DepiRemoteMulticastJoin, self).__init__(AttrType=self.AttrType,
                                                    VendorID=l2tpv3AVP.CableLabsVendor,
                                                    AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        if len(buf) != 34:
            msg = "parameter length error, expect 34 current is %d" % len(buf)
            raise l2tpv3AVPerror(msg)
        data = struct.unpack("!3L", buf[6:18])
        data1 = struct.unpack("!3L", buf[22:40])

        if data == data1 == (0, 0, 0):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6
        if family == socket.AF_INET:
            src_ip = socket.inet_ntop(family, buf[2:6])
            group_ip = socket.inet_ntop(family, buf[18:22])
        else:
            src_ip = socket.inet_ntop(family, buf[2:18])
            group_ip = socket.inet_ntop(family, buf[18:40])

        return DepiRemoteMulticastJoin(value=(src_ip, group_ip), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiRemoteMulticastJoin.AttrType)] = DepiRemoteMulticastJoin


class DepiRemoteMulticastLeave(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.DEPIRemoteMulticastLeave

    def __init__(self, value=(), attrValue=None):

        if not isinstance(value, tuple) or len(value) != 2:
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)
        src_ip, group_ip, = value
        grp_addrinfo = socket.getaddrinfo(group_ip, None)[0]
        src_addrinfo = socket.getaddrinfo(src_ip, None)[0]
        family = grp_addrinfo[0]
        self.src_ip = src_addrinfo[4][0]
        self.group_ip = grp_addrinfo[4][0]
        if attrValue is None:
            if family == socket.AF_INET:
                src_ip, = struct.unpack("!L", socket.inet_aton(self.src_ip))
                group_ip, = struct.unpack("!L", socket.inet_aton(self.group_ip))
                retStr = struct.pack(
                    "!H4L4L", 0, src_ip, 0, 0, 0, group_ip, 0, 0, 0)
            else:
                grp_bin = socket.inet_pton(grp_addrinfo[0], grp_addrinfo[4][0])
                src_bin = socket.inet_pton(src_addrinfo[0], src_addrinfo[4][0])
                retStr = struct.pack("!H",0) + src_bin + grp_bin
        else:
            retStr = attrValue

        super(
            DepiRemoteMulticastLeave, self).__init__(AttrType=self.AttrType,
                                                     VendorID=l2tpv3AVP.CableLabsVendor,
                                                     AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, pkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        if len(buf) != 34:
            msg = "parameter length error, expect 34 current is %d" % len(buf)
            raise l2tpv3AVPerror(msg)
        data = struct.unpack("!3L", buf[6:18])
        data1 = struct.unpack("!3L", buf[22:40])

        if data == data1 == (0, 0, 0):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6
        if family == socket.AF_INET:
            src_ip = socket.inet_ntop(family, buf[2:6])
            group_ip = socket.inet_ntop(family, buf[18:22])
        else:
            src_ip = socket.inet_ntop(family, buf[2:18])
            group_ip = socket.inet_ntop(family, buf[18:40])
        return DepiRemoteMulticastLeave(value=(src_ip, group_ip), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, DepiRemoteMulticastLeave.AttrType)] = DepiRemoteMulticastLeave


# Will set to zero
class UpstreamFlow(l2tpv3AVP):
    AttrType = l2tpV3CablelabsAVPDef.UpstreamFlow

    def __init__(self, value=(), attrValue=None):

        if not isinstance(value, tuple):
            msg = "parameter type error"
            raise l2tpv3AVPerror(msg)

        self.allocas = value  # with PHB, Flow
        if attrValue is None:
            retStr = ""
            for phb, flowid in value:
                retStr += struct.pack("!BB", phb, flowid)
        else:
            retStr = attrValue

        super(UpstreamFlow, self).__init__(AttrType=self.AttrType,
                                                   VendorID=l2tpv3AVP.CableLabsVendor,
                                                   AttrValue=retStr, MustAvp=True, HidenAVP=False)

    @addDebugLogToHandle
    def handleAvp(self, originPkt, retPak):
        return True

    def SetFlags(self, mustAvp=True, hiddenAvp=False):
        self.mustAvp = True
        self.hiddenAvp = hiddenAvp

    @staticmethod
    def decode(buf):
        # skip the reserved
        offset = 0
        if len(buf) % 2 or not len(buf):
            msg = "parameter length error, expect 2xn current is %d" % len(buf)
            raise l2tpv3AVPerror(msg)
        ret = list()
        while offset < len(buf):
            phb, flow = struct.unpack("!BB", buf[offset:offset + 2])
            offset += 2
            phb = phb & 0x3f
            flow = flow & 0x03
            ret.append((phb, flow))
        return UpstreamFlow(value=tuple(ret), attrValue=buf)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp


l2tpv3AVP.SubclassMapping[
    (l2tpv3AVP.CableLabsVendor, UpstreamFlow.AttrType)] = UpstreamFlow
