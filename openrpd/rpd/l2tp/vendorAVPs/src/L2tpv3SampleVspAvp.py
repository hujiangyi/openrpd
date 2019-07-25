#
# Copyright (c) 2016 Cisco and/or its affiliates,
#                    MaxLinear, Inc. ("MaxLinear"), and
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
This file should be used as a base class for vendors to add their Vendor Specific AVPs.
Note that AttributeValue of these AVPs are 'Vendor-specifically' interpreted 

"""

#import rpd.python_path_resolver
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror, addDebugLogToHandle
import l2tpv3.src.L2tpv3VspAvp_pb2 as L2tpv3VspAvp_pb2
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP
import struct
import socket

from rpd.common.rpd_logging import AddLoggerToClass
#
# Macros:
#
STANDARD_AVP_HEADER_LEN = 6
# Vendor's own assigned ID
DEFAULT_VENDOR_ID = 5555

# Some limitations:
MAX_ATTRIBUTE_VALUE = 100       # Attribute Type range [0,100].
MAX_ATTRIBUTE_STR_LEN = 100       # No more than 100 bytes.

# Enums: use with Update option flag
DONOT_UPDATE = 0    # attribute value cannot be udpated by OpenRPD driver via t_l2tpVspAvpMsg()
ALLOW_UPDATE = 1    # attribute value can be udpated by OpenRPD driver via t_l2tpVspAvpMsg()

# Enums: use with Notification option flag
NOTIFY_OPTION_OFF = 0    # Don't notify OpenRPD Driver if VSP AVPs are on received control packets.
NOTIFY_OPTION_ON = 1    # Notify OpenRPD Driver if VSP AVPs are on received control packets (HalNotification)
NOTIFY_OPTION_ON_WITH_CONFIRM = 2    # Notify OpenRPD Driver if VSP AVPs are on received control packets (HalConfig/HalConfigRsp)


class l2tpv3SampleVendorAvp(l2tpv3AVP):
    """

    This is a generic class for Vendor to add their own AVPs.
    Detail implementation/format of AVP Attribute Value is moved out to vendor side.
    For example, this class knows only how many bytes to pack/unpack.
    Thus, the vendor must prepare AVP Attribute Value buffer format.

    """
    VendorID = DEFAULT_VENDOR_ID  #
    AttrType = 0                  # each AVP should have a unique AttrType

    def __init__(self, vid, attrType,
                 UpdateOpt=DONOT_UPDATE,
                 notifyVendor=NOTIFY_OPTION_OFF,
                 OutCtrlIds=[],
                 attrValue=None):
        """

        This functions create l2tpv3SampleVendorAvp object which inherites l2tpv3AVP.

        : param vid: Vendor ID of the AVP
        : param attrType: Attribute of the AVP.
        : param UpdateOpt: [DONOT_UPDATE/ALLOW_UPDATE] Control if attrValue of the AVP 
                                can be changed at runtime.
        : param notifyVendor: [NOTIFY_OPTION_OFF/NOTIFY_OPTION_ON/NOTIFY_OPTION_ON_WITH_CONFIRM]
                                Control if Vendor wants to be notified if this AVP is in
                                the received control packet.
                                If notification is ON, whether to signal Vendor using HalNotification
                                or HalConfig/HalConfigRsp mechanism
        : param OutCtrlIds: [] a list of RFC3931 message codes that this AVP should be included when 
                                L2TP sends out a Control packet.  If the list is empty, then no inclusion.

        : return: 

        """

        if (attrType > MAX_ATTRIBUTE_VALUE or (attrType < 0) or not isinstance(attrType, int)) \
                or (not isinstance(vid, int)):
            msg = "parameter type error (vid:%d attrType:%d)" % (vid, attrType)
            raise l2tpv3AVPerror(msg)

        if not isinstance(OutCtrlIds, list):
            msg = "parameter type error (outCtrlPkts must be a list)"
            raise l2tpv3AVPerror(msg)

        VendorID = vid
        AttrType = attrType
        self.updateOpt = UpdateOpt         # buffer of AVP (attrValue) need to be updated at boot time.
        self.notifyVendorOpt = notifyVendor   # If this AVP is in a packet sent from the other side, notify Vendor about it with attrValue
        self.OutCtrlIdList = OutCtrlIds
        if attrValue is None:
            value = 0
            retStr = struct.pack("!H", value)
        else:
            retStr = attrValue

        if (len(retStr) > MAX_ATTRIBUTE_STR_LEN):
            msg = "Attribute buffer length is too long (%d > %d)" % (self.length, MAX_ATTRIBUTE_STR_LEN)
            raise l2tpv3AVPerror(msg)

        super(
            l2tpv3SampleVendorAvp, self).__init__(AttrType=attrType,
                                                  VendorID=vid,
                                                  AttrValue=retStr,
                                                  MustAvp=False, HidenAVP=False)

    @addDebugLogToHandle
    # This function creates a local AVP and append it to the 'retPak',
    # only if the return packet (retPak) has a messageType that is in
    # the OutCtrlIdList of the AVP.
    #
    def handleAvp(self, pkt, retPak):
        if retPak is None:
            return True

        # find the control message type, and if it is in the OutCtrlIdList,
        # append it.  Otherwise, do nothing
        ctrlPktNumber = 0xFFFF
        for avp in retPak.avps:
            if isinstance(avp, ControlMessageAVP):
                ctrlPktNumber = avp.messageType
                break

        if ctrlPktNumber in self.OutCtrlIdList:
            # print "insert it: %d" % ctrlPktNumber
            sampleAvp = l2tpv3SampleVendorAvp(self.vendorID, self.attrType,
                                              self.updateOpt,
                                              self.notifyVendorOpt,
                                              self.OutCtrlIdList,
                                              self.attrValue)
            retPak.avps.append(sampleAvp)
        return True

    def SetFlags(self, mustAvp=False, hiddenAvp=False):
        self.mustAvp = mustAvp
        self.hiddenAvp = hiddenAvp

    #@staticmethod
    # This function returns the AVP with new attrValue from the buffer 'buf'
    # Can be used to update from Vendor.
    def decode(self, buf):
        if len(buf) != (self.length - STANDARD_AVP_HEADER_LEN):
            raise l2tpv3AVPerror("Invalid attribute len: %d %d" % (len(buf), self.length))
        formatStr = str(self.length - STANDARD_AVP_HEADER_LEN) + "B"
        attrValue = str(struct.unpack(formatStr, buf))
        return l2tpv3SampleVendorAvp(self.vendorID, self.attrType,
                                     self.updateOpt,
                                     self.notifyVendorOpt,
                                     self.OutCtrlIdList,
                                     attrValue=attrValue)

    @staticmethod
    def ValidateFlags(mustAvp, hiddenAvp):
        return mustAvp and not hiddenAvp

# l2tpv3AVP.SubclassMapping[
#    (l2tpv3SampleVendorAvp.VendorID, l2tpv3SampleVendorAvp.AttrType)] = l2tpv3SampleVendorAvp
