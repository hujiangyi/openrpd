#
# Copyright (c) 2017 MaxLinear, Inc. ("MaxLinear") and
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
Vendor can define their own sub-TLV in vsp_tlv_def.py.
When build, the file VendorSpecificExtension.proto is generated.  Examine the t_VendorSpecificExtension
message in that file to know how to handle the object of this class RcpVendorTlv()
"""

from rpd.gpb import rcp_pb2
from rpd.gpb import cfg_pb2
from rpd.gpb import VendorSpecificExtension_pb2
from rpd.gpb.VendorSpecificExtension_pb2 import t_VendorSpecificExtension
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.gpb.cfg_pb2 import config
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.rcp.gcp.gcp_lib.gcp_tlv_def import TLVDescriptionSet, TLVDesc
import rpd.rcp.rcp_lib.rcp as rcp
from rpd.rcp.rcp_lib.rcp import RCP_SEQUENCE_MIN_LEN
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.gpb import rcp_pb2
from rpd.gpb import cfg_pb2
from rpd.rcp.vendorTLVs.src import vsp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_object, gcp_packet, gcp_msg_def
from rpd.rcp.rcp_lib.rcp import Message, RCPSequence, RCPMessage,\
    RCP_SEQUENCE_MIN_LEN

#
# Macros:
#

# Vendor's own assigned ID
DEFAULT_VENDOR_ID = 5555


class RcpVendorTlv(object):
    """

    This is a generic class for Vendor to modify their own TLVs.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self, vendorID=DEFAULT_VENDOR_ID):
        """

        This functions create RcpVendorTlv object which holds vendor ID
        : param vendorId: Vendor ID of the TLV
        : return: 

        """

        self.VendorID = vendorID

    def create_vendor_tlvs_sequence(self, gcp_message_id, rcp_message_id, operation):
        """ This functions create a RCPSequence object, and set t_VendorSpecificExtension()
        with appropriate values.

        : param gcp_message_id: GCP Message ID
        : param rcp_message_id: RCP Message ID
        : param operation: TLV Operation of this RCP Sequence

        : return: seq

        """

        seq = RCPSequence(gcp_message_id=gcp_message_id,
                          rcp_message_id=rcp_message_id,
                          operation=operation)

        if None is seq:
            return None

        # use the RCP TLV standard operation values instead of enum t_RpdDataOperation.
        if None is not seq.ipc_msg:
            if operation == rcp_tlv_def.RCP_OPERATION_TYPE_READ:
                seq.ipc_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
            elif operation == rcp_tlv_def.RCP_OPERATION_TYPE_WRITE:
                seq.ipc_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
            elif operation == rcp_tlv_def.RCP_OPERATION_TYPE_DELETE:
                seq.ipc_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_DELETE
            elif operation == rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE:
                seq.ipc_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE
            else:
                seq.ipc_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_OPER_NONE

        VspTlv = seq.VendorSpecificExtension
        VspTlv.VendorId.set_val(self.VendorID)

        if operation in [rcp_tlv_def.RCP_OPERATION_TYPE_WRITE, rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE]:
            # Driver could use this to verify its FW/HW before applying...
            VspTlv.FWVersion.set_val(0x0101)
            VspTlv.HWVersion.set_val(0x0A05)

            # Fill some data for OpenRpdDriver to write to HW
            rfChannel = VspTlv.RfChannel.add_new_repeated()
            rfChannel.RfChannelSelector.RfPortIndex.set_val(3)
            rfChannel.RfChannelSelector.RfChannelType.set_val(2)
            rfChannel.RfChannelSelector.RfChannelIndex.set_val(1)

            DsScQamChannelConfig = rfChannel.DsScQamChannelConfig

            DsScQamChannelConfig.AdminState.set_val(t_VendorSpecificExtension.t_RfChannel.t_DsScQamChannelConfig.ADMIN_STATE_4_TESTING)
            #DsScQamChannelConfig.CcapCoreOwner = ("\x00\x01\x02\x03\x04\x05")
            DsScQamChannelConfig.RfMute.set_val(True)
            DsScQamChannelConfig.TSID.set_val(6879)
            DsScQamChannelConfig.CenterFrequency.set_val(1000000)
            DsScQamChannelConfig.OperationalMode.set_val(t_VendorSpecificExtension.t_RfChannel.t_DsScQamChannelConfig.OPERATIONAL_MODE_2_CHANNEL_AS_DOCSIS_CHANNEL)
            DsScQamChannelConfig.Modulation.set_val(t_VendorSpecificExtension.t_RfChannel.t_DsScQamChannelConfig.MODULATION_57__4_QAM256)
            DsScQamChannelConfig.InterleaverDepth.set_val(t_VendorSpecificExtension.t_RfChannel.t_DsScQamChannelConfig.INTERLEAVER_DEPTH_4_TAPS16INCREMENT8)

            DsScQamChannelConfig.Annex.set_val(t_VendorSpecificExtension.t_RfChannel.t_DsScQamChannelConfig.ANNEX_3_ANNEX_A)
            DsScQamChannelConfig.SyncInterval.set_val(0xa5)
            #DsScQamChannelConfig.SyncMacAddress = ("\x00\x01\x02\x03\x04\x05")
            DsScQamChannelConfig.SymbolFrequencyDenominator.set_val(0x12)
            DsScQamChannelConfig.SymbolFrequencyNumerator.set_val(0x34)
            DsScQamChannelConfig.SymbolRateOverride.set_val(0x56)
            DsScQamChannelConfig.SpectrumInversionEnabled.set_val(False)
            DsScQamChannelConfig.PowerAdjust.set_val(0x89)
        elif (operation == rcp_tlv_def.RCP_OPERATION_TYPE_READ):
            # Driver should write its current values here so the requester knows...
            VspTlv.FWVersion.set_val(0x0)
            VspTlv.HWVersion.set_val(0x0)
        return seq

    def setDriverMsgCode(self, vid, value=None):
        """
        Vendor could check for a matching vid here, and parse
        the content to see what driver message code to use, etc.
        As of now, just return the HalConfigMsg.MsgTypeRcpVendorSpecific

        : param vid: VendorId on the VendorSpecificExtension TLV

        : return: pass_to_drv
        : return: HalConfigMsg.MsgTypeRcpVendorSpecific

        """
        pass_to_drv = 1
        if isinstance(vid, int):
            # Vendor can do here:
            #   1. check for vid
            #   2. parse value to see what driver message code to use.
            return pass_to_drv, HalConfigMsg.MsgTypeRcpVendorSpecific
        else:
            return 0, 0
