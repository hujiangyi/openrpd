#
# Copyright (c) 2016 Cisco and/or its affiliates, and
#                    Cable Television Laboratories, Inc. ("CableLabs")
#                    MaxLinear, Inc. ("MaxLinear")
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
import struct
from rpd.rcp.gcp.gcp_lib.ucd_pb2 import ucd as ucd_gpb
from rpd.rcp.gcp.gcp_lib.ocd_pb2 import ocd as ocd_gpb
from rpd.rcp.gcp.gcp_lib.dpd_pb2 import dpd as dpd_gpb
from rpd.rcp.gcp.gcp_lib.ucdBurstProfile_pb2 \
    import burstProfile as ucdBurst_gpb
from struct import unpack_from
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.utils import SysTools
from rpd.hal.src.HalConfigMsg import MsgTypeDocsisMsg, MsgTypeDocsisMsgUCD, MsgTypeDocsisMsgOCD, MsgTypeDocsisMsgDPD
from rpd.rcp.gcp.gcp_lib import gcp_object, gcp_packet
from rpd.rcp.rcp_lib import rcp_tlv_def, rcp
import binascii
from rpd.gpb.RfChannel_pb2 import t_RfChannel
SKIP_PARSING_DOCSIS_3p1 = True # Set to False to parse DOCSIS 3.1 payload in this file.
#
# DocsisMsg exceptions
#


class DocsisMsgException(gcp_object.GCPException):
    pass


class DocsisMsgEncodeDecodeError(gcp_object.GCPEncodeDecodeError,
                                 DocsisMsgException):
    pass


class DocsisMsgDecodeError(DocsisMsgEncodeDecodeError):
    pass


class DocsisMsgEncodeError(DocsisMsgEncodeDecodeError):
    pass


class DocsisMsgMacMessage(rcp.RCPSequence):

    DOCSIS_MAC_HEADER_LEN = 6
    DOCSIS_MMM_HEADER_LEN = 20
    DOCSIS_AND_MAC_HEADER_LEN = DOCSIS_MAC_HEADER_LEN + DOCSIS_MMM_HEADER_LEN

    OCD_RANGE_MIN = 0
    OCD_RANGE_MAX = 8191
    OCD_MAC_MESSAGE_MIN_LEN = 0
    OCD_MAC_MESSAGE_HDR_LEN = DOCSIS_AND_MAC_HEADER_LEN + 2
    OCDHeaderDef = (
        ("OCDDstreamChannelID", gcp_packet.TLVData.TLV_type_fmt),
        ("OCDConfChangeCnt", gcp_packet.TLVData.TLV_type_fmt),
    )

    DPD_MAC_MESSAGE_MIN_LEN = 0
    DPD_MAC_MESSAGE_HDR_LEN = DOCSIS_AND_MAC_HEADER_LEN + 3
    DPDHeaderDef = (
        ("DPDDstreamChannelID", gcp_packet.TLVData.TLV_type_fmt),
        ("DPDProfileIdentifier", gcp_packet.TLVData.TLV_type_fmt),
        ("DPDConfChangeCnt", gcp_packet.TLVData.TLV_type_fmt),
    )

    UCD_MAC_MESSAGE_MIN_LEN = 0
    UCD_MAC_MESSAGE_HDR_LEN = DOCSIS_AND_MAC_HEADER_LEN + 4
    UCDHeaderDef = (
        ("UCDUstreamChannelID", gcp_packet.TLVData.TLV_type_fmt),
        ("UCDConfChangeCnt", gcp_packet.TLVData.TLV_type_fmt),
        ("UCDMiniSlotSize", gcp_packet.TLVData.TLV_type_fmt),
        ("UCDDownstreamChannelID", gcp_packet.TLVData.TLV_type_fmt),
    )

    __metaclass__ = AddLoggerToClass

    def _get_tlv_fmts(self):
        """Returns dict of allowed TLVs' formats for RCP message specified
        by ID."""
        return self.tlvFmts

    def __init__(self):
        """
        :return: tlv
        """
        self.msgtype = MsgTypeDocsisMsg
        self.headDict = dict()
        self.tlvFmts = None
        self.macMsgHdrLen = 0
        self.convert_to_RCPSequence = None

        self.parent_gpb = None
        self.parent_fmt = None
        self._rcp_ext_dict = None

    def _update_tlv_dict(self, parent_gpb=None, parent_fmt=None):
        """update the parent_gpb and parent_fmt."""

        if None is parent_gpb:
            raise AttributeError("None parent_gpb passed")
        else:
            self.parent_gpb = parent_gpb
        if None is parent_fmt:
            raise AttributeError("None parent_fmt passed")
        else:
            self.parent_fmt = parent_fmt

    def _decode_process(self):
        """Implements decoding of RCP sequences

        :raises RCPSequenceDecodeError

        """
        if self.get_max_len() < self.DOCSIS_AND_MAC_HEADER_LEN:
            raise DocsisMsgDecodeError(
                "Docsis mac message buffer length ({}) is too low, min length "
                "is {} bytes".format(self.get_max_len(),
                                     self.DOCSIS_AND_MAC_HEADER_LEN))

        # decode the Mac Header
        MacHeaderLen = 0
        headVal = list()
        while MacHeaderLen < self.DOCSIS_AND_MAC_HEADER_LEN:
            headVal.extend(unpack_from("!B", self.buffer, self.offset))
            self.offset += 1
            MacHeaderLen += 1
        # version = headVal[-3]

        # Parse the length field (offsets 12-13) from the MMM header.  This
        # length includes the remainder of the MMM header (DSAP to end = 6
        # bytes) and the payload.  It does not include the CRC.
        length = (
            (headVal[self.DOCSIS_MAC_HEADER_LEN + 12] << 8) +
            headVal[self.DOCSIS_MAC_HEADER_LEN + 13])

        # Make sure that the length field value is large enough to include the
        # rest of the DOCSIS MMM header (DSAP to end = 6 bytes).
        if length < 6:
            raise DocsisMsgDecodeError("DOCSIS MMM header length field value "
                                       "is too small ({} < 6)".format(length))

        # Subtract the length of the rest of the DOCSIS MMM header.  The length
        # value will now equal the length of the MMM payload (no CRC).
        length = length - 6

        # Make sure that the length field value is not larger than the rest of
        # the buffer.
        if length > self.get_max_len():
            raise DocsisMsgDecodeError("DOCSIS MMM header length field value "
                                       "is too large ({} > {})".format(length, self.get_max_len()))

        # Calculate the number of bytes in the buffer after the MMM payload.
        appended_length = self.get_max_len() - length
        if (appended_length != 0) and (appended_length != 4):
            raise DocsisMsgDecodeError("DOCSIS message has an unexpected number "
                                       "of bytes appended ({}).".format(appended_length))

        # Reduce the buffer size to only include the MMM payload, eliminating
        # the CRC (if present).
        self.trim_max_len(appended_length)

        type = headVal[-2]
        if type in [2, 29, 35, ]:
            self.logger.debug("this is a Docsis Message with UCD")
            self.msgtype = MsgTypeDocsisMsgUCD
            self.tlvFmts = rcp_tlv_def.UCD_TLV_SET.child_dict_by_id
            self.macMsgHdrLen = self.UCD_MAC_MESSAGE_HDR_LEN
            self.HeaderDef = self.UCDHeaderDef
            self.convert_to_RCPSequence = self.UCD_to_RCPSequence
            self._update_tlv_dict(parent_gpb=ucd_gpb(), parent_fmt=rcp_tlv_def.UCD_TLV_SET)
            self.BurstProfile = list()
        elif type in [51, ]:
            self.logger.debug("this is a Docsis Message with OFDMA UCD")
            self.tlvFmts = rcp_tlv_def.UCD_TLV_SET.child_dict_by_id
            self.macMsgHdrLen = self.UCD_MAC_MESSAGE_HDR_LEN
            self.HeaderDef = self.UCDHeaderDef
            if SysTools.is_vrpd() and SKIP_PARSING_DOCSIS_3p1 == False:
                self.msgtype = MsgTypeDocsisMsgUCD
                self.convert_to_RCPSequence = self.UCD3d1_to_RCPSequence
            else:
                self.msgtype = None
                self.convert_to_RCPSequence = self.skip_convert
                self.logger.debug("UCD OFDMA parsing is skipped and msgtype is set to: %s" 
                                  %(self.msgtype))
            self._update_tlv_dict(parent_gpb=ucd_gpb(), parent_fmt=rcp_tlv_def.UCD_TLV_SET)
            self.BurstProfile = list()
        elif type in [49, ]:
            self.logger.debug("this is a Docsis Message with OCD")
            self.msgtype = MsgTypeDocsisMsgOCD
            self.tlvFmts = rcp_tlv_def.OCD_TLV_SET.child_dict_by_id
            self.macMsgHdrLen = self.OCD_MAC_MESSAGE_HDR_LEN
            self.HeaderDef = self.OCDHeaderDef
            if SysTools.is_vrpd():
                self.convert_to_RCPSequence = self.OCD_to_RCPSequence
            else:
                self.convert_to_RCPSequence = self.skip_convert
            self._update_tlv_dict(parent_gpb=ocd_gpb(), parent_fmt=rcp_tlv_def.OCD_TLV_SET)
        elif type in [50, ]:
            self.logger.debug("this is a Docsis Message with DPD")
            self.msgtype = MsgTypeDocsisMsgDPD
            self.tlvFmts = rcp_tlv_def.DPD_TLV_SET.child_dict_by_id
            self.macMsgHdrLen = self.DPD_MAC_MESSAGE_HDR_LEN
            self.HeaderDef = self.DPDHeaderDef
            if SysTools.is_vrpd():
                self.convert_to_RCPSequence = self.DPD_to_RCPSequence
            else:
                self.convert_to_RCPSequence = self.skip_convert
            self._update_tlv_dict(parent_gpb=dpd_gpb(), parent_fmt=rcp_tlv_def.DPD_TLV_SET)
        else:
            self.logger.error("this is a Docsis Message "
                              "with unsupported type: %d", type)
            self.convert_to_RCPSequence = self.skip_convert
            return gcp_object.GCPObject.DECODE_FAILED

        # self.logger.info ("_decode_process: len %d, offset: %d" %(self.get_max_len(), self.offset))
        for entry in self.HeaderDef:
            val = unpack_from(entry[1], self.buffer, self.offset)
            self.headDict[entry[0]] = val[0]
            self.offset += 1

        sequence_length = self.get_max_len()
        try:
            ret = self._fast_decode(self.parent_fmt, self.parent_gpb, self.offset,
                                    sequence_length, 0, tl_format="!BB", tl_offset=2)
            self.offset += sequence_length  # update the offset
        except Exception as e:
            self.logger.error("Docsis message Failed to decode TLVs of "
                              "sequence, unexpected reason: %s", str(e))
            return gcp_object.GCPObject.DECODE_FAILED

        if ret != gcp_object.GCPObject.DECODE_DONE:
            self.logger.error("Docsis message Failed to decode TLVs of "
                              "sequence, unexpected result: %u", ret)
            return gcp_object.GCPObject.DECODE_FAILED

        # self.logger.info ("_decode_process: len %d, offset: %d, done!" %(self.get_max_len(), self.offset))
        # extra data need to be decoded
        if type in [2, 29, 35, ] or (type == 51 and SKIP_PARSING_DOCSIS_3p1 == False):
            # decode the BurstProfile
            for burstProfiles in (self.parent_gpb.BurstDescDocsis1x,
                                  self.parent_gpb.BurstDescDocsis2x3x,
                                  self.parent_gpb.BurstDescDocsis3d1):
                burstType = 4
                if (burstProfiles == self.parent_gpb.BurstDescDocsis2x3x):
                    burstType = 5
                elif (burstProfiles == self.parent_gpb.BurstDescDocsis3d1):
                    burstType = 23

                for burstProfileData in burstProfiles:
                    burstProfile = UCDBurstProfile(
                        burstType, 0, ucdBurst_gpb())
                    if burstProfile.decode(burstProfileData, 0,
                                           len(burstProfileData)) == \
                            gcp_object.GCPObject.DECODE_DONE:
                        self.BurstProfile.append(burstProfile)
                    else:
                        self.logger.info("DocsisMessage DECODE FAILED")
                        return gcp_object.GCPObject.DECODE_FAILED

        return gcp_object.GCPObject.DECODE_DONE

    def _encode_process(self):  # pragma: no cover
        """Implements encoding of RCP sequence.

        :raises RCPSequenceEncodeError:

        """

        raise NotImplementedError()

    def skip_convert(self, gcp_message_id, rcp_message_id,
                     rf_ch_msg, operation):
        """Skip Convert the docsis message to cfg proto buf message,
        leave the driver to handle."""
        return None

    def OCD_to_RCPSequence(self, gcp_message_id, rcp_message_id,
                           rf_ch_msg, operation):
        """Convert the OCD to cfg proto buf message (instead of RCP sequence)."""
        rcpDsOfdmTlv = rf_ch_msg.DsOfdmChannelConfig
        # Set the values based on the mapping
        if self.parent_gpb.HasField("CyclicPrefix"):
            cyclicPrefix = self.parent_gpb.CyclicPrefix

            if cyclicPrefix is not None:
                cyclicPrefixMapping = {
                    0: 1,
                    1: 2,
                    2: 3,
                    3: 4,
                    4: 5
                }
                if cyclicPrefix in cyclicPrefixMapping:
                    rcpDsOfdmTlv.CyclicPrefix = cyclicPrefixMapping[cyclicPrefix]
                else:
                    self.logger.info("receive a reserved "
                                     "CyclicPrefix value currently")

        if self.parent_gpb.HasField("RollOff"):
            rollOff = self.parent_gpb.RollOff
            if rollOff is not None:
                rollOffMapping = {
                    0: 1,
                    1: 2,
                    2: 3,
                    3: 4,
                    4: 5
                }
                if rollOff in rollOffMapping:
                    rcpDsOfdmTlv.RollOffPeriod = rollOffMapping[rollOff]
                else:
                    self.logger.info("receive a reserved rollOff value currently")

        if self.parent_gpb.HasField("DiscreteFourierTransformsize"):
            discreteFourierTransformsize = \
                self.parent_gpb.DiscreteFourierTransformsize
            if discreteFourierTransformsize is not None:
                discreteFourierTransformsizeMapping = {
                    0: 2,
                    1: 1
                }
                if discreteFourierTransformsize in \
                        discreteFourierTransformsizeMapping:
                    rcpDsOfdmTlv.SubcarrierSpacing = \
                        discreteFourierTransformsizeMapping[
                            discreteFourierTransformsize]
                    # self.logger.info("rcpDsOfdmTlv.SubcarrierSpacing = %d", rcpDsOfdmTlv.SubcarrierSpacing)
                else:
                    self.logger.info("receive a reserved "
                                     "DFTsize value currently")

        if self.parent_gpb.HasField("OFDMSpectrumLocation"):
            oFDMSpectrumLocation = self.parent_gpb.OFDMSpectrumLocation
            if oFDMSpectrumLocation is not None:
                rcpDsOfdmTlv.SubcarrierZeroFreq = oFDMSpectrumLocation

        if self.parent_gpb.HasField("TimeInterleavingDepth"):
            timeInterleavingDepth = self.parent_gpb.TimeInterleavingDepth
            if timeInterleavingDepth is not None:
                rcpDsOfdmTlv.TimeInterleaverDepth = timeInterleavingDepth

        subcarrierAssignmentList = self.parent_gpb.SubcarrierAssignment
        activeIds = range(self.OCD_RANGE_MAX)
        if (rcpDsOfdmTlv.SubcarrierSpacing == rf_ch_msg.t_DsOfdmChannelConfig().SUBCARRIER_SPACING_2_50KHZ):
            activeIds = range((self.OCD_RANGE_MAX - 1) / 2)
        for subcarrierAssignment in subcarrierAssignmentList:
            head = struct.unpack('!B', subcarrierAssignment[0])[0]
            rangeorlist = head >> 6
            usage = head & 0x1f
            typeMapping = {
                0: 'range',
                1: 'rangewithskip',
                2: 'list',
                3: 'reserved'
            }
            usgMapping = {
                1: 4,
                16: 5,
                20: 3
            }
            if usage in usgMapping:
                usage = usgMapping[usage]
            else:
                self.logger.info("receive a reserved usage value currently")
                usage = 1

            if typeMapping[rangeorlist] is 'range':
                start = struct.unpack('!H', subcarrierAssignment[1:3])[0]
                end = struct.unpack('!H', subcarrierAssignment[3:5])[0]
                dsOfdmSubcarrierType = rcpDsOfdmTlv.DsOfdmSubcarrierType.add()
                dsOfdmSubcarrierType.StartSubcarrierId = start
                dsOfdmSubcarrierType.EndSubcarrierId = end
                dsOfdmSubcarrierType.SubcarrierUsage = usage
                if usage is 5:
                    for id in range(start, end + 1):
                        if id in activeIds:
                            activeIds.remove(id)

            elif typeMapping[rangeorlist] is 'list':
                if not (len(subcarrierAssignment) % 2):
                    self.logger.error("subcarrierAssignment list data error")
                    continue
                index = 1
                while index < len(subcarrierAssignment):
                    id = struct.unpack('!H', subcarrierAssignment[index:index + 2])[0]
                    dsOfdmSubcarrierType = rcpDsOfdmTlv.DsOfdmSubcarrierType.add()
                    dsOfdmSubcarrierType.StartSubcarrierId = id
                    dsOfdmSubcarrierType.SubcarrierUsage = usage
                    if usage is 5 and id in activeIds:
                        activeIds.remove(id)
                    index += 2

            elif typeMapping[rangeorlist] is 'rangewithskip':
                start = struct.unpack('!H', subcarrierAssignment[1:3])[0]
                end = struct.unpack('!H', subcarrierAssignment[3:5])[0]
                index = start
                while index < end:
                    id = index
                    dsOfdmSubcarrierType = rcpDsOfdmTlv.DsOfdmSubcarrierType.add()
                    dsOfdmSubcarrierType.StartSubcarrierId = id
                    dsOfdmSubcarrierType.SubcarrierUsage = usage
                    if usage is 5 and id in activeIds:
                        activeIds.remove(id)
                    index += 2
        # fixme: need confirm the define of active subcarrier
        if len(activeIds):
            rcpDsOfdmTlv.FirstActiveSubcarrier = min(activeIds)
            rcpDsOfdmTlv.LastActiveSubcarrier = max(activeIds)
            rcpDsOfdmTlv.NumActiveSubcarriers = len(activeIds)

        # self.logger.info("Return with LastActiveSubcarrier = %d", rcpDsOfdmTlv.LastActiveSubcarrier)
        return rf_ch_msg

    def DPD_to_RCPSequence(self, gcp_message_id, rcp_message_id,
                           rf_ch_msg, operation):
        """Convert the DPD to cfg proto buf message (instead of RCP sequence)."""
        rcpDsOfdmTlv = rf_ch_msg.DsOfdmProfile

        # Set the values based on the mapping
        subcarrierAssignmentList = self.parent_gpb.SubcarrierAssignment
        rcpDsOfdmTlv.ProfileId = self.headDict["DPDProfileIdentifier"]

        for subcarrierAssignment in subcarrierAssignmentList:
            head = struct.unpack('!B', subcarrierAssignment[0])[0]
            rangeorlist = head >> 6
            Modulation = head & 0xf
            typeMapping = {
                0: 'range',
                1: 'rangewithskip',
                2: 'list',
                3: 'reserved'
            }
            ModulationMapping = {
                0: 2,
                1: 1,
                2: 3,
                3: 1,
                4: 4,
                5: 1,
                6: 5,
                7: 6,
                8: 7,
                9: 8,
                10: 9,
                11: 10,
                12: 11,
                13: 12,
                14: 13,
                15: 1
            }
            if Modulation in ModulationMapping:
                Modulation = ModulationMapping[Modulation]

            if typeMapping[rangeorlist] is 'range':
                start = struct.unpack('!H', subcarrierAssignment[1:3])[0]
                end = struct.unpack('!H', subcarrierAssignment[3:5])[0]
                dsOfdmSubcarrierModulation = rcpDsOfdmTlv.DsOfdmSubcarrierModulation.add()
                dsOfdmSubcarrierModulation.StartSubcarrierId = start
                dsOfdmSubcarrierModulation.EndSubcarrierId = end
                dsOfdmSubcarrierModulation.Modulation = Modulation
            elif typeMapping[rangeorlist] is 'list':
                if not (len(subcarrierAssignment) % 2):
                    self.logger.error("subcarrierAssignment list data error")
                    continue
                index = 1
                while index < len(subcarrierAssignment):
                    id = struct.unpack('!H', subcarrierAssignment[index:index + 2])[0]
                    dsOfdmSubcarrierModulation = rcpDsOfdmTlv.DsOfdmSubcarrierModulation.add()
                    dsOfdmSubcarrierModulation.StartSubcarrierId = id
                    dsOfdmSubcarrierModulation.Modulation = Modulation
                    index += 2
            elif typeMapping[rangeorlist] is 'rangewithskip':
                start = struct.unpack('!H', subcarrierAssignment[1:3])[0]
                end = struct.unpack('!H', subcarrierAssignment[3:5])[0]
                index = start
                while index < end:
                    dsOfdmSubcarrierModulation = rcpDsOfdmTlv.DsOfdmSubcarrierModulation.add()
                    dsOfdmSubcarrierModulation.StartSubcarrierId = index
                    dsOfdmSubcarrierModulation.EndSubcarrierId = end
                    dsOfdmSubcarrierModulation.Modulation = Modulation
                    index += 2
        # subcarrierAssignmentVector = self.SubcarrierAssignmentVector.get_val()
        # for subcarrierAssignmentItem in subcarrierAssignmentVector:
        #     print repr(subcarrierAssignmentItem)

        return rf_ch_msg

    def UCD_to_RCPSequence(self, gcp_message_id, rcp_message_id,
                           rf_ch_msg, operation):
        """Convert the UCD to cfg proto buf message (instead of RCP sequence)."""
        rcpUsQamTlv = rf_ch_msg.UsScQamChannelConfig
        # Set the values based on the mapping
        if self.parent_gpb.HasField("ModulationRate"):
            modulationRate = self.parent_gpb.ModulationRate

            if modulationRate is not None:
                modulationRateMapping = {
                    1: 200000,
                    2: 400000,
                    4: 800000,
                    8: 1600000,
                    16: 3200000,
                    32: 6400000
                }
                rcpUsQamTlv.Width = modulationRateMapping[modulationRate]

        if self.parent_gpb.HasField("Frequency"):
            frequency = self.parent_gpb.Frequency
            if frequency is not None:
                rcpUsQamTlv.CenterFrequency = frequency

        # for preamble pattern
        if self.parent_gpb.HasField("PreamblePattern"):
            pp = self.parent_gpb.PreamblePattern
            if pp is not None:
                if self.parent_gpb.HasField("ExtendPreamblePattern"):
                    epp = self.parent_gpb.ExtendPreamblePattern
                    if epp is not None:
                        pp += epp
                rcpUsQamTlv.PreambleString = pp

        # for the Slotsize
        rcpUsQamTlv.SlotSize = self.headDict["UCDMiniSlotSize"]

        rcpUsQamTlv.UpStreamChanId = self.headDict["UCDUstreamChannelID"]
        rcpUsQamTlv.ConfigChangeCount = self.headDict["UCDConfChangeCnt"]
        rcpUsQamTlv.DownStreamChanId = self.headDict["UCDDownstreamChannelID"]

        # Other we can get it from the RCP TLV
        for burstProfile in self.BurstProfile:
            sub_tlv = rcpUsQamTlv.IntervalUsageCode.add()
            sub_tlv.Code = burstProfile.Code
            iuc_modulation_map = {
                1: 2,
                2: 4,
                3: 3,
                4: 5,
                5: 6,
                6: 7,
            }
            if burstProfile.parent_gpb.HasField("ModulationType"):
                ModulationType = burstProfile.parent_gpb.ModulationType
                if ModulationType in iuc_modulation_map:
                    sub_tlv.ModulationType = iuc_modulation_map[ModulationType]
                else:
                    sub_tlv.ModulationType = 1
                self.logger.debug("RCP change IUC modulation type from %d to %d",
                                  ModulationType, sub_tlv.ModulationType)

            if burstProfile.parent_gpb.HasField("DifferentialEncoding"):
                DifferentialEncoding = burstProfile.parent_gpb.DifferentialEncoding
                if DifferentialEncoding is not None:
                    if DifferentialEncoding == 1:
                        sub_tlv.DifferentialEncoding = 1
                    else:
                        sub_tlv.DifferentialEncoding = 0

            if burstProfile.parent_gpb.HasField("PreambleLength"):
                PreambleLength = burstProfile.parent_gpb.PreambleLength
                if PreambleLength is not None:
                    sub_tlv.PreambleLen = PreambleLength

            if burstProfile.parent_gpb.HasField("PreambleValueOffset"):
                PreambleValueOffset = burstProfile.parent_gpb.PreambleValueOffset
                if PreambleValueOffset is not None:
                    sub_tlv.PreambleOffsett = PreambleValueOffset

            if burstProfile.parent_gpb.HasField("FECErrorCorrection"):
                FECErrorCorrection = burstProfile.parent_gpb.FECErrorCorrection
                if FECErrorCorrection is not None:
                    sub_tlv.FecErrorCorrectionT = FECErrorCorrection

            if burstProfile.parent_gpb.HasField("FECCodewordInformationBytes"):
                FECCodewordInformationBytes = \
                    burstProfile.parent_gpb.FECCodewordInformationBytes
                if FECCodewordInformationBytes is not None:
                    sub_tlv.FecCodewordLength = FECCodewordInformationBytes

            if burstProfile.parent_gpb.HasField("ScramblerSeed"):
                ScramblerSeed = burstProfile.parent_gpb.ScramblerSeed
                if ScramblerSeed is not None:
                    sub_tlv.ScrambleSeed = ScramblerSeed

            if burstProfile.parent_gpb.HasField("MaximumBurstSize"):
                MaximumBurstSize = burstProfile.parent_gpb.MaximumBurstSize
                if MaximumBurstSize is not None:
                    sub_tlv.MaxBurstSize = MaximumBurstSize

            if burstProfile.parent_gpb.HasField("GuardTimeSize"):
                GuardTimeSize = burstProfile.parent_gpb.GuardTimeSize
                if GuardTimeSize is not None:
                    sub_tlv.GuardTime = GuardTimeSize

            if burstProfile.parent_gpb.HasField("LastCodewordLength"):
                LastCodewordLength = burstProfile.parent_gpb.LastCodewordLength
                if LastCodewordLength is not None:
                    sub_tlv.LasCodewordShortened = LastCodewordLength - 1

            if burstProfile.parent_gpb.HasField("ScramblerOnOff"):
                ScramblerOnOff = burstProfile.parent_gpb.ScramblerOnOff
                if ScramblerOnOff is not None:
                    if ScramblerOnOff == 1:
                        sub_tlv.Scrambler = 1
                    else:
                        sub_tlv.Scrambler = 0

            if burstProfile.parent_gpb.HasField("RSInterleaverDepth"):
                RSInterleaverDepth = burstProfile.parent_gpb.RSInterleaverDepth
                if RSInterleaverDepth is not None:
                    sub_tlv.ByteInterleaverDepth = RSInterleaverDepth
                else:
                    sub_tlv.ByteInterleaverDepth = 1

            if burstProfile.parent_gpb.HasField("RSInterleaverBlockSize"):
                RSInterleaverBlockSize = \
                    burstProfile.parent_gpb.RSInterleaverBlockSize
                if RSInterleaverBlockSize is not None:
                    sub_tlv.ByteInterleaverBlockSize = RSInterleaverBlockSize
                else:
                    sub_tlv.ByteInterleaverBlockSize = 0

            if burstProfile.parent_gpb.HasField("PreambleType"):
                PreambleType = burstProfile.parent_gpb.PreambleType
                if PreambleType is not None:
                    sub_tlv.PreambleModType = PreambleType

            if burstProfile.parent_gpb.HasField("TCMEncoding"):
                TCMEncoding = burstProfile.parent_gpb.TCMEncoding
                if TCMEncoding is not None:
                    if TCMEncoding == 1:
                        sub_tlv.TcmErrorCorrectionOn = 1
                    else:
                        sub_tlv.TcmErrorCorrectionOn = 0

        return rf_ch_msg

    def UCD3d1_to_RCPSequence(self, gcp_message_id, rcp_message_id,
                              rf_ch_msg, operation):
        """
        Convert the DOCSIS UCD 3.1 to cfg proto buf message (instead of RCP sequence).
        See rcp_hal.py rcp_cfg_req(), docsis_msg.convert_to_RCPSequence
        """
        rcpUsOfdmaTlv = rf_ch_msg.UsOfdmaChannelConfig
        # get parameters for rcpUsOfdmaTlv for the 3 additional fields
        rcpUsOfdmaTlv.UpStreamChanId = self.headDict["UCDUstreamChannelID"]
        rcpUsOfdmaTlv.ConfigChangeCount = self.headDict["UCDConfChangeCnt"]
        rcpUsOfdmaTlv.DownStreamChanId = self.headDict["UCDDownstreamChannelID"]

        self.logger.info("UCD3d1_to_RCPSequence: UsChanId %d, CCC %d, DsChanId %d" % (rcpUsOfdmaTlv.UpStreamChanId, rcpUsOfdmaTlv.ConfigChangeCount, rcpUsOfdmaTlv.DownStreamChanId))

        if self.parent_gpb.HasField("SubcarrierSpacing"):
            scSpacing = self.parent_gpb.SubcarrierSpacing
            if scSpacing is not None:
                rcpUsOfdmaTlv.SubcarrierSpacing = scSpacing

        # for preamble pattern
        if self.parent_gpb.HasField("PreamblePattern"):
            pp = self.parent_gpb.PreamblePattern
            if pp is not None:
                if self.parent_gpb.HasField("ExtendPreamblePattern"):
                    epp = self.parent_gpb.ExtendPreamblePattern
                    if epp is not None:
                        pp += epp
                rcpUsOfdmaTlv.PreambleString = pp

        # for OFDMACyclicPrefixSize
        if self.parent_gpb.HasField("OFDMACyclicPrefixSize"):
            cyclicPrefixSize = self.parent_gpb.OFDMACyclicPrefixSize
            if cyclicPrefixSize is not None:
                rcpUsOfdmaTlv.CyclicPrefix = cyclicPrefixSize

        # for RollOffPeriod
        if self.parent_gpb.HasField("OFDMARolloffPeriodSize"):
            rollOffPeriod = self.parent_gpb.OFDMARolloffPeriodSize
            if rollOffPeriod is not None:
                rcpUsOfdmaTlv.RollOffPeriod = rollOffPeriod

        # for SubcarrierZeroFreq
        if self.parent_gpb.HasField("CenterFrequencyOfSubcarrier0"):
            subcarrierZeroFreq = self.parent_gpb.CenterFrequencyOfSubcarrier0
            if subcarrierZeroFreq is not None:
                rcpUsOfdmaTlv.SubcarrierZeroFreq = subcarrierZeroFreq

        # for NumSymbolsPerFrame
        if self.parent_gpb.HasField("SymbolsInOFDMFrame"):
            numSymbolsPerFrame = self.parent_gpb.SymbolsInOFDMFrame
            if numSymbolsPerFrame is not None:
                rcpUsOfdmaTlv.NumSymbolsPerFrame = numSymbolsPerFrame

        # for StartingMinislot: get it as '32-bit DOCSIS timestamp' per section B.5.4.11.11
        if self.parent_gpb.HasField("OFDMATimestampSnapshot"):
            dts32Str = self.parent_gpb.OFDMATimestampSnapshot
            if dts32Str is not None:
                index = 0
                dts32 = 0
                for aByte in dts32Str:
                    if (index < 5):
                        dts32 = (dts32 << 8) | ord(aByte)
                    index += 1
                dts32 = dts32 >> 4
                rcpUsOfdmaTlv.StartingMinislot = dts32

        # init an array of 8191, each item is set to 2 =>subcarrier for DATA IUC.
        if (rcpUsOfdmaTlv.SubcarrierSpacing == rf_ch_msg.t_UsOfdmaChannelConfig().SUBCARRIER_SPACING_1_25KHZ):
            activeIds = [rf_ch_msg.t_UsOfdmaSubcarrierCfgState().SUBCARRIER_USAGE_13__2_DATA for i in range((self.OCD_RANGE_MAX + 1) / 2)]
            scPerMiniSlot = 16
        else:
            activeIds = [rf_ch_msg.t_UsOfdmaSubcarrierCfgState().SUBCARRIER_USAGE_13__2_DATA for i in range((self.OCD_RANGE_MAX + 1) / 4)]
            scPerMiniSlot = 8
        try:
            for scExcludeBand in (self.parent_gpb.SubcarrierExclusionBand):
                self._CreateUsOfdmaSubcarrierCfgState(activeIds, rf_ch_msg, rf_ch_msg.t_UsOfdmaSubcarrierCfgState().SUBCARRIER_USAGE_13__3_EXCLUDED, scExcludeBand)

            for scUnusedBand in (self.parent_gpb.UnusedSubcarrierSpecification):
                self._CreateUsOfdmaSubcarrierCfgState(activeIds, rf_ch_msg, rf_ch_msg.t_UsOfdmaSubcarrierCfgState().SUBCARRIER_USAGE_13__4_UNUSED, scUnusedBand)

            # Create another one for Data Subcarrier.  This one is just the remaining active subcarriers.
            self._CreateUsOfdmaSubcarrierCfgState(activeIds, rf_ch_msg, rf_ch_msg.t_UsOfdmaSubcarrierCfgState().SUBCARRIER_USAGE_13__2_DATA)

        except Exception as e:
            self.logger.error("_CreateUsOfdmaSubcarrierCfgState: "
                              "unexpected reason: %s", str(e))

        # for ScramblerSeed
        if self.parent_gpb.HasField("RandomizationSeed"):
            scramblerSeed = self.parent_gpb.RandomizationSeed
            if scramblerSeed is not None:
                rcpUsOfdmaTlv.ScramblerSeed = 0
                for seed in scramblerSeed:
                    rcpUsOfdmaTlv.ScramblerSeed = (rcpUsOfdmaTlv.ScramblerSeed << 8) | ord(seed)

        guardBand = 0
        preambleLen = 0
        preambleValOffset = 0
        backupActiveIds = list(activeIds)

        try:
            rcpUsOfdmaTlv.FirstActiveSubcarrierNum, rcpUsOfdmaTlv.LastActiveSubcarrierNum = self._FindFirstLastSubcarrierId(activeIds)
            rcpUsOfdmaTlv.NumActiveSubcarriers = rcpUsOfdmaTlv.LastActiveSubcarrierNum - rcpUsOfdmaTlv.FirstActiveSubcarrierNum + 1
        except Exception as e:
            self.logger.error("_FindFirstLastSubcarrierId: "
                              "unexpected reason: %s", str(e))

        for burstProfile in self.BurstProfile:
            rcpUsOfdmaInitialRangingIuc = rf_ch_msg.UsOfdmaInitialRangingIuc         # non-repeated: 1 per burst desc
            rcpUsOfdmaFineRangingIuc = rf_ch_msg.UsOfdmaFineRangingIuc               # non-repeated: 1 per burst desc
            if (burstProfile.Type != 23):
                # Only burst profile of type 23 allowed in UCD type 51
                self.logger.debug("Type %d, continue." % (burstProfile.Type))
                continue

            if burstProfile.parent_gpb.HasField("OFDMAIRPowerControl"):
                OFDMAIRPowerControl = burstProfile.parent_gpb.OFDMAIRPowerControl
                if OFDMAIRPowerControl is not None:
                    # This applied for IUC3 only.  Should it be used for setting rcpUsOfdmaTlv.TargetRxPower?
                    rcpUsOfdmaTlv.TargetRxPowerAdjust = OFDMAIRPowerControl & 0xFF
                    self.logger.debug("TargetRxPowerAdjust: %s", str(rcpUsOfdmaTlv.TargetRxPowerAdjust))

            if burstProfile.parent_gpb.HasField("OFDMAProfile"):
                OFDMAProfile = burstProfile.parent_gpb.OFDMAProfile
                rcpUsOfdmaDataIuc = rf_ch_msg.UsOfdmaDataIuc.add()                   # repeated
                rcpUsOfdmaDataIuc.DataIuc = burstProfile.Code
                activeIds = list(backupActiveIds)
                # Get the first active subc:
                lastActSubcId = self._FindFirstSubcarrierId(activeIds, 0, 0, scPerMiniSlot)
                # self.logger.debug("lastActSubcId: %d", lastActSubcId)
                if OFDMAProfile is not None:
                    startMiniSlot = 0  # assuming it starts from minislot 0
                    cnt = 0
                    dataBitLoading = 0
                    pilotPattern = 0
                    additionalNumMiniSlots = 0
                    for aByte in OFDMAProfile:
                        if (lastActSubcId == -1):
                            # self.logger.debug("No more active subc (%d)." %lastActSubcId)
                            break

                        # self.logger.debug("cnt: %d, byte %d dataBitLoading: %d, pilotPattern: %d" %(cnt, ord(aByte), dataBitLoading, pilotPattern))
                        if ((cnt % 2) == 0):
                            dataBitLoading = ord(aByte) >> 4
                            pilotPattern = ord(aByte) & 0xF
                        else:
                            additionalNumMiniSlots = ord(aByte)
                            rcpUsOfdmaDataIuc.StartingMinislot = startMiniSlot
                            rcpUsOfdmaDataIuc.NumConsecutiveMinislots = additionalNumMiniSlots
                            rcpUsOfdmaDataIuc.FirstSubcarrierId = lastActSubcId
                            try:
                                rcpUsOfdmaDataIuc.MinislotPilotPattern = pilotPattern
                            except Exception as e:
                                self.logger.error("UCD3d1 failed to decode pilot pattern (%d), reason: %s" % (pilotPattern, str(e)))

                            try:
                                rcpUsOfdmaDataIuc.DataSymbolModulation = dataBitLoading
                            except Exception as e:
                                self.logger.error("UCD3d1 failed to decode bit loading (%d), reason: %s" % (dataBitLoading, str(e)))
                            lastActSubcId = self._FindFirstSubcarrierId(activeIds, rcpUsOfdmaDataIuc.FirstSubcarrierId,
                                                                        additionalNumMiniSlots + 1, scPerMiniSlot)
                            startMiniSlot += (additionalNumMiniSlots + 1)
                            self.logger.info("lastActSubcId: %d, startMiniSlot: %d", lastActSubcId, startMiniSlot)
                        cnt += 1

            if burstProfile.parent_gpb.HasField("SubcarrierInitialRanging"):
                SubcarrierInitialRanging = burstProfile.parent_gpb.SubcarrierInitialRanging
                if SubcarrierInitialRanging is not None:
                    self.logger.info("SubcarrierInitialRanging: %d" % SubcarrierInitialRanging)
                    if ((SubcarrierInitialRanging % 2) == 0):
                        # Must be even
                        rcpUsOfdmaInitialRangingIuc.NumSubcarriers = (SubcarrierInitialRanging)
                    else:
                        # error catcher
                        pass

            if burstProfile.parent_gpb.HasField("SubcarrierFineRanging"):
                SubcarrierFineRanging = burstProfile.parent_gpb.SubcarrierFineRanging
                if SubcarrierFineRanging is not None:
                    if ((SubcarrierFineRanging % 2) == 0):
                        # Must be even
                        rcpUsOfdmaFineRangingIuc.NumSubcarriers = (SubcarrierFineRanging)
                    else:
                        # error catcher
                        pass

            if burstProfile.parent_gpb.HasField("PreambleLength"):
                preambleLen = burstProfile.parent_gpb.PreambleLength
                # Hold the value to check later.
                # There is no field in GPB to hold this (unused?)
            if burstProfile.parent_gpb.HasField("PreambleValueOffset"):
                preambleValOffset = burstProfile.parent_gpb.PreambleValueOffset

        self.logger.debug("UCD3d1_to_RCPSequence: exits")
        # Force rcp_hal to send a copy to HAL Driver.
        return None

    def _CreateUsOfdmaSubcarrierCfgState(self, activeIds, rf_ch_msg, scUsage, SubcAssignString=None):
        """ Prepare the activeIds array with subcarrier usage

        param activeIds: array of subcarriers
        param rf_ch_msg: RF Channel TLV.
        param scUsage: Subcarrier usage (exclude, used, data)
        param SubcAssignString: number of SubcarrierExclusionBand or UnusedSubcarrierSpecification.
                                This is NONE if scUsage is for DATA.
        """

        if (None is SubcAssignString):
            # self.logger.debug("_CreateUsOfdmaSubcarrierCfgState: scUsage: %d" %(scUsage))
            start = 0
            end = len(activeIds)
            foundActSubc = 0
            while start < end:
                if activeIds[start] == t_RfChannel.t_UsOfdmaSubcarrierCfgState.SUBCARRIER_USAGE_13__2_DATA:
                    if foundActSubc == 0:
                        rcpUsOfdmaSubcarrierCfgState = rf_ch_msg.UsOfdmaSubcarrierCfgState.add()
                        rcpUsOfdmaSubcarrierCfgState.SubcarrierUsage = scUsage
                        rcpUsOfdmaSubcarrierCfgState.StartingSubcarrierId = start
                        foundActSubc = 1
                if activeIds[start] == t_RfChannel.t_UsOfdmaSubcarrierCfgState.SUBCARRIER_USAGE_13__3_EXCLUDED or \
                    activeIds[start] == t_RfChannel.t_UsOfdmaSubcarrierCfgState.SUBCARRIER_USAGE_13__4_UNUSED:
                    if foundActSubc == 1:
                        foundActSubc = 0
                        rcpUsOfdmaSubcarrierCfgState.NumConsecutiveSubcarriers = \
                            (start - rcpUsOfdmaSubcarrierCfgState.StartingSubcarrierId - 1)
                start += 1
        else:
            index = 0
            endSubcIndex = 0
            for aByte in SubcAssignString:
                if ((index % 4) == 0):
                    rcpUsOfdmaSubcarrierCfgState = rf_ch_msg.UsOfdmaSubcarrierCfgState.add()
                    rcpUsOfdmaSubcarrierCfgState.SubcarrierUsage = scUsage
                    index = 0
                if (index < 2):
                    startingScId = (rcpUsOfdmaSubcarrierCfgState.StartingSubcarrierId << 8)
                    rcpUsOfdmaSubcarrierCfgState.StartingSubcarrierId = startingScId | ord(aByte)
                else:
                    numConsecutiveSc = (rcpUsOfdmaSubcarrierCfgState.NumConsecutiveSubcarriers << 8)
                    rcpUsOfdmaSubcarrierCfgState.NumConsecutiveSubcarriers = numConsecutiveSc | ord(aByte)

                index += 1
                if ((index % 4) == 0):
                    startingScId = rcpUsOfdmaSubcarrierCfgState.StartingSubcarrierId
                    numConsecutiveSc = rcpUsOfdmaSubcarrierCfgState.NumConsecutiveSubcarriers
                    start = rcpUsOfdmaSubcarrierCfgState.StartingSubcarrierId
                    end = numConsecutiveSc + 1
                    rcpUsOfdmaSubcarrierCfgState.NumConsecutiveSubcarriers = numConsecutiveSc - startingScId
                    while start < end:
                        activeIds[start] = scUsage
                        start += 1

    def _FindFirstSubcarrierId(self, activeIds, lastActSubcId, numMiniSlots, scPerMiniSlot):
        """ Find First Subcarrier Index for a group of minislots for DATA IUC
        given an array of subcarriers, last
        param activeIds: array of 2048 or 4096 bytes, each has value of 2, 3 or 4. (exclude, used, data)

        param lastActSubcId: last active subcarrier of the last minislot of previous range
        param numMiniSlots: number of minislot of previous range
        param scPerMiniSlot: subcarrier per minislot
        """
        start = lastActSubcId
        occupiedSubcRange = lastActSubcId + (numMiniSlots * scPerMiniSlot)
        end = len(activeIds)
        self.logger.debug("start: %d, occupiedSubcRange: %d, end: %d, numMiniSlots: %d, scPerMiniSlot: %d",
                          start, occupiedSubcRange, end, numMiniSlots, scPerMiniSlot)

        # Check if all subcs in range are truly for DATA IUC.
        while start < occupiedSubcRange and start < end:
            if activeIds[start] != 2:
                self.logger.info("non-data subc for this range of minislot")
                return -1
            # set subc as used now (exluded)
            activeIds[start] = 3
            start += 1

        # Search for next active subc for DATA IUC which is atleast equal or greater than subcPerMiniSlots
        activeSubcCounting = 0
        while start < end:
            if activeIds[start] == 2:
                activeSubcCounting += 1
                if activeSubcCounting == (scPerMiniSlot):
                    return (start + 1 - activeSubcCounting)
            start += 1
        return -1

    def _FindFirstLastSubcarrierId(self, activeIds):
        """
        This function tries to find first and last active subcarrier.
        It assumes there is only 1 range of active subcarriers for DATA.

        param activeIds: array of 2048 or 4096 bytes, each has value of 2, 3 or 4. (exclude, used, data)
        return: firstActSc, lastActSc that enclosed an active subcarrier range
        """
        firstActSc = 0
        lastActSc = 0
        start = 0

        while start < len(activeIds):
            if activeIds[start] != 2 and activeIds[start + 1] == 2:
                firstActSc = start + 1
            if activeIds[start] == 2 and activeIds[start + 1] != 2:
                lastActSc = start

            # return early
            if (firstActSc and lastActSc):
                return firstActSc, lastActSc
            start += 1

        if (firstActSc > lastActSc):
            self.logger.error("_FindFirstLastSubcarrierId: "
                              "firstActSc (%d) > lastActSc (%d)", firstActSc, lastActSc)
        return firstActSc, lastActSc


class UCDBurstProfile(DocsisMsgMacMessage):
    UCD_BURST_MIN_LEN = 1
    UCD_BURST_CODE_LEN = 1

    __metaclass__ = AddLoggerToClass

    def _get_tlv_fmts(self):
        """Returns dict of allowed TLVs' formats for RCP message specified by
        ID."""
        return rcp_tlv_def.UCD_BURST_PROFILE_TLV_SET.child_dict_by_id

    HeaderDef = (
        ("Type", gcp_packet.TLVData.TLV_type_fmt),
        ("Length", gcp_packet.TLVData.TLV_type_fmt),
        ("Code", gcp_packet.TLVData.TLV_type_fmt),
    )

    def __init__(self, type, code, parent_gpb=ucdBurst_gpb()):
        """

        :param parent_gpb: The parent GPB buffer class,
         default we will use the ucd definitions
        :return: UCD tlv

        """

        self.parent_gpb = parent_gpb
        self.parent_fmt = rcp_tlv_def.UCD_BURST_PROFILE_TLV_SET

        self.Type = type
        self.Length = 0
        self.Code = code

    def _decode_process(self):
        """Implements decoding of RCP sequences.

        :raises RCPSequenceDecodeError:

        """
        if self.get_max_len() < self.UCD_BURST_MIN_LEN:
            raise DocsisMsgDecodeError("UCD burst profile buffer "
                                       "length ({}) is too low, min "
                                       "length is {} bytes".format(
                                           self.get_max_len(), self.UCD_BURST_MIN_LEN))

        # decode the UCD Burst IUC
        # Type and Len is unpacked by UCD decode process
        val = unpack_from(
            gcp_packet.TLVData.TLV_type_fmt, self.buffer, self.offset)
        iuc_val = val[0]
        self.offset += 1

        self.Code = iuc_val

        sequence_length = self.get_max_len()
        try:
            ret = self._fast_decode(self.parent_fmt, self.parent_gpb, self.offset,
                                    sequence_length, 0, tl_format="!BB", tl_offset=2)
            self.offset += sequence_length  # update the offset
        except Exception as e:
            self.logger.error("UCD TLV Failed to decode TLVs of "
                              "sequence, unexpected reason: %s", str(e))
            return gcp_object.GCPObject.DECODE_FAILED

        if ret != gcp_object.GCPObject.DECODE_DONE:
            self.logger.error("decoding UCD TLV, unexpected result: %u", ret)
            return gcp_object.GCPObject.DECODE_FAILED

        return gcp_object.GCPObject.DECODE_DONE

    def _encode_process(self):  # pragma: no cover
        """Implements encoding of RCP sequence.

        :raises RCPSequenceEncodeError:

        """
        raise NotImplementedError()
