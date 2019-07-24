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
import struct
from rpd.rcp.gcp.gcp_lib.ucd_pb2 import ucd as ucd_gpb
from rpd.rcp.gcp.gcp_lib.ocd_pb2 import ocd as ocd_gpb
from rpd.rcp.gcp.gcp_lib.dpd_pb2 import dpd as dpd_gpb
from rpd.rcp.gcp.gcp_lib.ucdBurstProfile_pb2 \
    import burstProfile as ucdBurst_gpb
from struct import unpack_from
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.utils import SysTools
from rpd.hal.src.HalConfigMsg import *
from rpd.rcp.gcp.gcp_lib import gcp_object, gcp_packet
from rpd.rcp.rcp_lib import rcp_tlv_def, rcp

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
        if type in [2, 29, 35,]:
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
            self.msgtype = MsgTypeDocsisMsgUCD
            self.tlvFmts = rcp_tlv_def.UCD_TLV_SET.child_dict_by_id
            self.macMsgHdrLen = self.UCD_MAC_MESSAGE_HDR_LEN
            self.HeaderDef = self.UCDHeaderDef
            if SysTools.is_vrpd():
                self.convert_to_RCPSequence = self.UCD_to_RCPSequence
                self.BurstProfile = list()
            else:
                self.convert_to_RCPSequence = self.skip_convert
            self._update_tlv_dict(parent_gpb=ucd_gpb(), parent_fmt=rcp_tlv_def.UCD_TLV_SET)

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

        # extra data need to be decoded
        if type in [2, 29, 35,]:
            # decode the BurstProfile
            for burstProfiles in (self.parent_gpb.BurstDescDocsis1x,
                                  self.parent_gpb.BurstDescDocsis2x3x):
                for burstProfileData in burstProfiles:
                    burstProfile = UCDBurstProfile(
                        0, 0, ucdBurst_gpb())
                    if burstProfile.decode(burstProfileData, 0,
                                           len(burstProfileData)) == \
                            gcp_object.GCPObject.DECODE_DONE:
                        self.BurstProfile.append(burstProfile)
                    else:
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
                    id = struct.unpack('!H', subcarrierAssignment[index:index+2])[0]
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

        rcpUsQamTlv.UpStreamChanId    = self.headDict["UCDUstreamChannelID"]
        rcpUsQamTlv.ConfigChangeCount = self.headDict["UCDConfChangeCnt"]
        rcpUsQamTlv.DownStreamChanId  = self.headDict["UCDDownstreamChannelID"]

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


