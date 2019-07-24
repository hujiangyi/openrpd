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

from rpd.rcp.gcp.gcp_lib import gcp_tlv_def, gcp_msg_def
from rpd.rcp.rcp_lib.rcp_tlv_def import *

"""
Examples of defining RfChannel/RfPort TLVs as sub-TLVs of VendorSpecificExtension.
Vendors can add their own sub-TLVs here as needed.
"""

# Sub-TLV 21.1 was defined by Cisco in rcp_tlv_def.py
#RCPTLV(1, "VendorId", C_VendorSpecificExtension_21, "!H",rw=RW_FLAG_r)
RCPTLV(14, "FWVersion", C_VendorSpecificExtension_21, "!H",rw=RW_FLAG_r)
RCPTLV(15, "HWVersion", C_VendorSpecificExtension_21, "!H",rw=RW_FLAG_r)

"""
The 2 sub-TLVs below are for example: they are defined by RPHY, but re-use the format
of these here to show that Vendors can define their own customized TLV format. 
"""
C_RfChannel_16 = RCPTLV(16, "RfChannel", C_VendorSpecificExtension_21, rw=RW_FLAG_row_key)
C_RfPort_17 = RCPTLV(17, "RfPort", C_VendorSpecificExtension_21, rw=RW_FLAG_row_key)


#
# B.7.3 DOCSIS and MPEG Video Downstream Channel Configuration (Vendor Specific)
#
C_DsScQamChannelConfig_62 = \
    RCPTLV(62, "DsScQamChannelConfig", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "AdminState", C_DsScQamChannelConfig_62, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(2, "CcapCoreOwner", C_DsScQamChannelConfig_62, "MAC")
RCPTLV(3, "RfMute", C_DsScQamChannelConfig_62, "!B", constraint=BOOL_CONSTR)
RCPTLV(4, "TSID", C_DsScQamChannelConfig_62, "!H")
RCPTLV(5, "CenterFrequency", C_DsScQamChannelConfig_62, "!L")
RCPTLV(6, "OperationalMode", C_DsScQamChannelConfig_62, "!B",
       constraint=EnumConstraint(OPERATIONAL_MODE_DICT))
RCPTLV(7, "Modulation", C_DsScQamChannelConfig_62, "!B",
       constraint=EnumConstraint(MODULATION_57_DICT))
RCPTLV(8, "InterleaverDepth", C_DsScQamChannelConfig_62, "!B",
       constraint=EnumConstraint(INTERLEAVER_DEPTH_DICT))
RCPTLV(9, "Annex", C_DsScQamChannelConfig_62, "!B",
       constraint=EnumConstraint(ANNEX_DICT))
RCPTLV(10, "SyncInterval", C_DsScQamChannelConfig_62, "!B",
       constraint=RangeConstraint2(SYNC_INTERVAL_0_not_send[0],
                                   SYNC_INTERVAL_0_not_send[0],
                                   SYNC_INTERVAL_5_msec_min[0],
                                   SYNC_INTERVAL_255_msec_max[0]))
RCPTLV(11, "SyncMacAddress", C_DsScQamChannelConfig_62, "MAC")
RCPTLV(12, "SymbolFrequencyDenominator", C_DsScQamChannelConfig_62, "!H")
RCPTLV(13, "SymbolFrequencyNumerator", C_DsScQamChannelConfig_62, "!H")
RCPTLV(14, "SymbolRateOverride", C_DsScQamChannelConfig_62, "!L")
RCPTLV(15, "SpectrumInversionEnabled", C_DsScQamChannelConfig_62, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(16, "PowerAdjust", C_DsScQamChannelConfig_62, "!B")

#
# DsOfdmChannelConfig (Vendor Specific)
#
C_DsOfdmChannelConfig_63 = \
    RCPTLV(63, "DsOfdmChannelConfig", C_RfChannel_16, rw=RW_FLAG_row)
# TODO __DB__ RCPTLV(0, "Index"   , C_DsOfdmChannelConfig_6, "!H",
# rw=RW_FLAG_key) # ??? on DIAGRAM but MISSING IN TLV
RCPTLV(1, "AdminState", C_DsOfdmChannelConfig_63, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(2, "CcapCoreOwner", C_DsOfdmChannelConfig_63, "MAC")
RCPTLV(3, "RfMute", C_DsOfdmChannelConfig_63, "!B", constraint=BOOL_CONSTR)
RCPTLV(4, "SubcarrierZeroFreq", C_DsOfdmChannelConfig_63, "!I")
RCPTLV(5, "FirstActiveSubcarrier", C_DsOfdmChannelConfig_63, "!H")
RCPTLV(6, "LastActiveSubcarrier", C_DsOfdmChannelConfig_63, "!H")
RCPTLV(7, "NumActiveSubcarriers", C_DsOfdmChannelConfig_63, "!H")
RCPTLV(8, "CyclicPrefix", C_DsOfdmChannelConfig_63, "!B",
       constraint=EnumConstraint(CYCLIC_PREFIX_DICT))
RCPTLV(9, "RollOffPeriod", C_DsOfdmChannelConfig_63, "!B",
       constraint=EnumConstraint(ROLL_OFF_PERIOD_DICT))
RCPTLV(10, "PlcFReq", C_DsOfdmChannelConfig_63, "!I")
RCPTLV(11, "TimeInterleaverDepth", C_DsOfdmChannelConfig_63, "!B",
       constraint=RangeConstraint(TIME_INTERLEAVER_DEPTH_TYPES[0],
                                  TIME_INTERLEAVER_DEPTH_TYPES[-1]))
RCPTLV(12, "SubcarrierSpacing", C_DsOfdmChannelConfig_63, "!B",
       constraint=EnumConstraint(SUBCARRIER_SPACING_DICT))
C63_DsOfdmSubcarrierType_13 = \
    RCPTLV(13, "DsOfdmSubcarrierType", C_DsOfdmChannelConfig_63,
           rw=RW_FLAG_row)
RCPTLV(1, "StartSubcarrierId", C63_DsOfdmSubcarrierType_13, "!H",
       rw=RW_FLAG_key,
       constraint=RangeConstraint(SUBCARRIER_ID_TYPES[0],
                                  SUBCARRIER_ID_TYPES[-1]))
RCPTLV(2, "EndSubcarrierId", C63_DsOfdmSubcarrierType_13, "!H",
       constraint=RangeConstraint(SUBCARRIER_ID_TYPES[0],
                                  SUBCARRIER_ID_TYPES[-1]))
RCPTLV(3, "SubcarrierUsage", C63_DsOfdmSubcarrierType_13, "!B",
       constraint=EnumConstraint(SUBCARRIER_USAGE_DICT))

#
# DsOfdmProfile (Vendor Specific)
#
C_DsOfdmProfile_64 = \
    RCPTLV(64, "DsOfdmProfile", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "ProfileId", C_DsOfdmProfile_64, "!B",
       constraint=RangeConstraint(PROFILE_ID_TYPES[0], PROFILE_ID_TYPES[-1]))
C64_DsOfdmSubcarrierModulation_2 = \
RCPTLV(2, "DsOfdmSubcarrierModulation", C_DsOfdmProfile_64,
           rw=RW_FLAG_row)
RCPTLV(1, "StartSubcarrierId", C64_DsOfdmSubcarrierModulation_2, "!H",
       rw=RW_FLAG_key,
       constraint=RangeConstraint(SUBCARRIER_ID_TYPES[0],
                                  SUBCARRIER_ID_TYPES[-1]))
RCPTLV(2, "EndSubcarrierId", C64_DsOfdmSubcarrierModulation_2, "!H",
       constraint=RangeConstraint(SUBCARRIER_ID_TYPES[0],
                                SUBCARRIER_ID_TYPES[-1]))
RCPTLV(3, "Modulation", C64_DsOfdmSubcarrierModulation_2, "!B",
      constraint=EnumConstraint(DATA_SYMBOL_MODULATION_DICT))

#
# B.7.8 DOCSIS Upstream Channel Configuration (Vendor Specific)
#
C_UsScQamChannelConfig_65 = \
    RCPTLV(65, "UsScQamChannelConfig", C_RfChannel_16, rw=RW_FLAG_row)
# TODO __DB__ RCPTLV(0, "Index", C_UsScQamChannelConfig_8, "!H",
# rw=RW_FLAG_key) # ??? on DIAGRAM but MISSING IN TLV
RCPTLV(1, "AdminState", C_UsScQamChannelConfig_65, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(2, "CcapCoreOwner", C_UsScQamChannelConfig_65, "MAC")
RCPTLV(3, "Type", C_UsScQamChannelConfig_65, "!B",
       constraint=EnumConstraint(MULTIPLEX_TYPE_DICT))
RCPTLV(4, "CenterFrequency", C_UsScQamChannelConfig_65, "!I")
RCPTLV(5, "Width", C_UsScQamChannelConfig_65, "!I",
       constraint=EnumConstraint(BAND_WIDTH_DICT))
RCPTLV(6, "SlotSize", C_UsScQamChannelConfig_65, "!I")
RCPTLV(7, "StartingMinislot", C_UsScQamChannelConfig_65, "!I")
RCPTLV(8, "PreambleString", C_UsScQamChannelConfig_65, "bytes")  # ??? max 192
RCPTLV(9, "TargetRxPower", C_UsScQamChannelConfig_65, "!h")

# IntervalUsageCode (Vendor Specific)
C65_IntervalUsageCode_10 = \
    RCPTLV(10, "IntervalUsageCode", C_UsScQamChannelConfig_65, rw=RW_FLAG_row)
RCPTLV(1, "Code", C65_IntervalUsageCode_10, "!B", rw=RW_FLAG_key,
       constraint=RangeConstraint(INTERVAL_USAGE_CODE_TYPE[0],
                                  INTERVAL_USAGE_CODE_TYPE[-1]))
RCPTLV(2, "DifferentialEncoding", C65_IntervalUsageCode_10, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(3, "FecErrorCorrectionT", C65_IntervalUsageCode_10, "!B",
       constraint=RangeConstraint(FEC_ERROR_CORRECTION_TYPES[0],
                                  FEC_ERROR_CORRECTION_TYPES[-1]))
RCPTLV(4, "FecCodewordLength", C65_IntervalUsageCode_10, "!B",
       constraint=RangeConstraint(FEC_CODEWORD_LENGTH_TYPES[0],
                                  FEC_CODEWORD_LENGTH_TYPES[-1]))
RCPTLV(5, "PreambleLen", C65_IntervalUsageCode_10, "!H")
RCPTLV(6, "PreambleOffsett", C65_IntervalUsageCode_10, "!H")
RCPTLV(7, "PreambleModType", C65_IntervalUsageCode_10, "!B",
       constraint=EnumConstraint(PREAMBLE_MOD_TYPE_DICT))
RCPTLV(8, "Scrambler", C65_IntervalUsageCode_10, "!B", constraint=BOOL_CONSTR)
RCPTLV(9, "ScrambleSeed", C65_IntervalUsageCode_10, "!H")
RCPTLV(10, "MaxBurstSize", C65_IntervalUsageCode_10, "!B")
RCPTLV(11, "LasCodewordShortened", C65_IntervalUsageCode_10, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(12, "ByteInterleaverDepth", C65_IntervalUsageCode_10, "!B",
       constraint=EnumConstraint(BYTE_INTERLEAVER_DEPTH_DICT))
RCPTLV(13, "ByteInterleaverBlockSize", C65_IntervalUsageCode_10, "!H")
RCPTLV(14, "ModulationType", C65_IntervalUsageCode_10, "!B")
RCPTLV(15, "GuardTime", C65_IntervalUsageCode_10, "!B")

#
# UsOfdmaChannelConfig (Vendor Specific)
#
C_UsOfdmaChannelConfig_66 = \
    RCPTLV(66, "UsOfdmaChannelConfig", C_RfChannel_16, rw=RW_FLAG_row)
# TODO __DB__ RCPTLV(0, "Index" , C_UsOfdmaChannelConfig_9, "!H",
# rw=RW_FLAG_key) # ??? on DIAGRAM but MISSING IN TLV
RCPTLV(1, "AdminState", C_UsOfdmaChannelConfig_66, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(2, "CcapCoreOwner", C_UsOfdmaChannelConfig_66, "MAC")
RCPTLV(3, "SubcarrierZeroFreq", C_UsOfdmaChannelConfig_66, "!I")
RCPTLV(4, "FirstActiveSubcarrierNum", C_UsOfdmaChannelConfig_66, "!H")
RCPTLV(5, "LastActiveSubcarrierNum", C_UsOfdmaChannelConfig_66, "!H")
RCPTLV(6, "RollOffPeriod", C_UsOfdmaChannelConfig_66, "!H",
       constraint=EnumConstraint(ROLL_OFF_PERIOD_96_DICT))
RCPTLV(7, "CyclicPrefix", C_UsOfdmaChannelConfig_66, "!H",
       constraint=EnumConstraint(CYCLIC_PREFIX_97_DICT))
RCPTLV(8, "SubcarrierSpacing", C_UsOfdmaChannelConfig_66, "!B",
       constraint=EnumConstraint(SUBCARRIER_SPACING_DICT))
# additional restrictions as outlined in the DOCSIS 3.1 PHY
RCPTLV(9, "NumSymbolsPerFrame", C_UsOfdmaChannelConfig_66, "!B",
       constraint=RangeConstraint(NUM_SYMBOL_PER_FRAME_TYPES[0],
                                  NUM_SYMBOL_PER_FRAME_TYPES[-1]))
RCPTLV(10, "NumActiveSubcarriers", C_UsOfdmaChannelConfig_66, "!H")
RCPTLV(11, "StartingMinislot", C_UsOfdmaChannelConfig_66, "!I")
RCPTLV(12, "PreambleString", C_UsOfdmaChannelConfig_66, "var")  # ??? max 192
RCPTLV(13, "TargetRxPower", C_UsOfdmaChannelConfig_66, "!H")
RCPTLV(14, "EnableFlowTags", C_UsOfdmaChannelConfig_66, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(15, "ScramblerSeed", C_UsOfdmaChannelConfig_66, "!I")

#
# UsOfdmaInitialRangingIuc (Vendor Specific)
#
C_UsOfdmaInitialRangingIuc_67 = \
    RCPTLV(67, "UsOfdmaInitialRangingIuc", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "NumSubcarriers", C_UsOfdmaInitialRangingIuc_67, "!H",
       constraint=EvenConstraint())
RCPTLV(2, "Guardband", C_UsOfdmaInitialRangingIuc_67, "!H")

#
# UsOfdmaFineRangingIuc
#
C_UsOfdmaFineRangingIuc_68 = \
    RCPTLV(68, "UsOfdmaFineRangingIuc", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "NumSubcarriers", C_UsOfdmaFineRangingIuc_68, "!H",
       constraint=EvenConstraint())
RCPTLV(2, "Guardband", C_UsOfdmaFineRangingIuc_68, "!H")

#
# UsOfdmaDataIuc (Vendor Specific)
#
C_UsOfdmaDataIuc_69 = \
    RCPTLV(69, "UsOfdmaDataIuc", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "DataIuc", C_UsOfdmaDataIuc_69, "!B", rw=RW_FLAG_key,
       constraint=EnumConstraint(DATA_IUC_DICT))
# ??? 8bit value LEN == 2
RCPTLV(2, "StartingMinislot", C_UsOfdmaDataIuc_69, "!H",
       constraint=RangeConstraint(START_MIN_SLOT_TYPE[0],
                                  START_MIN_SLOT_TYPE[-1]))
RCPTLV(3, "FirstSubcarrierId", C_UsOfdmaDataIuc_69, "!H")
RCPTLV(4, "NumConsecutiveMinislots", C_UsOfdmaDataIuc_69, "!H")
RCPTLV(5, "MinislotPilotPattern", C_UsOfdmaDataIuc_69, "!B",
       constraint=RangeConstraint(MINISLOT_PILOT_TYPES[0],
                                  MINISLOT_PILOT_TYPES[-1]))
RCPTLV(6, "DataSymbolModulation", C_UsOfdmaDataIuc_69, "!B",
       constraint=EnumConstraint(DATA_SYMBOL_MODULATION_DICT))

#
# UsOfdmaSubcarrierCfgState (Vendor Specific)
#
C_UsOfdmaSubcarrierCfgState_70 = \
    RCPTLV(70, "UsOfdmaSubcarrierCfgState", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "StartingSubcarrierId", C_UsOfdmaSubcarrierCfgState_70, "!H",
       rw=RW_FLAG_key, constraint=RangeConstraint(
       STARTING_SUBCARRIER_ID_TYPES[0],
       STARTING_SUBCARRIER_ID_TYPES[-1]))
RCPTLV(2, "NumConsecutiveSubcarriers", C_UsOfdmaSubcarrierCfgState_70, "!H")
RCPTLV(3, "SubarrierUsage", C_UsOfdmaSubcarrierCfgState_70, "!B",
       constraint=EnumConstraint(SUBCARRIER_USAGE_13_DICT))

#
# SidQos (Vendor Specific)
#
C_SidQos_96 = \
    RCPTLV(96, "SidQos", C_RfChannel_16, rw=RW_FLAG_row_key)
RCPTLV(1, "StartSid", C_SidQos_96, "!H")
RCPTLV(2, "NumSids", C_SidQos_96, "!H")
RCPTLV(3, "SidSfType", C_SidQos_96, "!B")
RCPTLV(4, "SidUepiFlowId", C_SidQos_96, "!B")
RCPTLV(5, "SidFlowTag", C_SidQos_96, "!I")

#
# IucCounter (Vendor Specific)
#
C_IucCounter_98 = \
    RCPTLV(98, "IucCounter", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "CliCmd", C_IucCounter_98, "!H")
RCPTLV(2, "Slot", C_IucCounter_98, "!H")
RCPTLV(3, "DevId", C_IucCounter_98, "!B")
RCPTLV(4, "Pch", C_IucCounter_98, "!B")
RCPTLV(5, "LogChan", C_IucCounter_98, "!B")
RCPTLV(6, "Iuc", C_IucCounter_98, "!B")
RCPTLV(7, "RawData",C_IucCounter_98, "var", 
       constraint=StringLenConstraint(2048))
#
# Fft (Vendor Specific)
#
C_FftCfg_99 = \
    RCPTLV(99, "FftCfg", C_RfChannel_16, rw=RW_FLAG_row_key)
RCPTLV(1, "Sid", C_FftCfg_99, "!H")
RCPTLV(2, "Freq", C_FftCfg_99, "!I")
RCPTLV(3, "Iuc", C_FftCfg_99, "!B")
RCPTLV(4, "Size", C_FftCfg_99, "!I")
RCPTLV(5, "Mode", C_FftCfg_99, "!H")

#
# Status and performance TLVs (Vendor Specific)
#
C_DsRfPortPerf_71 = \
    RCPTLV(71, "DsRfPortPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_DsScQamChannelPerf_72 = \
    RCPTLV(72, "DsScQamChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsScQamChannelPerf_72, "!I", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsScQamChannelPerf_72, "!I", rw=RW_FLAG_r)

C_DsOfdmChannelPerf_73 = \
    RCPTLV(73, "DsOfdmChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsOfdmChannelPerf_73, "!I", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsOfdmChannelPerf_73, "!I", rw=RW_FLAG_r)
C73_DsOrdmProfilePerf_3 = \
    RCPTLV(3, "DsOfdmProfilePerf", C_DsOfdmChannelPerf_73, rw=RW_FLAG_row)
RCPTLV(1, "ProfileIndex", C73_DsOrdmProfilePerf_3, "!B", rw=RW_FLAG_r)
RCPTLV(2, "outCodewords", C73_DsOrdmProfilePerf_3, "!I", rw=RW_FLAG_r)

C_DsOob551IPerf_74 = \
    RCPTLV(74, "DsOob551IPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsOob551IPerf_74, "!I", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsOob551IPerf_74, "!I", rw=RW_FLAG_r)

C_DsOob552Perf_75 = \
    RCPTLV(75, "DsOob552Perf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsOob552Perf_75, "!I", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsOob552Perf_75, "!I", rw=RW_FLAG_r)

C_NdfPerf_76 = \
    RCPTLV(76, "NdfPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_NdfPerf_76, "!I", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_NdfPerf_76, "!I", rw=RW_FLAG_r)

C_UsRfPortPerf_77 = \
    RCPTLV(77, "UsRfPortPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_UsScQamChannelPerf_78 = \
    RCPTLV(78, "UsScQamChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
C78_UsScQamIucIPerf_1 = \
    RCPTLV(1, "UsScQamIucIPerf", C_UsScQamChannelPerf_78, rw=RW_FLAG_row)
RCPTLV(1, "UsIuc", C78_UsScQamIucIPerf_1, "!B", rw=RW_FLAG_r)
RCPTLV(2, "Collisions", C78_UsScQamIucIPerf_1, "!I", rw=RW_FLAG_r)
RCPTLV(3, "NoEnergy", C78_UsScQamIucIPerf_1, "!I", rw=RW_FLAG_r)

C_UsOfdmaChannelPerf_79 = \
    RCPTLV(79, "UsOfdmaChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_UsOob551IPerf_80 = \
    RCPTLV(80, "UsOob551IPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_UsOob552Perf_81 = \
    RCPTLV(81, "UsOob552Perf", C_RfChannel_16, rw=RW_FLAG_row)

C_NdrPerf_82 = \
    RCPTLV(82, "NdrPerf", C_RfChannel_16, rw=RW_FLAG_row)


#
# add general config RfChannelSelector and RfPortSelector for US and DS cfg (Vendor Specific)
#
C_RfChannelSelector_12 = RCPTLV(12, "RfChannelSelector", C_RfChannel_16,
                                  rw=RW_FLAG_row)
RCPTLV(1, "RfPortIndex", C_RfChannelSelector_12, "!B", rw=RW_FLAG_r)
RCPTLV(2, "RfChannelType", C_RfChannelSelector_12, "!B", rw=RW_FLAG_r)
RCPTLV(3, "RfChannelIndex", C_RfChannelSelector_12, "!B", rw=RW_FLAG_r)

C_RfPortSelector_13 = RCPTLV(13, "RfPortSelector", C_RfPort_17,
                               rw=RW_FLAG_row)
RCPTLV(1, "RfPortIndex", C_RfPortSelector_13, "!B", rw=RW_FLAG_r)
RCPTLV(2, "RfPortType", C_RfPortSelector_13, "!B", rw=RW_FLAG_r)



