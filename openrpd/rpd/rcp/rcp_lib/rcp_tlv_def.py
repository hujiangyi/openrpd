#
# Copyright (c) 2016 Cisco and/or its affiliates, and
#                    Teleste Corporation, and
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
from rpd.rcp.gcp.gcp_lib.gcp_data_description import BOOL_CONSTR
from rpd.rcp.gcp.gcp_lib.gcp_data_description import DataDescription
from rpd.rcp.gcp.gcp_lib.gcp_data_description import EnumConstraint
from rpd.rcp.gcp.gcp_lib.gcp_data_description import EvenConstraint
from rpd.rcp.gcp.gcp_lib.gcp_data_description import RangeConstraint
from rpd.rcp.gcp.gcp_lib.gcp_data_description import RangeConstraint2
from rpd.rcp.gcp.gcp_lib.gcp_data_description import StringLenConstraint
from rpd.rcp.gcp.gcp_lib.gcp_data_description import StringLenRangeConstraint

# Length of the Length field of RCP TLVs
RCP_TLV_LENGTH_LEN = 2  # Bytes

#
# RCP Message types
#
RCP_MSG_TYPE_NONE = 0
RCP_MSG_TYPE_IRA = 1
RCP_MSG_TYPE_REX = 2
RCP_MSG_TYPE_NTF = 3

RCP_MSG_IRA = RCP_MSG_TYPE_IRA, "IRA"
RCP_MSG_REX = RCP_MSG_TYPE_REX, "REX"
RCP_MSG_NTF = RCP_MSG_TYPE_NTF, "NTF"

RCP_MSG = (RCP_MSG_IRA,
           RCP_MSG_REX,
           RCP_MSG_NTF)
RCP_MSG_DICT = {n: s for n, s in RCP_MSG}
RCP_MSG_TYPES = tuple([n for n, s in RCP_MSG])

#
# RCP Operation types
#
RCP_OPERATION_TYPE_NONE = 0
RCP_OPERATION_TYPE_READ = 1
RCP_OPERATION_TYPE_WRITE = 2
RCP_OPERATION_TYPE_DELETE = 3
RCP_OPERATION_TYPE_READ_RESPONSE = 4
RCP_OPERATION_TYPE_WRITE_RESPONSE = 5
RCP_OPERATION_TYPE_DELETE_RESPONSE = 6
RCP_OPERATION_TYPE_ALLOCATE_WRITE = 7
RCP_OPERATION_TYPE_ALLOCATE_WRITE_RESPONSE = 8

RCP_OPERATION_READ = RCP_OPERATION_TYPE_READ, "OperationRead"
RCP_OPERATION_WRITE = RCP_OPERATION_TYPE_WRITE, "OperationWrite"
RCP_OPERATION_DELETE = RCP_OPERATION_TYPE_DELETE, "OperationDelete"
RCP_OPERATION_ALLOCATE_WRITE = RCP_OPERATION_TYPE_ALLOCATE_WRITE,\
    "OperationAllocateWrite"
RCP_OPERATION_READ_RESPONSE = RCP_OPERATION_TYPE_READ_RESPONSE,\
    "OperationReadResponse"
RCP_OPERATION_WRITE_RESPONSE = RCP_OPERATION_TYPE_WRITE_RESPONSE,\
    "OperationWriteResponse"
RCP_OPERATION_DELETE_RESPONSE = RCP_OPERATION_TYPE_DELETE_RESPONSE,\
    "OperationDeleteResponse"
RCP_OPERATION_ALLOCATE_WRITE_RESPONSE = RCP_OPERATION_TYPE_ALLOCATE_WRITE_RESPONSE,\
    "OperationAllocateWriteResponse"

RCP_OPERATION = (RCP_OPERATION_READ,
                 RCP_OPERATION_WRITE,
                 RCP_OPERATION_DELETE,
                 RCP_OPERATION_ALLOCATE_WRITE,
                 RCP_OPERATION_READ_RESPONSE,
                 RCP_OPERATION_WRITE_RESPONSE,
                 RCP_OPERATION_DELETE_RESPONSE,
                 RCP_OPERATION_ALLOCATE_WRITE_RESPONSE)
RCP_OPERATION_DICT = {n: s for n, s in RCP_OPERATION}
RCP_OPERATION_TYPES = tuple([n for n, s in RCP_OPERATION])

#
# Channel Types definitions
#
CHANNEL_TYPE_1_DsScQa_downstream_QAM = \
    1, "CHANNEL_TYPE_1_DsScQa_downstream_QAM"
CHANNEL_TYPE_2_DsOfdm_downstream_OFDM = \
    2, "CHANNEL_TYPE_2_DsOfdm_downstream_OFDM"
CHANNEL_TYPE_3_Ndf = \
    3, "CHANNEL_TYPE_3_Ndf"
CHANNEL_TYPE_4_DsScte55d1_downstream_SCTE_55_1 = \
    4, "CHANNEL_TYPE_4_DsScte55d1_downstream_SCTE_55_1"
CHANNEL_TYPE_5_UsAtdma_upstream_ATDMA = \
    5, "CHANNEL_TYPE_5_UsAtdma_upstream_ATDMA"
CHANNEL_TYPE_6_UsOfdma_upstream_OFDMA = \
    6, "CHANNEL_TYPE_6_UsOfdma_upstream_OFDMA"
CHANNEL_TYPE_7_Reserved = \
    7, "CHANNEL_TYPE_7_Reserved"
CHANNEL_TYPE_8_Ndr = \
    8, "CHANNEL_TYPE_8_Ndr"
CHANNEL_TYPE_9_UsScte55d1_upstream_SCTE_55_1 = \
    9, "CHANNEL_TYPE_9_UsScte55d1_upstream_SCTE_55_1"

CHANNEL_TYPE = (CHANNEL_TYPE_1_DsScQa_downstream_QAM,
                CHANNEL_TYPE_2_DsOfdm_downstream_OFDM,
                CHANNEL_TYPE_3_Ndf,
                CHANNEL_TYPE_4_DsScte55d1_downstream_SCTE_55_1,
                CHANNEL_TYPE_5_UsAtdma_upstream_ATDMA,
                CHANNEL_TYPE_6_UsOfdma_upstream_OFDMA,
                CHANNEL_TYPE_7_Reserved,
                CHANNEL_TYPE_8_Ndr,
                CHANNEL_TYPE_9_UsScte55d1_upstream_SCTE_55_1)
CHANNEL_TYPE_DICT = {n: s for n, s in CHANNEL_TYPE}
CHANNEL_TYPE_TYPES = tuple([n for n, s in CHANNEL_TYPE])

#
# Operational modes definitions
#
OPERATIONAL_MODE_1_Other = \
    1, "OPERATIONAL_MODE_1_Other"
OPERATIONAL_MODE_2_Channel_as_DOCSIS_channel = \
    2, "OPERATIONAL_MODE_2_Channel_as_DOCSIS_channel"
OPERATIONAL_MODE_3_Channel_as_synch_MPEG_video = \
    3, "OPERATIONAL_MODE_3_Channel_as_synch_MPEG_video"
OPERATIONAL_MODE_4_Channel_as_asynch_MPEG_video = \
    4, "OPERATIONAL_MODE_4_Channel_as_asynch_MPEG_video"
OPERATIONAL_MODE_5_Channel_as_CW_carrier_Pilot_or_Alignment = \
    5, "OPERATIONAL_MODE_5_Channel_as_CW_carrier_Pilot_or_Alignment"
OPERATIONAL_MODE = \
    (OPERATIONAL_MODE_1_Other,
     OPERATIONAL_MODE_2_Channel_as_DOCSIS_channel,
     OPERATIONAL_MODE_3_Channel_as_synch_MPEG_video,
     OPERATIONAL_MODE_4_Channel_as_asynch_MPEG_video,
     OPERATIONAL_MODE_5_Channel_as_CW_carrier_Pilot_or_Alignment)
OPERATIONAL_MODE_DICT = {n: s for n, s in OPERATIONAL_MODE}
OPERATIONAL_MODE_TYPES = tuple([n for n, s in OPERATIONAL_MODE])

#
# Admin states definitions
#
ADMIN_STATE_1_other = 1, "ADMIN_STATE_1_other"
ADMIN_STATE_2_up = 2, "ADMIN_STATE_2_up"
ADMIN_STATE_3_down = 3, "ADMIN_STATE_3_down"
ADMIN_STATE_4_testing = 4, "ADMIN_STATE_4_testing"
ADMIN_STATE = (ADMIN_STATE_1_other,
               ADMIN_STATE_2_up,
               ADMIN_STATE_3_down,
               ADMIN_STATE_4_testing)
ADMIN_STATE_DICT = {n: s for n, s in ADMIN_STATE}
ADMIN_STATE_TYPES = tuple([n for n, s in ADMIN_STATE])

RDTI_MODE_1_other = 1, "other"
RDTI_MODE_1_slave = 2, "RpdNodeSlave"
RDTI_MODE_1_master = 3, "RpdNodeMaster"

RDTI_MODE = (RDTI_MODE_1_other,
             RDTI_MODE_1_slave,
             RDTI_MODE_1_master)
RDTI_MODE_DICT = {n: s for n, s in RDTI_MODE}
RDTI_MODE_TYPES = tuple(RDTI_MODE_DICT.keys())


#
# Modulation types definitions
#
MODULATION_57__1_Unknown = 1, "MODULATION_57__1_Unknown"
MODULATION_57__2_Other = 2, "MODULATION_57__2_Other"
MODULATION_57__3_QAM64 = 3, "MODULATION_57__3_QAM64"
MODULATION_57__4_QAM256 = 4, "MODULATION_57__4_QAM256"
MODULATION_57 = (MODULATION_57__1_Unknown,
                 MODULATION_57__2_Other,
                 MODULATION_57__3_QAM64,
                 MODULATION_57__4_QAM256)
MODULATION_57_DICT = {n: s for n, s in MODULATION_57}
MODULATION_57_TYPES = tuple([n for n, s in MODULATION_57])

#
# Interleaver depth definitions
#
INTERLEAVER_DEPTH_1_unknown = \
    1, "INTERLEAVER_DEPTH_1_unknown"
INTERLEAVER_DEPTH_2_other = \
    2, "INTERLEAVER_DEPTH_2_other"
INTERLEAVER_DEPTH_3_taps8Increment16 = \
    3, "INTERLEAVER_DEPTH_3_taps8Increment16"
INTERLEAVER_DEPTH_4_taps16Increment8 = \
    4, "INTERLEAVER_DEPTH_4_taps16Increment8"
INTERLEAVER_DEPTH_5_taps32Increment4 = \
    5, "INTERLEAVER_DEPTH_5_taps32Increment4"
INTERLEAVER_DEPTH_6_taps64Increment2 = \
    6, "INTERLEAVER_DEPTH_6_taps64Increment2"
INTERLEAVER_DEPTH_7_taps128Increment1 = \
    7, "INTERLEAVER_DEPTH_7_taps128Increment1"
INTERLEAVER_DEPTH_8_taps12increment17 = \
    8, "INTERLEAVER_DEPTH_8_taps12increment17"
INTERLEAVER_DEPTH_9_taps128increment2 = \
    9, "INTERLEAVER_DEPTH_9_taps128increment2"
INTERLEAVER_DEPTH_10_taps128increment3 = \
    10, "INTERLEAVER_DEPTH_10_taps128increment3"
INTERLEAVER_DEPTH_11_taps128increment4 = \
    11, "INTERLEAVER_DEPTH_11_taps128increment4"
INTERLEAVER_DEPTH_12_taps128increment5 = \
    12, "INTERLEAVER_DEPTH_12_taps128increment5"
INTERLEAVER_DEPTH_13_taps128increment6 = \
    13, "INTERLEAVER_DEPTH_13_taps128increment6"
INTERLEAVER_DEPTH_14_taps128increment7 = \
    14, "INTERLEAVER_DEPTH_14_taps128increment7"
INTERLEAVER_DEPTH_15_taps128increment8 = \
    15, "INTERLEAVER_DEPTH_15_taps128increment8"
INTERLEAVER_DEPTH = (INTERLEAVER_DEPTH_1_unknown,
                     INTERLEAVER_DEPTH_2_other,
                     INTERLEAVER_DEPTH_3_taps8Increment16,
                     INTERLEAVER_DEPTH_4_taps16Increment8,
                     INTERLEAVER_DEPTH_5_taps32Increment4,
                     INTERLEAVER_DEPTH_6_taps64Increment2,
                     INTERLEAVER_DEPTH_7_taps128Increment1,
                     INTERLEAVER_DEPTH_8_taps12increment17,
                     INTERLEAVER_DEPTH_9_taps128increment2,
                     INTERLEAVER_DEPTH_10_taps128increment3,
                     INTERLEAVER_DEPTH_11_taps128increment4,
                     INTERLEAVER_DEPTH_12_taps128increment5,
                     INTERLEAVER_DEPTH_13_taps128increment6,
                     INTERLEAVER_DEPTH_14_taps128increment7,
                     INTERLEAVER_DEPTH_15_taps128increment8)
INTERLEAVER_DEPTH_DICT = {n: s for n, s in INTERLEAVER_DEPTH}
INTERLEAVER_DEPTH_TYPES = tuple([n for n, s in INTERLEAVER_DEPTH])

#
# ANNEX types definitions
#
ANNEX_1_Unknown = 1, "ANNEX_1_Unknown"
ANNEX_2_Other = 2, "ANNEX_2_Other"
ANNEX_3_annex_A = 3, "ANNEX_3_annex_A"
ANNEX_4_annex_B = 4, "ANNEX_4_annex_B"
ANNEX_5_annex_C = 5, "ANNEX_5_annex_C"
ANNEX = (ANNEX_1_Unknown,
         ANNEX_2_Other,
         ANNEX_3_annex_A,
         ANNEX_4_annex_B,
         ANNEX_5_annex_C)
ANNEX_DICT = {n: s for n, s in ANNEX}
ANNEX_TYPES = tuple([n for n, s in ANNEX])

#
# Sync interval definitions
#
SYNC_INTERVAL_0_not_send = 0, "SYNC_INTERVAL_0_not_send"
SYNC_INTERVAL_5_msec_min = 5, "SYNC_INTERVAL_5_msec_min"
SYNC_INTERVAL_255_msec_max = 255, "SYNC_INTERVAL_255_msec_max"
SYNC_INTERVAL = (SYNC_INTERVAL_0_not_send,
                 SYNC_INTERVAL_5_msec_min,
                 SYNC_INTERVAL_255_msec_max)
SYNC_INTERVAL_DICT = {n: s for n, s in SYNC_INTERVAL}
SYNC_INTERVAL_TYPES = tuple([n for n, s in SYNC_INTERVAL])

#
# Cyclic prefix definitions
#
CYCLIC_PREFIX_1_192 = 1, "CYCLIC_PREFIX_1_192"
CYCLIC_PREFIX_2_256 = 2, "CYCLIC_PREFIX_2_256"
CYCLIC_PREFIX_3_512 = 3, "CYCLIC_PREFIX_3_512"
CYCLIC_PREFIX_4_768 = 4, "CYCLIC_PREFIX_4_768"
CYCLIC_PREFIX_5_1024 = 5, "CYCLIC_PREFIX_5_1024"
CYCLIC_PREFIX = (CYCLIC_PREFIX_1_192,
                 CYCLIC_PREFIX_2_256,
                 CYCLIC_PREFIX_3_512,
                 CYCLIC_PREFIX_4_768,
                 CYCLIC_PREFIX_5_1024)
CYCLIC_PREFIX_DICT = {n: s for n, s in CYCLIC_PREFIX}
CYCLIC_PREFIX_TYPES = tuple([n for n, s in CYCLIC_PREFIX])

#
# Roll OFF period definitions
#
ROLL_OFF_PERIOD_1_0 = 1, "ROLL_OFF_PERIOD_1_0"
ROLL_OFF_PERIOD_2_64 = 2, "ROLL_OFF_PERIOD_2_64"
ROLL_OFF_PERIOD_3_128 = 3, "ROLL_OFF_PERIOD_3_128"
ROLL_OFF_PERIOD_4_192 = 4, "ROLL_OFF_PERIOD_4_192"
ROLL_OFF_PERIOD_5_256 = 5, "ROLL_OFF_PERIOD_5_256"
ROLL_OFF_PERIOD = (ROLL_OFF_PERIOD_1_0,
                   ROLL_OFF_PERIOD_2_64,
                   ROLL_OFF_PERIOD_3_128,
                   ROLL_OFF_PERIOD_4_192,
                   ROLL_OFF_PERIOD_5_256)
ROLL_OFF_PERIOD_DICT = {n: s for n, s in ROLL_OFF_PERIOD}
ROLL_OFF_PERIOD_TYPES = tuple([n for n, s in ROLL_OFF_PERIOD])

#
# Time Interleaver Depth definitions
#
TIME_INTERLEAVER_DEPTH_1_min = 1, "TIME_INTERLEAVER_DEPTH_1_min"
TIME_INTERLEAVER_DEPTH_32_max = 32, "TIME_INTERLEAVER_DEPTH_32_max"
TIME_INTERLEAVER_DEPTH = (TIME_INTERLEAVER_DEPTH_1_min,
                          TIME_INTERLEAVER_DEPTH_32_max)
TIME_INTERLEAVER_DEPTH_DICT = {n: s for n, s in TIME_INTERLEAVER_DEPTH}
TIME_INTERLEAVER_DEPTH_TYPES = tuple([n for n, s in TIME_INTERLEAVER_DEPTH])

#
# Subcarrier spacing definitions
#
SUBCARRIER_SPACING_1_25KHz = 1, "SUBCARRIER_SPACING_1_25KHz"
SUBCARRIER_SPACING_2_50KHz = 2, "SUBCARRIER_SPACING_2_50KHz"
SUBCARRIER_SPACING = (SUBCARRIER_SPACING_1_25KHz,
                      SUBCARRIER_SPACING_2_50KHz,)
SUBCARRIER_SPACING_DICT = {n: s for n, s in SUBCARRIER_SPACING}
SUBCARRIER_SPACING_TYPES = tuple([n for n, s in SUBCARRIER_SPACING])

#
# Profile ID definitions
#
PROFILE_ID_0_min = 0, "PROFILE_ID_0_min"
PROFILE_ID_15_max = 15, "PROFILE_ID_15_max"
PROFILE_ID = (PROFILE_ID_0_min,
              PROFILE_ID_15_max)
PROFILE_ID_DICT = {n: s for n, s in PROFILE_ID}
PROFILE_ID_TYPES = tuple([n for n, s in PROFILE_ID])

#
# Subcarrier ID definitions
#
SUBCARRIER_ID_0_min = 0, "SUBCARRIER_ID_0_min"
SUBCARRIER_ID_8191_max = 8191, "SUBCARRIER_ID_8191_max"
SUBCARRIER_ID = (SUBCARRIER_ID_0_min,
                 SUBCARRIER_ID_8191_max)
SUBCARRIER_ID_DICT = {n: s for n, s in SUBCARRIER_ID}
SUBCARRIER_ID_TYPES = tuple([n for n, s in SUBCARRIER_ID])

#
# Modulation definitions
#
MODULATION_722__1_Other = 1, "MODULATION_722__1_Other"
MODULATION_722__2_zeroValued = 2, "MODULATION_722__2_zeroValued"
MODULATION_722__3_qpsk = 3, "MODULATION_722__3_qpsk"
MODULATION_722__4_qam16 = 4, "MODULATION_722__4_qam16"
MODULATION_722__5_qam64 = 5, "MODULATION_722__5_qam64"
MODULATION_722__6_qam128 = 6, "MODULATION_722__6_qam128"
MODULATION_722__7_qam256 = 7, "MODULATION_722__7_qam256"
MODULATION_722__8_qam512 = 8, "MODULATION_722__8_qam512"
MODULATION_722__9_qam1024 = 9, "MODULATION_722__9_qam1024"
MODULATION_722__10_qam2048 = 10, "MODULATION_722__10_qam2048"
MODULATION_722__11_qam4096 = 11, "MODULATION_722__11_qam4096"
MODULATION_722__12_qam8192 = 12, "MODULATION_722__12_qam8192"
MODULATION_722__13_qam16384 = 13, "MODULATION_722__13_qam16384"
MODULATION_722 = (MODULATION_722__1_Other,
                  MODULATION_722__2_zeroValued,
                  MODULATION_722__3_qpsk,
                  MODULATION_722__4_qam16,
                  MODULATION_722__5_qam64,
                  MODULATION_722__6_qam128,
                  MODULATION_722__7_qam256,
                  MODULATION_722__8_qam512,
                  MODULATION_722__9_qam1024,
                  MODULATION_722__10_qam2048,
                  MODULATION_722__11_qam4096,
                  MODULATION_722__12_qam8192,
                  MODULATION_722__13_qam16384)
MODULATION_722_DICT = {n: s for n, s in MODULATION_722}
MODULATION_722_TYPES = tuple([n for n, s in MODULATION_722])

#
# Subcarrier usage definitions
#
SUBCARRIER_USAGE_1_Other = 1, "SUBCARRIER_USAGE_1_Other"
SUBCARRIER_USAGE_2_Data = 2, "SUBCARRIER_USAGE_2_Data"
SUBCARRIER_USAGE_3_Plc3 = 3, "SUBCARRIER_USAGE_3_Plc3"
SUBCARRIER_USAGE_4_Continuous_Pilot = 4, "SUBCARRIER_USAGE_4_Continuous_Pilot"
SUBCARRIER_USAGE_5_Excluded = 5, "SUBCARRIER_USAGE_5_Excluded"
SUBCARRIER_USAGE_6_Unused = 6, "SUBCARRIER_USAGE_6_Unused"
SUBCARRIER_USAGE = (SUBCARRIER_USAGE_1_Other,
                    SUBCARRIER_USAGE_2_Data,
                    SUBCARRIER_USAGE_3_Plc3,
                    SUBCARRIER_USAGE_4_Continuous_Pilot,
                    SUBCARRIER_USAGE_5_Excluded,
                    SUBCARRIER_USAGE_6_Unused)
SUBCARRIER_USAGE_DICT = {n: s for n, s in SUBCARRIER_USAGE}
SUBCARRIER_USAGE_TYPES = tuple([n for n, s in SUBCARRIER_USAGE])

#
# Multiplex types definitions
#
MULTIPLEX_TYPE_0_Unknown = 0, "TYPE_0_Unknown"
MULTIPLEX_TYPE_1_TDMA = 1, "TYPE_1_TDMA"
MULTIPLEX_TYPE_2_ATDMA = 2, "TYPE_2_ATDMA"
MULTIPLEX_TYPE_3_Reserved = 3, "TYPE_3_Reserved"
MULTIPLEX_TYPE_4_TDMAandATDMA = 4, "TYPE_4_TDMAandATDMA"
MULTIPLEX_TYPE = (MULTIPLEX_TYPE_0_Unknown,
                  MULTIPLEX_TYPE_1_TDMA,
                  MULTIPLEX_TYPE_2_ATDMA,
                  MULTIPLEX_TYPE_3_Reserved,
                  MULTIPLEX_TYPE_4_TDMAandATDMA)
MULTIPLEX_TYPE_DICT = {n: s for n, s in MULTIPLEX_TYPE}
MULTIPLEX_TYPE_TYPES = tuple([n for n, s in MULTIPLEX_TYPE])

#
# Band width definitions
#
BAND_WIDTH__200_000 = 200000, "WIDTH__200_000"
BAND_WIDTH__400_000 = 400000, "WIDTH__400_000"
BAND_WIDTH__800_000 = 800000, "WIDTH__800_000"
BAND_WIDTH__1_600_000 = 1600000, "WIDTH__1_600_000"
BAND_WIDTH__3_200_000 = 3200000, "WIDTH__3_200_000"
BAND_WIDTH__6_400_000 = 6400000, "WIDTH__6_400_000"
BAND_WIDTH = (BAND_WIDTH__200_000,
              BAND_WIDTH__400_000,
              BAND_WIDTH__800_000,
              BAND_WIDTH__1_600_000,
              BAND_WIDTH__3_200_000,
              BAND_WIDTH__6_400_000)
BAND_WIDTH_DICT = {n: s for n, s in BAND_WIDTH}
BAND_WIDTH_TYPES = tuple([n for n, s in BAND_WIDTH])

#
# Interval usage code definitions
#
INTERVAL_USAGE_CODE_1_min = 1, "CODE_1_min"
INTERVAL_USAGE_CODE_14_max = 14, "CODE_14_max"
INTERVAL_USAGE_CODE = (INTERVAL_USAGE_CODE_1_min,
                       INTERVAL_USAGE_CODE_14_max)
INTERVAL_USAGE_CODE_DICT = {n: s for n, s in INTERVAL_USAGE_CODE}
INTERVAL_USAGE_CODE_TYPE = tuple([n for n, s in INTERVAL_USAGE_CODE])

#
# FEC (error correction and codeword length) definitions
#
FEC_ERROR_CORRECTION_0_min = 0, "FEC_ERROR_CORRECTION_0_min"
FEC_ERROR_CORRECTION_16_min = 16, "FEC_ERROR_CORRECTION_16_min"
FEC_ERROR_CORRECTION = (FEC_ERROR_CORRECTION_0_min,
                        FEC_ERROR_CORRECTION_16_min)
FEC_ERROR_CORRECTION_DICT = {n: s for n, s in FEC_ERROR_CORRECTION}
FEC_ERROR_CORRECTION_TYPES = tuple([n for n, s in FEC_ERROR_CORRECTION])

FEC_CODEWORD_LENGTH_16_min = 16, "FEC_CODEWORD_LENGTH_16_min"
FEC_CODEWORD_LENGTH_253_min = 253, "FEC_CODEWORD_LENGTH_253_min"
FEC_CODEWORD_LENGTH = (FEC_CODEWORD_LENGTH_16_min,
                       FEC_CODEWORD_LENGTH_253_min)
FEC_CODEWORD_LENGTH_DICT = {n: s for n, s in FEC_CODEWORD_LENGTH}
FEC_CODEWORD_LENGTH_TYPES = tuple([n for n, s in FEC_CODEWORD_LENGTH])

#
# Preamble modulation definitions
#
PREAMBLE_MOD_TYPE_1_QPSK0 = 1, "PREAMBLE_MOD_TYPE_1_QPSK0"
PREAMBLE_MOD_TYPE_2_QPSK1 = 2, "PREAMBLE_MOD_TYPE_2_QPSK1"
PREAMBLE_MOD_TYPE = (PREAMBLE_MOD_TYPE_1_QPSK0,
                     PREAMBLE_MOD_TYPE_2_QPSK1)
PREAMBLE_MOD_TYPE_DICT = {n: s for n, s in PREAMBLE_MOD_TYPE}
PREAMBLE_MOD_TYPE_TYPES = tuple([n for n, s in PREAMBLE_MOD_TYPE])

#
# Byte Interleaver depth definitions
#
BYTE_INTERLEAVER_DEPTH_0_Dynamic_mode = \
    0, "BYTE_INTERLEAVER_DEPTH_0_Dynamic_mode"
BYTE_INTERLEAVER_DEPTH_1_RS_Interleaving_disabled = \
    1, "BYTE_INTERLEAVER_DEPTH_1_RS_Interleaving_disabled"
BYTE_INTERLEAVER_DEPTH = (BYTE_INTERLEAVER_DEPTH_0_Dynamic_mode,
                          BYTE_INTERLEAVER_DEPTH_1_RS_Interleaving_disabled)
BYTE_INTERLEAVER_DEPTH_DICT = {n: s for n, s in BYTE_INTERLEAVER_DEPTH}
BYTE_INTERLEAVER_DEPTH_TYPES = tuple([n for n, s in BYTE_INTERLEAVER_DEPTH])

#
# Roll Off period definitions
#
ROLL_OFF_PERIOD_96__1_0_samples = 1, "ROLL_OFF_PERIOD_96__1_0_samples"
ROLL_OFF_PERIOD_96__2_32_samples = 2, "ROLL_OFF_PERIOD_96__2_32_samples"
ROLL_OFF_PERIOD_96__3_64_samples = 3, "ROLL_OFF_PERIOD_96__3_64_samples"
ROLL_OFF_PERIOD_96__4_96_samples = 4, "ROLL_OFF_PERIOD_96__4_96_samples"
ROLL_OFF_PERIOD_96__5_128_samples = 5, "ROLL_OFF_PERIOD_96__5_128_samples"
ROLL_OFF_PERIOD_96__6_160_samples = 6, "ROLL_OFF_PERIOD_96__6_160_samples"
ROLL_OFF_PERIOD_96__7_192_samples = 7, "ROLL_OFF_PERIOD_96__7_192_samples"
ROLL_OFF_PERIOD_96__8_224_samples = 8, "ROLL_OFF_PERIOD_96__8_224_samples"
ROLL_OFF_PERIOD_96 = (ROLL_OFF_PERIOD_96__1_0_samples,
                      ROLL_OFF_PERIOD_96__2_32_samples,
                      ROLL_OFF_PERIOD_96__3_64_samples,
                      ROLL_OFF_PERIOD_96__4_96_samples,
                      ROLL_OFF_PERIOD_96__5_128_samples,
                      ROLL_OFF_PERIOD_96__6_160_samples,
                      ROLL_OFF_PERIOD_96__7_192_samples,
                      ROLL_OFF_PERIOD_96__8_224_samples)
ROLL_OFF_PERIOD_96_DICT = {n: s for n, s in ROLL_OFF_PERIOD_96}
ROLL_OFF_PERIOD_96_TYPES = tuple([n for n, s in ROLL_OFF_PERIOD_96])

#
# Cyclic prefix 97 definitions
#
CYCLIC_PREFIX_97__1_96_samples = 1, "CYCLIC_PREFIX_97__1_96_samples"
CYCLIC_PREFIX_97__2_128_samples = 2, "CYCLIC_PREFIX_97__2_128_samples"
CYCLIC_PREFIX_97__3_160_samples = 3, "CYCLIC_PREFIX_97__3_160_samples"
CYCLIC_PREFIX_97__4_192_samples = 4, "CYCLIC_PREFIX_97__4_192_samples"
CYCLIC_PREFIX_97__5_224_samples = 5, "CYCLIC_PREFIX_97__5_224_samples"
CYCLIC_PREFIX_97__6_256_samples = 6, "CYCLIC_PREFIX_97__6_256_samples"
CYCLIC_PREFIX_97__7_288_samples = 7, "CYCLIC_PREFIX_97__7_288_samples"
CYCLIC_PREFIX_97__8_320_samples = 8, "CYCLIC_PREFIX_97__8_320_samples"
CYCLIC_PREFIX_97__9_384_samples = 9, "CYCLIC_PREFIX_97__9_384_samples"
CYCLIC_PREFIX_97__10_512_samples = 10, "CYCLIC_PREFIX_97__10_512_samples"
CYCLIC_PREFIX_97__11_640_samples = 11, "CYCLIC_PREFIX_97__11_640_samples"
CYCLIC_PREFIX_97 = (CYCLIC_PREFIX_97__1_96_samples,
                    CYCLIC_PREFIX_97__2_128_samples,
                    CYCLIC_PREFIX_97__3_160_samples,
                    CYCLIC_PREFIX_97__4_192_samples,
                    CYCLIC_PREFIX_97__5_224_samples,
                    CYCLIC_PREFIX_97__6_256_samples,
                    CYCLIC_PREFIX_97__7_288_samples,
                    CYCLIC_PREFIX_97__8_320_samples,
                    CYCLIC_PREFIX_97__9_384_samples,
                    CYCLIC_PREFIX_97__10_512_samples,
                    CYCLIC_PREFIX_97__11_640_samples)
CYCLIC_PREFIX_97_DICT = {n: s for n, s in CYCLIC_PREFIX_97}
CYCLIC_PREFIX_97_TYPES = tuple([n for n, s in CYCLIC_PREFIX_97])

#
# Number of symbols per frame definitions
#
NUM_SYMBOL_PER_FRAME_6_min = 6, "NUM_SYMBOL_PER_FRAME_6_min"
NUM_SYMBOL_PER_FRAME_36_max = 36, "NUM_SYMBOL_PER_FRAME_36_max"
NUM_SYMBOL_PER_FRAME = (NUM_SYMBOL_PER_FRAME_6_min,
                        NUM_SYMBOL_PER_FRAME_36_max)
NUM_SYMBOL_PER_FRAME_DICT = {n: s for n, s in NUM_SYMBOL_PER_FRAME}
NUM_SYMBOL_PER_FRAME_TYPES = tuple([n for n, s in NUM_SYMBOL_PER_FRAME])

#
# Data IUC definitions
#
DATA_IUC_5 = 5, "DATA_IUC_5"
DATA_IUC_6 = 6, "DATA_IUC_6"
DATA_IUC_9 = 9, "DATA_IUC_9"
DATA_IUC_10 = 10, "DATA_IUC_10"
DATA_IUC_11 = 11, "DATA_IUC_11"
DATA_IUC_12 = 12, "DATA_IUC_12"
DATA_IUC_13 = 13, "DATA_IUC_13"
DATA_IUC = (DATA_IUC_5,
            DATA_IUC_6,
            DATA_IUC_9,
            DATA_IUC_10,
            DATA_IUC_11,
            DATA_IUC_12,
            DATA_IUC_13)
DATA_IUC_DICT = {n: s for n, s in DATA_IUC}
DATA_IUC_TYPE = tuple([n for n, s in DATA_IUC])

#
# MIN Slot definitions
#
START_MIN_SLOT_0_min = 0, "START_MIN_SLOT_0_min"
START_MIN_SLOT_237_max = 237, "START_MIN_SLOT_237_max"
START_MIN_SLOT = (START_MIN_SLOT_0_min,
                  START_MIN_SLOT_237_max)
START_MIN_SLOT_DICT = {n: s for n, s in START_MIN_SLOT}
START_MIN_SLOT_TYPE = tuple([n for n, s in START_MIN_SLOT])

MINISLOT_PILOT_0_min = 0, "MINISLOT_PILOT_0_min"
MINISLOT_PILOT_14_max = 14, "MINISLOT_PILOT_14_max"
MINISLOT_PILOT = (MINISLOT_PILOT_0_min,
                  MINISLOT_PILOT_14_max)
MINISLOT_PILOT_DICT = {n: s for n, s in MINISLOT_PILOT}
MINISLOT_PILOT_TYPES = tuple([n for n, s in MINISLOT_PILOT])

# FILE STATUS CONTROL for 40.3
CONTROL_OTHER = 1, "other"
CONTROL_UPLOAD = 2, "upload"
CONTROL_CANCELUPLOAD = 3, "cancelUpload"
CONTROL_DELETEFILE = 4, "delete"
CONTROL_UPLOADANDDELETE = 5, "uploadAndDelete"

# FILE DATA SERVER for 40.4
PROTOCOL_TFTP = 2, "tftp"
PROTOCOL_HTTP = 3, "http"
PROTOCOL_LIST = (PROTOCOL_TFTP,
                 PROTOCOL_HTTP)
PROTOCOL_NAME = {n: s for n, s in PROTOCOL_LIST}

FILE_CTRL_NAME_LIST = (CONTROL_OTHER,
                       CONTROL_UPLOAD,
                       CONTROL_CANCELUPLOAD,
                       CONTROL_DELETEFILE,
                       CONTROL_UPLOADANDDELETE)
FILE_CTRL_NAME = {n: s for n, s in FILE_CTRL_NAME_LIST}

# FILE STATUS for 100.20
STATUS_OTHER = 1, "other"
STATUS_AVAILFORUPLOAD = 2, "availableForUpload"
STATUS_UPLOADINPROGRESS = 3, "uploadInProgress"
STATUS_UPLOADCOMPLETED = 4, "uploadCompleted"
STATUS_UPLOADPENDING = 5, "uploadPending"
STATUS_UPLOADCANCELLED = 6, "uploadCancelled"
STATUS_ERROR = 7, "error"

FILE_STATUS_LIST = (STATUS_OTHER,
                    STATUS_AVAILFORUPLOAD,
                    STATUS_UPLOADINPROGRESS,
                    STATUS_UPLOADCOMPLETED,
                    STATUS_UPLOADPENDING,
                    STATUS_UPLOADCANCELLED,
                    STATUS_ERROR)
FILE_STATUS_NAME = {n: s for n, s in FILE_STATUS_LIST}

#
# Data Symbol Modulation definitions
#
DATA_SYMBOL_MODULATION__1_Other = \
    1, "DATA_SYMBOL_MODULATION__1_Other"
DATA_SYMBOL_MODULATION__2_zeroValued = \
    2, "DATA_SYMBOL_MODULATION__2_zeroValued"
DATA_SYMBOL_MODULATION__3_qpsk = \
    3, "DATA_SYMBOL_MODULATION__3_qpsk"
DATA_SYMBOL_MODULATION__4_qam8 = \
    4, "DATA_SYMBOL_MODULATION__4_qam8"
DATA_SYMBOL_MODULATION__5_qam16 = \
    5, "DATA_SYMBOL_MODULATION__5_qam16"
DATA_SYMBOL_MODULATION__6_qam32 = \
    6, "DATA_SYMBOL_MODULATION__6_qam32"
DATA_SYMBOL_MODULATION__7_qam64 = \
    7, "DATA_SYMBOL_MODULATION__7_qam64"
DATA_SYMBOL_MODULATION__8_qam128 = \
    8, "DATA_SYMBOL_MODULATION__8_qam128"
DATA_SYMBOL_MODULATION__9_qam256 = \
    9, "DATA_SYMBOL_MODULATION__9_qam256"
DATA_SYMBOL_MODULATION__10_qam512 = \
    10, "DATA_SYMBOL_MODULATION__10_qam512"
DATA_SYMBOL_MODULATION__11_qam1024 = \
    11, "DATA_SYMBOL_MODULATION__11_qam1024"
DATA_SYMBOL_MODULATION__12_qam2048 = \
    12, "DATA_SYMBOL_MODULATION__12_qam2048"
DATA_SYMBOL_MODULATION__13_qam4096 = \
    13, "DATA_SYMBOL_MODULATION__13_qam4096"
DATA_SYMBOL_MODULATION = (DATA_SYMBOL_MODULATION__1_Other,
                          DATA_SYMBOL_MODULATION__2_zeroValued,
                          DATA_SYMBOL_MODULATION__3_qpsk,
                          DATA_SYMBOL_MODULATION__4_qam8,
                          DATA_SYMBOL_MODULATION__5_qam16,
                          DATA_SYMBOL_MODULATION__6_qam32,
                          DATA_SYMBOL_MODULATION__7_qam64,
                          DATA_SYMBOL_MODULATION__8_qam128,
                          DATA_SYMBOL_MODULATION__9_qam256,
                          DATA_SYMBOL_MODULATION__10_qam512,
                          DATA_SYMBOL_MODULATION__11_qam1024,
                          DATA_SYMBOL_MODULATION__12_qam2048,
                          DATA_SYMBOL_MODULATION__13_qam4096)
DATA_SYMBOL_MODULATION_DICT = {n: s for n, s in DATA_SYMBOL_MODULATION}
DATA_SYMBOL_MODULATION_TYPES = tuple([n for n, s in DATA_SYMBOL_MODULATION])

#
# Starting subcarrier definitions
#
STARTING_SUBCARRIER_ID_0_min = 0, "STARTING_SUBCARRIER_ID_0_min"
STARTING_SUBCARRIER_ID_4096_max = 4096, "STARTING_SUBCARRIER_ID_4096_max"
STARTING_SUBCARRIER_ID = (STARTING_SUBCARRIER_ID_0_min,
                          STARTING_SUBCARRIER_ID_4096_max)
STARTING_SUBCARRIER_ID_DICT = {n: s for n, s in STARTING_SUBCARRIER_ID}
STARTING_SUBCARRIER_ID_TYPES = tuple([n for n, s in STARTING_SUBCARRIER_ID])

#
# Subcarrier usage definitions
#
SUBCARRIER_USAGE_13__1_Other = 1, "SUBCARRIER_USAGE_13__1_Other"
SUBCARRIER_USAGE_13__2_Data = 2, "SUBCARRIER_USAGE_13__2_Data"
SUBCARRIER_USAGE_13__3_Excluded = 3, "SUBCARRIER_USAGE_13__3_Excluded"
SUBCARRIER_USAGE_13__4_Unused = 4, "SUBCARRIER_USAGE_13__4_Unused"
SUBCARRIER_USAGE_13 = (SUBCARRIER_USAGE_13__1_Other,
                       SUBCARRIER_USAGE_13__2_Data,
                       SUBCARRIER_USAGE_13__3_Excluded,
                       SUBCARRIER_USAGE_13__4_Unused)
SUBCARRIER_USAGE_13_DICT = {n: s for n, s in SUBCARRIER_USAGE_13}
SUBCARRIER_USAGE_13_TYPES = tuple([n for n, s in SUBCARRIER_USAGE_13])

SIDSFTYPE_0_Disabled = 0, "SIDSFTYPE_0_Disabled"
SIDSFTYPE_1_Other = 1, "SIDSFTYPE_1_Other"
SIDSFTYPE_2_Legacy = 2, "SIDSFTYPE_2_Legacy"
SIDSFTYPE_3_Segment_Header_On = 3, "SIDSFTYPE_3_Segment_Header_On"
SIDSFTYPE_4_Segment_Header_Off = 4, "SIDSFTYPE_4_Segment_Header_Off"
SIDSFTYPE = (SIDSFTYPE_0_Disabled,
             SIDSFTYPE_1_Other,
             SIDSFTYPE_2_Legacy,
             SIDSFTYPE_3_Segment_Header_On,
             SIDSFTYPE_4_Segment_Header_Off)
SIDSFTYPE_DICT = {n: s for n, s in SIDSFTYPE}
SIDSFTYPE_TYPES = tuple([n for n, s in SIDSFTYPE])

#
# RCP TLV operation type: add, del, change
#
RCP_TLV_OPERATION_TYPE_ADD = 0
RCP_TLV_OPERATION_TYPE_DELETE = 1
RCP_TLV_OPERATION_TYPE_CHANGE = 2

RCP_TLV_OPERATION_ADD = RCP_TLV_OPERATION_TYPE_ADD, "Operation_Add"
RCP_TLV_OPERATION_DELETE = RCP_TLV_OPERATION_TYPE_DELETE, "Operation_Delete"
RCP_TLV_OPERATION_CHANGE = RCP_TLV_OPERATION_TYPE_CHANGE, "Operation_Change"

RCP_TLV_OPERATION = (RCP_TLV_OPERATION_ADD, RCP_TLV_OPERATION_DELETE,
                     RCP_TLV_OPERATION_CHANGE)
RCP_TLV_OPERATION_DICT = {n: s for n, s in RCP_TLV_OPERATION}
RCP_TLV_OPERATION_TYPES = tuple([n for n, s in RCP_TLV_OPERATION])

#
# RPD event log level
#
RPD_EVENT_LEVEL_EMERGENCY = 1, "emergency"
RPD_EVENT_LEVEL_ALERT = 2, "alert"
RPD_EVENT_LEVEL_CRITICAL = 3, "critical"
RPD_EVENT_LEVEL_ERROR = 4, "error"
RPD_EVENT_LEVEL_WARNING = 5, "warning"
RPD_EVENT_LEVEL_NOTICE = 6, "notice"
RPD_EVENT_LEVEL_INFORMATION = 7, "information"
RPD_EVENT_LEVEL_DEBUG = 8, "debug"
RPD_EVENT_LEVEL = (RPD_EVENT_LEVEL_EMERGENCY,
                   RPD_EVENT_LEVEL_ALERT,
                   RPD_EVENT_LEVEL_CRITICAL,
                   RPD_EVENT_LEVEL_ERROR,
                   RPD_EVENT_LEVEL_WARNING,
                   RPD_EVENT_LEVEL_NOTICE,
                   RPD_EVENT_LEVEL_INFORMATION,
                   RPD_EVENT_LEVEL_DEBUG)
RPD_EVENT_LEVEL_DICT = {n: s for n, s in RPD_EVENT_LEVEL}
RPD_EVENT_LEVEL_TYPES = tuple([n for n, s in RPD_EVENT_LEVEL])


#
# RPD event Notification
#
RPD_EVENT_NOTIFICATION_PENDING_LOG = 0, "pending"
RPD_EVENT_NOTIFICATION_LOCAL_LOG = 1, "local"
RPD_EVENT_NOTIFICATION = (
    RPD_EVENT_NOTIFICATION_PENDING_LOG,
    RPD_EVENT_NOTIFICATION_LOCAL_LOG,
)
RPD_EVENT_NOTIFICATION_DICT = {n: s for n, s in RPD_EVENT_NOTIFICATION}
RPD_EVENT_NOTIFICATION_TYPES = tuple([n for n, s in RPD_EVENT_NOTIFICATION])

GeneralNotificationType = {
    1: "StartUpNotification",
    2: "RedirectResultNotification",
    3: "PtpResultNotification",
    4: "AuxCoreResultNotification",
    5: "TimeOutNotification",
    6: "Deprecated",
    7: "ReconnectNotification",
    8: "AuxCoreGcpStatusNotification",
    9: "ChannelUcdRefreshRequest"
}

RpdRedirectResult = {
    0: "Success",
    1: "Failure"
}

PtpResult = {
    0: "PtpFreeRun",
    1: "PtpAcquire",
    2: "PtpHoOutofSpec",
    3: "PtpHoInSpec",
    4: "PtpSynchronized"
}

PtpClockSource = {
    0: "PtpPrimaryClockSource",
    1: "PtpAlternateClockSource"
}
#
# RPD event EvThrottleAdminStatus
#
RPD_EVENT_THROTTLE_UNCONSTRAINED = 1, "unconstrained"
RPD_EVENT_THROTTLE_BELOW = 2, "maintain_Below_Threshold"
RPD_EVENT_THROTTLE_STOP = 3, "stop_At_Threshold"
RPD_EVENT_THROTTLE_INHIBITED = 4, "inhibited"
RPD_EVENT_THROTTLE = (
    RPD_EVENT_THROTTLE_UNCONSTRAINED,
    RPD_EVENT_THROTTLE_BELOW,
    RPD_EVENT_THROTTLE_STOP,
    RPD_EVENT_THROTTLE_INHIBITED,
)
RPD_EVENT_THROTTLE_DICT = {n: s for n, s in RPD_EVENT_THROTTLE}
RPD_EVENT_THROTTLE_TYPES = tuple([n for n, s in RPD_EVENT_THROTTLE])

#
# RPD event NotifyEnable
#
RPD_EVENT_NTF_DISABLE = 0, "disable"
RPD_EVENT_NTF_ENABLE = 1, "enable"
RPD_EVENT_NTF_EN = {
    RPD_EVENT_NTF_ENABLE,
    RPD_EVENT_NTF_DISABLE
}
RPD_EVENT_NTF_EN_DICT = {n: s for n, s in RPD_EVENT_NTF_EN}
RPD_EVENT_NTF_EN_TYPES = tuple([n for n, s in RPD_EVENT_NTF_EN])

#
# RPD interface attributes
#
EnableStatus_1_UP = 1, "Intf_EnableStatus_1_up"
EnableStatus_2_DOWN = 2, "Intf_EnableStatus_2_down"
EnableStatus_TYPE = (EnableStatus_1_UP,
                     EnableStatus_2_DOWN)
EnableStatus_TYPE_DICT = {n: s for n, s in EnableStatus_TYPE}
EnableStatus_TYPE_TYPES = tuple([n for n, s in EnableStatus_TYPE])

#
# RPD interface ipaddress attributes
#
INETADDRESSTYPE_UNKNOWN = 0, 'INETADDRESSTYPE_UNKNOWN'
INETADDRESSTYPE_IPV4 = 1, 'INETADDRESSTYPE_IPV4'
INETADDRESSTYPE_IPV6 = 2, 'INETADDRESSTYPE_IPV6'
INETADDRESSTYPE_IPV4Z = 3, 'INETADDRESSTYPE_IPV4Z'
INETADDRESSTYPE_IPV6Z = 4, 'INETADDRESSTYPE_IPV6Z'
INETADDRESSTYPE_DNS = 16, 'INETADDRESSTYPE_DNS'

INETADDRESSTYPE = (INETADDRESSTYPE_UNKNOWN,
                   INETADDRESSTYPE_IPV4,
                   INETADDRESSTYPE_IPV6,
                   INETADDRESSTYPE_IPV4Z,
                   INETADDRESSTYPE_IPV6Z,
                   INETADDRESSTYPE_DNS)
INETADDRESSTYPE_DICT = {n: s for n, s in INETADDRESSTYPE}
INETADDRESSTYPE_TYPES = tuple([n for n, s in INETADDRESSTYPE])

#
# RPD interface ipaddress attributes
#
IPADDR_TYPE_1_unicast = 1, 'IPADDR_TYPE_1_unicast'
IPADDR_TYPE_2_anycast = 2, 'IPADDR_TYPE_2_anycast'
IPADDR_TYPE_3_broadcast = 3, 'IPADDR_TYPE_3_broadcast'
IPADDR_TYPE = (IPADDR_TYPE_1_unicast,
               IPADDR_TYPE_2_anycast,
               IPADDR_TYPE_3_broadcast)
IPADDR_TYPE_DICT = {n: s for n, s in IPADDR_TYPE}
IPADDR_TYPE_TYPES = tuple([n for n, s in IPADDR_TYPE])


IPADDR_ORIGIN_1_other = 1, "IPADDR_ORIGIN_1_other"
IPADDR_ORIGIN_2_manual = 2, "IPADDR_ORIGIN_2_manual"
IPADDR_ORIGIN_3_wellKnown = 3, "IPADDR_ORIGIN_3_wellKnown"
IPADDR_ORIGIN_4_dhcp = 4, "IPADDR_ORIGIN_4_dhcp"
IPADDR_ORIGIN_5_routerAdv = 5, "IPADDR_ORIGIN_5_routerAdv"
IPADDR_ORIGIN = (IPADDR_ORIGIN_1_other,
                 IPADDR_ORIGIN_2_manual,
                 IPADDR_ORIGIN_3_wellKnown,
                 IPADDR_ORIGIN_4_dhcp,
                 IPADDR_ORIGIN_5_routerAdv)
IPADDR_ORIGIN_DICT = {n: s for n, s in IPADDR_ORIGIN}
IPADDR_ORIGIN_TYPES = tuple([n for n, s in IPADDR_ORIGIN])


IPADDR_STATUS_1_preferred = 1, "IPADDR_STATUS_1_preferred"
IPADDR_STATUS_2_deprecated = 2, "IPADDR_STATUS_2_deprecated"
IPADDR_STATUS_3_invalid = 3, "IPADDR_STATUS_3_invalid"
IPADDR_STATUS_4_inaccessible = 4, "IPADDR_STATUS_4_inaccessible"
IPADDR_STATUS_5_unknown = 5, "IPADDR_STATUS_5_unknown"
IPADDR_STATUS_6_tentative = 6, "IPADDR_STATUS_6_tentative"
IPADDR_STATUS_7_duplicate = 7, "IPADDR_STATUS_7_duplicate"
IPADDR_STATUS_8_optimistic = 8, "IPADDR_STATUS_8_optimistic"
IPADDR_STATUS = (IPADDR_STATUS_1_preferred,
                 IPADDR_STATUS_2_deprecated,
                 IPADDR_STATUS_3_invalid,
                 IPADDR_STATUS_4_inaccessible,
                 IPADDR_STATUS_5_unknown,
                 IPADDR_STATUS_6_tentative,
                 IPADDR_STATUS_7_duplicate,
                 IPADDR_STATUS_8_optimistic)
IPADDR_STATUS_DICT = {n: s for n, s in IPADDR_STATUS}
IPADDR_STATUS_TYPES = tuple([n for n, s in IPADDR_STATUS])

#
# RPDInfo attributes
#
SEVERITYLEVEL_TYPE_0_emergency = 0, "emergency"
SEVERITYLEVEL_TYPE_1_alert = 1, "alert"
SEVERITYLEVEL_TYPE_2_critical = 2, "critical"
SEVERITYLEVEL_TYPE_3_error = 3, "error"
SEVERITYLEVEL_TYPE_4_warning = 4, "warning"
SEVERITYLEVEL_TYPE_5_notice = 5, "notice"
SEVERITYLEVEL_TYPE_6_information = 6, "information"
SEVERITYLEVEL_TYPE_7_debug = 7, "debug"
SEVERITYLEVEL_TYPE = (SEVERITYLEVEL_TYPE_0_emergency,
                      SEVERITYLEVEL_TYPE_1_alert,
                      SEVERITYLEVEL_TYPE_2_critical,
                      SEVERITYLEVEL_TYPE_3_error,
                      SEVERITYLEVEL_TYPE_4_warning,
                      SEVERITYLEVEL_TYPE_5_notice,
                      SEVERITYLEVEL_TYPE_6_information,
                      SEVERITYLEVEL_TYPE_7_debug)
SEVERITYLEVEL_TYPE_DICT = {n: s for n, s in SEVERITYLEVEL_TYPE}
SEVERITYLEVEL_TYPE_TYPES = tuple(SEVERITYLEVEL_TYPE_DICT.keys())

#
# L2tp session info OP_status
#
OP_STATUS_OTHER = 0
OP_STATUS_UP = 1
OP_STATUS_DOWN = 2
OP_STATUS_TESTING = 3
OP_STATUS_DORMANT = 4
OP_STATUS_NOT_PRESENT = 5
OP_STATUS_LOWER_DOWN = 6

#
# Internal definitions
#
RW_FLAG_row = DataDescription.RW_FLAG_row
RW_FLAG_repeatedFields = DataDescription.RW_FLAG_repeatedFields
RW_FLAG_key = DataDescription.RW_FLAG_key
RW_FLAG_row_key = DataDescription.RW_FLAG_row_key
RW_FLAG_r = DataDescription.RW_FLAG_r
RW_FLAG_rw = DataDescription.RW_FLAG_rw

# RPDIfStats definitions
RPD_IF_ENET_LN_UPDWN_ENABLE = 1, "RPD_IF_ENET_LN_UPDWN_ENABLE"
RPD_IF_ENET_LN_UPDWN_DISENABLE = 2, "RPD_IF_ENET_LN_UPDWN_DISENABLE"

RPD_IF_ENET_ADMIN_STATUS_UP = 1, "RPD_IF_ENET_ADMIN_STATUS_UP"
RPD_IF_ENET_ADMIN_STATUS_DW = 2, "RPD_IF_ENET_ADMIN_STATUS_DW"

RPD_IF_TYPE_OTHER = 1, "RPD_IF_TYPE_OTHER"
RPD_IF_TYPE_REGULAR1822 = 2, "RPD_IF_TYPE_REGULAR1822"
RPD_IF_TYPE_HDH1822 = 3, "RPD_IF_TYPE_HDH1822"
RPD_IF_TYPE_DDNX25 = 4, "RPD_IF_TYPE_DDNX25"
RPD_IF_TYPE_RFC877X25 = 5, "RPD_IF_TYPE_RFC877X25"
RPD_IF_TYPE_ETHERNETCSMACD = 6, "RPD_IF_TYPE_ETHERNETCSMACD"
RPD_IF_TYPE_ISO88023CSMACD = 7, "RPD_IF_TYPE_ISO88023CSMACD"

RPD_IF_ENET_ADMIN_OPER_STATUS_UP = 1, "RPD_IF_ENET_ADMIN_OPER_STATUS_UP"
RPD_IF_ENET_ADMIN_OPER_STATUS_DW = 2, "RPD_IF_ENET_ADMIN_OPER_STATUS_DW"

RPD_IF_ENET_PROMISCUOUSMODE_TRUE = 1, "RPD_IF_ENET_PROMISCUOUSMODE_TRUE"
RPD_IF_ENET_PROMISCUOUSMODE_FALSE = 2, "RPD_IF_ENET_PROMISCUOUSMODE_FALSE"

RPD_IF_ENET_CONNECTORPRESENT_TRUE = 1, "RPD_IF_ENET_CONNECTORPRESENT_TRUE"
RPD_IF_ENET_CONNECTORPRESENT_FALSE = 2, "RPD_IF_ENET_CONNECTORPRESENT_FALSE"

RPD_IF_ENET_LINKUPDOWNTRAPENABLE_TRUE = 1, "RPD_IF_ENET_LINKUPDOWNTRAPENABLE_TRUE"
RPD_IF_ENET_LINKUPDOWNTRAPENABLE_DISABLE = 2, "RPD_IF_ENET_LINKUPDOWNTRAPENABLE_DISABLE"

#
# RCP Messages and General Purpose TLVs
#

# global Reference to a RCP messages and RCP General Purpose TLV database
RCP_GP_TLV_SET = gcp_tlv_def.TLVDescriptionSet(hierarchy_name="RCP_GP_TLVs")


class RCPGPTLV(gcp_tlv_def.TLVDesc):

    """Implements description of the RCP General Purpose TLV data format."""

    def __init__(self, identifier, name, parent=(RCP_GP_TLV_SET, ),
                 format_str=None, length=None, constraint=None, rw=RW_FLAG_rw):
        super(RCPGPTLV, self).__init__(identifier, name, parent, format_str,
                                       length, constraint,
                                       length_field_len=RCP_TLV_LENGTH_LEN,
                                       rw=rw)


#
# RCP Messages
#
RCP_MSG_SET = gcp_tlv_def.TLVDescriptionSet(hierarchy_name="RCP_MSG")

RCP_MSG_IRA_01 = RCPGPTLV(*RCP_MSG_IRA, parent=RCP_MSG_SET)
RCP_MSG_REX_02 = RCPGPTLV(*RCP_MSG_REX, parent=RCP_MSG_SET)
RCP_MSG_NTF_03 = RCPGPTLV(*RCP_MSG_NTF, parent=RCP_MSG_SET)

# Associates RCP messages with all GCP Messages
# TODO specify TLV set per GCP message in order to be able to check
# TODO if the RCP message is expected in concrete GCP message
for msg_id, msg_descr in gcp_msg_def.GCP_MSG_SET.child_dict_by_id.iteritems():
    msg_descr.add_tlv_set(RCP_MSG_SET)

#
# RCP Configuration TLVs
#

# global Reference to a RCP CFG TLV database
RCP_CFG_TLV_SET = gcp_tlv_def.TLVDescriptionSet(hierarchy_name="RCP_CFG_TLVs")
RCP_CFG_IRA_TLV_SET = gcp_tlv_def.TLVDescriptionSet("IRA_TLVs")
RCP_CFG_REX_TLV_SET = gcp_tlv_def.TLVDescriptionSet("REX_TLVs")
RCP_CFG_NTF_TLV_SET = gcp_tlv_def.TLVDescriptionSet("NTF_TLVs")

#
# General Purpose TLVs
#
C_RCPSequence_09 = RCPGPTLV(9, "SequenceTLV",
                            parent=(RCP_MSG_IRA_01,
                                    RCP_MSG_REX_02,
                                    RCP_MSG_NTF_03))
C_SequenceNumber_10 = RCPGPTLV(10, "SequenceNumber", C_RCPSequence_09, "!H")
C_Operation_11 = RCPGPTLV(11, "Operation", C_RCPSequence_09, "!B",
                          constraint=EnumConstraint(RCP_OPERATION_DICT))

C_ReadCount_26 = RCPGPTLV(26, "ReadCount",
                          parent=(C_RCPSequence_09,
                                  RCP_CFG_TLV_SET),
                          format_str="!H")

# TODO add parents according new version of specification
C_EnetPortIndex_14 = RCPGPTLV(14, "EnetPortIndex", format_str="!B")

C_EnetPort_18 = RCPGPTLV(18, "EnetPort",
                         parent=(RCP_MSG_IRA_01, RCP_MSG_REX_02))
C_ResponseCode_19 = RCPGPTLV(19, "ResponseCode",
                             parent=(C_RCPSequence_09,
                                     RCP_CFG_TLV_SET),
                             format_str="!B")
C_ErrorMessage_20 = RCPGPTLV(20, "ErrorMessage",
                             parent=(C_RCPSequence_09,
                                     RCP_MSG_IRA_01,
                                     RCP_MSG_REX_02,
                                     RCP_MSG_NTF_03,
                                     RCP_CFG_TLV_SET),
                             format_str="var",
                             constraint=StringLenRangeConstraint(1, 255))


C_DocsisTimestamp32_23 = RCPGPTLV(23, "DocsisTimestamp32",
                                  format_str="!I")
C_DocsisTimestamp64_24 = RCPGPTLV(24, "DocsisTimestamp64",
                                  format_str="!Q")

# RCP Message ID: TLV SET mapping
RCP_MESSAGE_TLV_SET_MAPPING = {
    RCP_MSG_TYPE_IRA: RCP_CFG_IRA_TLV_SET,
    RCP_MSG_TYPE_REX: RCP_CFG_REX_TLV_SET,
    RCP_MSG_TYPE_NTF: RCP_CFG_NTF_TLV_SET
}

# TODO Specify and use more specific tuples of parents for TLVs which are not
# TODO expected in some RCP Message etc.
_ALL_RCP_CFG_TLV_PARENTS = (RCP_CFG_TLV_SET,
                            RCP_CFG_IRA_TLV_SET,
                            RCP_CFG_REX_TLV_SET,
                            RCP_CFG_NTF_TLV_SET)

RCP_TLV_SET_NTF_REQ_NTF = gcp_tlv_def.TLVDescriptionSet("RCP_NTF_REQ")


class RCPTLV(gcp_tlv_def.TLVDesc):

    """Implements description of the RCP TLV data format.

    Used to enforce usage of 2B long TLV length field for RCP TLVs.

    """

    def __init__(self, identifier, name,
                 parent=_ALL_RCP_CFG_TLV_PARENTS,
                 format_str=None, length=None, constraint=None, rw=RW_FLAG_rw):

        gcp_tlv_def.TLVDesc.__init__(self, identifier, name, parent, format_str,
                                     length, constraint,
                                     length_field_len=2, rw=rw)


C_RpdGlobal_15 = RCPTLV(15, "RpdGlobal", rw=RW_FLAG_row)
C_EvCfg_1 = RCPTLV(1, "EvCfg", C_RpdGlobal_15, rw=RW_FLAG_row)
C_EvControl_1 = RCPTLV(1, "EvControl", C_EvCfg_1, rw=RW_FLAG_row_key)
RCPTLV(1, "EvPriority", C_EvControl_1, format_str="!B", rw=RW_FLAG_key)
RCPTLV(2, "EvReporting", C_EvControl_1, format_str="!B", rw=RW_FLAG_key)

RCPTLV(2, "EvThrottleAdminStatus", C_EvCfg_1, format_str="!B",
       constraint=EnumConstraint(RPD_EVENT_THROTTLE_DICT))
RCPTLV(3, "EvThrottleThreshold", C_EvCfg_1, format_str="!I")
RCPTLV(4, "EvThrottleInterval", C_EvCfg_1, format_str="!I")
RCPTLV(5, "NotifyEnable", C_EvCfg_1, format_str="!B",
       constraint=EnumConstraint(RPD_EVENT_NTF_EN_DICT))

C_GcpConnVerification_2 = RCPTLV(2, "GcpConnVerification", C_RpdGlobal_15, rw=RW_FLAG_row)
RCPTLV(1, "CoreId", C_GcpConnVerification_2, "bytes")
RCPTLV(2, "MaxGcpIdleTime", C_GcpConnVerification_2, "!H")
RCPTLV(3, "GcpRecoveryAction", C_GcpConnVerification_2, "!B")
RCPTLV(4, "GcpRecoveryActionRetry", C_GcpConnVerification_2, "!B")
RCPTLV(5, "GcpRecoveryActionDelay", C_GcpConnVerification_2, "!H")
RCPTLV(6, "GcpReconnectTimeout", C_GcpConnVerification_2, "!H")

C_IpConfig_3 = RCPTLV(3, "IpConfig", C_RpdGlobal_15, rw=RW_FLAG_row)
RCPTLV(1, "IpStackControl", C_IpConfig_3, "!B")

C_UepiControl_4 = RCPTLV(4, "UepiControl", C_RpdGlobal_15, rw=RW_FLAG_row)
RCPTLV(1, "ScQamUseRngPw", C_UepiControl_4, "!B")
RCPTLV(2, "OfdmaMaxNumPayloadUnits", C_UepiControl_4, "!B")
RCPTLV(3, "OfdmaMaxNumTrailerUnits", C_UepiControl_4, "!B")

C_RfChannel_16 = RCPTLV(16, "RfChannel", rw=RW_FLAG_row_key)
C_RfPort_17 = RCPTLV(17, "RfPort", rw=RW_FLAG_row_key)
C_DocsisMsg_22 = RCPTLV(22, "DocsisMsg", C_RfChannel_16, "bytes", rw=RW_FLAG_r)

C_VendorSpecificExtension_21 = RCPTLV(21, "VendorSpecificExtension", rw=RW_FLAG_row)
RCPTLV(1, "VendorId", C_VendorSpecificExtension_21, "!H")

#
C_RpdRedirect_25 = RCPTLV(25, "RpdRedirect", rw=RW_FLAG_row)
RCPGPTLV(1, "RedirectIpAddress", C_RpdRedirect_25, "IPAddr", rw=RW_FLAG_key)

#
# B.6 RPD Capabilities and Identification
#
C_RpdCapabilities_50 = \
    RCPTLV(50, "RpdCapabilities", rw=RW_FLAG_row)
RCPTLV(1, "NumBdirPorts", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(2, "NumDsRfPorts", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(3, "NumUsRfPorts", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(4, "NumTenGeNsPorts", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(5, "NumOneGeNsPorts", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(6, "NumDsScQamChannels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(7, "NumDsOfdmChannels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(8, "NumUsScQamChannels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(9, "NumUsOfdmaChannels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(10, "NumDsOob55d1Channels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(11, "NumUsOob55d1Channels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(12, "NumOob55d2Modules", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(13, "NumUsOob55d2Demodulators", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(14, "NumNdfChannels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(15, "NumNdrChannels", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(16, "SupportsUdpEncap", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r,
       constraint=BOOL_CONSTR)
RCPTLV(17, "NumDsPspFlows", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(18, "NumUsPspFlows", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)

# RpdIdentification
C50_RpdIdentification_19 = \
    RCPTLV(19, "RpdIdentification", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "VendorName", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(2, "VendorId", C50_RpdIdentification_19, "!H", rw=RW_FLAG_r)
RCPTLV(3, "ModelNumber", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(4, "DeviceMacAddress", C50_RpdIdentification_19, "MAC", rw=RW_FLAG_r)
RCPTLV(5, "CurrentSwVersion", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(6, "BootRomVersion", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(7, "DeviceDescription", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(8, "DeviceAlias", C50_RpdIdentification_19, "var", rw=RW_FLAG_rw,
       constraint=StringLenConstraint(255))
RCPTLV(9, "SerialNumber", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(16))
RCPTLV(10, "UsBurstReceiverVendorId", C50_RpdIdentification_19, "!H",
       rw=RW_FLAG_r)
RCPTLV(11, "UsBurstReceiverModelNumber", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenRangeConstraint(3, 16))
RCPTLV(12, "UsBurstReceiverDriverVersion", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenRangeConstraint(3, 16))
RCPTLV(13, "UsBurstReceiverSerialNumber", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenRangeConstraint(5, 16))
RCPTLV(14, "RpdRcpProtocolVersion", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenRangeConstraint(3, 32))
RCPTLV(15, "RpdRcpSchemaVersion", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenRangeConstraint(5, 32))
RCPTLV(16, "HwRevision", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenConstraint(255))
RCPTLV(17, "AssetId", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_rw, constraint=StringLenConstraint(32))
RCPTLV(18, "VspSelector", C50_RpdIdentification_19, "var",
       rw=RW_FLAG_r, constraint=StringLenConstraint(16))
RCPTLV(19, "CurrentSwImageLastUpdate", C50_RpdIdentification_19, "bytes", rw=RW_FLAG_r,
       constraint=StringLenRangeConstraint(8, 11))
RCPTLV(20, "CurrentSwImageName", C50_RpdIdentification_19, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(21, "CurrentSwImageServer", C50_RpdIdentification_19, "IPAddr", rw=RW_FLAG_r)

# LcceChannelReachability
C50_LcceChannelReachability_20 = \
    RCPTLV(20, "LcceChannelReachability", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "EnetPortIndex", C50_LcceChannelReachability_20, "!B",
       rw=RW_FLAG_key)
RCPTLV(2, "ChannelType", C50_LcceChannelReachability_20, "!B", rw=RW_FLAG_key,
       constraint=EnumConstraint(CHANNEL_TYPE_DICT))
RCPTLV(3, "RfPortIndex", C50_LcceChannelReachability_20, "!B", rw=RW_FLAG_key)
RCPTLV(4, "StartChannelIndex", C50_LcceChannelReachability_20, "!B",
       rw=RW_FLAG_r)
RCPTLV(5, "EndChannelIndex", C50_LcceChannelReachability_20, "!B",
       rw=RW_FLAG_r)

# PilotToneCapabilities
C50_PilotToneCapabilities_21 = \
    RCPTLV(21, "PilotToneCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "NumCwToneGens", C50_PilotToneCapabilities_21, "!B", rw=RW_FLAG_r)
RCPTLV(2, "LowestCwToneFreq", C50_PilotToneCapabilities_21, "!I", rw=RW_FLAG_r)
RCPTLV(3, "HighestCwToneFreq", C50_PilotToneCapabilities_21, "!I",
       rw=RW_FLAG_r)
RCPTLV(4, "MaxPowerDedCwTone", C50_PilotToneCapabilities_21, "!H", rw=RW_FLAG_r)
RCPTLV(5, "QamAsPilot", C50_PilotToneCapabilities_21, "!B", rw=RW_FLAG_r,
       constraint=BOOL_CONSTR)
RCPTLV(6, "MinPowerDedCwTone", C50_PilotToneCapabilities_21, "!h", rw=RW_FLAG_r)
RCPTLV(7, "MaxPowerQamCwTone", C50_PilotToneCapabilities_21, "!H", rw=RW_FLAG_r)
RCPTLV(8, "MinPowerQamCwTone", C50_PilotToneCapabilities_21, "!h", rw=RW_FLAG_r)

# AllocDsChanResources
C50_AllocDsChanResources_22 = \
    RCPTLV(22, "AllocDsChanResources", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "DsPortIndex", C50_AllocDsChanResources_22, "!B",
       rw=RW_FLAG_key)  # ??? len 1 unsigned short
RCPTLV(2, "AllocatedDsOfdmChannels", C50_AllocDsChanResources_22, "!H",
       rw=RW_FLAG_r)
RCPTLV(3, "AllocatedDsScQamChannels", C50_AllocDsChanResources_22, "!H",
       rw=RW_FLAG_r)
RCPTLV(4, "AllocatedDsOob55d1Channels", C50_AllocDsChanResources_22, "!H",
       rw=RW_FLAG_r)
RCPTLV(5, "Deprecated", C50_AllocDsChanResources_22, "!H",
       rw=RW_FLAG_r)
RCPTLV(6, "AllocatedNdfChannels", C50_AllocDsChanResources_22, "!H",
       rw=RW_FLAG_r)

# AllocUsChanResources
C50_AllocUsChanResources_23 = \
    RCPTLV(23, "AllocUsChanResources", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "UsPortIndex", C50_AllocUsChanResources_23, "!B", rw=RW_FLAG_key)
RCPTLV(2, "AllocatedUsOfdmaChannels", C50_AllocUsChanResources_23, "!H",
       rw=RW_FLAG_r)
RCPTLV(3, "AllocatedUsScQamChannels", C50_AllocUsChanResources_23, "!H",
       rw=RW_FLAG_r)
RCPTLV(4, "AllocatedUsOob55d1Channels", C50_AllocUsChanResources_23, "!H",
       rw=RW_FLAG_r)
RCPTLV(5, "Deprecated", C50_AllocUsChanResources_23, "!H",
       rw=RW_FLAG_r)
RCPTLV(6, "AllocatedNdrChannels", C50_AllocUsChanResources_23, "!H",
       rw=RW_FLAG_r)

# DeviceLocation
C50_DeviceLocation_24 = \
    RCPTLV(24, "DeviceLocation", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "DeviceLocationDescription", C50_DeviceLocation_24, "var", rw=RW_FLAG_rw,
       constraint=StringLenRangeConstraint(1, 255))
RCPTLV(2, "GeoLocationLatitude", C50_DeviceLocation_24, "var", rw=RW_FLAG_rw,
       constraint=StringLenConstraint(9))
RCPTLV(3, "GeoLocationLongitude", C50_DeviceLocation_24, "var", rw=RW_FLAG_rw,
       constraint=StringLenConstraint(10))

RCPTLV(25, "NumAsyncVideoChannels", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(26, "SupportsFlowTags", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r,
       constraint=BOOL_CONSTR)
RCPTLV(27, "SupportsFrequencyTilt", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r,
       constraint=BOOL_CONSTR)
RCPTLV(28, "TiltRange", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)

RCPTLV(29, "BufferDepthMonitorAlertSupport", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(30, "BufferDepthConfigurationSupport", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(31, "RpdUcdProcessingTime", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(32, "RpdUcdChangeNullGrantTime", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(33, "SupportMultiSectionTimingMerReporting", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)

# R-DTI Capabilities

C50_RdtiCapabilities_34 = \
    RCPTLV(34, "RdtiCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "NumPtpPortsPerEnetPort", C50_RdtiCapabilities_34, "!B", rw=RW_FLAG_r)

RCPTLV(35, "MaxDsPspSegCount", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(36, "DirectDsFlowQueueMapping", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r)

C50_DsSchedulerPhbIdList_37 = \
    RCPTLV(37, "DsSchedulerPhbIdList", C_RpdCapabilities_50, "var", rw=RW_FLAG_r,
           constraint=StringLenConstraint(255))

RCPTLV(38, "RpdPendingEvRepQueueSize", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(39, "RpdLocalEventLogSize", C_RpdCapabilities_50, "!I", rw=RW_FLAG_r)
RCPTLV(40, "SupportsOpticalNodeRf", C_RpdCapabilities_50, "!B", rw=RW_FLAG_r,
       constraint=BOOL_CONSTR)
RCPTLV(41, "MaxDsFrequency", C_RpdCapabilities_50, "!I", rw=RW_FLAG_r)
RCPTLV(42, "MinDsFrequency", C_RpdCapabilities_50, "!I", rw=RW_FLAG_r)
RCPTLV(43, "MaxBasePower", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(44, "MinTiltValue", C_RpdCapabilities_50, "!h", rw=RW_FLAG_r)
RCPTLV(45, "MinPowerAdjustScQam", C_RpdCapabilities_50, "!h", rw=RW_FLAG_r)
RCPTLV(46, "MaxPowerAdjustScQam", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(47, "MinPowerAdjustOfdm", C_RpdCapabilities_50, "!h", rw=RW_FLAG_r)
RCPTLV(48, "MaxPowerAdjustOfdm", C_RpdCapabilities_50, "!H", rw=RW_FLAG_r)
C50_UsPowerCapabilities_49 = \
    RCPTLV(49, "UsPowerCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "MinBaseUsPowerTargetLevel", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(2, "MaxBaseUsPowerTargetLevel", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(3, "MinTargetRxPowerAdjustScqam", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(4, "MaxTargetRxPowerAdjustScqam", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(5, "MinTargetRxPowerAdjustOfdma", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(6, "MaxTargetRxPowerAdjustOfdma", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(7, "MinTargetRxPowerAdjustNdr", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
RCPTLV(8, "MaxTargetRxPowerAdjustNdr", C50_UsPowerCapabilities_49, "!h", rw=RW_FLAG_r)
C50_StaticPwCapabilities_50 = \
    RCPTLV(50, "StaticPwCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "MaxFwdStaticPws", C50_StaticPwCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(2, "MaxRetStaticPws", C50_StaticPwCapabilities_50, "!H", rw=RW_FLAG_r)
RCPTLV(3, "SupportsMptDepiPw", C50_StaticPwCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(4, "SupportsMpt55d1RetPw", C50_StaticPwCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(5, "SupportsPspNdfPw", C50_StaticPwCapabilities_50, "!B", rw=RW_FLAG_r)
RCPTLV(6, "SupportsPspNdrPw", C50_StaticPwCapabilities_50, "!B", rw=RW_FLAG_r)
C50_DsCapabilities_51 = \
    RCPTLV(51, "DsCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "DsScqamInterleaverSupport", C50_DsCapabilities_51, "!I", rw=RW_FLAG_r)
C50_GcpCapabilities_52 = \
    RCPTLV(52, "GcpCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "GcpKaResponseTime", C50_GcpCapabilities_52, "!H", rw=RW_FLAG_r)

C50_SwimageCapabilities_53 = \
    RCPTLV(53, "SwimageCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)

C50_OfdmConfigurationCapabilities_54 = \
    RCPTLV(54, "OfdmConfigurationCapabilities", C_RpdCapabilities_50, rw=RW_FLAG_row)
RCPTLV(1, "RequiresOfdmaImDurationConfig", C50_OfdmConfigurationCapabilities_54, "!B", rw=RW_FLAG_r,
       constraint=BOOL_CONSTR)
#
# Newly added for PTP clock status
#
C_RpdPTPClockStatus_51 = \
    RCPTLV(51, "RpdPTPClockStatus", format_str="!B", rw=RW_FLAG_r)

#
# RPD-CONFIG DONE
#
C_RpdConfigurationDone_52 = RCPTLV(52, "RpdConfigurationDone", format_str="!B", rw=RW_FLAG_rw)


# RPD EVENT LOG CONF
C_EventNotification_85 = RCPTLV(85, "EventNotification", rw=RW_FLAG_row_key)
RCPTLV(1, "RpdEvLogIndex", C_EventNotification_85, "!I")
RCPTLV(2, "PendingOrLocalLog", C_EventNotification_85, "!B",
       constraint=EnumConstraint(RPD_EVENT_NOTIFICATION_DICT))
RCPTLV(3, "EvFirstTime", C_EventNotification_85, "bytes",
       constraint=StringLenRangeConstraint(8, 11))
RCPTLV(4, "EvLastTime", C_EventNotification_85, "bytes",
       constraint=StringLenRangeConstraint(8, 11))
RCPTLV(5, "EvCounts", C_EventNotification_85, "!I")
RCPTLV(6, "EvLevel", C_EventNotification_85, "!B",
       constraint=EnumConstraint(RPD_EVENT_LEVEL_DICT))
RCPTLV(7, "EvId", C_EventNotification_85, "!I")
RCPTLV(8, "EvString", C_EventNotification_85, "var",
       constraint=StringLenRangeConstraint(1, 255))

C_GeneralNotification_86 = RCPTLV(86, "GeneralNotification", rw=RW_FLAG_row)
RCPTLV(1, "NotificationType", C_GeneralNotification_86, "!B", constraint=EnumConstraint(GeneralNotificationType))
RCPTLV(2, "RedirectResult", C_GeneralNotification_86, "!B", constraint=EnumConstraint(RpdRedirectResult))
RCPTLV(3, "RpdRedirectIpAddress", C_GeneralNotification_86, "IPAddr")
RCPTLV(4, "PtpEnetPortIndex", C_GeneralNotification_86, "!B")
RCPTLV(5, "PtpResult", C_GeneralNotification_86, "!B", constraint=EnumConstraint(PtpResult))
RCPTLV(6, "AuxCoreResult", C_GeneralNotification_86, "!B")
RCPTLV(7, "AuxCoreIpAddress", C_GeneralNotification_86, "IPAddr")
RCPTLV(8, "AuxCoreFailureType", C_GeneralNotification_86, "!B")
RCPTLV(9, "SpecificTimeout", C_GeneralNotification_86, "!B")
RCPTLV(10, "CoreTimedOutIpAddress", C_GeneralNotification_86, "IPAddr")
RCPTLV(11, "PtpRpdPtpPortIndex", C_GeneralNotification_86, "!B")
RCPTLV(12, "PtpClockSource", C_GeneralNotification_86, "!B", constraint=EnumConstraint(PtpClockSource))
#
# RPD STATE
#
C_RpdState_87 = RCPTLV(87, "RpdState", rw=RW_FLAG_row)
RCPTLV(1, "TopLevelRPDState", C_RpdState_87, "!B", rw=RW_FLAG_r)

C87_NetworkAuthenticationState_2 = \
    RCPTLV(2, "NetworkAuthenticationState", C_RpdState_87, rw=RW_FLAG_row)
RCPTLV(1, "NetworkAuthenticationPortIndex", C87_NetworkAuthenticationState_2, "!B", rw=RW_FLAG_key)
RCPTLV(2, "NetworkAuthenticationRpdState", C87_NetworkAuthenticationState_2, "!B", rw=RW_FLAG_r)

RCPTLV(3, "ConnectPrincipalCoreSubState", C_RpdState_87, "!B", rw=RW_FLAG_r)

C87_AuxCoreState_4 = \
    RCPTLV(4, "AuxCoreState", C_RpdState_87, rw=RW_FLAG_row)
RCPTLV(1, "AuxCoreIndex", C87_AuxCoreState_4, "!B", rw=RW_FLAG_key)
RCPTLV(2, "AuxCoreId", C87_AuxCoreState_4, "!B", rw=RW_FLAG_r)
RCPTLV(3, "AuxCoreIp", C87_AuxCoreState_4, "!B", rw=RW_FLAG_r)
RCPTLV(4, "AuxCoreRPDState", C87_AuxCoreState_4, "!B", rw=RW_FLAG_r)

RCPTLV(5, "LocalPtpSyncStatus", C_RpdState_87, "!B", rw=RW_FLAG_rw, constraint=BOOL_CONSTR)
#
# B5.5.9.4 CommonStaticPwConfig
#
C_StaticPwConfig_58 = \
    RCPTLV(58, "StaticPwConfig", rw=RW_FLAG_row)

C58_FwdStaticPwConfig_1 = \
    RCPTLV(1, "FwdStaticPwConfig", C_StaticPwConfig_58, rw=RW_FLAG_row)
RCPTLV(1, "Index", C58_FwdStaticPwConfig_1, "!H", rw=RW_FLAG_r)
RCPTLV(2, "CcapCoreOwner", C58_FwdStaticPwConfig_1, "MAC", rw=RW_FLAG_rw)
RCPTLV(3, "GroupAddress", C58_FwdStaticPwConfig_1, "IPAddr", rw=RW_FLAG_rw)
RCPTLV(4, "SourceAddress", C58_FwdStaticPwConfig_1, "IPAddr", rw=RW_FLAG_rw)

C58_RetStaticPwConfig_2 = \
    RCPTLV(2, "RetStaticPwConfig", C_StaticPwConfig_58, rw=RW_FLAG_row)
RCPTLV(1, "Index", C58_RetStaticPwConfig_2, "!H", rw=RW_FLAG_r)
RCPTLV(2, "CcapCoreOwner", C58_RetStaticPwConfig_2, "MAC", rw=RW_FLAG_rw)
RCPTLV(3, "DestAddress", C58_RetStaticPwConfig_2, "IPAddr", rw=RW_FLAG_rw)
RCPTLV(4, "MtuSize", C58_RetStaticPwConfig_2, "!H", rw=RW_FLAG_rw)
RCPTLV(5, "UsPhbId", C58_RetStaticPwConfig_2, "!B", rw=RW_FLAG_rw)

C58_CommonStaticPwConfig_3 = \
    RCPTLV(3, "CommonStaticPwConfig", C_StaticPwConfig_58, rw=RW_FLAG_row)
RCPTLV(1, "Direction", C58_CommonStaticPwConfig_3, "!B", rw=RW_FLAG_rw)
RCPTLV(2, "Index", C58_CommonStaticPwConfig_3, "!H", rw=RW_FLAG_r)
RCPTLV(4, "PwType", C58_CommonStaticPwConfig_3, "!H", rw=RW_FLAG_r)
RCPTLV(5, "DepiPwSubtype", C58_CommonStaticPwConfig_3, "!H", rw=RW_FLAG_rw)
RCPTLV(6, "L2SublayerType", C58_CommonStaticPwConfig_3, "!H", rw=RW_FLAG_rw)
RCPTLV(7, "DepiL2SublayerSubtype", C58_CommonStaticPwConfig_3, "!H", rw=RW_FLAG_rw)
RCPTLV(8, "SessionId", C58_CommonStaticPwConfig_3, "!I", rw=RW_FLAG_rw)
RCPTLV(9, "CircuitStatus", C58_CommonStaticPwConfig_3, "!H", rw=RW_FLAG_rw)
RCPTLV(10, "RpdEnetPortIndex", C58_CommonStaticPwConfig_3, "!B", rw=RW_FLAG_rw)

C58_PwAssociation_3_11 = \
    RCPTLV(11, "PwAssociation", C58_CommonStaticPwConfig_3, rw=RW_FLAG_row)
RCPTLV(1, "Index", C58_PwAssociation_3_11, "!B", rw=RW_FLAG_key)

C58_PwAssociation_3_11_2 = \
    RCPTLV(2, "ChannelSelector", C58_PwAssociation_3_11, rw=RW_FLAG_row)
RCPTLV(1, "RfPortIndex", C58_PwAssociation_3_11_2, "!B", rw=RW_FLAG_rw)
RCPTLV(2, "ChannelType", C58_PwAssociation_3_11_2, "!B", rw=RW_FLAG_rw)
RCPTLV(3, "ChannelIndex", C58_PwAssociation_3_11_2, "!B", rw=RW_FLAG_rw)

RCPTLV(12, "EnableStatusNotification", C58_CommonStaticPwConfig_3, "!B")

C_StaticPwStatus_59 = \
    RCPTLV(59, "StaticPwStatus", rw=RW_FLAG_row)
C59_StaticPwStatus_1 = \
    RCPTLV(1, "CommonStaticPwStatus", C_StaticPwStatus_59, rw=RW_FLAG_row)
RCPTLV(1, "Direction", C59_StaticPwStatus_1, "!B")
RCPTLV(2, "Index", C59_StaticPwStatus_1, "!H")
RCPTLV(3, "RpdCircuitStatus", C59_StaticPwStatus_1, "!H")


CoreMode = {
    1: "CoreModeActive",
    2: "CoreModeBackup",
    3: "CoreModeNotActing",
    4: "CoreModeDecisionPending",
    5: "CoreModeOutOfService",
    6: "CoreModeContactPending"
}

#
# B.7 RPD Operational Configuration
#
C_CcapCoreIdentification_60 = \
    RCPTLV(60, "CcapCoreIdentification", rw=RW_FLAG_row)
RCPTLV(1, "Index", C_CcapCoreIdentification_60, "!B",
       rw=RW_FLAG_key)  # ??? len 1
RCPTLV(2, "CoreId", C_CcapCoreIdentification_60, "bytes")
RCPTLV(3, "CoreIpAddress", C_CcapCoreIdentification_60, "IPAddr")
RCPTLV(4, "IsPrincipal", C_CcapCoreIdentification_60, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(5, "CoreName", C_CcapCoreIdentification_60, "var")
RCPTLV(6, "VendorId", C_CcapCoreIdentification_60, "!H")
RCPTLV(7, "CoreMode", C_CcapCoreIdentification_60, "!B", constraint=EnumConstraint(CoreMode))

RCPTLV(8, "InitialConfigurationComplete", C_CcapCoreIdentification_60, "!B", constraint=BOOL_CONSTR)
RCPTLV(9, "MoveToOperational", C_CcapCoreIdentification_60, "!B", constraint=BOOL_CONSTR)
RCPTLV(10, "CoreFunction", C_CcapCoreIdentification_60, "!H")
RCPTLV(11, "ResourceSetIndex", C_CcapCoreIdentification_60, "!B")
RCPTLV(12, "ProtocolSupport", C_CcapCoreIdentification_60, "!H")

#
# DsRfPort
#
C_DsRfPort_61 = \
    RCPTLV(61, "DsRfPort", C_RfPort_17, rw=RW_FLAG_row)
# RCPTLV(1, "PortIndex", C_DsRfPort_61, "!H", rw=RW_FLAG_key)
RCPTLV(2, "AdminState", C_DsRfPort_61, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(3, "BasePower", C_DsRfPort_61, "!H")  # [DRFI] in section 6.3.5.1.1,
RCPTLV(4, "RfMute", C_DsRfPort_61, "!B", constraint=BOOL_CONSTR)
RCPTLV(5, "TiltSlope", C_DsRfPort_61, "!h")
RCPTLV(6, "TiltMaximumFrequency", C_DsRfPort_61, "!I")

# DedicatedToneConfig
C61_DedicatedToneConfig_7 = \
    RCPTLV(7, "DedicatedToneConfig", C_DsRfPort_61, rw=RW_FLAG_row)
RCPTLV(1, "ToneIndex", C61_DedicatedToneConfig_7, "!B", rw=RW_FLAG_key)
RCPTLV(2, "ToneFrequency", C61_DedicatedToneConfig_7, "!I")
RCPTLV(3, "TonePower", C61_DedicatedToneConfig_7, "!h")
RCPTLV(4, "RfMute", C61_DedicatedToneConfig_7, "!B")
RCPTLV(5, "FrequencyFraction", C61_DedicatedToneConfig_7, "!B")

#
# B.7.3 DOCSIS and MPEG Video Downstream Channel Configuration
#
C_DsScQamChannelConfig_62 = \
    RCPTLV(62, "DsScQamChannelConfig", C_RfChannel_16, rw=RW_FLAG_row)
# TODO __DB__ RCPTLV(0, "Index"  , C_DsScQamChannelConfig_5, "!H",
# rw=RW_FLAG_key) # ??? on DIAGRAM but MISSING IN TLV
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
RCPTLV(16, "PowerAdjust", C_DsScQamChannelConfig_62, "!h")

#
# DsOfdmChannelConfig
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
RCPTLV(14, "PowerAdjust", C_DsOfdmChannelConfig_63, "!h")

#
# DsOfdmProfile
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
       constraint=EnumConstraint(MODULATION_722_DICT))

#
# DOCSIS Upstream Channel Configuration
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
RCPTLV(11, "EqualizationCoeff_Enable", C_UsScQamChannelConfig_65, "!B")
RCPTLV(12, "IngressNoiseCancel_Enable", C_UsScQamChannelConfig_65, "!B")
RCPTLV(13, "UpStreamChanId", C_UsScQamChannelConfig_65, "!B")
RCPTLV(14, "ConfigChangeCount", C_UsScQamChannelConfig_65, "!B")
RCPTLV(15, "DownStreamChanId", C_UsScQamChannelConfig_65, "!B")

# IntervalUsageCode
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
RCPTLV(12, "ByteInterleaverDepth", C65_IntervalUsageCode_10, "!B")
RCPTLV(13, "ByteInterleaverBlockSize", C65_IntervalUsageCode_10, "!H")
RCPTLV(14, "ModulationType", C65_IntervalUsageCode_10, "!B")
RCPTLV(15, "GuardTime", C65_IntervalUsageCode_10, "!B")

#
# UsOfdmaChannelConfig
#
C_UsOfdmaChannelConfig_66 = \
    RCPTLV(66, "UsOfdmaChannelConfig", C_RfChannel_16, rw=RW_FLAG_row)
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
RCPTLV(12, "PreambleString", C_UsOfdmaChannelConfig_66, "bytes")  # ??? max 192
RCPTLV(13, "TargetRxPowerAdjust", C_UsOfdmaChannelConfig_66, "!H")
RCPTLV(14, "EnableFlowTags", C_UsOfdmaChannelConfig_66, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(15, "ScramblerSeed", C_UsOfdmaChannelConfig_66, "!I")
RCPTLV(16, "ConfigMultiSectionTimingMer", C_UsOfdmaChannelConfig_66, "var")
# BwReqAggrControlOfdma
C66_BwReqAggrControlOfdma_17 = \
    RCPTLV(17, "BwReqAggrControlOfdma", C_UsOfdmaChannelConfig_66, rw=RW_FLAG_row)
RCPTLV(1, "MaxReqBlockEnqTimeout", C66_BwReqAggrControlOfdma_17, "!H")
RCPTLV(2, "MaxReqBlockEnqNumber", C66_BwReqAggrControlOfdma_17, "!B")
RCPTLV(18, "UpStreamChanId", C_UsOfdmaChannelConfig_66, "!B")
RCPTLV(19, "ConfigChangeCount", C_UsOfdmaChannelConfig_66, "!B")
RCPTLV(20, "DownStreamChanId", C_UsOfdmaChannelConfig_66, "!B")
RCPTLV(21, "BroadcastImRegionDuration", C_UsOfdmaChannelConfig_66, "!B")
RCPTLV(22, "UnicastImRegionDuration", C_UsOfdmaChannelConfig_66, "!B")

#
# UsOfdmaInitialRangingIuc
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
# UsOfdmaDataIuc
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
# UsOfdmaSubcarrierCfgState
#
C_UsOfdmaSubcarrierCfgState_70 = \
    RCPTLV(70, "UsOfdmaSubcarrierCfgState", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "StartingSubcarrierId", C_UsOfdmaSubcarrierCfgState_70, "!H",
       rw=RW_FLAG_key,
       constraint=RangeConstraint(STARTING_SUBCARRIER_ID_TYPES[0],
                                  STARTING_SUBCARRIER_ID_TYPES[-1]))
RCPTLV(2, "NumConsecutiveSubcarriers", C_UsOfdmaSubcarrierCfgState_70, "!H")
RCPTLV(3, "SubcarrierUsage", C_UsOfdmaSubcarrierCfgState_70, "!B",
       constraint=EnumConstraint(SUBCARRIER_USAGE_13_DICT))

#
# SidQos
#
C_SidQos_96 = \
    RCPTLV(96, "SidQos", C_RfChannel_16, rw=RW_FLAG_row_key)
RCPTLV(1, "StartSid", C_SidQos_96, "!H")
RCPTLV(2, "NumSids", C_SidQos_96, "!H")
RCPTLV(3, "SidSfType", C_SidQos_96, "!B")
RCPTLV(4, "SidUepiFlowId", C_SidQos_96, "!B")
RCPTLV(5, "SidFlowTag", C_SidQos_96, "!I")

C_UsRfPort_98 = \
    RCPTLV(98, "UsRfPort", C_RfPort_17, rw=RW_FLAG_row)
RCPTLV(1, "AdminState", C_UsRfPort_98, "!B", constraint=EnumConstraint(ADMIN_STATE_DICT))
C98_BwReqAggrControl = \
    RCPTLV(2, "BwReqAggrControl", C_UsRfPort_98, rw=RW_FLAG_row)
RCPTLV(1, "MaxReqBlockEnqTimeout", C98_BwReqAggrControl, "!H", constraint=RangeConstraint(0, 500))
RCPTLV(2, "MaxReqBlockEnqNumber", C98_BwReqAggrControl, "!B", constraint=RangeConstraint(1, 63))
RCPTLV(3, "BaseTargetRxPower", C_UsRfPort_98, "!h")

#
# Status and performance TLVs
#
C_DsRfPortPerf_71 = \
    RCPTLV(71, "DsRfPortPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_DsScQamChannelPerf_72 = \
    RCPTLV(72, "DsScQamChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsScQamChannelPerf_72, "!Q", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsScQamChannelPerf_72, "!Q", rw=RW_FLAG_r)

C_DsOfdmChannelPerf_73 = \
    RCPTLV(73, "DsOfdmChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsOfdmChannelPerf_73, "!Q", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsOfdmChannelPerf_73, "!Q", rw=RW_FLAG_r)
C73_DsOfdmProfilePerf_3 = \
    RCPTLV(3, "DsOfdmProfilePerf", C_DsOfdmChannelPerf_73, rw=RW_FLAG_row)
RCPTLV(1, "ProfileIndex", C73_DsOfdmProfilePerf_3, "!B", rw=RW_FLAG_r)
RCPTLV(2, "outCodewords", C73_DsOfdmProfilePerf_3, "!Q", rw=RW_FLAG_r)

C_DsOob551IPerf_74 = \
    RCPTLV(74, "DsOob551IPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsOob551IPerf_74, "!Q", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsOob551IPerf_74, "!Q", rw=RW_FLAG_r)

C_DsOob552Perf_75 = \
    RCPTLV(75, "DsOob552Perf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_DsOob552Perf_75, "!Q", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_DsOob552Perf_75, "!Q", rw=RW_FLAG_r)

C_NdfPerf_76 = \
    RCPTLV(76, "NdfPerf", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "outDiscards", C_NdfPerf_76, "!Q", rw=RW_FLAG_r)
RCPTLV(2, "outErrors", C_NdfPerf_76, "!Q", rw=RW_FLAG_r)

C_UsRfPortPerf_77 = \
    RCPTLV(77, "UsRfPortPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_UsScQamChannelPerf_78 = \
    RCPTLV(78, "UsScQamChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
C78_UsScQamIucIPerf_1 = \
    RCPTLV(1, "UsScQamIucIPerf", C_UsScQamChannelPerf_78, rw=RW_FLAG_row)
RCPTLV(1, "UsIuc", C78_UsScQamIucIPerf_1, "!B", rw=RW_FLAG_r)
RCPTLV(2, "Collisions", C78_UsScQamIucIPerf_1, "!I", rw=RW_FLAG_r)
RCPTLV(3, "NoEnergy", C78_UsScQamIucIPerf_1, "!I", rw=RW_FLAG_r)
C78_UcdRefreshScqam_10 = \
    RCPTLV(10, "UcdRefreshStatusScqam", C_UsScQamChannelPerf_78, rw=RW_FLAG_row)
RCPTLV(1, "UcdRefreshRequestScqam", C78_UcdRefreshScqam_10, "!B", rw=RW_FLAG_r, constraint=BOOL_CONSTR)
RCPTLV(2, "UcdRefreshReasonScqam", C78_UcdRefreshScqam_10, "var", rw=RW_FLAG_r, constraint=StringLenConstraint(32))

C_UsOfdmaChannelPerf_79 = \
    RCPTLV(79, "UsOfdmaChannelPerf", C_RfChannel_16, rw=RW_FLAG_row)
C79_UcdRefreshOfdma_10 = \
    RCPTLV(10, "UcdRefreshStatusOfdma", C_UsOfdmaChannelPerf_79, rw=RW_FLAG_row)
RCPTLV(1, "UcdRefreshRequestOfdma", C79_UcdRefreshOfdma_10, "!B", rw=RW_FLAG_r, constraint=BOOL_CONSTR)
RCPTLV(2, "UcdRefreshReasonOfdma", C79_UcdRefreshOfdma_10, "var", rw=RW_FLAG_r, constraint=StringLenConstraint(32))

C_UsOob551IPerf_80 = \
    RCPTLV(80, "UsOob551IPerf", C_RfChannel_16, rw=RW_FLAG_row)

C_UsOob552Perf_81 = \
    RCPTLV(81, "UsOob552Perf", C_RfChannel_16, rw=RW_FLAG_row)

C_NdrPerf_82 = \
    RCPTLV(82, "NdrPerf", C_RfChannel_16, rw=RW_FLAG_row)
#
# MultiCore
#
C_MultiCore_88 = \
    RCPTLV(88, "MultiCore", rw=RW_FLAG_row)

C88_ConfiguredCoreTable_1 = \
    RCPTLV(1, "ConfiguredCoreTable", C_MultiCore_88, rw=RW_FLAG_row)
RCPTLV(1, "Index", C88_ConfiguredCoreTable_1, "!B", rw=RW_FLAG_key)
RCPTLV(2, "ConfiguredCoreIp", C88_ConfiguredCoreTable_1, "IPAddr")

C88_ResourceSet_2 = \
    RCPTLV(2, "ResourceSet", C_MultiCore_88, rw=RW_FLAG_row)
RCPTLV(1, "ResourceSetIndex", C88_ResourceSet_2, "!B", rw=RW_FLAG_key)
RCPTLV(2, "CcapCoreOwner", C88_ResourceSet_2, "MAC")
RCPTLV(3, "DsRfPortStart", C88_ResourceSet_2, "!I")
RCPTLV(4, "DsRfPortEnd", C88_ResourceSet_2, "!I")
C88_DsChanGroup_2_5 = \
    RCPTLV(5, "DsChanGroup", C88_ResourceSet_2, rw=RW_FLAG_row)
RCPTLV(1, "DsChanGroupIndex", C88_DsChanGroup_2_5, "!I", rw=RW_FLAG_key)
RCPTLV(2, "DsChanType", C88_DsChanGroup_2_5, "!B")
RCPTLV(3, "DsChanIndexStart", C88_DsChanGroup_2_5, "!I")
RCPTLV(4, "DsChanIndexEnd", C88_DsChanGroup_2_5, "!I")
RCPTLV(6, "UsRfPortStart", C88_ResourceSet_2, "!I")
RCPTLV(7, "UsRfPortEnd", C88_ResourceSet_2, "!I")
C88_UsChanGroup_2_8 = \
    RCPTLV(8, "UsChanGroup", C88_ResourceSet_2, rw=RW_FLAG_row)
RCPTLV(1, "UsChanGroupIndex", C88_UsChanGroup_2_8, "!I", rw=RW_FLAG_key)
RCPTLV(2, "UsChanType", C88_UsChanGroup_2_8, "!B")
RCPTLV(3, "UsChanIndexStart", C88_UsChanGroup_2_8, "!I")
RCPTLV(4, "UsChanIndexEnd", C88_UsChanGroup_2_8, "!I")

RCPTLV(3, "PermitAuxSelfConfiguration", C_MultiCore_88, "!B")
C88_DownChannelConstraintTable_4 = \
    RCPTLV(4, "DownChannelConstraintTable", C_MultiCore_88, rw=RW_FLAG_row)
RCPTLV(1, "Index", C88_DownChannelConstraintTable_4, "!B", rw=RW_FLAG_key)
RCPTLV(2, "DownChanIndexStart", C88_DownChannelConstraintTable_4, "!I", rw=RW_FLAG_r)
RCPTLV(3, "DownChanIndexEnd", C88_DownChannelConstraintTable_4, "!I", rw=RW_FLAG_r)
RCPTLV(4, "LockParameters", C88_DownChannelConstraintTable_4, "!I", rw=RW_FLAG_r)
#
# Device Management TLVs
#

RESET_TYPE = {
    1: "softReset",
    2: "hardReset",
    3: "nvReset",
    4: "factoryReset",
}

C_RpdCtrl_40 = \
    RCPTLV(40, "RpdCtrl", rw=RW_FLAG_row)
C40_ResetCtrl_1 = \
    RCPTLV(1, "ResetCtrl", C_RpdCtrl_40, rw=RW_FLAG_row)
RCPTLV(1, "Reset", C40_ResetCtrl_1, "!B", constraint=EnumConstraint(RESET_TYPE), rw=RW_FLAG_rw)
C40_LogCtrl_2 = \
    RCPTLV(2, "LogCtrl", C_RpdCtrl_40, rw=RW_FLAG_row)
RCPTLV(1, "ResetLog", C40_LogCtrl_2, "!B", rw=RW_FLAG_rw)

C40_CrashDataFileCtrl_3 = \
    RCPTLV(3, "CrashDataFileCtrl", C_RpdCtrl_40, rw=RW_FLAG_row)
RCPTLV(1, "Index", C40_CrashDataFileCtrl_3, "!B", rw=RW_FLAG_key)
RCPTLV(2, "FileControl", C40_CrashDataFileCtrl_3, "!B", rw=RW_FLAG_rw)

C40_CrashDataServerCtrl_4 = \
    RCPTLV(4, "CrashDataServerCtrl", C_RpdCtrl_40, rw=RW_FLAG_row)
RCPTLV(1, "DestIpAddress", C40_CrashDataServerCtrl_4, "IPAddr", rw=RW_FLAG_rw)
RCPTLV(2, "DestPath", C40_CrashDataServerCtrl_4, "var", rw=RW_FLAG_rw)
RCPTLV(3, "Protocol", C40_CrashDataServerCtrl_4, "!B", rw=RW_FLAG_rw)


C_Ssd_90 = \
    RCPTLV(90, "Ssd", rw=RW_FLAG_row)
RCPTLV(1, "SsdServerAddress", C_Ssd_90, "IPAddr")
RCPTLV(2, "SsdTransport", C_Ssd_90, "!B")
RCPTLV(3, "SsdFilename", C_Ssd_90, "bytes")
RCPTLV(4, "SsdStatus", C_Ssd_90, "!B")
RCPTLV(5, "SsdControl", C_Ssd_90, "!B")
RCPTLV(6, "SsdManufCvcChain", C_Ssd_90, "bytes")
RCPTLV(7, "SsdCosignerCvcChain", C_Ssd_90, "bytes")

#
# SCTE 55-1 OOB Configuration TLVs
#
C_DsOob55d1_91 = \
    RCPTLV(91, "DsOob55d1", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "AdminState", C_DsOob55d1_91, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(2, "CcapCoreOwner", C_DsOob55d1_91, "MAC")
RCPTLV(3, "RfMute", C_DsOob55d1_91, "!B")
RCPTLV(4, "Frequency", C_DsOob55d1_91, "!I")
RCPTLV(5, "PowerAdjust", C_DsOob55d1_91, "!h")
RCPTLV(6, "SecondFrequency", C_DsOob55d1_91, "!I")
RCPTLV(7, "SfPowerAdjust", C_DsOob55d1_91, "!h")
RCPTLV(8, "SfAdminState", C_DsOob55d1_91, "!B")
RCPTLV(9, "SfMute", C_DsOob55d1_91, "!B")
C_UsOob55d1_92 = \
    RCPTLV(92, "UsOob55d1", C_RfChannel_16, rw=RW_FLAG_row)
RCPTLV(1, "AdminState", C_UsOob55d1_92, "!B",
       constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(2, "CcapCoreOwner", C_UsOob55d1_92, "MAC")
RCPTLV(3, "Frequency", C_UsOob55d1_92, "!I")
RCPTLV(4, "VarpdDeviceId", C_UsOob55d1_92, "!I")
RCPTLV(5, "VarpdRfPortId", C_UsOob55d1_92, "!B")
RCPTLV(6, "VarpdDemodId", C_UsOob55d1_92, "!B")

#
# SCTE 55-2 OOB Configuration TLVs
#
C_Oob55d2Config_93 = \
    RCPTLV(93, "Oob55d2Config", rw=RW_FLAG_row)
RCPTLV(1, "DsCenterFrequency", C_Oob55d2Config_93, "!I")
RCPTLV(2, "UsCenterFrequency", C_Oob55d2Config_93, "!I")
RCPTLV(3, "CcapCoreOwner", C_Oob55d2Config_93, "MAC")
C93_Oob55d2Module_4 = \
    RCPTLV(4, "Oob55d2Module", C_Oob55d2Config_93, rw=RW_FLAG_row)
RCPTLV(1, "ModuleIndex", C93_Oob55d2Module_4, "!B", rw=RW_FLAG_key)
RCPTLV(2, "ModulatorId", C93_Oob55d2Module_4, "!B")
RCPTLV(3, "ServiceChannelLastSlot", C93_Oob55d2Module_4, "!H")
RCPTLV(4, "DefaultRangingInterval", C93_Oob55d2Module_4, "!B")
RCPTLV(5, "DefaultRangingSlotConfiguration", C93_Oob55d2Module_4, "!H")
RCPTLV(6, "DefaultNonRangingSlotConfiguration", C93_Oob55d2Module_4, "!H")
RCPTLV(7, "Randomizer", C93_Oob55d2Module_4, "!B")
RCPTLV(8, "DsPower", C93_Oob55d2Module_4, "!h")
RCPTLV(9, "DsPortAssociation", C93_Oob55d2Module_4, "var", rw=RW_FLAG_r)
C93_4_Oob55d2Demod_10 = \
    RCPTLV(10, "Oob55d2Demod", C93_Oob55d2Module_4, rw=RW_FLAG_row)
RCPTLV(1, "DemodIndex", C93_4_Oob55d2Demod_10, "!B", rw=RW_FLAG_key)
RCPTLV(2, "UpstreamGroupId", C93_4_Oob55d2Demod_10, "!B")
RCPTLV(3, "MaxDhctDistance", C93_4_Oob55d2Demod_10, "!B")
RCPTLV(4, "UsPortAssociation", C93_4_Oob55d2Demod_10, "!B", rw=RW_FLAG_r)
RCPTLV(11, "RfMute", C93_Oob55d2Module_4, "!B",
       constraint=BOOL_CONSTR)

#
# NDF Configuration TLVs
#
C_NdfConfig_94 = \
    RCPTLV(94, "NdfConfig", rw=RW_FLAG_row)
# TODO: Index shown in UML diagram but missing in TLVs ???
RCPTLV(1, "AdminState", C_NdfConfig_94, "!B")
RCPTLV(2, "CcapCoreOwner", C_NdfConfig_94, "MAC")
RCPTLV(3, "RfMute", C_NdfConfig_94, "!B",
       constraint=BOOL_CONSTR)
RCPTLV(4, "CenterFrequency", C_NdfConfig_94, "!I")
RCPTLV(5, "ChannelWidth", C_NdfConfig_94, "!I")
RCPTLV(6, "PowerAdjust", C_NdfConfig_94, "!B")

#
# NDR Configuration TLVs
#
C_NdrConfig_95 = \
    RCPTLV(95, "NdrConfig", rw=RW_FLAG_row)
# TODO: Index shown in UML diagram but missing in TLVs ???
RCPTLV(1, "AdminState", C_NdrConfig_95, "!B")
RCPTLV(2, "CcapCoreOwner", C_NdrConfig_95, "MAC")
RCPTLV(3, "CenterFrequency", C_NdrConfig_95, "!I")
RCPTLV(4, "ChannelWidth", C_NdrConfig_95, "!I")
RCPTLV(5, "NdrPower", C_NdrConfig_95, "!B")


#
# RDTI Configuration
#
C_RdtiConfig_97 = \
    RCPTLV(97, "RdtiConfig", rw=RW_FLAG_row)
RCPTLV(1, "RpdRdtiMode", C_RdtiConfig_97, "!B", constraint=EnumConstraint(RDTI_MODE_DICT))
RCPTLV(2, "RpdPtpDefDsDomainNumber", C_RdtiConfig_97, "!B", constraint=RangeConstraint(0, 127))
RCPTLV(3, "RpdPtpDefDsPriority1", C_RdtiConfig_97, "!B", rw=RW_FLAG_rw)
RCPTLV(4, "RpdPtpDefDsPriority2", C_RdtiConfig_97, "!B", constraint=RangeConstraint(255, 255))
RCPTLV(5, "RpdPtpDefDsLocalPriority", C_RdtiConfig_97, "!B", constraint=RangeConstraint(1, 255))
RCPTLV(6, "RpdPtpProfileIdentifier", C_RdtiConfig_97, "MAC", rw=RW_FLAG_rw)
RCPTLV(7, "RpdPtpProfileVersion", C_RdtiConfig_97, "bytes", rw=RW_FLAG_rw)

C97_RpdPtpPortConfig_8 = \
    RCPTLV(8, "RpdPtpPortConfig", C_RdtiConfig_97, rw=RW_FLAG_row)
RCPTLV(1, "RpdEnetPortIndex", C97_RpdPtpPortConfig_8, "!H", rw=RW_FLAG_key)
RCPTLV(2, "RpdPtpPortIndex", C97_RpdPtpPortConfig_8, "!H", rw=RW_FLAG_key)
RCPTLV(3, "RpdPtpPortAdminState", C97_RpdPtpPortConfig_8, "!B", constraint=EnumConstraint(ADMIN_STATE_DICT))
RCPTLV(4, "RpdPtpPortClockSource", C97_RpdPtpPortConfig_8, "IPAddr", rw=RW_FLAG_rw)
RCPTLV(5, "RpdPtpPortClockAlternateSource", C97_RpdPtpPortConfig_8, "IPAddr", rw=RW_FLAG_rw)
RCPTLV(6, "RpdPtpPortClockSelectAlternateSourceFirst", C97_RpdPtpPortConfig_8, "!B", constraint=BOOL_CONSTR)
RCPTLV(7, "RpdPtpPortTransportType", C97_RpdPtpPortConfig_8, "!B", rw=RW_FLAG_rw)
RCPTLV(8, "RpdPtpPortTransportCos", C97_RpdPtpPortConfig_8, "!B", constraint=RangeConstraint(0, 7))
RCPTLV(9, "RpdPtpPortTransportDscp", C97_RpdPtpPortConfig_8, "!B", constraint=RangeConstraint(0, 63))
RCPTLV(10, "RpdPtpPortDsLocalPriority", C97_RpdPtpPortConfig_8, "!B", constraint=RangeConstraint(1, 255))
RCPTLV(11, "RpdPtpPortDsLogSyncInterval", C97_RpdPtpPortConfig_8, "!b", constraint=RangeConstraint(-7, 0))
RCPTLV(12, "RpdPtpPortDsLogAnnounceInterval", C97_RpdPtpPortConfig_8, "!b", constraint=RangeConstraint(-3, 0))
RCPTLV(13, "RpdPtpPortDsLogDelayReqInterval", C97_RpdPtpPortConfig_8, "!b", constraint=RangeConstraint(-7, 0))
RCPTLV(14, "RpdPtpPortDsAnnounceReceiptTimeout", C97_RpdPtpPortConfig_8, "!B", constraint=RangeConstraint(3, 255))
RCPTLV(15, "RpdPtpPortUnicastContractDuration", C97_RpdPtpPortConfig_8, "!H", constraint=RangeConstraint(60, 1000))
RCPTLV(16, "RpdPtpPortClockGW", C97_RpdPtpPortConfig_8, "IPAddr", rw=RW_FLAG_rw)
RCPTLV(17, "RpdPtpPortClockAlternateGW", C97_RpdPtpPortConfig_8, "IPAddr", rw=RW_FLAG_rw)

#
# RPD Operational Monitoring
#

C_RpdInfo_100 = \
    RCPTLV(100, "RpdInfo", rw=RW_FLAG_row)
C100_RpdDevInfo_1 = \
    RCPTLV(1, "RpdDevInfo", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "RpdSysUpTime", C100_RpdDevInfo_1, "!I", rw=RW_FLAG_r)
RCPTLV(2, "NumCrashFilesAvail", C100_RpdDevInfo_1, "!B", rw=RW_FLAG_r)

C100_RpdL2tpSessionInfo_2 = \
    RCPTLV(2, "RpdL2tpSessionInfo", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "SessionIpAddrType", C100_RpdL2tpSessionInfo_2, "!I",
       rw=RW_FLAG_key)
RCPTLV(2, "RemoteLcceIpAddr", C100_RpdL2tpSessionInfo_2, "IPAddr",
       rw=RW_FLAG_key)
RCPTLV(3, "RpdLcceIpAddress", C100_RpdL2tpSessionInfo_2, "IPAddr",
       rw=RW_FLAG_key)
RCPTLV(4, "Direction", C100_RpdL2tpSessionInfo_2, "!B",
       rw=RW_FLAG_key)
RCPTLV(5, "LocalL2tpSessionId", C100_RpdL2tpSessionInfo_2, "!I",
       rw=RW_FLAG_key)
RCPTLV(6, "CoreId", C100_RpdL2tpSessionInfo_2, "bytes", rw=RW_FLAG_r)
RCPTLV(7, "ConnCtrlId", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)
RCPTLV(8, "UdpPort", C100_RpdL2tpSessionInfo_2, "!H", rw=RW_FLAG_r)
RCPTLV(9, "Description", C100_RpdL2tpSessionInfo_2, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(10, "SessionType", C100_RpdL2tpSessionInfo_2, "!B", rw=RW_FLAG_r)
RCPTLV(11, "SessionSubType", C100_RpdL2tpSessionInfo_2, "!B", rw=RW_FLAG_r)
RCPTLV(12, "MaxPayload", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)
RCPTLV(13, "PathPayload", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)
RCPTLV(14, "RpdIfMtu", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)
RCPTLV(15, "CoreIfMtu", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)
RCPTLV(16, "ErrorCode", C100_RpdL2tpSessionInfo_2, "!B", rw=RW_FLAG_r)
RCPTLV(17, "CreationTime", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)
RCPTLV(18, "OperStatus", C100_RpdL2tpSessionInfo_2, "!B", rw=RW_FLAG_r)
RCPTLV(19, "LocalStatus", C100_RpdL2tpSessionInfo_2, "!B", rw=RW_FLAG_r)
RCPTLV(20, "LastChange", C100_RpdL2tpSessionInfo_2, "!I", rw=RW_FLAG_r)

C100_2_RpdL2tpSessionStats_21 = \
    RCPTLV(21, "SessionStats", C100_RpdL2tpSessionInfo_2, rw=RW_FLAG_row)
RCPTLV(1, "OutOfSequencePackets", C100_2_RpdL2tpSessionStats_21, "!I",
       rw=RW_FLAG_r)
RCPTLV(2, "InPacket", C100_2_RpdL2tpSessionStats_21, "!Q", rw=RW_FLAG_r)
RCPTLV(3, "InDiscards", C100_2_RpdL2tpSessionStats_21, "!Q", rw=RW_FLAG_r)
RCPTLV(4, "OutPackets", C100_2_RpdL2tpSessionStats_21, "!Q", rw=RW_FLAG_r)
RCPTLV(5, "OutErrors", C100_2_RpdL2tpSessionStats_21, "!Q", rw=RW_FLAG_r)
RCPTLV(6, "CounterDiscTime", C100_2_RpdL2tpSessionStats_21, "bytes",
       constraint=StringLenRangeConstraint(8, 11))

# 100.4 - DiagnosticStatus
C100_DiagnosticStatus_4 = \
    RCPTLV(4, "DiagnosticStatus", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "ProbableCause", C100_DiagnosticStatus_4, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(2, "AdditionalText", C100_DiagnosticStatus_4, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(3, "SeverityLevel", C100_DiagnosticStatus_4, "!B", rw=RW_FLAG_r,
       constraint=EnumConstraint(SEVERITYLEVEL_TYPE_DICT))

# 100.5 - DepiMcastSession
C100_DepiMcastSession_5 = \
    RCPTLV(5, "DepiMcastSession", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "IpAddrType", C100_DepiMcastSession_5, "!I", rw=RW_FLAG_key)
RCPTLV(2, "GroupIpAddr", C100_DepiMcastSession_5, "IPAddr", rw=RW_FLAG_key)
RCPTLV(3, "SrcIpAddr", C100_DepiMcastSession_5, "IPAddr", rw=RW_FLAG_key)
RCPTLV(4, "LocalLcceIpAddr", C100_DepiMcastSession_5, "IPAddr", rw=RW_FLAG_r)
RCPTLV(5, "RemoteLcceIpAddr", C100_DepiMcastSession_5, "IPAddr", rw=RW_FLAG_r)
RCPTLV(6, "SessionId", C100_DepiMcastSession_5, "!I", rw=RW_FLAG_key)
RCPTLV(7, "JoinTime", C100_DepiMcastSession_5, "bytes", rw=RW_FLAG_r)

# 100.6 - Entity
ClassType = {
    1: "other",
    2: "unknown",
    3: "chassis",
    4: "backplane",
    5: "container",
    6: "powerSupply",
    7: "fan",
    8: "sensor",
    9: "module",
    10: "port",
    11: "stack",
    12: "cpu"
}

C100_RpdEntity_6 = \
    RCPTLV(6, "RpdEntityTable", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "EntityIndex", C100_RpdEntity_6, "!I", rw=RW_FLAG_key)
RCPTLV(2, "Descr", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(3, "VendorType", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(4, "ContainedIn", C100_RpdEntity_6, "!I", rw=RW_FLAG_r)
RCPTLV(5, "Class", C100_RpdEntity_6, "!B", constraint=EnumConstraint(ClassType))
RCPTLV(6, "ParentRelPos", C100_RpdEntity_6, "!i", rw=RW_FLAG_r)
RCPTLV(7, "Name", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(8, "HardwareRev", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(9, "FirmwareRev", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(10, "SoftwareRev", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(11, "SerialNum", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(12, "MfgName", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(13, "ModelName", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(14, "Alias", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(15, "AssetId", C100_RpdEntity_6, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(16, "IsFRU", C100_RpdEntity_6, "!B", constraint=BOOL_CONSTR)
RCPTLV(17, "MfgDate", C100_RpdEntity_6, "bytes", rw=RW_FLAG_r,
       constraint=StringLenRangeConstraint(8, 11))
RCPTLV(18, "Uris", C100_RpdEntity_6, "bytes", rw=RW_FLAG_r,
       constraint=StringLenConstraint(2))
RCPTLV(19, "CoreIfIndex", C100_RpdEntity_6, "!I", rw=RW_FLAG_r)
RCPTLV(20, "Uuid", C100_RpdEntity_6, "bytes", rw=RW_FLAG_r,
       constraint=StringLenConstraint(16))

# rpd_sensor
SensorType = {
    1: "other",
    2: "unknown",
    3: "volts_ac",
    4: "volts_dc",
    5: "amperes",
    6: "watts",
    7: "herts",
    8: "celsius",
    9: "percentRH",
    10: "rpm",
    11: "cmm",
    12: "truthvalue"
}

ScaleType = {
    1: "yocto",
    2: "zepto",
    3: "atto",
    4: "femto",
    5: "pico",
    6: "nano",
    7: "micro",
    8: "milli",
    9: "units",
    10: "kilo",
    11: "mega",
    12: "giga",
    13: "tera",
    14: "exa",
    15: "peta",
    16: "zetta",
    17: "yotta"
}

OperStatusType = {
    1: "OK",
    2: "unavailable",
    3: "nonoperational"
}

C100_RpdSensor_7 = \
    RCPTLV(7, "RpdSensorTable", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "EntityIndex", C100_RpdSensor_7, "!I", rw=RW_FLAG_key)
RCPTLV(2, "SensorType", C100_RpdSensor_7, "!B", constraint=EnumConstraint(SensorType))
RCPTLV(3, "Scale", C100_RpdSensor_7, "!B", constraint=EnumConstraint(ScaleType))
RCPTLV(4, "Precision", C100_RpdSensor_7, "!b", rw=RW_FLAG_r)
RCPTLV(5, "Value", C100_RpdSensor_7, "!I", rw=RW_FLAG_r)
RCPTLV(6, "OperStatus", C100_RpdSensor_7, "!B", constraint=EnumConstraint(OperStatusType))
RCPTLV(7, "UnitsDisplay", C100_RpdSensor_7, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(8, "ValueTimeStamp", C100_RpdSensor_7, "!I", rw=RW_FLAG_r)
RCPTLV(9, "ValueUpdateRate", C100_RpdSensor_7, "!I", rw=RW_FLAG_r)

# EnetIfTable
C100_EnetIfTable_8 = \
    RCPTLV(8, "EnetIfTable", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "ifIndex", C100_EnetIfTable_8, "!B", rw=RW_FLAG_key)
RCPTLV(2, "ifName", C100_EnetIfTable_8, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(3, "ifDescr", C100_EnetIfTable_8, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(4, "ifType", C100_EnetIfTable_8, "!H", rw=RW_FLAG_r)
RCPTLV(5, "ifAlias", C100_EnetIfTable_8, "var", rw=RW_FLAG_r,
       constraint=StringLenConstraint(255))
RCPTLV(6, "ifMTU", C100_EnetIfTable_8, "!I", rw=RW_FLAG_r)
RCPTLV(7, "ifPhysAddress", C100_EnetIfTable_8, "MAC", rw=RW_FLAG_r)
RCPTLV(8, "ifAdminStatus", C100_EnetIfTable_8, "!B", rw=RW_FLAG_r)
RCPTLV(9, "ifOperStatus", C100_EnetIfTable_8, "!B", rw=RW_FLAG_r)
RCPTLV(10, "ifLastChange", C100_EnetIfTable_8, "!I", rw=RW_FLAG_r)
RCPTLV(11, "ifHighSpeed", C100_EnetIfTable_8, "!I", rw=RW_FLAG_r)
RCPTLV(12, "ifLinkUpDownTrapEnable", C100_EnetIfTable_8, "!B", rw=RW_FLAG_r)
RCPTLV(13, "ifPromiscuousMode", C100_EnetIfTable_8, "!B", rw=RW_FLAG_r)
RCPTLV(14, "ifConnectorPresent", C100_EnetIfTable_8, "!B", rw=RW_FLAG_r)

# 100.9 -  EnetIfStatsTable
C100_EnetIfTable_9 = \
    RCPTLV(9, "EnetIfStatsTable", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "ifIndex", C100_EnetIfTable_9, "!B", rw=RW_FLAG_key)
RCPTLV(2, "ifInOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(3, "ifInUnicastOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(4, "ifInMulticastOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(5, "ifInBroadcastOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(6, "ifInFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(7, "ifInUnicastFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(8, "ifInMulticastFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(9, "ifInBroadcastFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(10, "ifInDiscards", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(11, "ifInErrors", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(12, "ifInUnknownProtos", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(13, "ifOutOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(14, "ifOutUnicastOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(15, "ifOutMulticastOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(16, "ifOutBroadcastOctets", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(17, "ifOutFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(18, "ifOutUnicastFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(19, "ifOutMulticastFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(20, "ifOutBroadcastFrames", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(21, "ifOutDiscards", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(22, "ifOutErrors", C100_EnetIfTable_9, "!Q", rw=RW_FLAG_r)
RCPTLV(23, "ifCounterDiscontinuity", C100_EnetIfTable_9, "!I", rw=RW_FLAG_r)

# 100.10 - RpdEnetToCoreEntityMap
C100_RpdEnetToCoreEntityMap_10 = \
    RCPTLV(10, "RpdEnetToCoreEntityMap", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "EnetPortIndex", C100_RpdEnetToCoreEntityMap_10, "!B", rw=RW_FLAG_key)
RCPTLV(2, "EntityIndex", C100_RpdEnetToCoreEntityMap_10, "!I", rw=RW_FLAG_r)

# 100.11 - IpInterfaceGrp
C100_IpInterfaceGrp_11 = \
    RCPTLV(11, "IpInterfaceGrp", C_RpdInfo_100, rw=RW_FLAG_row)

# 100.12 - IpInterface
C100_Ipv4Interface_12 = \
    RCPTLV(12, "Ipv4Interfaces", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "EnetPortIndex", C100_Ipv4Interface_12, "!B", rw=RW_FLAG_key)
RCPTLV(3, "EnableStatus", C100_Ipv4Interface_12, "!B", rw=RW_FLAG_r)
RCPTLV(4, "RetransmitTime", C100_Ipv4Interface_12, "!I", rw=RW_FLAG_r)

C100_Ipv6Interface_13 = \
    RCPTLV(13, "Ipv6Interfaces", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "EnetPortIndex", C100_Ipv6Interface_13, "!B", rw=RW_FLAG_key)
RCPTLV(3, "EnableStatus", C100_Ipv6Interface_13, "!B", rw=RW_FLAG_r)
RCPTLV(4, "RetransmitTime", C100_Ipv6Interface_13, "!I", rw=RW_FLAG_r)
RCPTLV(5, "InterfaceIdentifier", C100_Ipv6Interface_13, "var", rw=RW_FLAG_r)
RCPTLV(6, "ReachableTime", C100_Ipv6Interface_13, "!I", rw=RW_FLAG_r)

C100_IpAddress_15 = RCPTLV(15, "IpAddress", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "AddrType", C100_IpAddress_15, "!B", rw=RW_FLAG_key)
RCPTLV(2, "IpAddress", C100_IpAddress_15, "IPAddr", rw=RW_FLAG_key)
RCPTLV(3, "EnetPortIndex", C100_IpAddress_15, "!B", rw=RW_FLAG_r)
RCPTLV(4, "Type", C100_IpAddress_15, "!B", constraint=EnumConstraint(IPADDR_TYPE_DICT), rw=RW_FLAG_r)
RCPTLV(5, "PrefixLen", C100_IpAddress_15, "!H", rw=RW_FLAG_r)
RCPTLV(6, "Origin", C100_IpAddress_15, "!B", constraint=EnumConstraint(IPADDR_ORIGIN_DICT), rw=RW_FLAG_r)
RCPTLV(7, "Status", C100_IpAddress_15, "!B", constraint=EnumConstraint(IPADDR_STATUS_DICT), rw=RW_FLAG_r)
RCPTLV(8, "Created", C100_IpAddress_15, "!I", rw=RW_FLAG_r)
RCPTLV(9, "LastChanged", C100_IpAddress_15, "!I", rw=RW_FLAG_r)

# 100.16 - IpNetToPhysical
NeighType = {
    1: "other",
    2: "invalid",
    3: "dynamic",
    4: "static",
    5: "local"
}

NeighState = {
    1: "reachable",
    2: "stale",
    3: "delay",
    4: "probe",
    5: "nonvalid",
    6: "unknown",
    7: "incomplete"
}

C100_IpNetToPhysical_16 = \
    RCPTLV(16, "IpNetToPhysical", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "EnetPortIndex", C100_IpNetToPhysical_16, "!B", rw=RW_FLAG_key)
RCPTLV(2, "AddrType", C100_IpNetToPhysical_16, "!I", rw=RW_FLAG_key)
RCPTLV(3, "IpAddress", C100_IpNetToPhysical_16, "IPAddr", rw=RW_FLAG_key)
RCPTLV(4, "PhysAddress", C100_IpNetToPhysical_16, "MAC", rw=RW_FLAG_r)
RCPTLV(5, "LastUpdated", C100_IpNetToPhysical_16, "!I", rw=RW_FLAG_r)
RCPTLV(6, "Type", C100_IpNetToPhysical_16, "!B", rw=RW_FLAG_r, constraint=EnumConstraint(NeighType))
RCPTLV(7, "State", C100_IpNetToPhysical_16, "!B", rw=RW_FLAG_r, constraint=EnumConstraint(NeighState))

# 100.17 - IpDefaultRouter
PreferenceType = {
    -2: "reserved",
    -1: "low",
    0: "medium",
    1: "high"
}

C100_IpDefaultRouter_17 = \
    RCPTLV(17, "IpDefaultRouter", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "AddrType", C100_IpDefaultRouter_17, "!H", rw=RW_FLAG_r)
RCPTLV(2, "IpAddress", C100_IpDefaultRouter_17, "IPAddr", rw=RW_FLAG_r)
RCPTLV(3, "EnetPortIndex", C100_IpDefaultRouter_17, "!B", rw=RW_FLAG_r)
RCPTLV(4, "Lifetime", C100_IpDefaultRouter_17, "!H", rw=RW_FLAG_r)
RCPTLV(5, "Preference", C100_IpDefaultRouter_17, "!b", constraint=EnumConstraint(PreferenceType))

C100_CrashDataFileStatus_20 = \
    RCPTLV(20, "CrashDataFileStatus", C_RpdInfo_100, rw=RW_FLAG_row)
RCPTLV(1, "Index", C100_CrashDataFileStatus_20, "!B", rw=RW_FLAG_key)
RCPTLV(2, "FileName", C100_CrashDataFileStatus_20, "var", rw=RW_FLAG_r)
RCPTLV(3, "FileStatus", C100_CrashDataFileStatus_20, "!B")

C100_RpdPtpInfo_24 = \
    RCPTLV(24, "RpdPtpInfo", C_RpdInfo_100, rw=RW_FLAG_row)

C100_24_RpdPtpCurrentDataset_1 = \
    RCPTLV(1, "RpdPtpCurrentDataset", C100_RpdPtpInfo_24, rw=RW_FLAG_row)
RCPTLV(1, "RpdPtpCurrentDatasetStepsRemoved", C100_24_RpdPtpCurrentDataset_1, "!I", rw=RW_FLAG_r)
RCPTLV(2, "RpdPtpCurrentDatasetOffsetFromMaster", C100_24_RpdPtpCurrentDataset_1, "!q", rw=RW_FLAG_r)
RCPTLV(3, "RpdPtpCurrentDatasetMeanPathDelay", C100_24_RpdPtpCurrentDataset_1, "!I", rw=RW_FLAG_r)

C100_24_PtpClockStatus_2 = \
    RCPTLV(2, "PtpClockStatus", C100_RpdPtpInfo_24, rw=RW_FLAG_row)
RCPTLV(1, "PtpClockClockState", C100_24_PtpClockStatus_2, "!B", rw=RW_FLAG_r)
RCPTLV(2, "PtpClockLastStateChange", C100_24_PtpClockStatus_2, "!Q", rw=RW_FLAG_r)
RCPTLV(3, "PtpClockPacketsSent", C100_24_PtpClockStatus_2, "!Q", rw=RW_FLAG_r)
RCPTLV(4, "PtpClockPacketsReceived", C100_24_PtpClockStatus_2, "!Q", rw=RW_FLAG_r)
RCPTLV(5, "PtpClockComputedPhaseOffset", C100_24_PtpClockStatus_2, "!Q", rw=RW_FLAG_r)
RCPTLV(6, "PtpClockCounterDiscontinuityTime", C100_24_PtpClockStatus_2, "!Q", rw=RW_FLAG_r)

C100_24_PtpPortDataset_3 = \
    RCPTLV(3, "PtpPortDataset", C100_RpdPtpInfo_24, rw=RW_FLAG_row)
RCPTLV(1, "PtpPortDatasetPortNumber", C100_24_PtpPortDataset_3, "!H", rw=RW_FLAG_key)
RCPTLV(2, "PtpPortDatasetPortState", C100_24_PtpPortDataset_3, "!B", rw=RW_FLAG_r)
RCPTLV(3, "PtpPortDatasetMeanPathDelay", C100_24_PtpPortDataset_3, "!i", rw=RW_FLAG_r)

C100_24_PtpPortStatus_4 = \
    RCPTLV(4, "PtpPortStatus", C100_RpdPtpInfo_24, rw=RW_FLAG_row)
RCPTLV(1, "PtpPortRpdEnetPortIndex", C100_24_PtpPortStatus_4, "!B", rw=RW_FLAG_key)
RCPTLV(2, "PtpPortPortNumber", C100_24_PtpPortStatus_4, "!B", rw=RW_FLAG_key)
RCPTLV(3, "PtpPortPacketsSent", C100_24_PtpPortStatus_4, "!Q", rw=RW_FLAG_r)
RCPTLV(4, "PtpPortPacketsReceived", C100_24_PtpPortStatus_4, "!Q", rw=RW_FLAG_r)
RCPTLV(5, "PtpPortCounterDiscontinuityTime", C100_24_PtpPortStatus_4, "!Q", rw=RW_FLAG_r)

C100_24_4_PtpPortStatus_6 = \
    RCPTLV(6, "PtpPortMasterClockStatus", C100_24_PtpPortStatus_4, rw=RW_FLAG_row)
RCPTLV(1, "PtpPortMasterClockMasterPriority", C100_24_4_PtpPortStatus_6, "!B", rw=RW_FLAG_key)
RCPTLV(2, "PtpPortMasterClockPacketsSent", C100_24_4_PtpPortStatus_6, "!Q", rw=RW_FLAG_r)
RCPTLV(3, "PtpPortMasterClockPacketsReceived", C100_24_4_PtpPortStatus_6, "!Q", rw=RW_FLAG_r)
RCPTLV(4, "PtpPortMasterClockMasterClockId", C100_24_4_PtpPortStatus_6, "bytes", rw=RW_FLAG_r,
       constraint=StringLenConstraint(8))
RCPTLV(5, "PtpPortMasterClockMasterClockPortNumber", C100_24_4_PtpPortStatus_6, "!H", rw=RW_FLAG_r)
RCPTLV(6, "PtpPortMasterClockTwoStepFlag", C100_24_4_PtpPortStatus_6, "!B", rw=RW_FLAG_r)
RCPTLV(7, "PtpPortMasterClockIsBmc", C100_24_4_PtpPortStatus_6, "!B", rw=RW_FLAG_r)
RCPTLV(8, "PtpPortMasterClockIsMasterConnected", C100_24_4_PtpPortStatus_6, "!B", rw=RW_FLAG_r)
RCPTLV(9, "PtpPortMasterClockStatusDomain", C100_24_4_PtpPortStatus_6, "!I", rw=RW_FLAG_r)
RCPTLV(10, "PtpPortMasterClockFreqOffset", C100_24_4_PtpPortStatus_6, "!I", rw=RW_FLAG_r)
RCPTLV(11, "PtpPortMasterClockCounterDiscontinuityTime", C100_24_4_PtpPortStatus_6, "!Q", rw=RW_FLAG_r)

# DOCS-IF31
C_DocsIf31_101 = \
    RCPTLV(101, "docsIf31", rw=RW_FLAG_row)
RCPTLV(1, "docsIf31CmtsCmDsOfdmProfileTotalCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
# TODO: length missing in spec
RCPTLV(2, "docsIf31CmtsCmUsOfdmaChannelMeanRxMer",
       C_DocsIf31_101, "!I", rw=RW_FLAG_r)
RCPTLV(3, "docsIf31CmtsCmUsOfdmaChannelMicroreflections",
       C_DocsIf31_101, "!I", rw=RW_FLAG_r)
RCPTLV(4, "docsIf31CmtsCmUsOfdmaChannelRxMerThreshold",
       C_DocsIf31_101, "!I", rw=RW_FLAG_r)
RCPTLV(5, "docsIf31CmtsCmUsOfdmaChannelRxPower",
       C_DocsIf31_101, "!H", rw=RW_FLAG_r)
RCPTLV(6, "docsIf31CmtsCmUsOfdmaProfileCorrectedCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
RCPTLV(7, "docsIf31CmtsCmUsOfdmaProfileTotalCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
RCPTLV(8, "docsIf31CmtsCmUsOfdmaProfileUnreliableCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
RCPTLV(9, "docsIf31CmtsUsOfdmaChanTargetRxPower",
       C_DocsIf31_101, "!H", rw=RW_FLAG_r)
RCPTLV(10, "docsIf31CmtsUsOfdmaDataIucStatsCorrectedCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
RCPTLV(11, "docsIf31CmtsUsOfdmaDataIucStatsInFrameCrcFailures",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
RCPTLV(12, "docsIf31CmtsUsOfdmaDataIucStatsMinislotModulation",
       C_DocsIf31_101, "!B", rw=RW_FLAG_r)
RCPTLV(13, "docsIf31CmtsUsOfdmaDataIucStatsMinislotPilotPattern",
       C_DocsIf31_101, "!I", rw=RW_FLAG_r)
RCPTLV(14, "docsIf31CmtsUsOfdmaDataIucStatsTotalCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)
RCPTLV(15, "docsIf31CmtsUsOfdmaDataIucStatsUnreliableCodewords",
       C_DocsIf31_101, "!Q", rw=RW_FLAG_r)

# DOCS-IF3
C_DocsIf3_102 = \
    RCPTLV(102, "docsIf3", rw=RW_FLAG_row)
RCPTLV(1, "docsIf3CmtsCmUsStatusHighResolutionTimingOffset",
       C_DocsIf3_102, "!i", rw=RW_FLAG_r)
RCPTLV(2, "docsIf3CmtsCmUsStatusMicroreflections",
       C_DocsIf3_102, "!I", rw=RW_FLAG_r)
RCPTLV(3, "docsIf3CmtsCmUsStatusModulationType",
       C_DocsIf3_102, "!B", rw=RW_FLAG_r)
RCPTLV(4, "docsIf3CmtsCmUsStatusRxPower",
       C_DocsIf3_102, "!H", rw=RW_FLAG_r)
RCPTLV(5, "docsIf3CmtsCmUsStatusSignalNoise",
       C_DocsIf3_102, "!H", rw=RW_FLAG_r)
RCPTLV(6, "docsIf3CmtsCmUsStatusCorrectables",
       C_DocsIf3_102, "!I", rw=RW_FLAG_r)
RCPTLV(7, "docsIf3CmtsCmUsStatusUncorrectables",
       C_DocsIf3_102, "!I", rw=RW_FLAG_r)
RCPTLV(8, "docsIf3CmtsCmUsStatusUnerroreds",
       C_DocsIf3_102, "!I", rw=RW_FLAG_r)
RCPTLV(9, "docsIf3CmtsSignalQualityExtCNIR",
       C_DocsIf3_102, "!H", rw=RW_FLAG_r)
RCPTLV(10, "docsIf3CmtsSpectrumAnalysisMeasAmplitudeData",
       C_DocsIf3_102, "var", rw=RW_FLAG_r)
RCPTLV(11, "docsIf3CmtsSpectrumAnalysisMeasTimeInterval",
       C_DocsIf3_102, "!I", rw=RW_FLAG_r)
RCPTLV(12, "docsIf3SignalQualityExtRxMER",
       C_DocsIf3_102, "!H", rw=RW_FLAG_r)

# DOCS-IF
C_DocsIf_103 = \
    RCPTLV(103, "docsIf", rw=RW_FLAG_row)
RCPTLV(1, "docsIfSigQExtCorrecteds", C_DocsIf_103, "!Q", rw=RW_FLAG_r)
RCPTLV(2, "docsIfSigQExtUncorrectables", C_DocsIf_103, "!Q", rw=RW_FLAG_r)
RCPTLV(3, "docsIfSigQExtUnerroreds", C_DocsIf_103, "!Q", rw=RW_FLAG_r)
RCPTLV(4, "docsIfSigQMicroreflections", C_DocsIf_103, "!I", rw=RW_FLAG_r)
RCPTLV(5, "docsIfSigQUncorrectables", C_DocsIf_103, "!Q", rw=RW_FLAG_r)
RCPTLV(6, "docsIfSigQUnerroreds", C_DocsIf_103, "!Q", rw=RW_FLAG_r)
RCPTLV(7, "docsIfSigQSignalNoise", C_DocsIf_103, "!H", rw=RW_FLAG_r)

# HOST-RESOURCES
C_HostResources_104 = \
    RCPTLV(104, "HostResources", rw=RW_FLAG_row)
RCPTLV(1, "hrMemorySize", C_HostResources_104, "!I", rw=RW_FLAG_r)
RCPTLV(2, "hrProcessorLoad", C_HostResources_104, "!I", rw=RW_FLAG_r)

C104_Storages_3 = \
    RCPTLV(3, "hrStorages", C_HostResources_104, rw=RW_FLAG_row_key)
RCPTLV(1, "hrStorageIndex", C104_Storages_3, "!I", rw=RW_FLAG_r)
RCPTLV(2, "hrStorageSize", C104_Storages_3, "!I", rw=RW_FLAG_r)
RCPTLV(3, "hrStorageType", C104_Storages_3, "!I", rw=RW_FLAG_r)
RCPTLV(4, "hrStorageUsed", C104_Storages_3, "!I", rw=RW_FLAG_r)
RCPTLV(5, "hrStorageAllocationFailures", C104_Storages_3, "!I", rw=RW_FLAG_r)
RCPTLV(6, "hrStorageAllocationUnits", C104_Storages_3, "!I", rw=RW_FLAG_r)

C104_Processes_4 = \
    RCPTLV(4, "hrProcesses", C_HostResources_104, rw=RW_FLAG_row_key)
RCPTLV(1, "hrSWRunIndex", C104_Processes_4, "!I", rw=RW_FLAG_r)
RCPTLV(2, "hrSWRunPerfCPU", C104_Processes_4, "!I", rw=RW_FLAG_r)
RCPTLV(3, "hrSWRunPerfMem", C104_Processes_4, "!I", rw=RW_FLAG_r)
RCPTLV(4, "hrSWRunStatus", C104_Processes_4, "!i", rw=RW_FLAG_r)
RCPTLV(5, "hrSWRunType", C104_Processes_4, "!i", rw=RW_FLAG_r)

# HA definition
C_RedundantCoreIpAddress_200 = \
    RCPTLV(200, "RedundantCoreIpAddress", rw=RW_FLAG_row)
RCPTLV(1, "ActiveCoreIpAddress", C_RedundantCoreIpAddress_200, "IPAddr", rw=RW_FLAG_key)
RCPTLV(2, "StandbyCoreIpAddress", C_RedundantCoreIpAddress_200, "IPAddr", rw=RW_FLAG_key)
RCPTLV(3, "Operation", C_RedundantCoreIpAddress_200, "!B",
       constraint=EnumConstraint(RCP_TLV_OPERATION_DICT))


# ActivePrincipalCore
C_ActivePrincipalCore_201 = \
    RCPTLV(201, "ActivePrincipalCore", format_str="IPAddr", rw=RW_FLAG_r)

# ActiveAuxCoreTable
C_ActiveAuxCoreTable_202 = \
    RCPTLV(202, "ActiveAuxCoreTable", rw=RW_FLAG_row)
RCPTLV(1, "ActiveAuxCoreIp", C_ActiveAuxCoreTable_202, "IPAddr", rw=RW_FLAG_key)
RCPTLV(2, "Operation", C_ActiveAuxCoreTable_202, "!B",
       constraint=EnumConstraint(RCP_TLV_OPERATION_DICT))

# Configured Core Table
C_ConfiguredCoreTable_203 = \
    RCPTLV(203, "ConfiguredCoreTable", rw=RW_FLAG_row)
RCPTLV(1, "ConfiguredCoreIp", C_ConfiguredCoreTable_203, "IPAddr", rw=RW_FLAG_key)
RCPTLV(2, "Operation", C_ConfiguredCoreTable_203, "!B",
       constraint=EnumConstraint(RCP_TLV_OPERATION_DICT))

# Cisco OIB Info related TLVs
C_CiscoOIB_233 = \
    RCPTLV(233, "CiscoOIB", rw=RW_FLAG_row)

RCPTLV(1, "CiscoOIBPS1p24v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(2, "CiscoOIBPS2p24v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(3, "CiscoOIBPS1p8v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(4, "CiscoOIBPS2p8v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(5, "CiscoOIBPS1p5v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(6, "CiscoOIBPS2p5v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(7, "CiscoOIBPS1n6v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(8, "CiscoOIBPS2n6v", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(9, "CiscoOIBPSAC1", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(10, "CiscoOIBPSAC2", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(11, "CiscoOIBTx1OptPower", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(12, "CiscoOIBTx2OptPower", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(13, "CiscoOIBRx1OptPower", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(14, "CiscoOIBTriSwitch", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)
RCPTLV(15, "CiscoOIBTamp", C_CiscoOIB_233, "!I", rw=RW_FLAG_r)

#
# UCD Related TLVs
#
UCD_TLV_SET = gcp_tlv_def.TLVDescriptionSet("UCD_TLVs")


class UCDTLV(gcp_tlv_def.TLVDesc):

    """Implements description of the UCD TLV data format."""

    def __init__(self, identifier, name, parent=(UCD_TLV_SET,),
                 format_str=None, length=None, constraint=None, rw=RW_FLAG_rw):
        super(UCDTLV, self).__init__(identifier, name, parent, format_str,
                                     length, constraint, length_field_len=1, rw=rw)


UCDTLV(1, "ModulationRate", UCD_TLV_SET, "!B")
UCDTLV(2, "Frequency", UCD_TLV_SET, "!I")
UCDTLV(3, "PreamblePattern", UCD_TLV_SET, "bytes")
UCDTLV(4, "BurstDescDocsis1x", UCD_TLV_SET, "bytes", rw=RW_FLAG_repeatedFields)
UCDTLV(5, "BurstDescDocsis2x3x", UCD_TLV_SET,
       "bytes", rw=RW_FLAG_repeatedFields)
UCDTLV(6, "ExtendPreamblePattern", UCD_TLV_SET, "bytes")
UCDTLV(7, "SCDMAModeEnable", UCD_TLV_SET, "!B")
UCDTLV(8, "SCDMASpreadingIntervalsPerFrame", UCD_TLV_SET, "!B")
UCDTLV(9, "SCDMACodesPerMiniSlot", UCD_TLV_SET, "!B")
UCDTLV(10, "SCDMANumberofActiveCodes", UCD_TLV_SET, "!B")
UCDTLV(11, "SCDMACodeHoppingSeed", UCD_TLV_SET, "!H")
UCDTLV(12, "SCDMAUSRatioNumeratorM", UCD_TLV_SET, "!H")
UCDTLV(13, "SCDMAUSRatioDenominatorN", UCD_TLV_SET, "!H")
UCDTLV(14, "SCDMATimestampSnapshot", UCD_TLV_SET, "bytes")
UCDTLV(15, "MaintainPowerSpectralDensity", UCD_TLV_SET, "!B")
UCDTLV(16, "RangingRequired", UCD_TLV_SET, "!B")
UCDTLV(17, "SCDMAMaximumScheduledCodesEnabled", UCD_TLV_SET, "!B")
UCDTLV(18, "RangingHoldOffPriorityField", UCD_TLV_SET, "!I")
UCDTLV(19, "ChannelClassID", UCD_TLV_SET, "!B")
UCDTLV(20, "SCDMASelectionModeForActiveCodesAndCodeHopping", UCD_TLV_SET, "!B")
UCDTLV(21, "SCDMASelectionStringForActiveCodes", UCD_TLV_SET, "bytes")
UCDTLV(22, "HigherUCDForTheSameUCIDPresentBitmap", UCD_TLV_SET, "!B")
UCDTLV(23, "BurstDescDocsis3d1", UCD_TLV_SET, "bytes", rw=RW_FLAG_repeatedFields)
UCDTLV(24, "UcdChangeIndicatorBitmask", UCD_TLV_SET, "!H")
UCDTLV(25, "OFDMATimestampSnapshot", UCD_TLV_SET, "bytes")
UCDTLV(26, "OFDMACyclicPrefixSize", UCD_TLV_SET, "!B")
UCDTLV(27, "OFDMARolloffPeriodSize", UCD_TLV_SET, "!B")
UCDTLV(28, "SubcarrierSpacing", UCD_TLV_SET, "!B")
UCDTLV(29, "CenterFrequencyOfSubcarrier0", UCD_TLV_SET, "!I")
UCDTLV(30, "SubcarrierExclusionBand", UCD_TLV_SET, "bytes", rw=RW_FLAG_repeatedFields)
UCDTLV(31, "UnusedSubcarrierSpecification", UCD_TLV_SET, "bytes", rw=RW_FLAG_repeatedFields)
UCDTLV(32, "SymbolsInOFDMFrame", UCD_TLV_SET, "!B")
UCDTLV(33, "RandomizationSeed", UCD_TLV_SET, "bytes")


# For the burst Profile
UCD_BURST_PROFILE_TLV_SET = gcp_tlv_def.TLVDescriptionSet(
    "UCD_BURST_PROFILE_TLVs")


class UCDUburstProfileTLV(gcp_tlv_def.TLVDesc):

    """Implements description of the UCD BurstProfile TLV data format."""

    def __init__(self, identifier, name, parent=(UCD_BURST_PROFILE_TLV_SET,),
                 format_str=None, length=None, constraint=None, rw=RW_FLAG_rw):
        super(
            UCDUburstProfileTLV, self).__init__(identifier, name, parent, format_str,
                                                length, constraint, length_field_len=1, rw=rw)


UCDUburstProfileTLV(1, "ModulationType", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(2, "DifferentialEncoding", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(3, "PreambleLength", UCD_BURST_PROFILE_TLV_SET, "!H")
UCDUburstProfileTLV(4, "PreambleValueOffset", UCD_BURST_PROFILE_TLV_SET, "!H")
UCDUburstProfileTLV(5, "FECErrorCorrection", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(
    6, "FECCodewordInformationBytes", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(7, "ScramblerSeed", UCD_BURST_PROFILE_TLV_SET, "!H")
UCDUburstProfileTLV(8, "MaximumBurstSize", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(9, "GuardTimeSize", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(10, "LastCodewordLength", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(11, "ScramblerOnOff", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(12, "RSInterleaverDepth", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(
    13, "RSInterleaverBlockSize", UCD_BURST_PROFILE_TLV_SET, "!H")
UCDUburstProfileTLV(14, "PreambleType", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(15, "SCDMASpreaderOnOff", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(
    16, "SCDMACodesPerSubframe", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(
    17, "SCDMAFramerInterleavingStepSize", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(18, "TCMEncoding", UCD_BURST_PROFILE_TLV_SET, "!B")
UCDUburstProfileTLV(19, "SubcarrierInitialRanging", UCD_BURST_PROFILE_TLV_SET, "!H")
UCDUburstProfileTLV(20, "SubcarrierFineRanging", UCD_BURST_PROFILE_TLV_SET, "!H")
UCDUburstProfileTLV(21, "OFDMAProfile", UCD_BURST_PROFILE_TLV_SET, "bytes")
UCDUburstProfileTLV(22, "OFDMAIRPowerControl", UCD_BURST_PROFILE_TLV_SET, "!H")


# Maps TLV sets for sequences per RCP message
_IRA_SEQ_TLV_SET = gcp_tlv_def.TLVDescriptionSet(hierarchy_name="IRA_SEQ_TLVs", id=RCP_MSG_TYPE_IRA)
_IRA_SEQ_TLV_SET.update_descriptions(C_RCPSequence_09)
_IRA_SEQ_TLV_SET.update_descriptions(RCP_CFG_IRA_TLV_SET)

_REX_SEQ_TLV_SET = gcp_tlv_def.TLVDescriptionSet(hierarchy_name="REX_SEQ_TLVs", id=RCP_MSG_TYPE_REX)
_REX_SEQ_TLV_SET.update_descriptions(C_RCPSequence_09)
_REX_SEQ_TLV_SET.update_descriptions(RCP_CFG_REX_TLV_SET)

_NTF_SEQ_TLV_SET = gcp_tlv_def.TLVDescriptionSet(hierarchy_name="NTF_SEQ_TLVs", id=RCP_MSG_TYPE_NTF)
_NTF_SEQ_TLV_SET.update_descriptions(C_RCPSequence_09)
_NTF_SEQ_TLV_SET.update_descriptions(RCP_CFG_NTF_TLV_SET)

RCP_SEQ_RCP_MSG_TLV_SET_MAPPING = {
    RCP_MSG_TYPE_IRA: _IRA_SEQ_TLV_SET,
    RCP_MSG_TYPE_REX: _REX_SEQ_TLV_SET,
    RCP_MSG_TYPE_NTF: _NTF_SEQ_TLV_SET
}

#
# OCD Related TLVs
#
OCD_TLV_SET = gcp_tlv_def.TLVDescriptionSet("OCD_TLVs")


class OCDTLV(gcp_tlv_def.TLVDesc):

    """Implements description of the UCD TLV data format."""

    def __init__(self, identifier, name, parent=(OCD_TLV_SET,),
                 format_str=None, length=None, constraint=None, rw=RW_FLAG_rw):
        super(OCDTLV, self).__init__(identifier, name, parent, format_str,
                                     length, constraint, length_field_len=1, rw=rw)


OCDTLV(0, "DiscreteFourierTransformsize", OCD_TLV_SET, "!B")
OCDTLV(1, "CyclicPrefix", OCD_TLV_SET, "!B")
OCDTLV(2, "RollOff", OCD_TLV_SET, "!B")
OCDTLV(3, "OFDMSpectrumLocation", OCD_TLV_SET, "!I")
OCDTLV(4, "TimeInterleavingDepth", OCD_TLV_SET, "!B")
OCDTLV(5, "SubcarrierAssignment", OCD_TLV_SET, "bytes",
       rw=RW_FLAG_repeatedFields)
OCDTLV(6, "PrimaryCapabilityIndicator", OCD_TLV_SET, "!B")


#
# dpd Related TLVs
# DATA_SYMBOL_MODULATION__4_QAM8
DPD_TLV_SET = gcp_tlv_def.TLVDescriptionSet("DPD_TLVs")


class DPDTLV(gcp_tlv_def.TLVDesc):

    """Implements description of the DPD TLV data format."""

    def __init__(self, identifier, name, parent=(DPD_TLV_SET,),
                 format_str=None, length=None, constraint=None, rw=RW_FLAG_rw):
        super(DPDTLV, self).__init__(identifier, name, parent, format_str,
                                     length, constraint, length_field_len=1, rw=rw)


DPDTLV(5, "SubcarrierAssignment", DPD_TLV_SET, "bytes",
       rw=RW_FLAG_repeatedFields)
DPDTLV(6, "SubcarrierAssignmentVector", DPD_TLV_SET, "bytes",
       rw=RW_FLAG_repeatedFields)


#
# add general config RfChannelSelector and RfPortSelector for US and DS cfg
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
