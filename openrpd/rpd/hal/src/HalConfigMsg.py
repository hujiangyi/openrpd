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
# System configure message type
MsgTypeRpdCapabilities = 0
MsgTypeCcapCoreIdentification = 1
MsgTypeSsd = 2
MsgTypeRpdInfo = 3
MsgTypeRpdSysUpTime = 4
MsgTypeRedundantCoreIpAddress = 5
MsgTypeHostResources = 6

# DS PHY configure message type
MsgTypeDsRfPort = 1024
MsgTypeDsScQamChannelConfig = 1025
MsgTypeDsOfdmChannelConfig = 1026
MsgTypeDsOfdmProfile = 1027
MsgTypeDsRfPortPerf = 1028
MsgTypeDsScQamChannelPerf = 1029
MsgTypeDsOfdmChannelPerf = 1030
MsgTypeDsOob551IPerf = 1031
MsgTypeDsOob552Perf = 1032
MsgTypeNdfPerf = 1033
MsgTypeDsOob55D1ChannelConfig = 1034
MsgTypeOob55D2Config = 1035

# US PHY configure message type
MsgTypeUsRfPortPerf = 2048
MsgTypeUsScQamChannelConfig = 2049
MsgTypeUsOfdmaChannelConfig = 2050
MsgTypeUsOfdmaInitialRangingIuc = 2051
MsgTypeUsOfdmaFineRangingIuc = 2052
MsgTypeUsOfdmaDataRangingIuc = 2053
MsgTypeUsOfdmaSubcarrierCfgState = 2054
MsgTypeUsScQamChannelPerf = 2055
MsgTypeUsOfdmaChannelPerf = 2056
MsgTypeUsOob551IPerf = 2057
MsgTypeUsOob552Perf = 2058
MsgTypeNdrPerf = 2059
MsgTypeSidQos = 2060
MsgTypeIucCounter = 2061
MsgTypeFftCfg = 2070
MsgTypeUsOob55D1ChannelConfig = 2080

MsgTypeDocsisMsg = 2100
MsgTypeDocsisMsgUCD = 2101
MsgTypeDocsisMsgOCD = 2102
MsgTypeDocsisMsgDPD = 2103

# RCP Vendor Specific (21.1, 21.2, etc.)
MsgTypeRcpVendorSpecific = 2200

# L2TP message type
"""
The message content structure could be found at L2tpV3Hal.proto
"""
MsgTypeL2tpv3SessionReqNone = 3072
# HalNotification + t_l2tpSessionCircuitStatus
MsgTypeL2tpv3SessionStatusNotification = 3073
# HalConfig + t_l2tpCapabilityQuery
# expect a HalConfigRsp or another TBD HalNotification
MsgTypeL2tpv3CapabilityQuery = 3074


"""
1. DS-OFDM
2. DS-OFDM-PLC
3. DS-SCQAM
4. US-ATDMA
5. US-OFDMA
6. SCTE-55-1-FWD
7. SCTE-55-1-RET
8. SCTE-55-2-FWD
9. SCTE-55-2-RET
10. NDF
11. NDR
"""
# HalConfig + t_l2tpSessionReq
MsgTypeL2tpv3SessionReqDsOfdm = 3075
MsgTypeL2tpv3SessionReqDsOfdmPlc = 3076
MsgTypeL2tpv3SessionReqDsScqam = 3077
MsgTypeL2tpv3SessionReqUsAtdma = 3078
MsgTypeL2tpv3SessionReqUsOfdma = 3079
MsgTypeL2tpv3SessionReqScte551Fwd = 3080
MsgTypeL2tpv3SessionReqScte551Ret = 3081
MsgTypeL2tpv3SessionReqScte552Fwd = 3082
MsgTypeL2tpv3SessionReqScte552Ret = 3083
MsgTypeL2tpv3SessionReqNdf = 3084
MsgTypeL2tpv3SessionReqNdr = 3085
MsgTypeL2tpv3CinIfAssignment = 3086
MsgTypeL2tpv3LcceIdAssignment = 3087

# end L2TP message type

# HalConfig t_Ipv4Interfaces
MsgTypeIpv4Interface = 4012

# VendorSpecificExtension
MsgTypeRpdGroupInfo = 5011
MsgTypeRequestRpdOutput = 5012

# end HalConfig t_Ipv4Interfaces

# HalConfig t_l2tpVspAvpMsg
MsgTypeVspAvpExchange = 5000
MsgTypeGcppToL2tp = 5001
# end HalConfig t_l2tpVspAvpMsg

# GeneralNotification
MsgTypeGeneralNtf = 8190
# Ptp related message type
MsgTypePtpClockStatus = 8192
MsgTypeRoutePtpStatus = 8193
MsgTypePtpStatusGet = 8194
MsgTypeRdtiConfig = 8195
MsgTypeUsPhySubSync = 8196
MsgTypeUsPhySubSyncDone = 8197
MsgTypeRpdIpv6Info = 8198
MsgTypeStaticPwStatus = 8199
MsgTypeRpdState = 8200

# Fault management message type
MsgTypeFaultManagement = 8600
MsgTypeRpdGlobal = 8601
MsgTypetEventNotification = 8602

MsgTypeCiscoOIB = 8700

MsgTypeInvalid = 0xffff

RCP_TO_HAL_MSG_TYPE = {
    'RpdCapabilities': MsgTypeRpdCapabilities,
    'CcapCoreIdentification': MsgTypeCcapCoreIdentification,
    'Ssd': MsgTypeSsd,
    'RpdInfo': MsgTypeRpdInfo,
    'HostResources': MsgTypeHostResources,
    'RedundantCoreIpAddress': MsgTypeRedundantCoreIpAddress,

    'DsRfPort': MsgTypeDsRfPort,
    'DsScQamChannelConfig': MsgTypeDsScQamChannelConfig,
    'DsOfdmChannelConfig': MsgTypeDsOfdmChannelConfig,
    'DsOfdmProfile': MsgTypeDsOfdmProfile,
    'DsRfPortPerf': MsgTypeDsRfPortPerf,
    'DsScQamChannelPerf': MsgTypeDsScQamChannelPerf,
    'DsOfdmChannelPerf': MsgTypeDsOfdmChannelPerf,
    'DsOob551IPerf': MsgTypeDsOob551IPerf,
    'DsOob552Perf': MsgTypeDsOob552Perf,
    'NdfPerf': MsgTypeNdfPerf,

    'UsRfPortPerf': MsgTypeUsRfPortPerf,
    'UsScQamChannelConfig': MsgTypeUsScQamChannelConfig,
    'UsOfdmaChannelConfig': MsgTypeUsOfdmaChannelConfig,
    'UsOfdmaInitialRangingIuc': MsgTypeUsOfdmaInitialRangingIuc,
    'UsOfdmaFineRangingIuc': MsgTypeUsOfdmaFineRangingIuc,
    'UsOfdmaDataRangingIuc': MsgTypeUsOfdmaDataRangingIuc,
    'UsOfdmaSubcarrierCfgState': MsgTypeUsOfdmaSubcarrierCfgState,
    'UsScQamChannelPerf': MsgTypeUsScQamChannelPerf,
    'UsOfdmaChannelPerf': MsgTypeUsOfdmaChannelPerf,
    'UsOob551IPerf': MsgTypeUsOob551IPerf,
    'UsOob552Perf': MsgTypeUsOob552Perf,
    'NdrPerf': MsgTypeNdrPerf,
    'SidQos': MsgTypeSidQos,
    'FftCfg': MsgTypeFftCfg,
    'RdtiConfig': MsgTypeRdtiConfig,
    'RpdState': MsgTypeRpdState,
    'IucCounter': MsgTypeIucCounter,
    'DsOob55d1': MsgTypeDsOob55D1ChannelConfig,
    'UsOob55d1': MsgTypeUsOob55D1ChannelConfig,
    'Oob55d2Config': MsgTypeOob55D2Config,

    'Ipv4Interface': MsgTypeIpv4Interface,
    "RpdGlobal": MsgTypeRpdGlobal,
    "EventNotification": MsgTypetEventNotification,
    "CiscoOIB": MsgTypeCiscoOIB,

    "RpdGroupInfo": MsgTypeRpdGroupInfo,
    "RequestRpdOutput": MsgTypeRequestRpdOutput,
    "StaticPwConfig": MsgTypeGcppToL2tp,
}

####ssd api####
MsgTypeSsdApi = 20000

API_TO_HAL_MSG_TYPE = {
    'ssdController': MsgTypeSsdApi,
}
