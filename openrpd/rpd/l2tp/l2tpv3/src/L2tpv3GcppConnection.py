#
# Copyright (c) 2017 Cisco and/or its affiliates,
# Cable Television Laboratories, Inc. ("CableLabs")
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

import time
import socket
import ipaddress
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.utils import SysTools, Convert
import l2tpv3.src.L2tpv3GlobalSettings as globalSettings

from rpd.confdb.rpd_redis_db import RPDAllocateWriteRecord


class StaticPseudoChannel(object):

    def __init__(self):
        self.rfPortIndex = 0
        self.channelType = 0
        self.channelIndex = 0


class StaticL2tpSession(RPDAllocateWriteRecord):
    # DepiPwSubtype
    # DepiL2SublayerSubtype
    DEPI_SUBTYPE_MPT_PW = 1
    DEPI_SUBTYPE_MPT_55_1_RET_PW = 18
    DEPI_SUBTYPE_PSP_NDF_PW = 21
    DEPI_SUBTYPE_PSP_NDR_PW = 22
    #
    # L2SublayerType
    L2_SUBTYPE_LAYER_MPT = 2
    L2_SUBTYPE_LAYER_PSP = 4
    #
    # Direction
    DIRECTION_FORWARD = 0
    DIRECTION_RETURN = 1
    #
    # ChannelType
    RF_CHANNEL_TYPE_DS_SCQAM = 3
    RF_CHANNEL_TYPE_SCTE_55_1_FWD = 6
    RF_CHANNEL_TYPE_SCTE_55_1_RET = 7
    RF_CHANNEL_TYPE_NDF = 10
    RF_CHANNEL_TYPE_NDR = 11
    #
    # EnableStatusNotification
    ENABLE_RPD_CIRCUIT_STATUS = 0
    DISABLE_RPD_CIRCUIT_STATUS = 1

    CIRCUIT_STATUS_UP = 1
    CIRCUIT_STATUS_DOWN = 0
    CIRCUIT_STATUS_UNKNOWN = -1
    #
    # Index
    MAX_STATIC_PWS = 0xFFFF

    DEFAULT_IP_ADDR = "127.0.0.1"
    DEFAULT_MAC_ADDR = "00:00:00:00:00:00"

    def __init__(self, index):
        super(StaticL2tpSession, self).__init__(
            StaticL2tpSession.MAX_STATIC_PWS)
        self.index = index
        self.fwdFlag = False
        self.groupAddress = ""
        self.mtuSize = 0
        self.usPhbId = 0
        self.direction = -1
        self.ccapCoreOwner = None
        self.pwType = 0
        self.depiPwSubtype = 0
        self.l2SublayerType = 0
        self.depiL2SublayerSubtype = 0
        self.sessionId = 0
        self.circuitStatus = 0
        self.rpdEnetPortIndex = 0
        self.enableNotifications = 0
        self.pwAssociation = dict()
        self.lastchangetime = time.time()
        self.status = False
        self.sourceAddress = StaticL2tpSession.DEFAULT_IP_ADDR
        self.destAddress = StaticL2tpSession.DEFAULT_IP_ADDR
        self.localAddress = StaticL2tpSession.DEFAULT_IP_ADDR

    def allocateIndex(self, index=None):
        for key in self.get_keys():
            ses = StaticL2tpSession(key)
            ses.read()
            if ses.localAddress == self.localAddress and ses.sessionId == \
                    self.sessionId:
                self.index = ses.index
                return ses.index

        super(StaticL2tpSession, self).allocateIndex(index)

    def updateComStaticPseudowire(self, rcp_msg):
        if rcp_msg.HasField("CommonStaticPwConfig"):
            commonStaticPwCfg = rcp_msg.CommonStaticPwConfig
            commonStaticPwCfg.Index = self.index
            if commonStaticPwCfg.HasField("Direction"):
                self.direction = commonStaticPwCfg.Direction
            if commonStaticPwCfg.HasField("SessionId"):
                self.sessionId = commonStaticPwCfg.SessionId
            if commonStaticPwCfg.HasField("PwType"):
                self.pwType = commonStaticPwCfg.PwType
            if commonStaticPwCfg.HasField("DepiPwSubtype"):
                self.depiPwSubtype = commonStaticPwCfg.DepiPwSubtype
            if commonStaticPwCfg.HasField("L2SublayerType"):
                self.l2SublayerType = commonStaticPwCfg.L2SublayerType
            if commonStaticPwCfg.HasField("DepiL2SublayerSubtype"):
                self.depiL2SublayerSubtype = \
                    commonStaticPwCfg.DepiL2SublayerSubtype
            if commonStaticPwCfg.HasField("CircuitStatus"):
                self.circuitStatus = commonStaticPwCfg.CircuitStatus
            if commonStaticPwCfg.HasField("RpdEnetPortIndex"):
                self.rpdEnetPortIndex = commonStaticPwCfg.RpdEnetPortIndex
            if commonStaticPwCfg.HasField("EnableStatusNotification"):
                self.enableNotifications = \
                    commonStaticPwCfg.EnableStatusNotification
            self.updatePwAssociation(commonStaticPwCfg)

    def updatePwAssociation(self, rcp_msg):
        for pwAssociate in rcp_msg.PwAssociation:
            index = pwAssociate.Index
            if pwAssociate.HasField("ChannelSelector"):
                channelSelector = pwAssociate.ChannelSelector
                pseudoChannelBean = StaticPseudoChannel()
                if channelSelector.HasField("RfPortIndex"):
                    pseudoChannelBean.rfPortIndex = channelSelector.RfPortIndex
                if channelSelector.HasField("ChannelType"):
                    pseudoChannelBean.channelType = channelSelector.ChannelType
                if channelSelector.HasField("ChannelIndex"):
                    pseudoChannelBean.channelIndex = \
                        channelSelector.ChannelIndex
                self.pwAssociation[index] = pseudoChannelBean

    def updateRetstaticPseudowire(self, rcp_msg):
        if rcp_msg.HasField("RetStaticPwConfig"):
            retStaticCfg = rcp_msg.RetStaticPwConfig
            retStaticCfg.Index = self.index
            self.direction = StaticL2tpSession.DIRECTION_RETURN
            if retStaticCfg.HasField("DestAddress"):
                self.destAddress = retStaticCfg.DestAddress
            if retStaticCfg.HasField("MtuSize"):
                self.mtuSize = retStaticCfg.MtuSize
            if retStaticCfg.HasField("UsPhbId"):
                self.usPhbId = retStaticCfg.UsPhbId
            if retStaticCfg.HasField("CcapCoreOwner"):
                self.ccapCoreOwner = retStaticCfg.CcapCoreOwner
            self.localAddress = L2tpv3GcppProvider.getLocalIp(self.destAddress)

    def updateFwdStaticPseudowire(self, rcp_msg):
        if rcp_msg.HasField("FwdStaticPwConfig"):
            fwdStaticCfg = rcp_msg.FwdStaticPwConfig
            fwdStaticCfg.Index = self.index
            self.direction = StaticL2tpSession.DIRECTION_FORWARD
            if fwdStaticCfg.HasField("CcapCoreOwner"):
                self.ccapCoreOwner = fwdStaticCfg.CcapCoreOwner
            if fwdStaticCfg.HasField("GroupAddress"):
                self.groupAddress = fwdStaticCfg.GroupAddress
            if fwdStaticCfg.HasField("SourceAddress"):
                self.sourceAddress = fwdStaticCfg.SourceAddress
            self.localAddress = \
                L2tpv3GcppProvider.getLocalIp(self.sourceAddress)

    def get_static_pw_index(self, rcp_msg):
        if rcp_msg.HasField("FwdStaticPwConfig"):
            if rcp_msg.FwdStaticPwConfig.HasField("Index"):
                self.index = rcp_msg.FwdStaticPwConfig.Index
        elif rcp_msg.HasField("RetStaticPwConfig"):
            if rcp_msg.RetStaticPwConfig.HasField("Index"):
                self.index = rcp_msg.RetStaticPwConfig.Index
        elif rcp_msg.HasField("CommonStaticPwConfig"):
            if rcp_msg.CommonStaticPwConfig.HasField("Index"):
                self.index = rcp_msg.CommonStaticPwConfig.Index
        return self.index

    @classmethod
    def getStaticSessionBySesId(self, localSesId, localIp):
        for key in self.get_keys():
            ses = StaticL2tpSession(key)
            ses.read()
            if ses.localAddress == localIp and ses.sessionId == localSesId:
                return True, ses
        return False, None


class L2tpv3GcppProvider(object):

    __metaclass__ = AddLoggerToClass
    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = \
                super(L2tpv3GcppProvider, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    # TODO remove it later
    @staticmethod
    def getLocalIp(core_ip):
        intf = 'eth0'
        family = socket.AF_INET
        if core_ip is not None:
            is_ipv6 = Convert.is_valid_ipv6_address(core_ip)
            family = (socket.AF_INET, socket.AF_INET6)[is_ipv6]
        if core_ip is None or core_ip == "127.0.0.1" or core_ip == "::1":
            intf = 'eth0'
        else:
            intf = SysTools.get_interface()
        local_ip = SysTools.get_ip_address(intf, family)
        if local_ip is None:
            return globalSettings.L2tpv3GlobalSettings.LocalIPAddress
        return local_ip

    @staticmethod
    def isMultiCast(groupAddr):
        if not groupAddr.strip():
            return False
        grpIp = groupAddr
        if not isinstance(grpIp, unicode):
            grpIp = unicode(grpIp, 'utf-8')
        return ipaddress.ip_address(grpIp).is_multicast

    def printStaticL2tpMsg(self, staticL2tpSession):
        self.logger.debug("index=%d  sessionId=%d", staticL2tpSession.index,
                          staticL2tpSession.sessionId)
        self.logger.debug(
            "direction=%d groupAddress=%s sourceAddress=%s destAddress=%s "
            "ccapCoreOwner=%s",
            staticL2tpSession.direction, staticL2tpSession.groupAddress,
            staticL2tpSession.sourceAddress, staticL2tpSession.destAddress,
            staticL2tpSession.ccapCoreOwner)
        for key, pwAssociation in staticL2tpSession.pwAssociation.items():
            self.logger.debug(
                "rfPortIndex =%d channelType =%d channelIndex=%d",
                pwAssociation.rfPortIndex, pwAssociation.channelType,
                pwAssociation.channelIndex)
