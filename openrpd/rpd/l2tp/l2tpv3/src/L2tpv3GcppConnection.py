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
from subprocess import check_output
from random import randint
import l2tpv3.src.L2tpv3GlobalSettings as globalSettings


class StaticPseudoChannel(object):
    def __init__(self):
        self.rfPortIndex = 0
        self.channelType = 0
        self.channelIndex = 0


class StaticL2tpSession(object):
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
    MAX_FWD_STATIC_PWS = -1
    MAX_RET_STATIC_PWS = -1

    DEFAULT_IP_ADDR = "127.0.0.1"
    DEFAULT_MAC_ADDR = "00:00:00:00:00:00"

    indexList = []

    @staticmethod
    def getAllocatedIndex():
        if len(StaticL2tpSession.indexList) >= 0xFFFF:
            return -1
        while True:
            index = randint(0, 0xFFFF)
            if index in StaticL2tpSession.indexList:
                continue
            else:
                StaticL2tpSession.indexList.append(index)
                return index
        return -1

    def __init__(self):
        self.index = StaticL2tpSession.getAllocatedIndex()
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


class L2tpv3GcppProvider(object):
    staticPseudowireDB = dict()

    __metaclass__ = AddLoggerToClass
    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = \
                super(L2tpv3GcppProvider, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    #TODO remove it later
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

    def saveGcppSessionData(self, staticPwCfg):
        staticL2tpSession = self.getStaticPseudowireSession(staticPwCfg)
        if staticL2tpSession is None:
            return False, None
        self.updateComStaticPseudowire(staticPwCfg, staticL2tpSession)
        self.updateFwdStaticPseudowire(staticPwCfg, staticL2tpSession)
        self.updateRetStaticPseudowire(staticPwCfg, staticL2tpSession)
        return True, staticL2tpSession

    def getStaticPseudowireSession(self, rcp_msg):
        direction = -1
        sessionId = -1
        if rcp_msg.HasField("CommonStaticPwConfig"):
            commonStaticPwCfg = rcp_msg.CommonStaticPwConfig
            if commonStaticPwCfg.HasField("Direction"):
                direction = commonStaticPwCfg.Direction
            if commonStaticPwCfg.HasField("SessionId"):
                sessionId = commonStaticPwCfg.SessionId
        if direction == -1 or sessionId == -1:
            self.logger.debug(" Pseudowire direction or sessionId is not exist")
            return None
        if direction == StaticL2tpSession.DIRECTION_FORWARD and \
                not rcp_msg.HasField("FwdStaticPwConfig"):
            return None
        if direction == StaticL2tpSession.DIRECTION_RETURN and \
                not rcp_msg.HasField("RetStaticPwConfig"):
            return None
        if (sessionId, direction) in L2tpv3GcppProvider.staticPseudowireDB.keys():
            staticL2tpSession = L2tpv3GcppProvider.staticPseudowireDB.get((sessionId, direction))
            staticL2tpSession.status = False
        else:
            staticL2tpSession = StaticL2tpSession()
            L2tpv3GcppProvider.staticPseudowireDB[(sessionId, direction)] = staticL2tpSession
        return staticL2tpSession

    def updateComStaticPseudowire(self, rcp_msg, staticL2tpSession):
        if rcp_msg.HasField("CommonStaticPwConfig"):
            commonStaticPwCfg = rcp_msg.CommonStaticPwConfig
            index = staticL2tpSession.index
            commonStaticPwCfg.Index = index
            if commonStaticPwCfg.HasField("Direction"):
                staticL2tpSession.direction = commonStaticPwCfg.Direction
            if commonStaticPwCfg.HasField("SessionId"):
                staticL2tpSession.sessionId = commonStaticPwCfg.SessionId
            if commonStaticPwCfg.HasField("PwType"):
                staticL2tpSession.pwType = commonStaticPwCfg.PwType
            if commonStaticPwCfg.HasField("DepiPwSubtype"):
                staticL2tpSession.depiPwSubtype = commonStaticPwCfg.DepiPwSubtype
            if commonStaticPwCfg.HasField("L2SublayerType"):
                staticL2tpSession.l2SublayerType = commonStaticPwCfg.L2SublayerType
            if commonStaticPwCfg.HasField("DepiL2SublayerSubtype"):
                staticL2tpSession.depiL2SublayerSubtype = commonStaticPwCfg.DepiL2SublayerSubtype
            if commonStaticPwCfg.HasField("CircuitStatus"):
                staticL2tpSession.circuitStatus = commonStaticPwCfg.CircuitStatus
            if commonStaticPwCfg.HasField("RpdEnetPortIndex"):
                staticL2tpSession.rpdEnetPortIndex = commonStaticPwCfg.RpdEnetPortIndex
            if commonStaticPwCfg.HasField("EnableStatusNotification"):
                staticL2tpSession.enableNotifications = commonStaticPwCfg.EnableStatusNotification
            self.updatePwAssociation(staticL2tpSession, commonStaticPwCfg)

    def updateFwdStaticPseudowire(self, rcp_msg, staticL2tpSession):
        if staticL2tpSession.direction != StaticL2tpSession.DIRECTION_FORWARD:
            return
        if rcp_msg.HasField("FwdStaticPwConfig"):
            fwdStaticCfg = rcp_msg.FwdStaticPwConfig
            fwdStaticCfg.Index = staticL2tpSession.index
            staticL2tpSession.fwdFlag = True
            if fwdStaticCfg.HasField("GroupAddress"):
                staticL2tpSession.groupAddress = fwdStaticCfg.GroupAddress
            if fwdStaticCfg.HasField("SourceAddress"):
                staticL2tpSession.sourceAddress = fwdStaticCfg.SourceAddress
            else:
                if L2tpv3GcppProvider.isMultiCast(staticL2tpSession.groupAddress):  # ASM
                    staticL2tpSession.sourceAddress = staticL2tpSession.groupAddress
            if fwdStaticCfg.HasField("CcapCoreOwner"):
                if (fwdStaticCfg.CcapCoreOwner != StaticL2tpSession.DEFAULT_MAC_ADDR):
                    staticL2tpSession.ccapCoreOwner = fwdStaticCfg.CcapCoreOwner
                else:
                    staticL2tpSession.ccapCoreOwner = None
            staticL2tpSession.localAddress = \
                L2tpv3GcppProvider.getLocalIp(staticL2tpSession.sourceAddress)
            self.printStaticL2tpMsg(staticL2tpSession)

    def updateRetStaticPseudowire(self, rcp_msg, staticL2tpSession):
        if staticL2tpSession.direction != StaticL2tpSession.DIRECTION_RETURN:
            return
        if rcp_msg.HasField("RetStaticPwConfig"):
            retStaticCfg = rcp_msg.RetStaticPwConfig
            retStaticCfg.Index = staticL2tpSession.index
            if retStaticCfg.HasField("DestAddress"):
                staticL2tpSession.destAddress = retStaticCfg.DestAddress
            if retStaticCfg.HasField("MtuSize"):
                staticL2tpSession.mtuSize = retStaticCfg.MtuSize
            if retStaticCfg.HasField("UsPhbId"):
                staticL2tpSession.usPhbId = retStaticCfg.UsPhbId
            if retStaticCfg.HasField("CcapCoreOwner"):
                if retStaticCfg.CcapCoreOwner != StaticL2tpSession.DEFAULT_MAC_ADDR:
                    staticL2tpSession.ccapCoreOwner = retStaticCfg.CcapCoreOwner
                else:
                    staticL2tpSession.ccapCoreOwner = None
            staticL2tpSession.localAddress = \
                L2tpv3GcppProvider.getLocalIp(staticL2tpSession.destAddress)
            self.printStaticL2tpMsg(staticL2tpSession)

    def updatePwAssociation(self, staticL2tpSession, rcp_msg):
        pwAssociation = rcp_msg.PwAssociation
        for pwAssociate in pwAssociation:
            index = pwAssociate.Index
            if pwAssociate.HasField("ChannelSelector"):
                channelSelector = pwAssociate.ChannelSelector
                pseudoChannelBean = StaticPseudoChannel()
                if channelSelector.HasField('RfPortIndex'):
                    pseudoChannelBean.rfPortIndex = channelSelector.RfPortIndex
                if channelSelector.HasField('ChannelType'):
                    pseudoChannelBean.channelType = channelSelector.ChannelType
                if channelSelector.HasField('ChannelIndex'):
                    pseudoChannelBean.channelIndex = channelSelector.ChannelIndex
                staticL2tpSession.pwAssociation[index]= pseudoChannelBean

    def removeStaticSession(self, sessionId, direction):
        if (sessionId, direction) not in L2tpv3GcppProvider.staticPseudowireDB.keys():
            self.logger.debug("Err: The sessionId %d and direction %d is not in current"
                              " static pseudowires", sessionId, direction)
            return
        L2tpv3GcppProvider.staticPseudowireDB.pop((sessionId, direction))
        self.logger.debug("Delete GCPP static l2tp session [sessiondId= %d direction= %d]",
                          sessionId, direction)

    def getStaticSessionBySesId(self, localSesId, localIp, remoteIp):
        for key, staticL2tpSession in L2tpv3GcppProvider.staticPseudowireDB.items():
            if staticL2tpSession.localAddress == localIp \
                    and staticL2tpSession.sessionId == localSesId:
                if (staticL2tpSession.direction == StaticL2tpSession.DIRECTION_FORWARD) or \
                        (staticL2tpSession.direction == StaticL2tpSession.DIRECTION_RETURN):
                    return True, staticL2tpSession
        return False, None

    def printStaticL2tpMsg(self, staticL2tpSession):
        self.logger.debug("index=%d  sessionId=%d",
                          staticL2tpSession.index, staticL2tpSession.sessionId)
        self.logger.debug("direction=%d groupAddress=%s sourceAddress=%s destAddress=%s ccapCoreOwner=%s",
                          staticL2tpSession.direction, staticL2tpSession.groupAddress,
                          staticL2tpSession.sourceAddress, staticL2tpSession.destAddress,
                          staticL2tpSession.ccapCoreOwner)
        for key, pwAssociation in staticL2tpSession.pwAssociation.items():
            self.logger.debug("rfPortIndex =%d channelType =%d channelIndex=%d",
                              pwAssociation.rfPortIndex, pwAssociation.channelType,
                              pwAssociation.channelIndex)
