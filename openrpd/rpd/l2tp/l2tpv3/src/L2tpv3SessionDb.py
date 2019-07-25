#
# Copyright (c) 2018 Cisco and/or its affiliates, and
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
import socket

from rpd.confdb.rpd_redis_db import DBRecord
from rpd.common.utils import Convert
from rpd.rcp.rcp_lib.rcp_tlv_def import INETADDRESSTYPE_IPV4, \
    INETADDRESSTYPE_IPV6, INETADDRESSTYPE_UNKNOWN
from rpd.rcp.rcp_sessions import CcapCoreIdentification


class L2tpSessionKey(object):
    """
    :param init_str: need to follow below format:
    str(sessionIpAddrType)&&str(ccapLcceIpAddr)&&str(rpdLcceIpAddr)
        &&str(direction)&&str(l2tpSessionId)
    """

    # Direction
    DIRECTION_FORWARD = 0
    DIRECTION_RETURN = 1
    DIRECTION_UNKNOWN = -1

    DIRECTIONS = [DIRECTION_FORWARD, DIRECTION_RETURN]

    def __init__(self, initStr=None):
        self.sessionIpAddrType = INETADDRESSTYPE_UNKNOWN[0]

        self.ccapLcceIpAddr = ''
        self.rpdLcceIpAddr = ''
        self.direction = -1
        self.l2tpSessionId = 0
        self.str2value(initStr)

    def __str__(self):
        return '%s&&%s&&%s&&%s&&%s' % (str(self.sessionIpAddrType),
                                       str(self.ccapLcceIpAddr),
                                       str(self.rpdLcceIpAddr),
                                       str(self.direction),
                                       str(self.l2tpSessionId))

    def __cmp__(self, other):
        if not hasattr(other, "sessionIpAddrType"):
            return 0
        if self.sessionIpAddrType != other.sessionIpAddrType:
            return self.sessionIpAddrType.__cmp__(other.sessionIpAddrType)

        if not hasattr(other, "ccapLcceIpAddr"):
            return 0
        if self.ccapLcceIpAddr != other.ccapLcceIpAddr:
            return Convert.compare_ip(self.ccapLcceIpAddr,
                                      other.ccapLcceIpAddr)

        if not hasattr(other, "rpdLcceIpAddr"):
            return 0
        if self.rpdLcceIpAddr != other.rpdLcceIpAddr:
            return Convert.compare_ip(self.rpdLcceIpAddr,
                                      other.rpdLcceIpAddr)

        if not hasattr(other, "direction"):
            return 0
        if self.direction != other.direction:
            return self.direction.__cmp__(other.direction)

        if not hasattr(other, "l2tpSessionId"):
            return 0
        if self.l2tpSessionId != other.l2tpSessionId:
            return self.l2tpSessionId.__cmp__(other.l2tpSessionId)

        return 0

    def str2value(self, initStr):
        if isinstance(initStr, str):
            values = initStr.split('&&')
            if len(values) == 5:
                self.sessionIpAddrType = int(values[0])
                self.ccapLcceIpAddr = str(values[1])
                self.rpdLcceIpAddr = str(values[2])
                self.direction = int(values[3])
                self.l2tpSessionId = int(values[4])

    def isValid(self):
        return self.getInetAddrType(self.ccapLcceIpAddr) == \
            self.sessionIpAddrType \
            and self.getInetAddrType(self.rpdLcceIpAddr) == \
            self.sessionIpAddrType \
            and self.direction in L2tpSessionKey.DIRECTIONS \
            and isinstance(self.l2tpSessionId, (int, long))

    def isDefault(self):
        return INETADDRESSTYPE_UNKNOWN == self.sessionIpAddrType and \
            '' == self.ccapLcceIpAddr and '' == self.rpdLcceIpAddr and \
            -1 == self.direction and 0 == self.l2tpSessionId

    @staticmethod
    def getInetAddrType(address):
        try:
            localAddressInfo = socket.getaddrinfo(address, None)[0]
            family = localAddressInfo[0]
            if socket.AF_INET == family:
                return INETADDRESSTYPE_IPV4[0]
            if socket.AF_INET6 == family:
                return INETADDRESSTYPE_IPV6[0]
        except Exception:
            pass
        return INETADDRESSTYPE_UNKNOWN[0]


class L2tpSessionRecord(DBRecord):

    # pw type, used to parse sessionType
    PW_MPT = 12
    PW_PSP = 13

    # SessionType
    SESSIONTYPE_ERR = 0
    SESSIONTYPE_PSP = 1
    SESSIONTYPE_MPT = 2

    # SubType
    NONE_SESSION_TYPE = 0
    MPT_LEGACY = 1
    PSP_LEGACY = 2
    MCM = 3
    PSP_DEPI = 4
    PSP_UEPI_SCQAM = 5
    PSP_UEPI_OFDMA = 6
    PSP_BW_REQ_SCQ = 7
    PSP_BW_REQ_OFDMA = 8
    PSP_PROBE = 9
    PSP_RNG_REQ_SCQ = 10
    PSP_RNG_REQ_OFDMA = 11
    PSP_MAP_SCQ = 12
    PSP_MAP_OFDMA = 13
    PSP_SPECMAN = 14
    PSP_PNM = 15
    PSP_55_1_FWD = 16
    PSP_55_1_RET = 17
    PSP_55_2_FWD = 18
    PSP_55_2_RET = 29
    PSP_NDF = 20
    PSP_NDR = 21

    # chan type, used to parse direction
    CHANTYPE_RESERVED = 0
    CHANTYPE_DS_OFDM = 1
    CHANTYPE_DS_OFDM_PLC = 2
    CHANTYPE_DS_SCQAM = 3
    CHANTYPE_US_ATDMA = 4
    CHANTYPE_US_OFDM = 5
    CHANTYPE_55_1_FWD = 6
    CHANTYPE_55_1_RET = 7
    CHANTYPE_55_2_FWD = 8
    CHANTYPE_55_2_RET = 9
    CHANTYPE_NDF = 10
    CHANTYPE_NDR = 11

    CT_FORWARD = [CHANTYPE_DS_OFDM, CHANTYPE_DS_OFDM_PLC, CHANTYPE_DS_SCQAM,
                  CHANTYPE_55_1_FWD, CHANTYPE_55_2_FWD, CHANTYPE_NDF]

    def __init__(self, index=None):
        """
        Keys: SessionIpAddrType, CcapLcceIpAddr, RpdLcceIpAddr, Direction,
              L2tpSessionId
        """
        if index and isinstance(index, L2tpSessionKey):
            self.index = index
        else:
            self.index = L2tpSessionKey()

        self.coreId = ''
        self.connCtrlId = 0
        self.udpPort = 0
        self.descr = ''
        self.sessionType = 0
        self.sessionSubType = 0
        self.maxPayload = 0
        self.pathPayload = 0
        self.rpdIfMtu = 0
        self.coreIfMtu = 0
        self.errorCode = 0
        self.creationTime = 0
        self.operStatus = -1
        self.localStatus = -1
        self.lastChange = 0
        self.outOfSequencePackets = 0
        self.inPackets = 0
        self.inDiscards = 0
        self.outPackets = 0
        self.outErrors = 0
        self.counterDiscontinuityTime = ''

    @classmethod
    def decode_index(cls, init_str):
        return L2tpSessionKey(init_str)

    def updateL2tpSessionKey(self,
                             ccapLcceIpAddr='',
                             rpdLcceIpAddr='',
                             direction=-1,
                             l2tpSessionId=0):
        self.index.sessionIpAddrType = \
            self.index.getInetAddrType(rpdLcceIpAddr)
        self.index.ccapLcceIpAddr = ccapLcceIpAddr
        self.index.rpdLcceIpAddr = rpdLcceIpAddr
        self.index.direction = direction
        self.index.l2tpSessionId = l2tpSessionId

    def updateL2tpSessionRecordData(self,
                                    coreId='',
                                    connCtrlId=0,
                                    udpPort=0,
                                    descr='',
                                    sessionType=0,
                                    sessionSubType=0,
                                    maxPayload=0,
                                    pathPayload=0,
                                    rpdIfMtu=0,
                                    coreIfMtu=0,
                                    errorCode=0,
                                    creationTime=0,
                                    operStatus=-1,
                                    localStatus=-1,
                                    lastChange=0,
                                    counterDiscontinuityTime=''):
        self.coreId = coreId
        self.connCtrlId = connCtrlId
        self.udpPort = udpPort
        self.descr = descr
        self.sessionType = sessionType
        self.sessionSubType = sessionSubType
        self.maxPayload = maxPayload
        self.pathPayload = pathPayload
        self.rpdIfMtu = rpdIfMtu
        self.coreIfMtu = coreIfMtu
        self.errorCode = errorCode
        self.creationTime = creationTime
        self.operStatus = operStatus
        self.localStatus = localStatus
        self.lastChange = lastChange
        self.counterDiscontinuityTime = counterDiscontinuityTime

    def updateL2tpSessionRecordData_dpconfig(self,
                                             operStatus=-1):
        self.operStatus = operStatus

    def updateL2tpSessionCounters(self,
                                  outOfSequencePackets=0,
                                  inPackets=0,
                                  inDiscards=0,
                                  outPackets=0,
                                  outErrors=0):
        self.outOfSequencePackets = outOfSequencePackets
        self.inPackets = inPackets
        self.inDiscards = inDiscards
        self.outPackets = outPackets
        self.outErrors = outErrors

    def deleteAll(self):
        for idx in self.get_keys():
            sess = L2tpSessionRecord(idx)
            sess.delete()

    @staticmethod
    def parseSessionType(pwtype):
        if pwtype == L2tpSessionRecord.PW_PSP:
            return L2tpSessionRecord.SESSIONTYPE_PSP
        elif pwtype == L2tpSessionRecord.PW_MPT:
            return L2tpSessionRecord.SESSIONTYPE_MPT
        return L2tpSessionRecord.SESSIONTYPE_ERR

    @staticmethod
    def parseSessionSubType(l2_subtype):
        # sessSubType remove 'reverse = 5' between PSP_DEPI and PSP_UEPI_SCQAM
        if l2_subtype > L2tpSessionRecord.PSP_DEPI:
            return (l2_subtype - 1)
        else:
            return l2_subtype

    @staticmethod
    def parseDirection(rfChanList):
        # only need check one item in list,
        # if there's ch type confilct, there must be err with sess initiator
        for chanSel in rfChanList:
            chtype = chanSel[1]
            if chtype in L2tpSessionRecord.CT_FORWARD:
                return L2tpSessionKey.DIRECTION_FORWARD
            else:
                return L2tpSessionKey.DIRECTION_RETURN
        return L2tpSessionKey.DIRECTION_UNKNOWN

    def getCoreId(self, ccapLcceIpAddr=None):
        if not ccapLcceIpAddr:
            ccapLcceIpAddr = self.index.ccapLcceIpAddr
        identRecord = CcapCoreIdentification()
        identRecord.allocateIndex(ccapLcceIpAddr)
        return identRecord.core_id

    def getDescription(self, rfChanList):
        result = []
        for rfchan in rfChanList:
            result.append("(%s:%s:%s)"
                          % (str(rfchan[0]), str(rfchan[1]), str(rfchan[2])))
        return ",".join(result)

    def write(self):
        if self.index.isValid():
            super(L2tpSessionRecord, self).write()

    def delete(self):
        try:
            super(L2tpSessionRecord, self).delete()
        except Exception:
            pass
