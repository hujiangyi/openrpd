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


import time
from datetime import datetime
import unittest
from rpd.l2tp.l2tpv3.src.L2tpv3SessionDb import L2tpSessionRecord, \
    L2tpSessionKey
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis
from rpd.rcp.rcp_lib.rcp_tlv_def import INETADDRESSTYPE_IPV4, \
    INETADDRESSTYPE_IPV6, INETADDRESSTYPE_UNKNOWN
from rpd.common import utils


class test_L2tpSessionKey(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass


class test_L2tpSessionRecord(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()
        sessRecord = L2tpSessionRecord()
        sessRecord.deleteAll()

    def tearDown(self):
        sessRecord = L2tpSessionRecord()
        sessRecord.deleteAll()
        stop_test_redis()

    def test_updateL2tpSessionKey(self):
        sessRecord = L2tpSessionRecord()
        # 1. default key
        sessRecord.updateL2tpSessionKey()
        self.assertEquals(sessRecord.index.sessionIpAddrType,
                          INETADDRESSTYPE_UNKNOWN[0])
        self.assertEquals(sessRecord.index.ccapLcceIpAddr, '')
        self.assertEquals(sessRecord.index.rpdLcceIpAddr, '')
        self.assertEquals(sessRecord.index.direction, -1)
        self.assertEquals(sessRecord.index.l2tpSessionId, 0)

        # 2. Add ipv4 key
        sessRecord.updateL2tpSessionKey(
            ccapLcceIpAddr='10.1.2.3',
            rpdLcceIpAddr='10.1.2.10',
            direction=1,
            l2tpSessionId=100)
        self.assertEquals(sessRecord.index.sessionIpAddrType,
                          INETADDRESSTYPE_IPV4[0])
        self.assertEquals(sessRecord.index.ccapLcceIpAddr, '10.1.2.3')
        self.assertEquals(sessRecord.index.rpdLcceIpAddr, '10.1.2.10')
        self.assertEquals(sessRecord.index.direction, 1)
        self.assertEquals(sessRecord.index.l2tpSessionId, 100)

        # 3. Add ipv6 key
        sessRecord.updateL2tpSessionKey(
            ccapLcceIpAddr='2001:20:1:2::3',
            rpdLcceIpAddr='2001:20:1:2::4',
            direction=0,
            l2tpSessionId=200)
        self.assertEquals(sessRecord.index.sessionIpAddrType,
                          INETADDRESSTYPE_IPV6[0])

        self.assertEquals(sessRecord.index.ccapLcceIpAddr, '2001:20:1:2::3')
        self.assertEquals(sessRecord.index.rpdLcceIpAddr, '2001:20:1:2::4')
        self.assertEquals(sessRecord.index.direction, 0)
        self.assertEquals(sessRecord.index.l2tpSessionId, 200)

    def test_updateL2tpSessionRecordData(self):
        sessRecord = L2tpSessionRecord()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=100)

        self.assertEquals(sessRecord.index.sessionIpAddrType,
                          INETADDRESSTYPE_IPV4[0])
        self.assertEquals(sessRecord.index.ccapLcceIpAddr, '10.1.2.3')
        self.assertEquals(sessRecord.index.rpdLcceIpAddr, '10.1.2.10')
        self.assertEquals(sessRecord.index.direction, 1)
        self.assertEquals(sessRecord.index.l2tpSessionId, 100)

        coreId = "1:2:3"
        rfChanList = ((0, 1, 2), (1, 2, 3))
        current = time.time()
        currentInt = int(current)
        sessRecord.updateL2tpSessionRecordData(
            coreId=coreId,
            connCtrlId=1,
            udpPort=1,
            descr=sessRecord.getDescription(rfChanList),
            sessionType=1,
            sessionSubType=1,
            maxPayload=1,
            pathPayload=1,
            rpdIfMtu=1,
            coreIfMtu=1,
            errorCode=1,
            creationTime=currentInt,
            operStatus=1,
            localStatus=1,
            lastChange=currentInt,
            counterDiscontinuityTime=utils.Convert.pack_timestamp_to_string(
                currentInt))
        self.assertEquals(sessRecord.coreId, coreId)
        self.assertEquals(sessRecord.connCtrlId, 1)
        self.assertEquals(sessRecord.udpPort, 1)
        self.assertEquals(sessRecord.descr, sessRecord.getDescription(
            rfChanList))
        self.assertEquals(sessRecord.sessionType, 1)
        self.assertEquals(sessRecord.sessionSubType, 1)
        self.assertEquals(sessRecord.maxPayload, 1)
        self.assertEquals(sessRecord.pathPayload, 1)
        self.assertEquals(sessRecord.rpdIfMtu, 1)
        self.assertEquals(sessRecord.coreIfMtu, 1)
        self.assertEquals(sessRecord.errorCode, 1)
        self.assertEquals(sessRecord.creationTime, currentInt)
        self.assertEquals(sessRecord.operStatus, 1)
        self.assertEquals(sessRecord.localStatus, 1)
        self.assertEquals(sessRecord.lastChange, currentInt)
        self.assertEquals(sessRecord.counterDiscontinuityTime,
                          utils.Convert.pack_timestamp_to_string(currentInt))

    def test_updateL2tpSessionCounters(self):
        sessRecord = L2tpSessionRecord()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=100)

        self.assertEquals(sessRecord.index.sessionIpAddrType,
                          INETADDRESSTYPE_IPV4[0])
        self.assertEquals(sessRecord.index.ccapLcceIpAddr, '10.1.2.3')
        self.assertEquals(sessRecord.index.rpdLcceIpAddr, '10.1.2.10')
        self.assertEquals(sessRecord.index.direction, 1)
        self.assertEquals(sessRecord.index.l2tpSessionId, 100)

        outOfSeq = 2
        inPkts = 10
        inDisc = 1
        outPkts = 10
        outErr = 3
        sessRecord.updateL2tpSessionCounters(
            outOfSequencePackets=outOfSeq,
            inPackets=inPkts,
            inDiscards=inDisc,
            outPackets=outPkts,
            outErrors=outErr)
        self.assertEquals(sessRecord.outOfSequencePackets, outOfSeq)
        self.assertEquals(sessRecord.inPackets, inPkts)
        self.assertEquals(sessRecord.inDiscards, inDisc)
        self.assertEquals(sessRecord.outPackets, outPkts)
        self.assertEquals(sessRecord.outErrors, outErr)

    def test_readwrite(self):
        sessRecord = L2tpSessionRecord()
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=100)
        sessRecord.write()
        rets = sessRecord.get_all()
        i = 0
        for ret in rets:
            i = i + 1
        self.assertEquals(i, 1)

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=101)
        coreId = "1:2:3"
        rfChanList = ((0, 1, 2), (1, 2, 3))
        current = time.time()
        currentInt = int(current)
        sessRecord.updateL2tpSessionRecordData(
            coreId=coreId,
            connCtrlId=1,
            udpPort=1,
            descr=sessRecord.getDescription(rfChanList),
            sessionType=1,
            sessionSubType=1,
            maxPayload=1,
            pathPayload=1,
            rpdIfMtu=1,
            coreIfMtu=1,
            errorCode=1,
            creationTime=currentInt,
            operStatus=1,
            localStatus=1,
            lastChange=currentInt,
            counterDiscontinuityTime=utils.Convert.pack_timestamp_to_string(
                currentInt))
        sessRecord.write()
        rets = sessRecord.get_all()
        i = 0
        for ret in rets:
            i = i + 1
        self.assertEquals(i, 2)

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=100)
        sessRecord.read()
        self.assertEquals(sessRecord.index.l2tpSessionId, 100)
        self.assertEquals(sessRecord.coreId, '')
        self.assertEquals(sessRecord.connCtrlId, 0)
        self.assertEquals(sessRecord.udpPort, 0)
        self.assertEquals(sessRecord.descr, '')
        self.assertEquals(sessRecord.sessionType, 0)
        self.assertEquals(sessRecord.sessionSubType, 0)
        self.assertEquals(sessRecord.maxPayload, 0)
        self.assertEquals(sessRecord.pathPayload, 0)
        self.assertEquals(sessRecord.rpdIfMtu, 0)
        self.assertEquals(sessRecord.coreIfMtu, 0)
        self.assertEquals(sessRecord.errorCode, 0)
        self.assertEquals(sessRecord.creationTime, 0)
        self.assertEquals(sessRecord.operStatus, -1)
        self.assertEquals(sessRecord.localStatus, -1)
        self.assertEquals(sessRecord.lastChange, 0)
        self.assertEquals(sessRecord.counterDiscontinuityTime, '')

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=101)
        sessRecord.read()
        self.assertEquals(sessRecord.coreId, coreId)
        self.assertEquals(sessRecord.connCtrlId, 1)
        self.assertEquals(sessRecord.udpPort, 1)
        self.assertEquals(sessRecord.descr,
                          sessRecord.getDescription(rfChanList))
        self.assertEquals(sessRecord.sessionType, 1)
        self.assertEquals(sessRecord.sessionSubType, 1)
        self.assertEquals(sessRecord.maxPayload, 1)
        self.assertEquals(sessRecord.pathPayload, 1)
        self.assertEquals(sessRecord.rpdIfMtu, 1)
        self.assertEquals(sessRecord.coreIfMtu, 1)
        self.assertEquals(sessRecord.errorCode, 1)
        self.assertEquals(sessRecord.creationTime, currentInt)
        self.assertEquals(sessRecord.operStatus, 1)
        self.assertEquals(sessRecord.localStatus, 1)
        self.assertEquals(sessRecord.lastChange, currentInt)
        self.assertEquals(sessRecord.counterDiscontinuityTime,
                          utils.Convert.pack_timestamp_to_string(currentInt))

        sessRecord.creationTime = 0
        sessRecord.write()
        sessRecord.read()
        self.assertEquals(sessRecord.creationTime, 0)

    def test_get_all(self):
        sessRecord = L2tpSessionRecord()
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=100)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=101)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=102)

        sessRecord.write()
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=103)
        sessRecord.write()
        rets = sessRecord.get_all()
        i = 0
        for ret in rets:
            i = i + 1
        self.assertEquals(i, 4)

    def test_get_next_n(self):
        sessRecord = L2tpSessionRecord()
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=107)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=101)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=102)

        sessRecord.write()
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=103)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=104)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=105)
        sessRecord.write()

        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=106)

        sessRecord.write()
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=100)
        sessRecord.write()

        # None key query.
        ret = sessRecord.get_next_n(key=None, count=2)
        i = 0
        for j in ret:
            if i == 0:
                self.assertEquals(j.index.l2tpSessionId, 100)
            i = i + 1
        self.assertEquals(i, 2)

        # Key is invalid
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=120)
        testKey = sessRecord.index
        ret = sessRecord.get_next_n(key=testKey, count=2)
        i = 0
        for j in ret:
            i = i + 1
        self.assertEquals(i, 0)
        # Count is larger than db
        sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                        rpdLcceIpAddr='10.1.2.10',
                                        direction=1,
                                        l2tpSessionId=107)
        ret = sessRecord.get_next_n(key=testKey, count=10)
        i = 0
        for j in ret:
            i = i + 1
        self.assertEquals(i, 1)
        # Performance test
        keys = 1000
        for i in range(1, keys + 1):
            sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                            rpdLcceIpAddr='10.1.2.10',
                                            direction=1,
                                            l2tpSessionId=i)
            sessRecord.write()
        print("current time is: %s" % str(datetime.fromtimestamp(time.time())))
        ret = sessRecord.get_next_n(count=keys)
        print("End time is: %s" % str(datetime.fromtimestamp(time.time())))

        print("current time is: " + str(datetime.fromtimestamp(time.time())))
        ret = sessRecord.get_next_n(count=20)
        print("End time is: %s" % str(datetime.fromtimestamp(time.time())))
        print("current time is: %s" % str(datetime.fromtimestamp(time.time())))
        ret = sessRecord.get_all()
        # self.assertEquals(len(ret), test_count)
        print("End time is: %s" % str(datetime.fromtimestamp(time.time())))

    def test_delete(self):
        sessRecord = L2tpSessionRecord()
        keys = 1000
        for i in range(1, keys + 1):
            sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                            rpdLcceIpAddr='10.1.2.10',
                                            direction=1,
                                            l2tpSessionId=i)
            sessRecord.write()
        print("Before 1000 times delete: %s" % str(datetime.fromtimestamp(
            time.time())))
        for i in range(1, keys + 1):
            sessRecord.updateL2tpSessionKey(ccapLcceIpAddr='10.1.2.3',
                                            rpdLcceIpAddr='10.1.2.10',
                                            direction=1,
                                            l2tpSessionId=i)
            sessRecord.delete()
        print("After 1000 times delete: %s" % str(datetime.fromtimestamp(
            time.time())))

    def test_parseSessionType(self):
        sessRecord = L2tpSessionRecord()
        pw = L2tpSessionRecord.PW_PSP
        sestype = sessRecord.parseSessionType(pw)
        self.assertEquals(sestype, L2tpSessionRecord.SESSIONTYPE_PSP)

    def test_parseSessionSubType(self):
        sessRecord = L2tpSessionRecord()
        l2_subtype = 6
        subtype = sessRecord.parseSessionSubType(l2_subtype)
        self.assertEquals(subtype, L2tpSessionRecord.PSP_UEPI_SCQAM)

    def test_parseDirection(self):
        sessRecord = L2tpSessionRecord()
        rfChanList = [(0, L2tpSessionRecord.CHANTYPE_US_ATDMA, 1)]
        dir = sessRecord.parseDirection(rfChanList)
        self.assertEquals(dir, L2tpSessionKey.DIRECTION_RETURN)


if __name__ == "__main__":
    unittest.main()
