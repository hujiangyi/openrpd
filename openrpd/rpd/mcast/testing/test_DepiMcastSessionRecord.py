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
import datetime
import unittest
from rpd.mcast.src.DepiMcastSessionRecord import DepiMcastSessionRecord, DepiMcastSessionKey
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis
from rpd.common.utils import Convert


class test_DepiMcastSessionKey(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("MCAST", "Mcast.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_cmp(self):
        try:
            DepiMcastSessionKey("2123144")
        except Exception as e:
            self.fail(str(e))
        key1 = DepiMcastSessionKey("1&&10.79.31.1&&10.79.31.1&&1")
        key2 = DepiMcastSessionKey()
        for name in key2.__dict__.keys():
            delattr(key2, name)
        self.assertEqual(key1, key2)
        key2.IpAddrType = key1.IpAddrType
        self.assertEqual(key1, key2)
        key2.GroupIpAddr = key1.GroupIpAddr
        self.assertEqual(key1, key2)
        key2.SrcIpAddr = key1.SrcIpAddr
        self.assertEqual(key1, key2)
        key2.SessionId = key1.SessionId
        self.assertEqual(key1, key2)


class test_DepiMcastSessionRecord(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("MCAST", "Mcast.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

    def tearDown(self):
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

        stop_test_redis()

    def test_updateDepiMcastSessionKey(self):
        sessRec = DepiMcastSessionRecord()
        self.assertIsInstance(sessRec, DepiMcastSessionRecord)
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        self.assertEquals(sessRec.index.IpAddrType, 1)
        self.assertEquals(sessRec.index.SrcIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SessionId, 1)

    def test_updateDepiMcastSessionData(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        self.assertEquals(sessRec.index.IpAddrType, 1)
        self.assertEquals(sessRec.index.SrcIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SessionId, 1)
        testIP1 = "127.0.0.1"
        testIP2 = "127.0.0.2"
        testTime = Convert.pack_timestamp_to_string(time.time())
        sessRec.updateDepiMcastSessionData(LocalLcceIpAddr=testIP1, RemoteLcceIpAddr=testIP2,
                                           JoinTime=testTime)
        self.assertEquals(sessRec.LocalLcceIpAddr, testIP1)
        self.assertEquals(sessRec.RemoteLcceIpAddr, testIP2)
        self.assertEquals(sessRec.JoinTime, testTime)

    def test_no_dup_record(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        sessRec.write()
        sessRec = None
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        sessRec.write()
        ret = []
        for ses in sessRec.get_all():
            ret.append(ses)
        self.assertEquals(len(ret), 1)

    def test_readwrite(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        self.assertEquals(sessRec.index.IpAddrType, 1)
        self.assertEquals(sessRec.index.SrcIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SessionId, 1)
        sessRec.write()

        # get_all
        ret = []
        for ses in sessRec.get_all():
            ret.append(ses)
        self.assertEquals(len(ret), 1)

        sessRec = None
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        sessRec.read()
        self.assertEquals(sessRec.index.IpAddrType, 1)
        self.assertEquals(sessRec.index.GroupIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SrcIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SessionId, 1)
        self.assertEquals(sessRec.JoinTime, "")
        self.assertEquals(sessRec.LocalLcceIpAddr, "")
        self.assertEquals(sessRec.RemoteLcceIpAddr, "")

        # modify the property
        currtime = Convert.pack_timestamp_to_string(time.time())
        sessRec.JoinTime = currtime
        sessRec.write()
        sessRec.read()
        self.assertEquals(sessRec.index.IpAddrType, 1)
        self.assertEquals(sessRec.index.GroupIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SrcIpAddr, "10.79.31.1")
        self.assertEquals(sessRec.index.SessionId, 1)
        self.assertEquals(sessRec.JoinTime, currtime)
        self.assertEquals(sessRec.LocalLcceIpAddr, "")
        self.assertEquals(sessRec.RemoteLcceIpAddr, "")

        # get_all
        ret = []
        for ses in sessRec.get_all():
            ret.append(ses)
        self.assertEquals(len(ret), 1)

    def test_get_all(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        sessRec.write()
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.78.31.1", SessionId=1)
        sessRec.write()
        ret = []
        for ses in sessRec.get_all():
            ret.append(ses)
        self.assertEquals(len(ret), 2)

    def test_get_next_n(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=1)
        sessRec.write()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=2)
        sessRec.write()
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.78.31.1", SessionId=1)
        sessRec.write()
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.78.31.1", SessionId=2)
        sessRec.write()
        print "#########step 1: None key query, return value from the very first record"
        ret = []
        for record in sessRec.get_next_n(key=None, count=2):
            ret.append(record)
        self.assertEquals(len(ret), 2)

        print "#########step 2: key query, request count is larger than db have"
        record = DepiMcastSessionRecord()
        record.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.79.31.1", SessionId=2)
        test_key = record.index
        ret = []
        for record in sessRec.get_next_n(key=None, count=2):
            ret.append(record)
        self.assertEquals(len(ret), 2)

        print "#########step 3: key query, request key is larger than db have"
        record = DepiMcastSessionRecord()
        record.updateDepiMcastSessionKey(IpAddrType=1, GroupIpAddr="10.79.31.1", SrcIpAddr="10.90.31.1", SessionId=1)
        ret = []
        for record in sessRec.get_next_n(key=None, count=2):
            ret.append(record)
        self.assertEquals(len(ret), 2)

    def test_performance(self):
        sessRec = DepiMcastSessionRecord()
        test_count = 1000
        print "#########: perfermance test about %s session in store" % test_count
        current_time = time.time()
        print "current time is: " + str(datetime.datetime.fromtimestamp(current_time))
        for test_session in range(0, test_count):
            sessRec.updateDepiMcastSessionKey(IpAddrType=1,
                                              GroupIpAddr="10.79.31.1",
                                              SrcIpAddr="10.90.31.1",
                                              SessionId=test_session)
            test_time = Convert.pack_timestamp_to_string(time.time())
            sessRec.updateDepiMcastSessionData("10.1.1.1", "1.1.1.1", test_time)
            sessRec.write()
        print "Write " + str(test_count) + " records need : " + str(time.time() - current_time)
        current_time = time.time()
        ret = []
        for record in sessRec.get_next_n(count=test_count):
            ret.append(record)
        self.assertEquals(len(ret), test_count)
        print "get_next_n " + str(test_count) + " records need : " + str(time.time() - current_time)

        print "current time is: " + str(datetime.datetime.fromtimestamp(time.time()))
        current_time = time.time()
        ret = []
        for record in sessRec.get_next_n(count=20):
            ret.append(record)
        self.assertEquals(len(ret), 20)
        end_time = time.time()
        print "get_next_n " + str(20) + " records need : " + str(end_time - current_time)
        print "End time is: " + str(datetime.datetime.fromtimestamp(end_time))
        self.assertEquals(len(ret), 20)

        current_time = time.time()
        ret = []
        for ses in sessRec.get_all():
            ret.append(ses)
        print "get_next_all " + str(test_count) + " records need : " + str(time.time() - current_time)
        self.assertEquals(len(ret), test_count)

    def test_write(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.LocalLcceIpAddr = "0.0.0.0"
        sessRec.write()
        sessRec.LocalLcceIpAddr = "134.123.123.213"
        sessRec.write()
        sessRec.read()
        self.assertEquals(sessRec.LocalLcceIpAddr, "134.123.123.213")

    def test_get_all_ipv6(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1,
                                          GroupIpAddr="2001::1",
                                          SrcIpAddr="2001::1",
                                          SessionId=1)
        sessRec.write()
        ret = []
        for ses in sessRec.get_all():
            ret.append(ses)
        self.assertEquals(len(ret), 1)


if __name__ == "__main__":
    unittest.main()
