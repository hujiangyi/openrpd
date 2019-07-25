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
#

import unittest
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis
from rpd.mcast.src.DepiMcastSessionRecord import DepiMcastSessionRecord
import time
import datetime
from rpd.gpb.cfg_pb2 import config
from rpd.rcp.rcp_lib.arrayTLVRead import ArrayTLVRead, ArrayTLVReadException
from rpd.rcp.rcp_lib.rcp_tlv_def import C100_DepiMcastSession_5, C100_DiagnosticStatus_4
from rpd.common.utils import Convert
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging


class test_ArrayTLVRead(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("GCP", "gcp.log")
        setup_test_redis()
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

    @classmethod
    def tearDownClass(cls):
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()
        stop_test_redis()

    def setUp(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

    def tearDown(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

    def create_ipv4_ipv6_record(self, test_count=1000):
        sessRec = DepiMcastSessionRecord()
        print "#########: write %s session in db." % (test_count * 2)
        current_time = time.time()
        print "current time is: " + str(datetime.datetime.fromtimestamp(current_time))
        for test_session in range(0, test_count):
            sessRec.updateDepiMcastSessionKey(IpAddrType=1,
                                              GroupIpAddr="10.79.31.1",
                                              SrcIpAddr="10.90.31.1",
                                              SessionId=test_session + 1)
            test_time = Convert.pack_timestamp_to_string(time.time())

            sessRec.updateDepiMcastSessionData("10.1.1.1", "1.1.1.1", time.time())
            sessRec.write()
            sessRec.updateDepiMcastSessionKey(IpAddrType=2,
                                              GroupIpAddr="2001::1",
                                              SrcIpAddr="2001::2",
                                              SessionId=test_session + 1)

            sessRec.updateDepiMcastSessionData("2001::1", "2001::1", test_time)
            sessRec.write()
        current_time = time.time()
        print "end time is: " + str(datetime.datetime.fromtimestamp(current_time))
        return True

    def test_gpb_array_read_readcout_with_key(self):
        self.assertTrue(self.create_ipv4_ipv6_record())
        data = config()
        readCount = 3
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        item.IpAddrType = 1
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record, readCount)
        for item in gpb:
            self.assertEqual(len(item.ListFields()), 6)
            self.assertEqual(item.IpAddrType, 1)
            self.assertFalse(item.HasField("JoinTime"))
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), readCount)

    def test_gpb_array_read_readcout_without_key(self):
        self.assertTrue(self.create_ipv4_ipv6_record())
        data = config()
        readCount = 3
        gpb = data.RpdInfo.DepiMcastSession
        gpb.add()
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record, readCount)
        for item in gpb:
            print item
            self.assertEqual(len(item.ListFields()), 6)
            self.assertFalse(item.HasField("JoinTime"))
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), readCount)

    def test_gpb_array_read_readcout_with_leaf(self):
        self.assertTrue(self.create_ipv4_ipv6_record())
        data = config()
        readCount = 10
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        item.IpAddrType = 2
        value = getattr(item, "LocalLcceIpAddr")
        setattr(item, "LocalLcceIpAddr", value)
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record, readCount)
        for item in gpb:
            self.assertEqual(len(item.ListFields()), 5)
            self.assertEqual(item.IpAddrType, 2)
            self.assertFalse(item.HasField("JoinTime"))
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), readCount)

    def test_gpb_array_read_read_all(self):
        test_count = 1000
        self.assertTrue(self.create_ipv4_ipv6_record(test_count))
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), test_count * 2)

    def test_gpb_array_read_read_with_keys(self):
        test_count = 10
        self.assertTrue(self.create_ipv4_ipv6_record(test_count))
        print "============ 1: key is in db==============="
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        item.IpAddrType = 2
        item.GroupIpAddr = "2001::1"
        item.SrcIpAddr = "2001::2"
        item.SessionId = 1
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), 1)
        self.assertTrue(len(data.RpdInfo.DepiMcastSession[0].ListFields()), 6)
        print "============ 2: key is not in db==============="
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        item.IpAddrType = 2
        item.GroupIpAddr = "2001:1::1"
        item.SrcIpAddr = "2001::2"
        item.SessionId = 1
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), 1)
        self.assertEqual(len(data.RpdInfo.DepiMcastSession[0].ListFields()), 5)
        print "============ 3: request keys is in db==============="
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        for ses in (0, test_count):
            item = gpb.add()
            item.IpAddrType = 2
            item.GroupIpAddr = "2001::1"
            item.SrcIpAddr = "2001::2"
            item.SessionId = ses + 1
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertTrue(len(data.RpdInfo.DepiMcastSession), test_count)

    def test_gpb_array_read_read_with_partial_keys(self):
        test_count = 1000
        self.assertTrue(self.create_ipv4_ipv6_record(test_count))
        print "============ 1: request partial keys is in db==============="
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        for ses in range(0, test_count):
            item = gpb.add()
            item.SessionId = ses + 1
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertEqual(len(data.RpdInfo.DepiMcastSession), test_count * 2)

    def test_gpb_array_read_read_with_partial_two_keys(self):
        test_count = 1000
        self.assertTrue(self.create_ipv4_ipv6_record(test_count))
        print "============ 1: request partial keys is in db==============="
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        item.IpAddrType = 1
        item.GroupIpAddr = "10.79.31.1"
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertEqual(len(data.RpdInfo.DepiMcastSession), test_count)

    def test_gpb_array_read_read_with_partial_leaf(self):
        test_count = 1000
        self.assertTrue(self.create_ipv4_ipv6_record(test_count))
        print "============ 1: request partial leaf is in db==============="
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        item.LocalLcceIpAddr = "10.1.1.1"
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        self.assertEqual(len(data.RpdInfo.DepiMcastSession), test_count * 2)

    def test_gpb_array_read_invalid_read(self):
        data = config()
        gpb = data.RpdInfo.DiagnosticStatus
        try:
            ArrayTLVRead(gpb, C100_DiagnosticStatus_4)
        except ArrayTLVReadException as e:
            self.assertEqual(str(e), "rcptlv is not Array instance")

        try:
            ArrayTLVRead(gpb, "test")
        except ArrayTLVReadException as e:
            self.assertEqual(str(e), "rcptlv is not an instance of RCPTLV")

        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        try:
            mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
            mcast_array.array_read("test")
        except ArrayTLVReadException as e:
            self.assertEqual(str(e), "record is not instance of RCPRecord")

    def test_invalid_key(self):
        sessRec = DepiMcastSessionRecord()
        sessRec.updateDepiMcastSessionKey(IpAddrType=1,
                                          GroupIpAddr="test",
                                          SrcIpAddr="10.90.31.1",
                                          SessionId=0x80010001)
        sessRec.updateDepiMcastSessionData("10.1.1.1", "1.1.1.1", time.time())
        sessRec.write()
        data = config()
        gpb = data.RpdInfo.DepiMcastSession
        item = gpb.add()
        record = DepiMcastSessionRecord()
        mcast_array = ArrayTLVRead(gpb, C100_DepiMcastSession_5)
        mcast_array.array_read(record)
        print gpb[0]
        self.assertEqual(len(data.RpdInfo.DepiMcastSession), 1)


if __name__ == "__main__":
    unittest.main()
