#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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

import json
import os
import subprocess
from unittest import TestCase
import time
import unittest
from rpd.confdb.rpd_redis_db import RCPDB, DBRecord, RPDAllocateWriteRecord


CONF_FILE = '/tmp/rcp_db.conf'
SOCKET_PATH = '/tmp/testRedis.sock'


def create_db_conf():
    conf_dict = {}
    conf_dict['RES_DB_NUM'] = 2
    conf_dict['DB_SOCKET_PATH'] = SOCKET_PATH
    with open(CONF_FILE, 'w') as f:
        f.writelines(json.dumps(conf_dict))
        f.close()


def start_redis():
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        SOCKET_PATH + " \nunixsocketperm 700\n"
    filename = "/tmp/test_halmgr.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)
        f.close

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(SOCKET_PATH):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")


def stop_redis():
    subprocess.call("killall redis-server".split())
    time.sleep(2)


def setup_test_redis():
    create_db_conf()
    start_redis()
    RCPDB.DB_CFG_FILE = CONF_FILE
    assert RCPDB().redis_db is not None


def stop_test_redis():
    stop_redis()
    os.remove(CONF_FILE)


class SubRCPDBRecord(DBRecord):

    def __init__(self):
        self.index = 0
        self.value = "test"


class SubRCPAllocaWriteRecord(RPDAllocateWriteRecord):

    MAX_INDEX = 0xF

    def __init__(self):
        super(SubRCPAllocaWriteRecord, self).__init__(
            SubRCPAllocaWriteRecord.MAX_INDEX)
        self.index = 0
        self.value = "test"


class SubRCPAllocaWriteRecord1(RPDAllocateWriteRecord):

    MAX_INDEX = 0xFF

    def __init__(self):
        super(SubRCPAllocaWriteRecord1, self).__init__(
            SubRCPAllocaWriteRecord1.MAX_INDEX)
        self.index = 0
        self.ip = "127.0.0.1"


class Sub2RCPAllocaWriteRecord(RPDAllocateWriteRecord):

    MAX_INDEX = 0xFF

    def __init__(self):
        super(Sub2RCPAllocaWriteRecord, self).__init__(
            Sub2RCPAllocaWriteRecord.MAX_INDEX)
        self.index = 0
        self.ip = "127.0.0.1"


class TestRCPDBRecord(TestCase):

    @classmethod
    def setUpClass(cls):
        create_db_conf()
        start_redis()
        RCPDB.DB_CFG_FILE = CONF_FILE

    @classmethod
    def tearDownClass(cls):
        stop_redis()
        os.remove(CONF_FILE)

    def setUp(self):
        self.record = SubRCPDBRecord()
        self.record.index = 1
        self.record.value = "test1"
        self.db = RCPDB()

    def test_db_singleton(self):
        db2 = RCPDB()
        db3 = RCPDB()
        self.assertEqual(db2, self.db)
        self.assertEqual(id(db2), id(self.db))
        self.assertEqual(id(db3), id(self.db))

    def test_save_read(self):
        self.record.write()
        record1 = SubRCPDBRecord()
        record1.index = 1
        record1.read()
        self.assertEqual(self.record.index, record1.index)
        self.assertEqual(self.record.value, record1.value)
        self.record.delete()
        record1.value = 'test2'
        record1.read()
        self.assertEqual(record1.value, "test2")

    def test_RPDAllocateWriteRecord(self):
        self.awRecord = SubRCPAllocaWriteRecord()
        self.awRecord.allocateIndex(12)
        self.awRecord.value = "test2"
        self.awRecord.write()
        self.assertEqual(len(self.awRecord.getIndexPool()), 0xF - 1)
        self.assertEqual(self.awRecord.index, 12)
        self.awRecord1 = SubRCPAllocaWriteRecord()
        self.awRecord1.allocateIndex(11)
        self.awRecord1.value = "index111"
        self.awRecord1.write()
        self.assertEqual(len(self.awRecord1.getIndexPool()), 0xF - 2)
        self.assertEqual(self.awRecord1.index, 11)
        self.awRecord2 = Sub2RCPAllocaWriteRecord()
        self.awRecord2.allocateIndex()
        self.awRecord2.ip = "127.0.0.1"
        self.awRecord2.write()
        self.assertEqual(len(self.awRecord2.getIndexPool()), 0xFF - 1)
        self.awRecord3 = SubRCPAllocaWriteRecord1()
        self.assertEqual(len(self.awRecord3.getIndexPool()), 0xFF)
        self.awRecord.delete()
        self.awRecord1.delete()
        self.awRecord2.delete()
        self.awRecord2.index = 333
        self.awRecord2.delete()
        self.assertEqual(len(self.awRecord2.getIndexPool()),
                         Sub2RCPAllocaWriteRecord.MAX_INDEX)

    def test_unexpect_AWDB(self):
        self.awRecord = SubRCPAllocaWriteRecord()
        self.awRecord.allocateIndex(12)
        self.awRecord.value = "test2"
        self.awRecord.write()
        self.assertEqual(len(self.awRecord.getIndexPool()), 0xF - 1)
        self.awRecord1 = SubRCPAllocaWriteRecord()
        self.awRecord1.allocateIndex(13)
        self.awRecord1.value = "test3"
        self.awRecord1.write()
        self.assertEqual(len(self.awRecord1.getIndexPool()), 0xF - 2)
        self.awRecord.delete()
        self.awRecord1.delete()
        self.awRecord1 = SubRCPAllocaWriteRecord()
        self.awRecord1.index = 11
        self.awRecord1.value = "index11"
        self.awRecord1.write()
        self.assertEqual(len(self.awRecord1.getIndexPool()), 0xF - 1)
        self.awRecord1.delete()
        self.awRecord1.index = 11
        self.awRecord1.delete()


if __name__ == "__main__":
    unittest.main()
