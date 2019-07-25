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
import unittest
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis
from rpd.provision.manager.src.dhcpinfoDb import DhcpInfoRecord


class test_DhcpInfoRecord(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.deleteAll()

    def tearDown(self):
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.deleteAll()
        stop_test_redis()

    def test_updateDhcpInfoKey(self):
        dhcpRecord = DhcpInfoRecord()
        # 1. default key
        dhcpRecord.updateDhcpInfoKey()
        self.assertEquals(dhcpRecord.index.interface, '')
        # 2. Add vbh0
        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        self.assertEquals(dhcpRecord.index.interface, 'vbh0')
        # 3. Add vbh1
        dhcpRecord.updateDhcpInfoKey(interface='vbh1')
        self.assertEquals(dhcpRecord.index.interface, 'vbh1')
        # 4. Add invalid interface
        dhcpRecord.updateDhcpInfoKey(interface='test')
        self.assertEquals(dhcpRecord.index.interface, 'test')

    def test_updateDhcpInfoRecordData(self):
        dhcpRecord = DhcpInfoRecord()

        # vbh0
        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        self.assertEquals(dhcpRecord.index.interface, 'vbh0')
        CreatedTime = 21117

        dhcpRecord.updateDhcpInfoRecordData(CreatedTime=CreatedTime)
        dhcpRecord.write()
        self.assertEquals(dhcpRecord.createdTime, CreatedTime)

        # vbh1
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.updateDhcpInfoKey(interface='vbh1')
        self.assertEquals(dhcpRecord.index.interface, 'vbh1')
        CreatedTime = 21118

        dhcpRecord.updateDhcpInfoRecordData(CreatedTime=CreatedTime)
        dhcpRecord.write()
        self.assertEquals(dhcpRecord.createdTime, CreatedTime)

    def test_readwrite(self):
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        dhcpRecord.write()
        rets = dhcpRecord.get_all()
        i = 0
        for ret in rets:
            i = i + 1
        self.assertEquals(i, 1)

        dhcpRecord.updateDhcpInfoKey(interface='vbh1')
        CreatedTime = 21117

        dhcpRecord.updateDhcpInfoRecordData(CreatedTime=CreatedTime)
        dhcpRecord.write()
        rets = dhcpRecord.get_all()
        i = 0
        for ret in rets:
            i = i + 1
        self.assertEquals(i, 2)

        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        dhcpRecord.read()
        self.assertEquals(dhcpRecord.index.interface, 'vbh0')

        dhcpRecord.updateDhcpInfoKey(interface='vbh1')
        dhcpRecord.read()
        self.assertEquals(dhcpRecord.createdTime, CreatedTime)

        dhcpRecord.createdTime = 88
        dhcpRecord.write()
        dhcpRecord.read()
        self.assertEquals(dhcpRecord.createdTime, 88)

    def test_get_all(self):
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        dhcpRecord.write()

        dhcpRecord.updateDhcpInfoKey(interface='vbh1')
        dhcpRecord.write()

        rets = dhcpRecord.get_all()
        i = 0

        for ret in rets:
            i = i + 1
        self.assertEquals(i, 2)

    def test_get_next_n(self):
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        dhcpRecord.write()

        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.updateDhcpInfoKey(interface='vbh1')
        dhcpRecord.write()

        # None key query.
        ret = dhcpRecord.get_next_n(key=None, count=1)
        i = 0
        for j in ret:
            i = i + 1
        self.assertEquals(i, 1)

        # Key is invalid
        dhcpRecord.updateDhcpInfoKey(interface='eth1')
        dhcpRecord.write()
        testKey = 'eth1'
        ret = dhcpRecord.get_next_n(key=testKey, count=2)
        i = 0
        for j in ret:
            i = i + 1
        self.assertEquals(i, 2)

        # Count is larger than db
        testKey = 'vbh0'
        ret = dhcpRecord.get_next_n(key=testKey, count=10)
        i = 0
        for j in ret:
            i = i + 1
        self.assertEquals(i, 3)

    def test_delete(self):
        dhcpRecord = DhcpInfoRecord()
        Interface_list = ['vbh0', 'vbh1']

        for intf in Interface_list:
            dhcpRecord.updateDhcpInfoKey(interface=intf)
            dhcpRecord.write()

        for key in Interface_list:
            dhcpRecord.updateDhcpInfoKey(interface=key)
            dhcpRecord.delete()

    def test_getDhcpInfoCreatedTime(self):
        dhcpRecord = DhcpInfoRecord()
        dhcpRecord.updateDhcpInfoKey(interface='vbh0')
        CreatedTime = 33333

        dhcpRecord.updateDhcpInfoRecordData(CreatedTime=CreatedTime)
        dhcpRecord.write()

        dhcpRecord.read()
        value_time = dhcpRecord.getDhcpInfoCreatedTime()
        self.assertEquals(value_time, CreatedTime)


if __name__ == "__main__":
    unittest.main()
