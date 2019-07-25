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
from rpd.confdb.rpd_nettophy_rec import IpNettophyRec
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis


class test_IpNettophyKey(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("IpNettophy", "IpNettophy.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass


class test_IpNettophyRec(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("IpNettophy", "IpNettophy.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()
        # clear db records
        rec = IpNettophyRec()
        rec.delete_all()

    def tearDown(self):
        # clear db records
        rec = IpNettophyRec()
        rec.delete_all()
        stop_test_redis()

    def test_markAsDel(self):
        rec = IpNettophyRec()
        rec.index.IpAddress = "123.123.123.123"
        rec.write()
        rec.markAsDel()
        rec.read()
        self.assertEqual(rec.Type, IpNettophyRec.NEIGH_TYPE_INVALID)

    def test_updateRec(self):
        rec = IpNettophyRec()
        item = {'EnetPortIndex': 1,
                'AddrType': 1,
                'IpAddress': '1.1.1.1',
                'PhysAddress': 'aa:aa:aa:aa:aa:aa',
                'LastUpdated': 1,
                'Type': 1,
                'State': 1}
        rec.updateRec(item)
        rec.write()
        rec.PhysAddress = 'bb:bb:bb:bb:bb:bb'
        rec.LastUpdate = 0
        rec.Type = 0
        rec.State = 0
        rec.read()
        self.assertEqual(rec.PhysAddress, 'aa:aa:aa:aa:aa:aa')
        self.assertEqual(rec.LastUpdated, 1)
        self.assertEqual(rec.Type, 1)
        self.assertEquals(rec.State, 1)


if __name__ == "__main__":
    unittest.main()
