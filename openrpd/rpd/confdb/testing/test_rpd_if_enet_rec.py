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
from rpd.confdb.rpd_if_enet_rec import RpdEnetRec
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis


class test_RpdIfStats(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("rpdIfStats", "rpdIfStats.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()
        # clear db records
        rec = RpdEnetRec()
        rec.delete_all()

    def tearDown(self):
        # clear db records
        rec = RpdEnetRec()
        rec.delete_all()
        stop_test_redis()

    def test_updateRec(self):
        rec = RpdEnetRec()
        item = {
            'EnetPortIndex': 1,
            'ifDescr': "cisco virtual back hal tge interface",
            'ifAlias': "rpd , a powerful product.",
            'ifPhysAddress': "192.168.1.1",
            'ifAdminStatus': 2,
            'ifLinkUpDownTrapEnable': 1,
            'ifInOctets': 56000,
            'ifInUnicastFrames': 3200,
            'ifInErrors': 88,
            'ifOutUnicastFrames': 9600,
        }
        rec.updateRec(item)
        rec.write()
        rec.index = 1
        rec.read()
        self.assertEqual(rec.ifAlias, 'rpd , a powerful product.')
        self.assertEqual(rec.ifLinkUpDownTrapEnable, 1)
        self.assertEqual(rec.ifAdminStatus, 2)
        self.assertEquals(rec.ifInUnicastFrames, 3200)


if __name__ == "__main__":
    unittest.main()
