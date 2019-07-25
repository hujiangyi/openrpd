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

import unittest
from rpd.confdb.rpd_rcp_db_record import RCPDBRecord
from rpd.confdb.rpd_redis_db import DBRecord
from rpd.rcp.rcp_lib.rcpRecord import RCPRecord
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis


class test_RCPDBRecord(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        setup_test_redis()

    def tearDown(self):
        stop_test_redis()

    def test_init(self):
        test = RCPDBRecord()
        test.index = 1
        self.assertIsInstance(test, RCPRecord)
        self.assertIsInstance(test, DBRecord)
        self.assertEqual(test.get_index(), 1)


if __name__ == "__main__":
    unittest.main()
