#
# Copyright (c) 2016 Cisco and/or its affiliates, and
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
import unittest
from rpd.mcast.src.mcast import Mcast, McastException
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.rpd_logging import setup_logging
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis


class test_Mcast(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging('MCAST', filename="Mcast.log")
        setup_test_redis()
        for key in Mcast.McastDb.keys():
            Mcast.McastDb[key].close()

    @classmethod
    def tearDownClass(cls):
        stop_test_redis()
        for key in Mcast.McastDb.keys():
            Mcast.McastDb[key].close()

    def test_join(self):
        session = ("127.0.0.1", "127.0.0.1", 1233, 12323)
        mcast = Mcast(address=("127.0.0.1", "5.5.5.1", "229.1.1.255", 0))
        self.assertIn(("127.0.0.1", "5.5.5.1", "229.1.1.255", 0), Mcast.McastDb.keys())
        self.assertIn(mcast, Mcast.McastDb.values())
        mcast.join(session)
        self.assertEqual(mcast.status, Mcast.JOINED)
        time.sleep(0.1)
        mcast.close()
        self.assertEqual(mcast.status, Mcast.LEAVED)
        self.assertNotIn(("127.0.0.1", "5.5.5.1", "229.1.1.255", 0), Mcast.McastDb.keys())
        self.assertNotIn(mcast, Mcast.McastDb.values())

    def test_Mcast_error(self):
        session = ("127.0.0.1", "127.0.0.1", 1233, 12323)
        try:
            mcast = Mcast(address=("127.0.0.8", "5.5.5.1", "229.1.1.255", 0))
        except Exception as e:
            self.assertIsInstance(e, McastException)
        try:
            mcast = Mcast(None)
        except Exception as e:
            self.assertIsInstance(e, McastException)
        try:
            mcast = Mcast(address=("127.0.0.1", "5.5.5.1"))
        except Exception as e:
            self.assertIsInstance(e, McastException)

        try:
            mcast = Mcast.findMcastInstance(address=("127.0.0.1", "5.5.5.1"))
        except McastException as e:
            self.assertEqual(str(e), "init address %s is not expected" % str(("127.0.0.1", "5.5.5.1")))

        mcast = Mcast(address=("127.0.0.1", "5.5.5.1", "229.1.1.255", 1))
        mcast.join(session)
        self.assertEqual(mcast.status, Mcast.NOT_JOINED)

        mcast = Mcast(address=("127.0.0.1", "5.5.5.1", "229.1.1.255", 60002))
        mcast.join(session)
        self.assertEqual(mcast.status, Mcast.JOINED)
        mcast.leave(session)

    def test_join_1(self):
        session = ("127.0.0.1", "127.0.0.1", 1233, 12323)
        address_1 = ("127.0.0.1", "5.5.5.1", "229.1.1.255", 0)
        address_2 = ("127.0.0.1", "7.5.5.2", "229.1.1.255", 0)
        address_3 = ("127.0.0.1", "3.5.5.2", "228.1.1.255", 0)

        mcast = Mcast(address=address_1)
        self.assertIn(("127.0.0.1", "5.5.5.1", "229.1.1.255", 0), Mcast.McastDb.keys())
        self.assertIn(mcast, Mcast.McastDb.values())
        mcast.rejoin()
        self.assertEqual(mcast.status, Mcast.NOT_JOINED)
        mcast.join(session)
        self.assertEqual(mcast.status, Mcast.JOINED)
        time.sleep(0.1)
        # no operation in joined status
        mcast.join(session)
        self.assertEqual(mcast.status, Mcast.JOINED)

        mcast_3 = Mcast(address=address_3)
        self.assertIn(address_3, Mcast.McastDb.keys())
        time.sleep(0.1)
        # no operation in joined status
        mcast_3.join(session)
        self.assertEqual(mcast_3.status, Mcast.JOINED)

        try:
            mcast_test = Mcast.findMcastInstance(None)
        except McastException as e:
            pass

        mcast_test = Mcast.findMcastInstance(address_1)

        self.assertEqual(mcast_test.status, Mcast.JOINED)
        self.assertEqual(mcast_test, mcast)

        try:
            mcast = Mcast(address=address_1)
        except McastException as e:
            self.assertEqual(str(e), "init address %s was already initiated" % str(address_1))

        mcast_test = Mcast.findMcastInstance(address_2)
        self.assertIsNone(mcast_test)

        mcast_2 = Mcast(address=address_2)
        self.assertIn(("127.0.0.1", "5.5.5.1", "229.1.1.255", 0), Mcast.McastDb.keys())
        self.assertIn(mcast_2, Mcast.McastDb.values())
        mcast_2.join(session)
        self.assertEqual(mcast_2.status, Mcast.JOINED)

        time.sleep(0.1)
        mcast_3.close()
        mcast.close()
        self.assertEqual(mcast.status, Mcast.LEAVED)
        time.sleep(1)
        self.assertNotIn(("127.0.0.1", "5.5.5.1", "229.1.1.255", 0), Mcast.McastDb.keys())
        self.assertNotIn(Mcast, Mcast.McastDb.values())
        for key in Mcast.McastDb.keys():
            Mcast.McastDb[key].close()
        time.sleep(1)
        self.assertEqual(len(Mcast.McastDb), 0)

    def test_multi_session_join(self):
        session_1 = ("127.0.0.1", "127.0.0.1", 1, 1)
        session_2 = ("127.0.0.1", "127.0.0.1", 2, 2)
        session_3 = ("127.0.0.1", "127.0.0.1", 3, 3)
        address = ("127.0.0.1", "5.5.5.1", "229.1.1.255", 0)
        mcast = Mcast(address=address)
        self.assertIn(("127.0.0.1", "5.5.5.1", "229.1.1.255", 0), Mcast.McastDb.keys())
        self.assertIn(mcast, Mcast.McastDb.values())
        mcast.join(session_1)
        time.sleep(0.1)
        self.assertEqual(mcast.status, Mcast.JOINED)
        self.assertIn(session_1, mcast.sessionList)
        mcast.join(session_2)
        self.assertIn(session_1, mcast.sessionList)
        self.assertIn(session_2, mcast.sessionList)
        mcast.leave(session_1)
        time.sleep(0.1)
        self.assertNotIn(session_1, mcast.sessionList)
        self.assertIn(session_2, mcast.sessionList)
        self.assertEqual(mcast.status, Mcast.JOINED)
        mcast.leave(session_3)
        self.assertNotIn(session_1, mcast.sessionList)
        self.assertIn(session_2, mcast.sessionList)
        self.assertEqual(mcast.status, Mcast.JOINED)
        mcast.leave(session_2)
        time.sleep(0.1)
        self.assertEqual(0, len(mcast.sessionList))
        self.assertEqual(mcast.status, Mcast.LEAVED)

    def test_interface_check(self):
        address = ("127.0.0.1", "5.5.5.1", "229.1.1.255", 0)
        session_1 = ("127.0.0.1", "127.0.0.1", 1, 1)
        mcast = Mcast(address=address)
        mcast.join(session_1)
        time.sleep(1)
        mcast.rejoin()
        mcast.interface_state_change("lo", 'UP')
        self.assertEqual(mcast.interfaceList['lo'], Mcast.interface_up)
        mcast.interface_state_change("lo", 'DOWN')
        self.assertEqual(mcast.interfaceList['lo'], Mcast.interface_down)
        mcast.interface_state_change("lo", 'UP')
        self.assertEqual(mcast.interfaceList['lo'], Mcast.interface_up)
        for key in mcast.McastDb.keys():
            mcast.McastDb[key].close()

    def test_mld_join(self):
        session_1 = ("::1", "::1", 1, 1)
        session_2 = ("::1", "::1", 2, 2)
        session_3 = ("::1", "::1", 3, 3)
        address = ("::1", "2001::1", "ff15:7079:7468:6f6e:6465:6d6f:6d63:6173", 0)
        mcast = Mcast(address=address)
        self.assertIn(address, Mcast.McastDb.keys())
        self.assertIn(mcast, Mcast.McastDb.values())
        mcast.join(session_1)
        time.sleep(0.1)
        self.assertEqual(mcast.status, Mcast.JOINED)
        self.assertIn(session_1, mcast.sessionList)
        mcast.join(session_2)
        self.assertIn(session_1, mcast.sessionList)
        self.assertIn(session_2, mcast.sessionList)
        mcast.leave(session_1)
        time.sleep(0.1)
        self.assertNotIn(session_1, mcast.sessionList)
        self.assertIn(session_2, mcast.sessionList)
        self.assertEqual(mcast.status, Mcast.JOINED)
        mcast.leave(session_3)
        self.assertNotIn(session_1, mcast.sessionList)
        self.assertIn(session_2, mcast.sessionList)
        self.assertEqual(mcast.status, Mcast.JOINED)
        mcast.leave(session_2)
        time.sleep(0.1)
        self.assertEqual(0, len(mcast.sessionList))
        self.assertEqual(mcast.status, Mcast.LEAVED)


if __name__ == "__main__":
    unittest.main()
