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
#

import unittest
import time

from rpd.dispatcher.timer import DpTimerManager, Timer


class TestTimer(unittest.TestCase):

    def test_essential(self):
        tmgr = DpTimerManager()
        self.assertEqual(tmgr._timers, {})

        t = 10
        mytimer1 = tmgr.add(t, object)
        next_timeout = tmgr.get_next_timeout()
        self.assertIsInstance(mytimer1, Timer)
        self.assertEqual(len(tmgr._timers), 1)
        self.assertAlmostEqual(t, next_timeout, places=2)

        tmgr.delete(mytimer1)
        self.assertEqual(len(tmgr._timers), 0)

        tmgr.delete(mytimer1)  # no exception allowed

    def test_internal_storage(self):
        tmgr = DpTimerManager()
        tmgr.add(0, object)
        tmgr.add(1, object)
        tmgr.add(2, object)

        timers = tmgr._timers

        self.assertIsInstance(timers, dict)
        self.assertEqual(len(timers), 3)
        for k in timers.keys():
            self.assertIsInstance(k, type(0.0))
            self.assertIsInstance(timers[k], dict)
            self.assertEqual(1, len(timers[k]))
            for kk in timers[k].keys():
                self.assertIsInstance(kk, Timer)
                self.assertIsInstance(timers[k][kk], tuple)
                self.assertEqual(4, len(timers[k][kk]))
                self.assertEqual(object, timers[k][kk][0])
                self.assertEqual(None, timers[k][kk][1])

    def test_get_timeouted(self):
        num_timers = 100

        tmgr = DpTimerManager()

        for i in xrange(num_timers):
            tmgr.add(0, i)
        time.sleep(0.2)

        res = tmgr._get_timeouted()

        self.assertEqual(len(res), num_timers)
        self.assertIsInstance(res, dict)
        for k in res.keys():
            self.assertIsInstance(k, Timer)
            self.assertIsInstance(res[k], tuple)
            self.assertEqual(len(res[k]), 4)
            self.assertIsInstance(res[k][0], object)
            self.assertIsNone(res[k][1])

if __name__ == '__main__':
    unittest.main()
