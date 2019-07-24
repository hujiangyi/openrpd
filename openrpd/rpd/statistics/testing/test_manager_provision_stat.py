#copyright (c) 2017 Cisco and/or its affiliates, and
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
import time
import threading
from collections import OrderedDict
from rpd.provision.manager.src.manager_process import ManagerProcess
import rpd.provision.manager.src.manager_fsm as ManagerFsm
from rpd.statistics.manager_provision_stat import ManagerProvisionStateMachineRecord

uTMgrProcess = None
uTMgrApiDispatch = None

def demoMgrProcess():
    global uTMgrProcess
    global uTMgrApiDispatch
    print "demoMgrProcess thread start!"
    uTMgrProcess = ManagerProcess(test_flag=True)
    uTMgrApiDispatch = uTMgrProcess.dispatcher
    uTMgrProcess.start()
    print "demoMgrProcess thread done!"

class TestManagerProvisionStat(unittest.TestCase):

    """test fmt_timestamp and update."""

    @classmethod
    def setUpClass(cls):
        global uTMgrProcess
        t = threading.Thread(target=demoMgrProcess)
        t.start()
        time.sleep(2)
        cls.mgr = uTMgrProcess


    @classmethod
    def tearDownClass(cls):
        global uTMgrProcess
        global uTMgrApiDispatch
        if uTMgrProcess is not None:
            uTMgrProcess.dispatcher.fd_unregister(uTMgrProcess.mgr_api.manager_api_sock.sock)
            time.sleep(1)
            uTMgrProcess.mgr_api.manager_api_sock.sock.close()
        if uTMgrApiDispatch is not None:
            print "end loop here"
            uTMgrApiDispatch.end_loop()
            time.sleep(2)

    def setUp(self):
        self.object_statistics = ManagerProvisionStateMachineRecord()

    def tearDown(self):
        self.object_statistics = None

    def test_cleanup(self):
        self.object_statistics.cleanup()
        self.assertTrue(self.object_statistics.statistics == {})

    def test_fmt_timestamp(self):
        current_time = 1509567005.51
        self.assertEqual(self.object_statistics.fmt_timestamp(current_time), '2017 Nov 01 20:10:05:510000')

    def _fsm_enter_state_init(self, event):
        """Called when event triggered."""
        print ("Entering state %s from state %s, triggered by event:%s." % (event.fsm.current,
                                                                            event.src, event.event))
        self.object_statistics.update(self.mgr, event)
        print(self.object_statistics.statistics)

    def test_update(self):
        callbacks = [
            {
                "Type": "event",
                "Name": ManagerFsm.ManagerFsm.EVENT_STARTUP,
                "TrackPoint": "on",
                "Handler": self._fsm_enter_state_init,
            },
        ]
        self.fsm = ManagerFsm.ManagerFsm(callbacks=callbacks)
        self.fsm.Startup()


if __name__ == '__main__':
    unittest.main()
