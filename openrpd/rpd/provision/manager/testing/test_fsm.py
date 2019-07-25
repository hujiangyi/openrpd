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

import unittest
import rpd.provision.manager.src.manager_fsm as CCAPFsm


class TestProvisionFsm(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.callbacks_startup = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_INIT,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_INTERFACE_UP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_8021X_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_DHCP_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_TOD_OK,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_FAIL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsmStartup.STATE_CHANGE,
                "TrackPoint": ("on",),
                "Handler": self.callback,
            },
            # event callbacks
        ]
        self.callbacks_gcp = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_IPSEC,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_REINIT_IPSEC,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_FAIL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_CHANGE,
                "TrackPoint": ("on",),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT_TCP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT_GCP_IRA,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT_GCP_CFG,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT_GCP_CFG_CPL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT_GCP_OP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_REINIT_TCP,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_REINIT_GCP_IRA,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_ONLINE,
                "TrackPoint": ("on",),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_ONLINE,
                "TrackPoint": ("leave",),
                "Handler": self.callback,
            },
        ]
        self.callbacks_mgr = [
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_STARTUP,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_INTERFACE_SCAN,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_USER_MGMT,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_GCP_MGMT,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_DHCP,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_STARTUP_DHCP_OK,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_PROVISION_INTERFACE_FAIL,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_OPERATIONAL,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_OPERATIONAL,
                "TrackPoint": "leave",
                "Handler": self.callback,
            },
            {
                "Type": "event",
                "Name": CCAPFsm.ManagerFsm.EVENT_CORE_FAIL,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_FAIL,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_PRINCIPLE_RETRY_FIRST,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_PRINCIPLE_RETRY_SECOND,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_PRINCIPLE_RETRY_THIRD,
                "TrackPoint": ("reenter", "on"),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_CHANGE,
                "TrackPoint": ("on",),
                "Handler": self.callback,
            },
            {
                "Type": "state",
                "Name": CCAPFsm.ManagerFsm.STATE_PRINCIPAL_FOUND,
                "TrackPoint": ("on", "reenter"),
                "Handler": self.callback,
            },
        ]
        self.cb_cnt = 0
        self.cb_cnt = 0

    def tearDown(self):
        self.cb_cnt = 0

    def callback(self, event):
        print ("Entering state %s from state %s, triggered by event:%s." % (event.fsm.current,
                                                                            event.src, event.event))
        self.cb_cnt += 1

    def test_fsm_state_callbacks(self):
        """test FsmBase callback generate process."""
        print("Test event state callback about FsmBase")
        callbacks = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT_IPSEC,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test event state callback about FsmBase")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": ["on"],
                "Handler": self.callback,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test event state enter list callback about FsmBase")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": ["before"],
                "Handler": self.callback,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test event state enter string callback about FsmBase")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": "after",
                "Handler": self.callback,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test leave event callback, will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": "leave",
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test leave event in list callback, also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": ["leave"],
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test leave event in dict callback, also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": {"leave"},
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test event name not support, also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "event",
                "Name": "Not Supported",
                "TrackPoint": "on",
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test state TrackPoint not support, also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": "Not Supported",
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test state TrackPoint in list not support, also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": ["Not Supported"],
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test state TrackPoint in dict , also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": {"on"},
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test state Name not support , also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "state",
                "Name": "Not Supported",
                "TrackPoint": "on",
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test Type not support , also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "Not Supported",
                "Name": CCAPFsm.CCAPFsm.EVENT_STARTUP,
                "TrackPoint": "on",
                "Handler": self.callback,
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

        print("Test state handler isn't callable, also will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_FAIL,
                "TrackPoint": 'on',
                "Handler": 'Not Callable',
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

    def _fsm_enter_state_callback(self, event):
        print ("Entering state %s from state %s, triggered by event:%s." % (event.fsm.current,
                                                                            event.src, event.event))

    def test_fsm_CCAPFsm(self):
        fsm = CCAPFsm.CCAPFsm(callbacks=self.callbacks_gcp)
        fsm.TRIGGER_Startup()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_INIT_IPSEC)
        fsm.TRIGGER_IPSEC_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_INIT_TCP)
        fsm.TRIGGER_TCP_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_INIT_GCP_IRA)
        fsm.TRIGGER_GCP_IRA()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_INIT_GCP_CFG)
        fsm.TRIGGER_GCP_CFG()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_INIT_GCP_CFG_CPL)
        fsm.TRIGGER_GCP_CFG_CPL()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_INIT_GCP_OP)
        fsm.TRIGGER_GCP_OP()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_ONLINE)
        fsm.TRIGGER_TCP_FAIL()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_REINIT_IPSEC)
        fsm.TRIGGER_IPSEC_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_REINIT_TCP)
        fsm.TRIGGER_TCP_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_REINIT_GCP_IRA)
        fsm.TRIGGER_GCP_IRA()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_ONLINE)

        # other branch
        fsm.TRIGGER_GCP_NO_CFG_CPL()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsm.STATE_ONLINE)

    def test_fsm_CCAPFsmStartup(self):
        fsm = CCAPFsm.CCAPFsmStartup(callbacks=self.callbacks_startup)
        fsm.TRIGGER_Startup()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsmStartup.STATE_INIT)
        fsm.TRIGGER_INTERFACE_UP()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsmStartup.STATE_INTERFACE_UP)
        fsm.TRIGGER_MAC_8021X_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsmStartup.STATE_8021X_OK)
        fsm.TRIGGER_DHCP_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsmStartup.STATE_DHCP_OK)
        fsm.TRIGGER_TOD_OK()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsmStartup.STATE_TOD_OK)
        # other branch
        fsm.TRIGGER_DHCP_FAIL()
        self.assertEqual(fsm.current, CCAPFsm.CCAPFsmStartup.STATE_8021X_OK)

    def test_fsm_ManagerFsm(self):
        fsm = CCAPFsm.ManagerFsm(callbacks=self.callbacks_mgr)
        self.assertIsInstance(fsm, CCAPFsm.ManagerFsm)
        fsm.Startup()
        result = fsm.is_startup()
        self.assertTrue(result)
        fsm.INTERFACE_SCAN()
        result = fsm.is_startup()
        self.assertTrue(result)
        result = fsm.is_provisioning()
        self.assertFalse(result)
        fsm.STARTUP_DHCP_OK()
        result = fsm.is_provisioning()
        self.assertTrue(result)
        result = fsm.is_startup()
        self.assertFalse(result)
        fsm.SEEK_PRINCIPAL_FAIL()
        result = fsm.is_provision_retry()
        self.assertTrue(result)
        result = fsm.is_principal_found()
        self.assertFalse(result)
        result = fsm.is_operational()
        self.assertFalse(result)
        fsm.SEEK_PRINCIPAL_OK()
        result = fsm.is_principal_found()
        self.assertTrue(result)
        fsm.OPERATIONAL_OK()
        result = fsm.is_operational()
        self.assertTrue(result)
        result = fsm.is_fail()
        self.assertFalse(result)
        fsm.Error()
        result = fsm.is_fail()
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
