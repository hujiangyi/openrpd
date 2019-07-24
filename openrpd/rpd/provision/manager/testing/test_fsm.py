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
    def test_principle_fsm(self):
        """test CCAPFsm state machine running procedure."""
        fsm = CCAPFsm.PrincipleCCAPFsm([])

        # test the straight normal case
        fsm.TRIGGER_Startup()
        fsm.TRIGGER_INTERFACE_UP()
        self.assertEqual(fsm.STATE_INTERFACE_UP, fsm.current)

        fsm.TRIGGER_MAC_8021X_OK()
        self.assertEqual(fsm.STATE_8021X_OK, fsm.current)

        fsm.TRIGGER_DHCP_OK()
        self.assertEqual(fsm.STATE_DHCP_OK, fsm.current)

        fsm.TRIGGER_TOD_OK()
        self.assertEqual(fsm.STATE_TOD_OK, fsm.current)

        fsm.TRIGGER_IPSEC_OK()
        self.assertEqual(fsm.STATE_IPSEC_OK, fsm.current)

        fsm.TRIGGER_RCP_OK()
        self.assertEqual(fsm.STATE_RCP_OK, fsm.current)

        fsm.TRIGGER_PTPT1588_OK()
        self.assertEqual(fsm.STATE_PTP1588_OK, fsm.current)
        # test "fail" case

        fsm.TRIGGER_PTP1588_FAIL()
        self.assertEqual(fsm.STATE_RCP_OK, fsm.current)

        fsm.TRIGGER_RCP_FAIL()
        self.assertEqual(fsm.STATE_IPSEC_OK, fsm.current)

        fsm.TRIGGER_IPSEC_FAIL()
        self.assertEqual(fsm.STATE_TOD_OK, fsm.current)

        fsm.TRIGGER_TOD_FAIL()
        self.assertEqual(fsm.STATE_DHCP_OK, fsm.current)

        fsm.TRIGGER_DHCP_FAIL()
        self.assertEqual(fsm.STATE_8021X_OK, fsm.current)

        fsm.TRIGGER_MAC_8021X_FAIL()
        self.assertEqual(fsm.STATE_INTERFACE_UP, fsm.current)

        fsm.TRIGGER_INTERFACE_DOWN()
        self.assertEqual(fsm.STATE_INIT, fsm.current)

        # test the random events
        fsm.TRIGGER_INTERFACE_UP()
        fsm.TRIGGER_MAC_8021X_OK()
        fsm.TRIGGER_DHCP_OK()
        fsm.TRIGGER_TOD_OK()
        fsm.TRIGGER_IPSEC_OK()
        fsm.TRIGGER_RCP_OK()
        fsm.TRIGGER_PTPT1588_OK()

        fsm.TRIGGER_INTERFACE_DOWN()

        self.assertEqual(fsm.STATE_INIT, fsm.current)

        fsm.TRIGGER_INTERFACE_UP()
        fsm.TRIGGER_MAC_8021X_OK()
        fsm.TRIGGER_DHCP_OK()
        fsm.TRIGGER_TOD_OK()
        fsm.TRIGGER_IPSEC_OK()
        fsm.TRIGGER_RCP_OK()
        fsm.TRIGGER_PTPT1588_OK()

        fsm.TRIGGER_RCP_FAIL()
        self.assertEqual(fsm.STATE_IPSEC_OK, fsm.current)

        # Test the timeout and can not reach
        fsm.TRIGGER_TIMEOUT()
        self.assertEqual(fsm.STATE_FAIL, fsm.current)

    def test_gcpp_principle_fsm(self):
        """test CCAPFsm state machine running procedure."""
        fsm = CCAPFsm.PrincipleCCAPFsm([])

        # test the straight normal case
        fsm.TRIGGER_Startup()
        fsm.TRIGGER_INTERFACE_UP()
        self.assertEqual(fsm.STATE_INTERFACE_UP, fsm.current)

        fsm.TRIGGER_MAC_8021X_OK()
        self.assertEqual(fsm.STATE_8021X_OK, fsm.current)

        fsm.TRIGGER_DHCP_OK()
        self.assertEqual(fsm.STATE_DHCP_OK, fsm.current)

        fsm.TRIGGER_TOD_OK()
        self.assertEqual(fsm.STATE_TOD_OK, fsm.current)

        fsm.TRIGGER_IPSEC_OK()
        self.assertEqual(fsm.STATE_IPSEC_OK, fsm.current)

        fsm.TRIGGER_RCP_OK()
        self.assertEqual(fsm.STATE_RCP_OK, fsm.current)

        fsm.TRIGGER_PTPT1588_OK()
        self.assertEqual(fsm.STATE_PTP1588_OK, fsm.current)

        fsm.TRIGGER_MOVE_OPERATIONAL()
        self.assertEqual(fsm.STATE_OPERATIONAL_OK, fsm.current)

        fsm.TRIGGER_PTP1588_FAIL()
        self.assertEqual(fsm.STATE_RCP_OK, fsm.current)

        fsm.TRIGGER_RCP_FAIL()
        self.assertEqual(fsm.STATE_IPSEC_OK, fsm.current)

        fsm.TRIGGER_IPSEC_FAIL()
        self.assertEqual(fsm.STATE_TOD_OK, fsm.current)

        fsm.TRIGGER_TOD_FAIL()
        self.assertEqual(fsm.STATE_DHCP_OK, fsm.current)

        fsm.TRIGGER_DHCP_FAIL()
        self.assertEqual(fsm.STATE_8021X_OK, fsm.current)

        fsm.TRIGGER_MAC_8021X_FAIL()
        self.assertEqual(fsm.STATE_INTERFACE_UP, fsm.current)

        fsm.TRIGGER_INTERFACE_DOWN()
        self.assertEqual(fsm.STATE_INIT, fsm.current)

        # test the random events
        fsm.TRIGGER_INTERFACE_UP()
        fsm.TRIGGER_MAC_8021X_OK()
        fsm.TRIGGER_DHCP_OK()
        fsm.TRIGGER_TOD_OK()
        fsm.TRIGGER_IPSEC_OK()
        fsm.TRIGGER_RCP_OK()
        fsm.TRIGGER_PTPT1588_OK()
        fsm.TRIGGER_MOVE_OPERATIONAL()

        fsm.TRIGGER_INTERFACE_DOWN()

        self.assertEqual(fsm.STATE_INIT, fsm.current)

        fsm.TRIGGER_INTERFACE_UP()
        fsm.TRIGGER_MAC_8021X_OK()
        fsm.TRIGGER_DHCP_OK()
        fsm.TRIGGER_TOD_OK()
        fsm.TRIGGER_IPSEC_OK()
        fsm.TRIGGER_RCP_OK()
        fsm.TRIGGER_PTPT1588_OK()
        fsm.TRIGGER_MOVE_OPERATIONAL()

        fsm.TRIGGER_RCP_FAIL()
        self.assertEqual(fsm.STATE_IPSEC_OK, fsm.current)

        # Test the timeout and can not reach
        fsm.TRIGGER_TIMEOUT()
        self.assertEqual(fsm.STATE_FAIL, fsm.current)

    def test_auxiliary_fsm(self):
        """Create an auxiliary core fsm."""
        fsm = CCAPFsm.AuxiliaryCCAPFsm([])

    def test_manager_fsm(self):
        """Create an manager fsm."""
        CCAPFsm.ManagerFsm([])

    def _fsm_enter_state_init(self, event):
        """Called when event triggered.

        :param event: trigger event

        """
        print ("Entering state %s from state %s, triggered by event:%s." % (event.fsm.current,
                                                                                      event.src, event.event))

    def test_fsm_state_callbacks(self):
        """test FsmBase callback generate process."""
        print("Test event state callback about FsmBase")
        callbacks = [
            {
                "Type": "state",
                "Name": CCAPFsm.CCAPFsm.STATE_INIT,
                "TrackPoint": "on",
                "Handler": self._fsm_enter_state_init,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test event state callback about FsmBase")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": ["on"],
                "Handler": self._fsm_enter_state_init,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test event state enter list callback about FsmBase")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": ["before"],
                "Handler": self._fsm_enter_state_init,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test event state enter string callback about FsmBase")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": "after",
                "Handler": self._fsm_enter_state_init,
            },
        ]
        CCAPFsm.CCAPFsm(callbacks=callbacks)

        print("Test leave event callback, will raise CCAPFsmError")
        callbacks = [
            {
                "Type": "event",
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": "leave",
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": ["leave"],
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": {"leave"},
                "Handler": self._fsm_enter_state_init,
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
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": "Not Supported",
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": ["Not Supported"],
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": {"on"},
                "Handler": self._fsm_enter_state_init,
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
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": "on",
                "Handler": self._fsm_enter_state_init,
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
                "Name": CCAPFsm.CCAPFsm.EVENT_INTERFACE_UP,
                "TrackPoint": 'on',
                "Handler": 'Not Callable',
            },
        ]
        try:
            CCAPFsm.CCAPFsm(callbacks=callbacks)
        except CCAPFsm.CCAPFsmError:
            pass

if __name__ == '__main__':
    unittest.main()
