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

import os
import unittest
from rpd.common.rpd_event_def import RpdEventConfig, EventCommonOperation, RpdEventOrderedBuffer, RpdEventTag
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.gpb.cfg_pb2 import config


class TestFaultEvent(unittest.TestCase):

    def setUp(self):
        # init config
        RpdEventConfig.init_config()

        EventCommonOperation.BUFFERED_TYPE = {
            EventCommonOperation.BUFFERED_LOCAL: "test_fault_local.json",
            EventCommonOperation.BUFFERED_PENDING: "test_fault_pending.json",
        }

        self.send_count = 0
        self.send_throttle = 5
        self.schedule_timer = None

    def enable_notify_send(self):
        # enable notify
        RpdEventConfig.GLOBAL_CONFIG['Enable'] = rcp_tlv_def.RPD_EVENT_NTF_ENABLE[0]
        # error+ msg to local and pending, error- msg to pending
        control = RpdEventConfig.GLOBAL_CONFIG["Control"] = {}
        for lvl, _ in rcp_tlv_def.RPD_EVENT_LEVEL:
            if lvl <= rcp_tlv_def.RPD_EVENT_LEVEL_ERROR[0]:
                control[str(lvl)] = RpdEventConfig.LOCAL_MAK + RpdEventConfig.PENDING_MARK
            else:
                control[str(lvl)] = RpdEventConfig.PENDING_MARK

    def tearDown(self):
        EventCommonOperation.read_log(EventCommonOperation.BUFFERED_LOCAL)
        EventCommonOperation.read_log(EventCommonOperation.BUFFERED_PENDING)

    def schedule_fault_msg(self, disp):
        """schedule the fault management send plan."""

        if RpdEventConfig.is_notify_en():
            total_msg = EventCommonOperation.read_log(EventCommonOperation.BUFFERED_PENDING)
            threshold = RpdEventConfig.GLOBAL_CONFIG['Threshold']

            if RpdEventConfig.is_unconstrained():
                while True:
                    ret = RpdEventOrderedBuffer.pop_operational_event(total_msg)
                    if None is not ret:
                        print ret
                    else:
                        break
                # pop initiating process event
                for key, data in total_msg.items():
                    print data
                    total_msg.pop(key)

            else:
                for _ in range(threshold):
                    ret = RpdEventOrderedBuffer.pop_operational_event(total_msg)
                    if None is not ret:
                        print ret
                        continue
                    # pop initiating process event
                    for key, data in total_msg.items():
                        total_msg.pop(key)
                        break
            EventCommonOperation.write_log(total_msg, EventCommonOperation.BUFFERED_PENDING)
        else:
            print("Can not send msg, NotifyEnable(%d)" % RpdEventConfig.is_notify_en())

        self.send_count += 1
        # only send 5 times for test.
        if self.send_count <= self.send_throttle:
            disp.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg, arg=disp)
            disp.timer_register(0.1, EventCommonOperation.store_fault_message, arg="66070206: test message 7")
        else:
            disp.end_loop()

    def schedule_fault_msg_operational(self, disp):
        """schedule the fault management send plan."""

        if RpdEventConfig.is_notify_en():
            total_msg = EventCommonOperation.read_log(EventCommonOperation.BUFFERED_PENDING)
            threshold = RpdEventConfig.GLOBAL_CONFIG['Threshold']

            if RpdEventConfig.is_unconstrained():
                while True:
                    ret = RpdEventOrderedBuffer.pop_operational_event(total_msg)
                    if None is not ret:
                        print ret
                    else:
                        break
            else:
                for _ in range(threshold):
                    ret = RpdEventOrderedBuffer.pop_operational_event(total_msg)
                    if None is not ret:
                        print ret
                    else:
                        break
            EventCommonOperation.write_log(total_msg, EventCommonOperation.BUFFERED_PENDING)
        else:
            print("Can not send msg, NotifyEnable(%d)" % RpdEventConfig.is_notify_en())

        self.send_count += 1
        # only send 5 times for test.
        if self.send_count <= self.send_throttle:
            disp.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg_operational,
                                arg=disp)
            disp.timer_register(0.1, EventCommonOperation.store_fault_message, arg="66070206: test message 7")
        else:
            disp.end_loop()

    def test_event_tag_format(self):
        mac = '00:0:0:0:0:01'
        version = '0.0.1'
        convert_mac = 'RPD-MAC=' + mac
        convert_ver = 'RPD-VER=' + version

        rpd_event = RpdEventTag()
        rpd_mac = rpd_event.rpd_mac(mac)
        self.assertEqual(convert_mac, rpd_mac)
        rpd_ver = rpd_event.rpd_ver(version)
        self.assertEqual(convert_ver, rpd_ver)

    def test_event_send_unconstrained(self):
        print '*' * 80
        print 'Send message unconstrained'
        print '*' * 80
        # unconstrained throttle
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_UNCONSTRAINED[0]
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070200: test message 1")
        EventCommonOperation.store_fault_message("66070201: test message 2")
        EventCommonOperation.store_fault_message("66070202: test message 3")
        EventCommonOperation.store_fault_message("66070203: test message 4")
        EventCommonOperation.store_fault_message("66070204: test message 5")
        EventCommonOperation.store_fault_message("66070205: test message 6")
        dispatcher = Dispatcher()
        dispatcher.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg, arg=dispatcher)
        dispatcher.loop()

    def test_event_send_below(self):
        print '*' * 80
        print 'Send message below threshold'
        print '*' * 80
        # below throttle
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070200: test message 1")
        EventCommonOperation.store_fault_message("66070201: test message 2")
        EventCommonOperation.store_fault_message("66070202: test message 3")
        EventCommonOperation.store_fault_message("66070203: test message 4")
        EventCommonOperation.store_fault_message("66070204: test message 5")
        EventCommonOperation.store_fault_message("66070205: test message 6")
        dispatcher = Dispatcher()
        dispatcher.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg, arg=dispatcher)
        dispatcher.loop()

    def test_event_operational(self):
        print '*' * 80
        print 'Send message when operational'
        print '*' * 80
        # below throttle
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        EventCommonOperation.store_fault_message("66070201: test message 2", operational=True)
        EventCommonOperation.store_fault_message("66070202: test message 3", operational=True)
        EventCommonOperation.store_fault_message("66070203: test message 4", operational=True)
        EventCommonOperation.store_fault_message("66070204: test message 5", operational=True)
        EventCommonOperation.store_fault_message("66070205: test message 6", operational=True)
        dispatcher = Dispatcher()
        dispatcher.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg_operational,
                                  arg=dispatcher)
        dispatcher.loop()

    def test_set_config(self):
        print '*' * 80
        print 'test Global TLV handling'
        print '*' * 80
        RpdEventConfig.event_config_file = "test.config"

        # construct RpdGlobal config
        cfg_global = config()
        cfg = cfg_global.RpdGlobal
        for lvl, _ in rcp_tlv_def.RPD_EVENT_LEVEL:
            ctrl = cfg.EvCfg.EvControl.add()
            ctrl.EvPriority = lvl
            if lvl <= rcp_tlv_def.RPD_EVENT_LEVEL_ERROR[0]:
                ctrl.EvReporting = RpdEventConfig.LOCAL_MAK + RpdEventConfig.PENDING_MARK
            else:
                ctrl.EvReporting = RpdEventConfig.PENDING_MARK
        cfg.EvCfg.EvThrottleAdminStatus = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        cfg.EvCfg.EvThrottleThreshold = 10
        cfg.EvCfg.EvThrottleInterval = 10
        cfg.EvCfg.NotifyEnable = 1
        RpdEventConfig.set_config(cfg_global)

        # verify the result
        self.assertEqual(RpdEventConfig.GLOBAL_CONFIG['Threshold'], 10, msg="Threshold set fail")
        self.assertEqual(RpdEventConfig.GLOBAL_CONFIG['Interval'], 10, msg="Interval set fail")
        self.assertEqual(RpdEventConfig.GLOBAL_CONFIG['Enable'], 1, msg="Enable set fail")
        self.assertTrue(os.path.exists(RpdEventConfig.event_config_file),
                        msg="Failed to store the configuration file")
        os.remove(RpdEventConfig.event_config_file)

    def test_pop_operational_event(self):
        print '*' * 80
        print 'test operational event log pop'
        print '*' * 80
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070200: test message 1")
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        EventCommonOperation.store_fault_message("66070201: test message 2", operational=True)
        EventCommonOperation.store_fault_message("66070202: test message 3", operational=True)
        # as 203 stored in pending file, so not generate it.
        # EventCommonOperation.store_fault_message("66070203: test message 4", operational=True)
        EventCommonOperation.store_fault_message("66070204: test message 4", operational=True)
        EventCommonOperation.store_fault_message("66070205: test message 5", operational=True)

        cfg = config()
        notify_req = cfg.EventNotification.add()
        notify_req.RpdEvLogIndex = 3
        notify_req.PendingOrLocalLog = 1
        if notify_req.HasField("PendingOrLocalLog"):
            if notify_req.PendingOrLocalLog:
                local = EventCommonOperation.BUFFERED_LOCAL
            else:
                local = EventCommonOperation.BUFFERED_PENDING
            ntf_msg = EventCommonOperation.read_log(local)
            operational_cnt = 5

            cnt = 0
            while True:
                ret = RpdEventOrderedBuffer.pop_operational_event(ntf_msg)
                if None is not ret:
                    print ret
                    cnt += 1
                else:
                    break

            # pop initiating process event
            for key, data in ntf_msg.items():
                print data
                ntf_msg.pop(key)

            # verify the result
            self.assertEqual(operational_cnt, cnt,
                             msg="pop operational event from local fail %d, %d" % (operational_cnt, cnt))
            self.assertEqual("operational" not in ntf_msg, True, msg="pop whole operational event fail")
            self.assertEqual(len(ntf_msg), 0, msg="pop  initiating process event fail")

    def test_send_ptp_message(self):
        print '*' * 80
        print 'Send PTP SYNC/LOST SYNC/HOLDOVER Message'
        print '*' * 80
        # below throttle
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070700: PTP clock synchronized to Master", operational=True)
        EventCommonOperation.store_fault_message("66070701: PTP clock lost synchronized to Master", operational=True)
        EventCommonOperation.store_fault_message("66070702: PTP clock ecxessive holdover to Master", operational=True)
        dispatcher = Dispatcher()
        dispatcher.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg_operational,
                                  arg=dispatcher)
        dispatcher.loop()

    def test_move_all_event_to_nonoperational(self):
        print '*' * 80
        print 'test operational event log pop'
        print '*' * 80
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070200: test message 1")
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        EventCommonOperation.store_fault_message("66070201: test message 2", operational=True)
        EventCommonOperation.store_fault_message("66070202: test message 3", operational=True)

        RpdEventOrderedBuffer.move_all_event_to_nonoperational()

        ntf_msg = EventCommonOperation.read_log(EventCommonOperation.BUFFERED_PENDING)
        self.assertEqual(len(ntf_msg), 4)
        ret = RpdEventOrderedBuffer.pop_operational_event(ntf_msg)
        self.assertIsNone(ret)

    def test_send_self_diagnostic_message(self):
        print '*' * 80
        print 'Send Self Diagnostic Message'
        print '*' * 80
        # below throttle
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070218: Diagnostic Self Test Failure", operational=True)
        dispatcher = Dispatcher()
        dispatcher.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg_operational,
                                  arg=dispatcher)
        dispatcher.loop()

    def test_send_local_craft_port_open_message(self):
        print '*' * 80
        print 'Send Enclosure Door Open Message'
        print '*' * 80
        # below throttle
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.enable_notify_send()

        # generate log
        EventCommonOperation.store_fault_message("66070504: Enclosure Door Open", operational=True)
        dispatcher = Dispatcher()
        dispatcher.timer_register(RpdEventConfig.GLOBAL_CONFIG["Interval"], self.schedule_fault_msg_operational,
                                  arg=dispatcher)
        dispatcher.loop()


if __name__ == "__main__":
    unittest.main()
