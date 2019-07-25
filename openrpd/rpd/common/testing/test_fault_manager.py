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
from rpd.common.rpd_event_def import RpdEventConfig, EventCommonOperation, RpdEventOrderedBuffer
from rpd.common.rpd_fault_manager import FaultManager
from rpd.common.rpd_system_fault import SystemMonitorFault
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.gpb.cfg_pb2 import config
from rpd.hal.src.HalConfigMsg import MsgTypeFaultManagement, MsgTypeRpdGlobal, MsgTypetEventNotification, MsgTypeRpdCtrl
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.gpb.monitor_pb2 import t_LED
from rpd.provision.proto.MonitorMsgType import MsgTypeSetLed
from rpd.hal.src.msg import HalCommon_pb2


class TestFaultManager(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") - 2
        cls.rootpath = "/".join(dirs[:rpd_index])

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.rootpath + 'test_fault_local.txt'):
            os.remove(cls.rootpath + 'test_fault_local.txt')
        if os.path.exists(cls.rootpath + 'test_fault_pending.txt'):
            os.remove(cls.rootpath + 'test_fault_pending.txt')

    def setUp(self):

        # init config
        if os.path.exists('/tmp/fm_sock'):
            os.remove('/tmp/fm_sock')
        RpdEventConfig.init_config()

        EventCommonOperation.BUFFERED_TYPE = {
            EventCommonOperation.BUFFERED_LOCAL: "test_fault_local.json",
            EventCommonOperation.BUFFERED_PENDING: "test_fault_pending.json",
        }

        self.fm = FaultManager()

        self.sys_fault = SystemMonitorFault()

    def tearDown(self):
        if os.path.exists('/tmp/fm_sock'):
            os.remove('/tmp/fm_sock')
        self.clear_buffer_file()

    def create_pending_anbd_local_file(self):
        fp = open(self.rootpath + "test_fault_local.txt", 'w')
        fp.close()
        fp = open(self.rootpath + "test_fault_pending.txt", 'w')
        fp.close()

    def clear_buffer_file(self):
        if os.path.exists(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_LOCAL]):
            os.remove(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_LOCAL])
        if os.path.exists(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_PENDING]):
            os.remove(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_PENDING])

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

    def test_fm_action_1(self):
        # fm_action api test 1 with no logs
        logs = ''
        self.fm.fm_syslog_parse(logs)
        self.fm.fm_action(logs)

    def test_fm_action_2(self):
        # fm_action api test 2 with useless logs
        logs = 'fm_action_2 testing'
        self.fm.fm_syslog_parse(logs)
        self.fm.fm_action(logs)

    def test_fm_action_3(self):
        # fm_action api test 2 with correct logs
        logs = 'fm_action_3 testing'
        self.fm.fm_syslog_parse(logs)
        self.fm.fm_action(logs)

    def test_fm_system_monitor_filenoexit(self):
        # fm_system_monitor_action api test
        logs = 'System Monitor Alert : CPU High'
        os.system('rm /tmp/system_monitor.log')
        self.fm.fm_syslog_parse(logs)

    def test_fm_system_monitor_action(self):
        # fm_system_monitor_action api test
        logs = 'System Monitor Alert : CPU High'
        self.fm.fm_syslog_parse(logs)

    def test_fm_system_monitor_rotate(self):
        # fm_system_monitor_action api test
        logs = 'System Monitor Alert : CPU High'
        system_monitor_size = os.path.getsize('/tmp/system_monitor.log')
        while system_monitor_size < self.fm.SYSTEM_MONITOR_LOG_SIZE:
            system_monitor_size = os.path.getsize('/tmp/system_monitor.log')
            # make a big file
            os.system('echo "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
                      "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
                      "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
                      "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
                      "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
                      "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
                      "1111111111111111111111111111111111111111111111111111i11111222i2221111112111111111111111111111" \
                      "1111111111111" >> /tmp/system_monitor.log')
        self.fm.fm_syslog_parse(logs)

    def test_fm_syslog_trigger(self):
        # fm_system_monitor_action api test
        self.fm.fm_syslog_trigger(1, 0)
        self.fm.fm_syslog_trigger(1, 1)
        self.fm.fm_syslog_trigger(self.fm.fm_sock.fileno(), 0)
        # self.fm.fm_syslog_trigger(self.fm.fm_sock.fileno(), 0xffff)

    def test_recvCfgMsgCb(self):
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()

        # test normal
        cfgMsg = HalMessage("HalConfig",
                            SrcClientID="testRpdFM",
                            SeqNum=322,
                            CfgMsgType=MsgTypetEventNotification,
                            CfgMsgPayload=payload)

        self.fm.fault_ipc.recvCfgMsgCb(cfgMsg)
        # test Exception
        cfgMsg = HalMessage("HalConfig",
                            SrcClientID="testRpdFM",
                            SeqNum=322,
                            CfgMsgType=MsgTypetEventNotification + 1000,
                            CfgMsgPayload=payload)
        self.fm.fault_ipc.recvCfgMsgCb(cfgMsg)

    def test_set_global_conf(self):
        print '*' * 80
        print 'test Global TLV handling'
        print '*' * 80
        RpdEventConfig.event_config_file = "test.config"

        # construct RpdGlobal config
        cfg_global = config()
        # cfg = t_RpdGlobal()
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

        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        payload = rcp_msg.SerializeToString()
        print payload
        cfgMsg = HalMessage("HalConfig",
                            SrcClientID="testRpdFM",
                            SeqNum=322,
                            CfgMsgType=MsgTypeRpdGlobal,
                            CfgMsgPayload=payload)

        cfgMsg.msg.CfgMsgPayload = rcp_msg.SerializeToString()

        self.fm.fault_ipc.set_global_conf(cfgMsg)

    def test_set_operational_mode(self):
        led_msg = t_LED()
        led_msg.setLed.ledType = led_msg.LED_TYPE_STATUS
        led_msg.setLed.color = led_msg.LED_COLOR_GREEN
        led_msg.setLed.action = led_msg.LED_ACTION_LIT

        payload = led_msg.SerializeToString()

        cfgMsg = HalMessage("HalConfig",
                            SrcClientID="testRpdFM",
                            SeqNum=322,
                            CfgMsgType=MsgTypeSetLed,
                            CfgMsgPayload=payload)

        self.fm.fault_ipc.set_operational_mode(cfgMsg.msg.CfgMsgPayload)

        led_msg.setLed.action = led_msg.LED_ACTION_DARK
        payload = led_msg.SerializeToString()

        cfgMsg = HalMessage("HalConfig",
                            SrcClientID="testRpdFM",
                            SeqNum=322,
                            CfgMsgType=MsgTypeSetLed,
                            CfgMsgPayload=payload)

        self.fm.fault_ipc.set_operational_mode(cfgMsg.msg.CfgMsgPayload)

    def test_read_notification_handler(self):

        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        evcfg = config()
        # test PendingOrLocalLog 0
        notify_req = evcfg.EventNotification.add()
        notify_req.PendingOrLocalLog = 0
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(evcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()

        ntMsg = HalMessage("HalConfig",
                           SrcClientID="testRpdFM",
                           SeqNum=322,
                           CfgMsgType=MsgTypetEventNotification,
                           CfgMsgPayload=payload)

        self.fm.fault_ipc.read_notification_handler(ntMsg)
        # test PendingOrLocalLog 1
        notify_req.PendingOrLocalLog = 1
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(evcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()

        ntMsg = HalMessage("HalConfig",
                           SrcClientID="testRpdFM",
                           SeqNum=322,
                           CfgMsgType=MsgTypetEventNotification,
                           CfgMsgPayload=payload)

        self.fm.fault_ipc.read_notification_handler(ntMsg)

    def test_process_notification_msg(self):
        led_msg = t_LED()
        led_msg.setLed.ledType = led_msg.LED_TYPE_STATUS
        led_msg.setLed.color = led_msg.LED_COLOR_GREEN
        led_msg.setLed.action = led_msg.LED_ACTION_LIT

        payload = led_msg.SerializeToString()
        # test supported msg
        ntf = HalMessage("HalNotification", ClientID="testRpdFM",
                         HalNotificationType=MsgTypeSetLed,
                         HalNotificationPayLoad=payload)
        self.fm.fault_ipc.recvNotificationCb(ntf)

        # test unsupported msg
        ntf = HalMessage("HalNotification", ClientID="testRpdFM",
                         HalNotificationType=0,
                         HalNotificationPayLoad=payload)
        self.fm.fault_ipc.recvNotificationCb(ntf)

    def test_clear_msg_cnt(self):
        self.fm.clear_msg_cnt(None)
        self.assertEqual(self.fm.msg_cnt_in_interval, 0)
        self.assertIsNotNone(self.fm.clear_msg_cnt_timer)

    def test_schedule_poll_local(self):
        # generate log
        self.clear_buffer_file()
        self.fm.msg_cnt_in_sec = 0
        EventCommonOperation.store_fault_message("66070200: test message 1")
        self.fm.schedule_poll_local(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 1)

        # reach max limit in sec
        self.fm.msg_cnt_in_sec = 20
        EventCommonOperation.store_fault_message("66070200: test message 1")
        self.fm.schedule_poll_local(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 20)
        self.assertTrue(os.path.exists(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_LOCAL]))

    def test_schedule_poll_pending(self):
        # generate log
        self.clear_buffer_file()
        self.fm.msg_cnt_in_sec = 0
        self.enable_notify_send()
        EventCommonOperation.store_fault_message("66070200: test message 1")
        self.fm.schedule_poll_pending(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 1)

        # reach max limit in sec
        self.fm.msg_cnt_in_sec = 20
        EventCommonOperation.store_fault_message("66070200: test message 1")
        self.fm.schedule_poll_pending(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 20)
        self.assertTrue(os.path.exists(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_PENDING]))

    def test_schedule_fault_msg(self):
        self.clear_buffer_file()
        self.fm.fault_ipc.operational = True
        self.fm.msg_cnt_in_sec = 0
        RpdEventConfig.GLOBAL_CONFIG['Enable'] = rcp_tlv_def.RPD_EVENT_NTF_ENABLE[0]
        self.enable_notify_send()
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        self.fm.schedule_fault_msg(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 1)

        # reach max limit in sec, reset
        self.fm.msg_cnt_in_sec = 20
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        self.fm.schedule_fault_msg(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 1)
        self.assertTrue(os.path.exists(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_PENDING]))

        # reach max limit in interval
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.fm.msg_cnt_in_interval = RpdEventConfig.GLOBAL_CONFIG['Threshold']
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        self.fm.schedule_fault_msg(None)
        self.assertEqual(self.fm.msg_cnt_in_interval, RpdEventConfig.GLOBAL_CONFIG['Threshold'])
        self.assertTrue(os.path.exists(EventCommonOperation.BUFFERED_TYPE[EventCommonOperation.BUFFERED_PENDING]))

        # set the poll timer
        self.fm.fault_ipc.poll_local_flag = True
        self.fm.fault_ipc.poll_pending_flag = True

        self.fm.schedule_fault_msg(None)
        self.assertIsNotNone(self.fm.poll_local_timer)
        self.assertIsNotNone(self.fm.poll_pending_timer)
        self.assertFalse(self.fm.fault_ipc.poll_local_flag)
        self.assertFalse(self.fm.fault_ipc.poll_pending_flag)

        # set refresh config
        self.clear_buffer_file()
        self.fm.fault_ipc.config_refreshed = True
        self.fm.schedule_fault_msg(None)
        self.assertFalse(self.fm.fault_ipc.config_refreshed)
        self.assertEqual(self.fm.msg_cnt_in_interval, 0)

    def test_schedule_fault_msg_interval(self):
        self.clear_buffer_file()
        self.fm.fault_ipc.operational = True
        self.fm.msg_cnt_in_sec = 0
        RpdEventConfig.GLOBAL_CONFIG['Enable'] = rcp_tlv_def.RPD_EVENT_NTF_ENABLE[0]
        self.enable_notify_send()
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_INHIBITED[0]

    def test_clear_operational_tag_in_buffer(self):
        self.clear_buffer_file()
        self.fm.fault_ipc.operational = False
        self.fm.fault_ipc.op_state_change = True
        RpdEventConfig.GLOBAL_CONFIG['Enable'] = rcp_tlv_def.RPD_EVENT_NTF_ENABLE[0]
        self.enable_notify_send()
        EventCommonOperation.store_fault_message("66070200: test message 1", operational=True)
        self.fm.clear_operational_tag_in_buffer()
        self.fm.schedule_fault_msg(None)
        self.assertEqual(self.fm.msg_cnt_in_sec, 0)
        ntf_msg = EventCommonOperation.read_log(EventCommonOperation.BUFFERED_PENDING)
        ret = RpdEventOrderedBuffer.pop_operational_event(ntf_msg)
        self.assertIsNone(ret)

    def test_clear_msg_cnt2(self):

        self.fm.msg_cnt_in_interval = 5
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_UNCONSTRAINED[0]
        self.fm.clear_msg_cnt(None)
        self.assertEqual(self.fm.msg_cnt_in_interval, 0)

        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]
        self.fm.clear_msg_cnt(None)
        self.assertEqual(self.fm.msg_cnt_in_interval, 0)

        self.fm.msg_cnt_in_interval = 5
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_INHIBITED[0]
        self.fm.clear_msg_cnt(None)
        self.assertEqual(self.fm.msg_cnt_in_interval, 5)

        self.fm.msg_cnt_in_interval = 5
        RpdEventConfig.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_STOP[0]
        self.fm.clear_msg_cnt(None)
        self.assertEqual(self.fm.msg_cnt_in_interval, 5)

    def test_reset_rpd_log(self):
        print '*' * 80
        print 'test reset rpd log'
        print '*' * 80
        self.fm.fault_ipc.event_buffered_local_file = self.rootpath + 'test_fault_local.txt'
        self.fm.fault_ipc.event_buffered_pending_file = self.rootpath + 'test_fault_pending.txt'
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION

        # test payload does not have RpdCtrl field
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        return_str = self.fm.fault_ipc.reset_rpd_log(msg)
        self.assertEquals(str(return_str), "{'Status': %d, 'ErrorDescription': 'Rcp Msg Do Not Have RpdCtrl Field'}" %
                          HalCommon_pb2.SUCCESS_IGNORE_RESULT)

        # test payload operation is RPD_CFG_READ
        rpdlogcfg = config()
        rpdlogcfg.RpdCtrl.LogCtrl.ResetLog = 0
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdlogcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        return_str = self.fm.fault_ipc.reset_rpd_log(msg)
        self.assertEquals(str(return_str), "{'Status': %d, 'ErrorDescription': "
                                           "'Operation 2 for Rpd Log Control Can Be Ignored'}" %
                          HalCommon_pb2.SUCCESS_IGNORE_RESULT)

        # test payload operation neither read nor write
        rpdlogcfg = config()
        rpdlogcfg.RpdCtrl.LogCtrl.ResetLog = 0
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdlogcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 3
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        return_str = self.fm.fault_ipc.reset_rpd_log(msg)
        self.assertEquals(str(return_str), "{'Status': %d, 'ErrorDescription': "
                                           "'Operation 3 for LogCtrl is not supported'}" % HalCommon_pb2.FAILED)

        # test pending and local files not exist
        self.assertFalse(os.path.exists(self.rootpath + 'test_fault_pending.txt'))
        self.assertFalse(os.path.exists(self.rootpath + 'test_fault_local.txt'))
        rpdlogcfg = config()
        rpdlogcfg.RpdCtrl.LogCtrl.ResetLog = 0
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdlogcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 1
        payload = rcp_msg.SerializeToString()

        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        self.fm.fault_ipc.reset_rpd_log(msg)

        # create pending and local files
        self.create_pending_anbd_local_file()
        self.assertTrue(os.path.exists(self.rootpath + 'test_fault_pending.txt'))
        self.assertTrue(os.path.exists(self.rootpath + 'test_fault_local.txt'))

        # test ResetLog pendinglog
        rpdlogcfg = config()
        rpdlogcfg.RpdCtrl.LogCtrl.ResetLog = 1
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdlogcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 1
        payload = rcp_msg.SerializeToString()

        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        self.fm.fault_ipc.reset_rpd_log(msg)

        is_local_file_exist = True
        is_pending_file_exist = True
        if not (os.path.exists(self.rootpath + 'test_fault_pending.txt')):
            is_pending_file_exist = False
        if not (os.path.exists(self.rootpath + 'test_fault_local.txt')):
            is_local_file_exist = False
        self.assertFalse(is_pending_file_exist)
        self.assertTrue(is_local_file_exist)

        # test ResetLog locallog
        rpdlogcfg.RpdCtrl.LogCtrl.ResetLog = 2
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdlogcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 1
        payload = rcp_msg.SerializeToString()
        fp = open(self.rootpath + 'test_fault_pending.txt', 'w')
        fp.close()

        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        self.fm.fault_ipc.reset_rpd_log(msg)

        is_local_file_exist = True
        is_pending_file_exist = True
        if not (os.path.exists(self.rootpath + 'test_fault_local.txt')):
            is_local_file_exist = False
        if not (os.path.exists(self.rootpath + 'test_fault_pending.txt')):
            is_pending_file_exist = False
        self.assertFalse(is_local_file_exist)
        self.assertTrue(is_pending_file_exist)


if __name__ == "__main__":
    unittest.main()
