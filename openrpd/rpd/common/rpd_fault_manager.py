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
import socket
import zmq
import json

from zmq.utils.monitor import recv_monitor_message
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.HalConfigMsg import MsgTypeFaultManagement, MsgTypeRpdGlobal, MsgTypetEventNotification, MsgTypeRpdCtrl
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.gpb.monitor_pb2 import t_LED
from rpd.provision.proto.MonitorMsgType import MsgTypeSetLed
from rpd.common import rpd_event_def
from rpd.gpb.EventNotification_pb2 import t_EventNotification
from rpd.common import utils


class FaultManagementClient(HalDriverClient):
    """
    refactor the class for fault management
    """
    __metaclass__ = AddLoggerToClass

    RESET_LOG = {
        "PENDING": 1,
        "LOCAL": 2,
    }

    EVENT_VER = '0.0.1'
    event_buffered_local_file = "/tmp/fault_local_%s.json" % EVENT_VER
    event_buffered_pending_file = "/tmp/fault_pending_%s.json" % EVENT_VER

    def __init__(self, appName, appDesc, appVer, disp, supportedMsgType,
                 supportedNotificationMsgs, interestedNotification=None, send_cb=None):

        super(FaultManagementClient, self).__init__(appName, appDesc, appVer, supportedMsgType,
                                                    supportedNotificationMsgs, interestedNotification)
        self.operational = False

        self.dispatcher = disp
        self.send_ntf = send_cb
        self.poll_local_flag = False
        self.poll_pending_flag = False
        self.config_refreshed = False

        self.HalConfigMsgHandlers = {
            MsgTypeRpdGlobal: self.set_global_conf,
            MsgTypetEventNotification: self.read_notification_handler,
            MsgTypeRpdCtrl: self.reset_rpd_log,
        }
        self.HalNotificationMsgHandler = {
            MsgTypeSetLed: self.set_operational_mode,
        }
        rpd_event_def.RpdEventConfig.init_config()

    def set_global_conf(self, cfg):
        """set event global configuration default value."""

        config_data = t_RcpMessage()
        config_data.ParseFromString(cfg.msg.CfgMsgPayload)
        config = config_data.RpdDataMessage.RpdData
        self.logger.debug("Recv global event configuration message, %s" % config)
        rpd_event_def.RpdEventConfig.set_config(config)
        config_data.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        cfg.msg.CfgMsgPayload = config_data.SerializeToString()
        self.config_refreshed = True

    def read_notification_handler(self, cfg):
        """CCAP core pull operation."""

        config_data = t_RcpMessage()
        config_data.ParseFromString(cfg.msg.CfgMsgPayload)
        config = config_data.RpdDataMessage.RpdData
        self.logger.debug("Recv read request message, %s" % config_data)

        # prepare the response
        rsp_data = t_RcpMessage()
        rsp_data.RcpMessageType = config_data.RcpMessageType
        rsp_data.RpdDataMessage.RpdDataOperation = config_data.RpdDataMessage.RpdDataOperation

        read_count = None
        if config.HasField("ReadCount"):
            read_count = config.ReadCount

        # go through all requests and create the appropriate response
        for notify_req in config.EventNotification:
            # according to the spec the PendingOrLocalLog TLV must be set
            if notify_req.HasField("PendingOrLocalLog"):
                if notify_req.PendingOrLocalLog:
                    buffered = rpd_event_def.EventCommonOperation.BUFFERED_LOCAL
                else:
                    buffered = rpd_event_def.EventCommonOperation.BUFFERED_PENDING

                idx = None
                if notify_req.HasField("RpdEvLogIndex"):
                    idx = notify_req.RpdEvLogIndex
                    if read_count is None:
                        read_count = 1
                else:
                    idx = 0

                evtNtfs = self.read_events(buffered, idx, read_count)

                if evtNtfs:
                    for evt in evtNtfs:
                        newEvt = rsp_data.RpdDataMessage.RpdData.EventNotification.add()
                        newEvt.CopyFrom(evt)
                else:
                    # no events found return an empty event notification with the
                    # required fields set
                    newEvt = rsp_data.RpdDataMessage.RpdData.EventNotification.add()
                    newEvt.PendingOrLocalLog = notify_req.PendingOrLocalLog
                    newEvt.RpdEvLogIndex = idx
            else:
                # return the request content
                # Note: The default value for EvFirstTime and EvLastTime
                # is automatically set to R_Dummy, which is wrong for that data
                # type - so set 1970-1-1T00:00:00.0+0:00 as value
                newEvt = rsp_data.RpdDataMessage.RpdData.EventNotification.add()
                newEvt.CopyFrom(notify_req)
                if newEvt.HasField("EvFirstTime") and newEvt.EvFirstTime == 'R_Dummy':
                    newEvt.EvFirstTime = utils.Convert.pack_timestamp_to_string(0)
                if newEvt.HasField("EvLastTime") and newEvt.EvLastTime == 'R_Dummy':
                    newEvt.EvFirstTime = utils.Convert.pack_timestamp_to_string(0)

        rsp_data.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        cfg.msg.CfgMsgPayload = rsp_data.SerializeToString()

    def read_events(self, buffered, idx, rdCnt):
        """ Read events from the pending queue or local log """

        evtNtfList = []
        evts = rpd_event_def.EventCommonOperation.read_log(buffered)

        # calculate the number of elements to read;
        # if the index is not set, then treat it as 0
        numElements = len(evts)
        if rdCnt is None:
            rdCnt = numElements
        elif rdCnt > (numElements - idx):
            rdCnt = numElements - idx

        keys = evts.keys()[idx:(idx + rdCnt)]
        for entry in keys:
            event, msg = evts[entry]
            text = msg['text']

            evtNtfEntry = t_EventNotification()
            evtNtfEntry.RpdEvLogIndex = idx
            idx += 1
            evtNtfEntry.PendingOrLocalLog = msg['PENDING_LOCAL']
            evtNtfEntry.EvFirstTime = utils.Convert.pack_timestamp_to_string(int(msg['FirstTime']))
            evtNtfEntry.EvLastTime = utils.Convert.pack_timestamp_to_string(int(msg['LastTime']))
            evtNtfEntry.EvCounts = msg['Counts']
            evtNtfEntry.EvLevel = msg['Level']
            evtNtfEntry.EvId = int(event)
            evtNtfEntry.EvString = text.strip()
            evtNtfList.append(evtNtfEntry)

            evts.pop(entry)

        if len(evts):
            rpd_event_def.EventCommonOperation.write_log(evts, buffered)

        return evtNtfList

    def clear_rpd_log(self, reset_log):
        if reset_log & self.RESET_LOG["PENDING"]:
            if os.path.exists(self.event_buffered_pending_file):
                os.remove(self.event_buffered_pending_file)

        if reset_log & self.RESET_LOG["LOCAL"]:
            if os.path.exists(self.event_buffered_local_file):
                os.remove(self.event_buffered_local_file)

    def reset_rpd_log(self, cfg):
        """reset rpd pending and local log."""

        rcp_msg = t_RcpMessage()
        rcp_msg.ParseFromString(cfg.msg.CfgMsgPayload)
        if rcp_msg is None:
            return {"Status": HalCommon_pb2.FAILED,
                    "ErrorDescription": "DeSerialize ConfigMsgPayload fail"}

        recv_rcp_msg = rcp_msg.RpdDataMessage.RpdData
        if recv_rcp_msg.HasField("RpdCtrl") and recv_rcp_msg.RpdCtrl.HasField("LogCtrl"):
            if rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_WRITE:
                ctrl_log = recv_rcp_msg.RpdCtrl.LogCtrl
                reset_log = ctrl_log.ResetLog
                self.clear_rpd_log(reset_log)
                rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
                cfg.msg.CfgMsgPayload = rcp_msg.SerializeToString()
                return {"Status": HalCommon_pb2.SUCCESS,
                        "ErrorDescription": "Get Rpd Control success"}
            elif rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_READ:
                return {"Status": HalCommon_pb2.SUCCESS_IGNORE_RESULT,
                        "ErrorDescription": "Operation %d for Rpd Log Control Can Be Ignored" %
                        rcp_msg.RpdDataMessage.RpdDataOperation}
            else:
                return {"Status": HalCommon_pb2.FAILED,
                        "ErrorDescription": "Operation %d for LogCtrl is not supported"
                        % rcp_msg.RpdDataMessage.RpdDataOperation}
        else:
            return {"Status": HalCommon_pb2.SUCCESS_IGNORE_RESULT,
                    "ErrorDescription": "Rcp Msg Do Not Have RpdCtrl Field"}

    def set_operational_mode(self, cfg):
        """use set led msg to figure system operational status."""

        led_msg = t_LED()
        led_msg.ParseFromString(cfg)
        self.logger.debug("Set operational msg %s" % str(led_msg))
        action = led_msg.setLed.action
        if action == led_msg.LED_ACTION_LIT and led_msg.setLed.ledType == led_msg.LED_TYPE_STATUS \
                and not self.operational:
            self.operational = True
        elif action == led_msg.LED_ACTION_DARK and led_msg.setLed.ledType == led_msg.LED_TYPE_STATUS \
                and self.operational:
            self.operational = False

    def process_notification_msg(self, cfg):
        """process notification msg."""

        ntf_msg = cfg.msg
        msg_type = ntf_msg.HalNotificationType
        if msg_type not in self.HalNotificationMsgHandler or self.HalNotificationMsgHandler[msg_type] is None:
            self.logger.error("msgType %d is not supported" % msg_type)
            return
        self.HalNotificationMsgHandler[msg_type](ntf_msg.HalNotificationPayLoad)

    def start(self):
        """Connection setup.

        :return:

        """

        self.logger.debug("Start the client setup...")
        self.connection_setup()
        self.register(self.drvID)

    def connection_setup(self):
        """Create the connection to the mgr and setup the poller.

        :return:

        """

        self.logger.debug("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr,
                                          HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)

        # create the poller
        if self.poller is None:
            self.poller = self.dispatcher.get_poll()

        # register the mgr socket
        self.dispatcher.fd_register(self.mgrConnection.socket, self.dispatcher.EV_FD_IN, self.fault_management_cb)
        self.dispatcher.fd_register(self.mgrConnection.monitor, self.dispatcher.EV_FD_IN, self.fault_management_cb)

    def recvRegisterMsgCb(self, cfg):  # pragma: no cover
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
        :return:

        """

        # self.logger.debug("Recv a Message from the Hal:" % str(cfg.msg))

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.error("Cannot register to Hal, reason[%s]", cfg.msg.Rsp.ErrorDescription)
            return

        self.drvID = cfg.msg.ClientID

        # Setup the push and pull connection
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

        # get the index of the path
        index = self._getIndexFromPath()
        if index == -1:
            self.logger.error("Cannot get index from the path [%s]" % self.pushPath)
            return
        if self.index == -1:
            self.index = index
            self.pushSock = HalTransport(
                HalTransport.HalTransportClientAgentPull,
                HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPushMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            self.pullSock = HalTransport(
                HalTransport.HalTransportClientAgentPush,
                HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPullMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            # register to the poller
            self.dispatcher.fd_register(self.pullSock.socket, zmq.POLLIN, self.fault_management_cb)
            self.dispatcher.fd_register(self.pushSock.monitor, zmq.POLLIN, self.fault_management_cb)
            self.dispatcher.fd_register(self.pullSock.monitor, zmq.POLLIN, self.fault_management_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        if self.interestedNotification is not None:
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def fault_management_cb(self, sock, mask):  # pragma: no cover
        """Fault management callback.

        :param sock: zmq socket
        :param mask: event mask
        :return:

        """

        if self.pushSock is not None and sock == self.pushSock.monitor:
            self.pushSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.pullSock is not None and sock == self.pullSock.monitor:
            self.pullSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.mgrConnection is not None and sock == self.mgrConnection.monitor:
            self.mgrConnection.monitorHandler(recv_monitor_message(sock))
            return

        while sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
            try:
                bin = sock.recv(flags=zmq.NOBLOCK)
                msg = HalMessage.DeSerialize(bin)
                self.logger.debug("###########Got a zmq msg:%s" % msg.msg)
                if msg.type in self.HalMsgsHandler:
                    handler = self.HalMsgsHandler[msg.type]
                    handler(msg)
            except zmq.ZMQError as e:
                self.logger.debug("Getting an error when trying with nonblock read:" + str(e))
                break
            except Exception as e:
                self.logger.error("Error happens, reason:%s" % str(e))
                break

    def recvCfgMsgCb(self, cfg):
        """Receive a configuration message from the Hal, processing it.

        :param cfg:
        :return:

        """
        try:
            handler = self.HalConfigMsgHandlers[cfg.msg.CfgMsgType]
            handler(cfg)
            self.logger.debug("Recv a configuration message, send the rsp to it")
            self.sendCfgRspMsg(cfg)
        except Exception as e:
            self.logger.error("Got an error:%s, the cfg msg:%s", str(e), cfg.msg)

    def recvNotificationCb(self, msg):
        """
        Receive a configuration message from the Hal, processing it
        :param msg:
        :return:
        """

        self.logger.debug("Recv a notification message\n%s", str(msg.msg))
        self.process_notification_msg(msg)


class FaultManager(object):

    __metaclass__ = AddLoggerToClass
    MAX_LIMIT_PER_SEC = 20
    REPORT_CHECK_INTERVAL = 1

    SYSTEM_MONITOR_LOG = "/tmp/system_monitor.log"
    SYSTEM_MONITOR_LOG_SIZE = 1024 * 1024 * 5

    def __init__(self):
        # Fault Manager init a /tmp/fm_sock and wait for rsyslog to send ERROR logs to it.
        self.fm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.fm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fm_sock.bind('/tmp/fm_sock')

        # restore fault json file log
        rpd_event_def.EventCommonOperation.restore_log()

        # create a dispatcher
        self.dispatcher = Dispatcher()
        self.fault_ipc = FaultManagementClient("FaultManager", "This is for Fault management",
                                               "1.0.0", self.dispatcher, (MsgTypeRpdGlobal, MsgTypetEventNotification,
                                                                          MsgTypeRpdCtrl),
                                               (MsgTypeFaultManagement, ), (MsgTypeSetLed, ), self.send_fault_msg)
        self.fault_ipc.start()
        self.dispatcher.fd_register(self.fm_sock.fileno(),
                                    self.dispatcher.EV_FD_IN, self.fm_syslog_trigger)
        self.schedule_send_timer = self.dispatcher.timer_register(FaultManager.REPORT_CHECK_INTERVAL,
                                                                  self.schedule_fault_msg)
        self.clear_msg_cnt_timer = self.dispatcher.timer_register(
            rpd_event_def.RpdEventConfig.GLOBAL_CONFIG["Interval"], self.clear_msg_cnt)

        self.msg_cnt_in_interval = 0
        self.msg_cnt_in_sec = 0
        self.poll_local_timer = None
        self.poll_pending_timer = None
        self.clear_operational_tag_in_buffer()

    def clear_operational_tag_in_buffer(self):
        rpd_event_def.RpdEventOrderedBuffer.move_all_event_to_nonoperational()

    def schedule_fault_msg(self, _):
        """schedule the fault management send plan."""

        # reset second counter
        self.msg_cnt_in_sec = 0

        # if configure refreshed, we reset the counter
        if self.fault_ipc.config_refreshed:
            self.fault_ipc.config_refreshed = False
            self.msg_cnt_in_interval = 0

        # start poll timer
        if self.fault_ipc.poll_local_flag:
            self.fault_ipc.poll_local_flag = False
            if self.poll_local_timer is None:
                self.poll_local_timer = self.dispatcher.timer_register(
                    FaultManager.REPORT_CHECK_INTERVAL, self.schedule_poll_local)

        if self.fault_ipc.poll_pending_flag:
            self.fault_ipc.poll_pending_flag = False
            if self.poll_pending_timer is None:
                self.poll_pending_timer = self.dispatcher.timer_register(
                    FaultManager.REPORT_CHECK_INTERVAL, self.schedule_poll_pending)

        # send message
        if self.fault_ipc.operational and rpd_event_def.RpdEventConfig.is_notify_en():
            total_msg = rpd_event_def.EventCommonOperation.read_log(
                rpd_event_def.EventCommonOperation.BUFFERED_PENDING)
            threshold = rpd_event_def.RpdEventConfig.GLOBAL_CONFIG['Threshold']
            if rpd_event_def.RpdEventConfig.is_unconstrained():
                while self.msg_cnt_in_sec < FaultManager.MAX_LIMIT_PER_SEC:
                    ret = rpd_event_def.RpdEventOrderedBuffer.pop_operational_event(total_msg)
                    if None is not ret:
                        self.send_fault_msg(ret)
                        self.msg_cnt_in_sec += 1
                    else:
                        break
            elif rpd_event_def.RpdEventConfig.is_belowcfg() or rpd_event_def.RpdEventConfig.is_stopcfg():
                while (self.msg_cnt_in_interval < threshold) and (self.msg_cnt_in_sec < FaultManager.MAX_LIMIT_PER_SEC):
                    ret = rpd_event_def.RpdEventOrderedBuffer.pop_operational_event(total_msg)
                    if None is not ret:
                        self.send_fault_msg(ret)
                        self.msg_cnt_in_sec += 1
                        self.msg_cnt_in_interval += 1
                    else:
                        break
                if (self.msg_cnt_in_interval >= threshold) or (self.msg_cnt_in_sec >= FaultManager.MAX_LIMIT_PER_SEC):
                    self.logger.debug("Fault Manager reached the threshold: %d for [%d]s, %d per sec",
                                      self.msg_cnt_in_interval, rpd_event_def.RpdEventConfig.GLOBAL_CONFIG["Interval"],
                                      self.msg_cnt_in_sec)
            else:
                pass

            rpd_event_def.EventCommonOperation.write_log(
                total_msg, rpd_event_def.EventCommonOperation.BUFFERED_PENDING)
        else:
            pass

        # restart the timer, this should be the only entrance except init
        if(self.schedule_send_timer):
            self.dispatcher.timer_unregister(self.schedule_send_timer)
        self.schedule_send_timer = self.dispatcher.timer_register(FaultManager.REPORT_CHECK_INTERVAL,
                                                                  self.schedule_fault_msg)

    def clear_msg_cnt(self, _):
        """ clear msg cnt for interval time expired."""

        if rpd_event_def.RpdEventConfig.is_unconstrained() or rpd_event_def.RpdEventConfig.is_belowcfg():
            self.msg_cnt_in_interval = 0
        else:
            pass

        # restart the timer
        if(self.clear_msg_cnt_timer):
            self.dispatcher.timer_unregister(self.clear_msg_cnt_timer)
        self.clear_msg_cnt_timer = self.dispatcher.timer_register(
            rpd_event_def.RpdEventConfig.GLOBAL_CONFIG["Interval"], self.clear_msg_cnt)

    def schedule_poll_local(self, _):
        local = rpd_event_def.EventCommonOperation.BUFFERED_LOCAL
        ntf_msg = rpd_event_def.EventCommonOperation.read_log(local)
        # pop initiating process event
        while self.msg_cnt_in_sec < FaultManager.MAX_LIMIT_PER_SEC:
            ret = rpd_event_def.RpdEventOrderedBuffer.pop_event(ntf_msg)
            if None is not ret:
                self.send_fault_msg(ret)
                self.msg_cnt_in_sec += 1
            else:
                break
        if len(ntf_msg):
            rpd_event_def.EventCommonOperation.write_log(ntf_msg, local)
            self.logger.debug("schedule_poll_local schedule a new timer: %d left:%d", self.msg_cnt_in_sec, len(ntf_msg))
            self.poll_local_timer = self.dispatcher.timer_register(
                FaultManager.REPORT_CHECK_INTERVAL, self.schedule_poll_local)
        else:
            self.poll_local_timer = None

    def schedule_poll_pending(self, _):
        pending = rpd_event_def.EventCommonOperation.BUFFERED_PENDING
        ntf_msg = rpd_event_def.EventCommonOperation.read_log(pending)
        # pop initiating process event
        while self.msg_cnt_in_sec < FaultManager.MAX_LIMIT_PER_SEC:
            ret = rpd_event_def.RpdEventOrderedBuffer.pop_event(ntf_msg)
            if None is not ret:
                self.send_fault_msg(ret)
                self.msg_cnt_in_sec += 1
            else:
                break

        if len(ntf_msg):
            rpd_event_def.EventCommonOperation.write_log(ntf_msg, pending)
            self.poll_pending_timer = self.dispatcher.timer_register(
                FaultManager.REPORT_CHECK_INTERVAL, self.schedule_poll_pending)
        else:
            self.poll_pending_timer = None

    def send_fault_msg(self, msg):
        """send msg to CCAP core."""

        self.logger.debug("Fault management message send: {}".format(msg))
        try:
            self.fault_ipc.sendNotificationMsg(MsgTypeFaultManagement, json.dumps(msg))
        except:
            self.logger.warn("Fault management message failed to send msg to hal: {}".format(msg))

    def fm_action(self, logs):
        # GCP error to CORE
        self.logger.debug("Fault management message: %s", logs)
        if logs.strip() and logs.strip() != '\n':
            ret, reason = rpd_event_def.EventCommonOperation.store_fault_message(
                logs, operational=self.fault_ipc.operational)
            if not ret:
                self.logger.warn(reason)

    def fm_system_monitor_action(self):
        if not os.path.exists(self.SYSTEM_MONITOR_LOG):
            os.system("touch %s" % self.SYSTEM_MONITOR_LOG)

        os.system('date >> /tmp/system_monitor.log')
        os.system('top -n 1 >> /tmp/system_monitor.log')
        os.system('netstat >> /tmp/system_monitor.log')
        os.system('ifconfig >> /tmp/system_monitor.log')
        os.system('free -h >> /tmp/system_monitor.log')

        # Rotate if needed
        system_monitor_size = os.path.getsize(self.SYSTEM_MONITOR_LOG)
        if system_monitor_size > self.SYSTEM_MONITOR_LOG_SIZE:
            os.system('/usr/sbin/log_rotate_archive.sh system_monitor.log')

    def fm_syslog_parse(self, logs):
        # error syslog from openrpd/seres/Glances cpu/mem/disk
        error_logs = logs
        if 'System Monitor Alert' in str(error_logs):
            # cpu/mem/disk alert
            self.fm_system_monitor_action()

        self.fm_action(error_logs)

    def fm_syslog_trigger(self, fd, eventmask):
        # Receive the msg from the remote
        if eventmask == 0 or self.fm_sock.fileno() != fd:
            self.logger.warn("Got a fake process event, ignore it")
            return

        if Dispatcher.EV_FD_IN & eventmask == 0:
            self.logger.debug("Got a fake event, the receive is not ready!")
            return

        try:
            error_logs = self.fm_sock.recv(1024)
            self.fm_syslog_parse(error_logs)
        except Exception:  # as e:
            pass

    def fm_run(self):
        self.dispatcher.loop()


if __name__ == "__main__":  # pragma: no cover
    setup_logging("FaultManagement", filename="fault_management.log")
    driver = FaultManager()
    driver.fm_run()
