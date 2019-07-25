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
#

import zmq
from rpd.hal.src.HalConfigMsg import MsgTypeHostResources, MsgTypeRpdCtrl
from RpdCrashFileHandler import CrashFileCtrlHandler
from RpdHostResourceHandler import HostResourceHandler
from rpd.dispatcher.timer import DpTimerManager
from zmq.utils.monitor import recv_monitor_message
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage


class RpdResHalClient(HalDriverClient):

    __metaclass__ = AddLoggerToClass

    def __init__(self, appName, appDesc, appVer, disp, supportedMsgType,
                 supportedNotificationMsgs, interestedNotification=None, send_cb=None):

        super(RpdResHalClient, self).__init__(appName, appDesc, appVer, supportedMsgType,
                                              supportedNotificationMsgs, interestedNotification)
        self.operational = False

        self.dispatcher = disp

        self.HalConfigMsgHandlers = {
            MsgTypeHostResources: self.processHostCfgMsg,
            MsgTypeRpdCtrl: self.processRpdCtrlCfgMsg,
        }
        self.crashFileCtrlHandler = CrashFileCtrlHandler()
        self.hostResourceHandler = HostResourceHandler()

    def processRpdCtrlCfgMsg(self, cfgMsg):
        rcp_msg = t_RcpMessage()
        rcp_msg.ParseFromString(cfgMsg.msg.CfgMsgPayload)
        status = HalCommon_pb2.SUCCESS_IGNORE_RESULT

        recv_rcp_msg = rcp_msg.RpdDataMessage.RpdData
        if recv_rcp_msg.HasField("RpdCtrl"):
            rpdCtrl = recv_rcp_msg.RpdCtrl
            op = rcp_msg.RpdDataMessage.RpdDataOperation
            rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            flag = False
            if rpdCtrl.HasField("CrashDataServerCtrl"):
                status = HalCommon_pb2.SUCCESS
                self.logger.debug("Recv an RpdCtrlCfgMsg op %d, %s:" % (op, rpdCtrl))
                if op == t_RpdDataMessage.RPD_CFG_WRITE:
                    self.crashFileCtrlHandler.save_crash_data_server(rpdCtrl.CrashDataServerCtrl)
                    flag = True
                if op == t_RpdDataMessage.RPD_CFG_READ:
                    self.crashFileCtrlHandler.get_crash_data_server(rpdCtrl.CrashDataServerCtrl)
                    flag = True
            if len(rpdCtrl.CrashDataFileCtrl) > 0 and op == t_RpdDataMessage.RPD_CFG_WRITE:
                flag = True
                index = 0
                for crashDataCtrl in rpdCtrl.CrashDataFileCtrl:
                    if crashDataCtrl.HasField("Index"):
                        index = crashDataCtrl.Index
                    else:
                        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR
                    if crashDataCtrl.HasField("FileControl"):
                        fileControl = crashDataCtrl.FileControl
                        if not self.crashFileCtrlHandler.update_pending_file_idx_list(
                                index, fileControl):
                            status = HalCommon_pb2.FAILED
                            rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR
            if not flag:
                status = HalCommon_pb2.SUCCESS_IGNORE_RESULT
            else:
                status = HalCommon_pb2.SUCCESS
        elif rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_READ:
            status = HalCommon_pb2.SUCCESS_IGNORE_RESULT
        else:
            status = HalCommon_pb2.FAILED
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID=cfgMsg.msg.SrcClientID, SeqNum=cfgMsg.msg.SeqNum,
                         Rsp={
                             "Status": status,
                             "ErrorDescription": "Get Rpd Control rsp"
                         },
                         CfgMsgType=cfgMsg.msg.CfgMsgType,
                         CfgMsgPayload=payload)
        return msg

    def processHostCfgMsg(self, cfgMsg):
        rsp = t_RcpMessage()
        # rsp.ParseFromString(cfgMsg.CfgMsgPayload)
        req = t_RcpMessage()
        req.ParseFromString(cfgMsg.msg.CfgMsgPayload)

        rsp.RpdDataMessage.RpdDataOperation = req.RpdDataMessage.RpdDataOperation
        rsp.RcpMessageType = req.RcpMessageType

        # load the rpd host resources information
        hr = rsp.RpdDataMessage.RpdData.HostResources
        hr.hrMemorySize = self.hostResourceHandler.getMemorySize()
        hr.hrProcessorLoad = self.hostResourceHandler.getProcessorLoad()
        self.hostResourceHandler.getStorages(hr.hrStorages)
        self.hostResourceHandler.getProcesses(hr.hrProcesses)

        rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        payload = rsp.SerializeToString()

        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.msg.SrcClientID, SeqNum=cfgMsg.msg.SeqNum,
            Rsp={
                "Status": HalCommon_pb2.SUCCESS,
                "ErrorDescription": "Host Resource"
            },
            CfgMsgType=cfgMsg.msg.CfgMsgType,
            CfgMsgPayload=payload)
        return msg

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
        self.dispatcher.fd_register(self.mgrConnection.socket, self.dispatcher.EV_FD_IN, self.host_management_cb)
        self.dispatcher.fd_register(self.mgrConnection.monitor, self.dispatcher.EV_FD_IN, self.host_management_cb)

    def recvRegisterMsgCb(self, cfg):
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
        :return:

        """
        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.error("Cannot register to Hal, reason[%s]", cfg.msg.Rsp.ErrorDescription)
            return

        self.drvID = cfg.msg.ClientID
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

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
            self.dispatcher.fd_register(self.pullSock.socket, zmq.POLLIN, self.host_management_cb)
            self.dispatcher.fd_register(self.pushSock.monitor, zmq.POLLIN, self.host_management_cb)
            self.dispatcher.fd_register(self.pullSock.monitor, zmq.POLLIN, self.host_management_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        if self.interestedNotification is not None:
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def host_management_cb(self, sock, mask):
        """

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
            if not self.hal_message_cb(sock):
                break

    def hal_message_cb(self, sock):
        try:
            bin = sock.recv(flags=zmq.NOBLOCK)
            msg = HalMessage.DeSerialize(bin)
            self.logger.debug("###########Got a zmq msg:%s" % msg.msg)
            if msg.type in self.HalMsgsHandler:
                handler = self.HalMsgsHandler[msg.type]
                handler(msg)
        except zmq.ZMQError as e:
            self.logger.debug("Getting an error when trying with nonblock read:" + str(e))
            return False
        except Exception as e:
            self.logger.error("Error happens, reason:%s" % str(e))
            return False
        return True

    def recvCfgMsgCb(self, cfg):
        """Receive a configuration message from the Hal, processing it.

        :param cfg:
        :return:

        """
        try:
            handler = self.HalConfigMsgHandlers[cfg.msg.CfgMsgType]
            msg = handler(cfg)
            if self.pushSock:
                self.pushSock.send(msg.Serialize())
            self.logger.debug("Recv a configuration message, send the rsp to it")
        except Exception as e:
            self.logger.error("Got an error:%s, the cfg msg:%s", str(e), cfg.msg)


class HostManager(object):

    __metaclass__ = AddLoggerToClass
    UPD_CRASH_FILE_TIME = 2

    def __init__(self):

        # create a dispatcher
        self.dispatcher = Dispatcher()
        self.driver_client =\
            RpdResHalClient("RpdHostRes_hal",
                            "This is RPD Resources hal client",
                            "1.0.0", self.dispatcher,
                            (MsgTypeHostResources, MsgTypeRpdCtrl), ())

        self.driver_client.start()

        self.crash_ctrl_timer = self.dispatcher.timer_register(
            HostManager.UPD_CRASH_FILE_TIME,
            self.driver_client.crashFileCtrlHandler.update_crash_file_table,
            None,
            timer_type=DpTimerManager.TIMER_REPEATED)

    def host_run(self):
        self.dispatcher.loop()


if __name__ == "__main__":
    setup_logging("HAL", filename="RpdResource_hal_client.log")

    driver = HostManager()
    driver.host_run()
