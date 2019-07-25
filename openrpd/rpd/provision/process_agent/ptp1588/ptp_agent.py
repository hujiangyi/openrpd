#
# Copyright (c) 2016 Cisco and/or its affiliates,
#                    MaxLinear, Inc. ("MaxLinear"), and
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
from zmq.utils.monitor import recv_monitor_message
import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.hal.lib.clients.HalClient0 import HalClient, HalClientError
from rpd.hal.src.HalConfigMsg import MsgTypeGeneralNtf, MsgTypeRoutePtpStatus, \
    MsgTypePtpClockStatus, MsgTypeRpdState, MsgTypePtpStatusGet
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification


class HalPtpClientError(HalClientError):

    def __init__(self, msg, expr=None):
        super(HalPtpClientError, self).__init__(msg)
        self.msg = "HalPtpClientError: " + msg


class HalPtpClient(HalClient):
    """The PTP Client for Hal."""
    SYNC = "ALIGNED"
    LOS = "LOSS OF SYNC"

    __metaclass__ = AddLoggerToClass

    def __init__(self, appName, appDesc, appVer, supportedNotification, supportedMsgsTypes, dispatcher,
                 notifyCb, logConfigurePath=None):

        # sanity check the input args
        super(HalPtpClient, self).__init__(appName, appDesc, appVer,
                                           supportedNotification,
                                           logConfigurePath,
                                           supportedMsgsTypes)

        if not isinstance(supportedNotification, tuple) and not isinstance(supportedNotification, list):
            raise HalClientError(
                "supportedMsgsTypes should be a tuple or list")

        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalSetLoggingLevelRsp": self.recvHalSetLoggingLevelRspCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfigRsp": self.recvCfgMsgRspCb,
            "HalClientInterestNotificationCfgRsp": self.sendInterestedNotificationsRspCb,
            "HalNotification": self.recvNotificationCb,
            "HalConfig": self.recvCfgMsgCb,
        }

        self.notifyHandler = notifyCb
        self.dispatcher = dispatcher
        self.supportedNotificationMsgs = list(supportedNotification)
        self.dispatcher.timer_register(1, self.checkPtpStatus, timer_type=1)
        self.ptp_result = t_GeneralNotification.PTPACQUIRE

    def checkPtpStatus(self, fd):
        self.sendCfgMsg(MsgTypePtpStatusGet, "GetPtpStatus")

    def start(self):
        """Start polling the transport socket."""
        self.logger.debug("Start the client poll...")
        self.connectionSetup(self.dispatcher)
        self.register(self.clientID)

    def connectionSetup(self, disp=None):
        """Create the connection to the mgr and setup the poller."""
        self.logger.debug("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr,
                                          HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)
        # register the mgr socket
        disp.fd_register(self.mgrConnection.socket,
                         zmq.POLLIN, self.ptp_hal_cb)
        disp.fd_register(self.mgrConnection.monitor,
                         zmq.POLLIN, self.ptp_hal_cb)

    def connectionDisconnectCb(self, msg):
        """The connection has been detected disconnected , register it again
        We have reconenct, we have to assure the regiter message is received
        by the HAL.

        :param msg:
        :return:

        """
        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return
        self.logger.debug("Detected disconnected, register again")
        # clean up the push and pull socket
        if 1:
            self.pushSock.close()
            self.pullSock.close()

            self.dispatcher.fd_unregister(self.pullSock.socket)
            self.dispatcher.fd_unregister(self.pullSock.monitor)
            self.dispatcher.fd_unregister(self.pullSock.monitor)

            self.pushSock = None
            self.pullSock = None
            self.mgrConnection = None
            # self.clientID = None #will not set it to none since

            self.connectionSetup(self.dispatcher)

    def recvRegisterMsgCb(self, cfg):
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
        :return:

        """
        # self.logger.debug("Recv a Message from the Hal:" % str(cfg.msg))

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.error("Cannot register to Hal, reason[%s]" % cfg.msg.Rsp.ErrorDescription)
            return

        self.clientID = cfg.msg.ClientID

        # Setup the push and pull connection
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

        # get the index of the path
        index = self._getIndexFromPath()
        if index == -1:
            self.logger.error(
                "Cannot get index from the path [%s]" % self.pushPath)
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
            self.dispatcher.fd_register(self.pullSock.socket,
                                        zmq.POLLIN, self.ptp_hal_cb)
            self.dispatcher.fd_register(self.pushSock.monitor,
                                        zmq.POLLIN, self.ptp_hal_cb)
            self.dispatcher.fd_register(self.pullSock.monitor,
                                        zmq.POLLIN, self.ptp_hal_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        self.sendInterestedNotifications(self.interestedNotification)
        self.disconnected = False

        return

    def recvCfgMsgCb(self, cfgMsg):
        """Receive a configuration message from the Hal, processing it.

        :param cfgMsg:
        :return:

        """
        try:
            msgType = cfgMsg.msg.CfgMsgType
            if msgType == MsgTypeRpdState:
                self.getRpdPtpState(cfgMsg)
        except Exception as e:  # pragma: no cover
            self.logger.error("Got an error:%s, the cfg msg:%s",
                              str(e), cfgMsg)
            rsp = {
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": "Process configuration failed, reason:%s"
                                    % str(e)
            }
            self.sendCfgRspMsg(cfgMsg, rsp)

    def recvCfgMsgRspCb(self, cfg):
        """Receive a configuration response message from the Hal, processing it.

        :param cfg:
        :return:

        """
        self.logger.debug(
            "Recv a ptp configuration response message:" + str(cfg.msg))

        if cfg.msg.CfgMsgType == MsgTypePtpStatusGet:
            if cfg.msg.CfgMsgPayload in [self.LOS, self.SYNC]:
                self.notifyHandler(cfg.msg.CfgMsgPayload)
                self.logger.debug(
                    "send %s notification to provision", cfg.msg.CfgMsgPayload)

    def ptp_hal_cb(self, sock, mask):
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
                self.logger.debug(
                    "Geting an error when trying with nonblock read:" + str(e))
                break
            except Exception as e:
                self.logger.error("Error happens, reason:%s" % str(e))
                break

    def recvNotificationCb(self, msg):
        """Receive the notification from ptp hal driver.

        :param msg:
        :return:

        """
        self.logger.info("recv the notification from ptp driver")
        print msg.msg.HalNotificationType
        print msg.msg.HalNotificationPayLoad
        if msg.msg.HalNotificationType == MsgTypePtpClockStatus:
            if msg.msg.HalNotificationPayLoad in [self.LOS, self.SYNC]:
                self.notifyHandler(msg.msg.HalNotificationPayLoad)
                print "send %s notification to provision" % msg.msg.HalNotificationPayLoad

    def getRpdPtpState(self, cfg):
        rsp = t_RcpMessage()
        rsp.ParseFromString(cfg.msg.CfgMsgPayload)
        config = rsp.RpdDataMessage.RpdData
        try:
            config.RpdState.LocalPtpSyncStatus = \
                True if self.ptp_result == t_GeneralNotification.PTPSYNCHRONIZED else False
            cfg.CfgMsgPayload = config.SerializeToString()
            rsp.RpdDataMessage.RpdData.CopyFrom(config)
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            payload = rsp.SerializeToString()
            self.logger.info("Send rpd state LocalPtpSyncStatus response, %s" % rsp)
            msg = HalMessage(
                "HalConfigRsp", SrcClientID=cfg.msg.SrcClientID, SeqNum=cfg.msg.SeqNum,
                Rsp={
                    "Status": HalCommon_pb2.SUCCESS,
                    "ErrorDescription": "PTP LOCALPTPSYNCSTATUS query success"
                },
                CfgMsgType=cfg.msg.CfgMsgType,
                CfgMsgPayload=payload)
            self.pushSock.send(msg.Serialize())
        except Exception as e:
            self.logger.error("excpetipn:%s", str(e))
        return


class PtpAgent(agent.ProcessAgent):
    SYNC = "ALIGNED"
    LOS = "LOSS OF SYNC"

    ptp_status_to_result = {
        SYNC: 'UP',
        LOS: 'DOWN',
    }

    def __init__(self, agent_id=agent.ProcessAgent.AGENTTYPE_PTP):

        super(PtpAgent, self).__init__(agent_id)

        self.ptp_requester = []
        self.ptp_status = self.LOS
        self.PtpClient = HalPtpClient(
            "PTPClient", "This is a PTP application", "1.9.0",
            [MsgTypeRoutePtpStatus, MsgTypeGeneralNtf, ],
            [MsgTypeRpdState, MsgTypePtpClockStatus, ], self.dispatcher,
            self.PtpNotifyHandler, logConfigurePath="../../../hal/conf/ClientLogging.conf")
        self.PtpClient.start()

    def process_event_action(self, action):
        """Process the request from the client.

        :param action:
        :return:

        """
        id = action.ccap_core_id
        event_action = action.action

        self.logger.debug("Receive an event action:%s", action)

        if id not in self.ccap_cores:
            self.logger.error(
                "Cannot process the event action for id %s, reason: id is not registered" % id)
            return

        # Get the transport
        ccap_core = self.ccap_cores[id]
        transport = self.mgrs[ccap_core["mgr"]]['transport']

        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            # check if we are in the requester list, if yes,
            # we just send a current status to it
            if id not in self.ptp_requester:
                self.ptp_requester.append(id)

            event_request_rsp = protoDef.msg_event_notification()
            event_request_rsp.core_event.id = id
            event_request_rsp.core_event.ccap_core_id = id
            event_request_rsp.core_event.status = protoDef.msg_core_event_notification.OK
            event_request_rsp.core_event.reason = "Id has been issue this " \
                                                  "action, send current status to you"
            event_request_rsp.core_event.event_id = self.id
            event_request_rsp.core_event.result = self.ptp_status_to_result[self.ptp_status]
            transport.sock.send(
                event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)

            self.PtpClient.sendNotificationMsg(
                MsgTypeRoutePtpStatus, self.ptp_status)
            gen_ntf_msg = t_GeneralNotification()
            gen_ntf_msg.NotificationType = t_GeneralNotification.PTPRESULTNOTIFICATION
            gen_ntf_msg.PtpResult = self.PtpClient.ptp_result
            self.PtpClient.sendNotificationMsg(
                MsgTypeGeneralNtf, gen_ntf_msg.SerializeToString())
            self.logger.info(
                "successfully process an start/poll event action for id"
                " %s, return:%s" % (id, event_request_rsp))
            return

        if event_action == protoDef.msg_event.STOP:
            event_request_rsp = protoDef.msg_event_notification()
            event_request_rsp.core_event.id = id
            event_request_rsp.core_event.ccap_core_id = id
            event_request_rsp.core_event.event_id = self.id
            event_request_rsp.core_event.status = protoDef.msg_core_event_notification.OK
            event_request_rsp.core_event.result = self.ptp_status_to_result[self.ptp_status]

            if id in self.ptp_requester:
                self.ptp_requester.remove(id)
                event_request_rsp.core_event.reason = "Successful stop event."
            else:
                event_request_rsp.core_event.reason = "Successful stop event, not request before"
            transport.sock.send(
                event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)

            self.logger.info(
                "successfully process an stop event action for id %s, "
                "return:%s" % (id, event_request_rsp))
            return

    def PtpNotifyHandler(self, new_status):
        if self.ptp_status == self.SYNC and self.ptp_status == new_status:
            pass
        else:
            self.logger.debug(
                "The new status:%s, old status:%s" % (new_status, self.ptp_status))
        if self.ptp_status != new_status:
            self.ptp_status = new_status
            if self.ptp_status == self.SYNC:
                self.PtpClient.ptp_result = t_GeneralNotification.PTPSYNCHRONIZED
            else:
                self.PtpClient.ptp_result = t_GeneralNotification.PTPACQUIRE

            if len(self.ptp_requester):
                self.PtpClient.sendNotificationMsg(
                    MsgTypeRoutePtpStatus, self.ptp_status)
                gen_ntf_msg = t_GeneralNotification()
                gen_ntf_msg.NotificationType = t_GeneralNotification.PTPRESULTNOTIFICATION
                gen_ntf_msg.PtpResult = self.PtpClient.ptp_result
                self.PtpClient.sendNotificationMsg(
                    MsgTypeGeneralNtf, gen_ntf_msg.SerializeToString())
            else:
                self.logger.info(
                    "No ccap core started yet, ccap cores:%s, requesters:%s"
                    % (self.ccap_cores, self.ptp_requester))

            for id in self.ptp_requester:
                if id not in self.ccap_cores:
                    self.ptp_requester.remove(id)
                    continue
                event_request_rsp = protoDef.msg_event_notification()
                event_request_rsp.core_event.id = id
                event_request_rsp.core_event.ccap_core_id = id
                event_request_rsp.core_event.status = protoDef.msg_core_event_notification.OK
                event_request_rsp.core_event.reason = "Status changed"
                event_request_rsp.core_event.event_id = self.id
                event_request_rsp.core_event.result = self.ptp_status_to_result[self.ptp_status]
                ccap_core = self.ccap_cores[id]
                transport = self.mgrs[ccap_core["mgr"]]['transport']
                try:
                    transport.sock.send(
                        event_request_rsp.SerializeToString(),
                        flags=zmq.NOBLOCK)
                    self.logger.info("Send status change to id %s, msg:%s" %
                                     (id, event_request_rsp))
                except zmq.Again as e:
                    pass
                except Exception as e:
                    self.logger.error("Cannot send the event, reason:%s" % str(e))


if __name__ == "__main__":
    setup_logging("PROVISION", filename="provision_ptp.log")
    ptp_agent = PtpAgent()
    ptp_agent.start()
