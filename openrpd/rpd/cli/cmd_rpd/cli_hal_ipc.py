#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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


"""
    All the Client code locates on a single file
    The Client sample code will cover the following part
    1. Driver registration/Connection setup/ Hello msg
    2. Connection Monitor / Reconnection
    3. send the interest msg to HAL
"""

# Add the path to system
import re

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.gpb.HalMsgType import CLI_TO_HAL_MSG_TYPE
from rpd.gpb.cli_pb2 import t_CliMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalTransport


class HalClientError(Exception):

    def __init__(self, msg, expr=None):
        super(HalClientError, self).__init__(msg)
        self.msg = msg
        self.expr = expr


class CliHalIpc(object):
    """
    The Client for Hal
    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, appName, appDesc, appVer, interestedNotification, logConfigurePath=None):
        """
        :param appName: The application name, such as RPD CLI
        :param appDesc: A brief description about this application, such as the functionality description
        :param appVer: Driver specific version, such as 1.0.1
        :param interestedNotification: a tuple or list for the application interested msg types, the form will be
                                       (1, 2, 456, 10)
        :return: HalClient object
        """
        # sanity check the input args
        if not isinstance(appName, str) or not isinstance(appDesc, str) or not isinstance(appVer, str):
            raise HalClientError("Driver name/desc/version should be a str type")

        if not isinstance(interestedNotification, tuple) and not isinstance(interestedNotification, list):
            raise HalClientError("supportedMsgType should be a tuple or list")

        self.appName = appName
        self.appDesc = appDesc
        self.appVer = appVer
        self.interestedNotification = list(interestedNotification)

        # setup the logging
        # self.logger = log
        self.pollTimeout = 2000

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalClientInterestNotificationCfgRsp": self.sendInterestedNotificationsRspCb,
        }

        self.clientID = None

        self.mgrConnection = None
        self.pushSock = None
        self.pullSock = None

        self.disconnected = True

        self.seqNum = 0
        self.index = -1
        self.CfgMsgId_dict = dict(CLI_TO_HAL_MSG_TYPE.items())

    def start(self):
        """
        start poll the transport socket
        :return:
        """
        self.logger.debug("Start connect to hal...")
        self.connectionSetup()

        self.register(self.clientID)

    def connectionSetup(self):
        """
        Create the connection to the mgr and setup the poller
        :return:
        """
        self.logger.debug("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr, HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)

    def register(self, clientID):
        """
        send a register message to Hal and get the device ID from the Hal.
        :return:
        """
        if clientID is None:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.appName,
                                     ClientDescription=self.appDesc,
                                     ClientVersion=self.appVer)
        else:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.appName,
                                     ClientDescription=self.appDesc,
                                     ClientVersion=self.appVer,
                                     ClientID=clientID)

        if self.mgrConnection is None:
            errMsg = "Cannot send the register since the mgr connection is not setup"
            self.logger.error(errMsg)
            raise HalClientError(errMsg)
        self.logger.debug("Send the register msg to Hal...")
        self.mgrConnection.send(registerMsg.Serialize())
        bin = self.mgrConnection.recv()
        rsp = HalMessage.DeSerialize(bin)
        self.recvRegisterMsgCb(rsp)

    def _send(self, msg):
        if self.pushSock:
            self.pushSock.send(msg)
        else:
            self.logger.error("Cannot send the msg since the push socket is NULL")

    def sendMsg(self, cfgMsg):
        """
        The configutaion response routine, the driver implementor should fill
        sth into this function
        :param cfg: The original configutaion message
        :return:
        """
        if self.disconnected:
            self.logger.error("The client is on disconencted state,"
                              " skip to send the message.")
            return

        if cfgMsg is None or not isinstance(cfgMsg, t_CliMessage):
            self.logger.error("Cannot send a None or incorrect type to HAL")
            return

        for desc, value in cfgMsg.CliData.ListFields():
            if desc.name not in self.CfgMsgId_dict:
                self.logger.error("Cannot not find %s" % desc.name)
                return
            msg = HalMessage("HalConfig", SrcClientID=self.clientID,
                             SeqNum=self.seqNum,
                             CfgMsgType=self.CfgMsgId_dict[desc.name],
                             CfgMsgPayload=cfgMsg.SerializeToString())
            self._send(msg.Serialize())

            seq = self.seqNum
            self.seqNum += 1
            return seq

    def recvMsg(self, timeout=None):
        if self.pullSock:
            try:
                bin = self.pullSock.recv()
            except Exception as e:
                print("Got exception when receiving the msg, reason:%s" % str(e))
                return None
            rsp = HalMessage.DeSerialize(bin)
            if rsp.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
                self.logger.error("Get rsp msg fail, reason[%s]" % rsp.msg.Rsp.ErrorDescription)
                return None
            cli_msg = t_CliMessage()
            cli_msg.ParseFromString(rsp.msg.CfgMsgPayload)
            return cli_msg
        else:
            self.logger.error("Cannot receive msg since the pull socket is NULL")
            return None

    def sayHelloToHal(self):
        """
        Send a hello message to verify the agent path is correct
        :return:
        """
        self.logger.debug("Send a Hello message to Hal")
        helloMsg = HalMessage("HalClientHello", ClientID=self.clientID)
        self._send(helloMsg.Serialize())

    def sendInterestedNotifications(self, notifications):
        """
        Send the notifications to the HAL
        :param notifications:
        :return:
        """
        self.logger.debug("Send a Interested notification configuration msg to HAL")
        if notifications is not None and not isinstance(notifications, tuple) and not isinstance(notifications, list):
            self.logger.error("Cannot set an notification with wrong type, you can pass a tuple or list to it ")
            return
        configMsg = HalMessage("HalClientInterestNotificationCfg", ClientID=self.clientID,
                               ClientNotificationMessages=notifications)
        self.mgrConnection.send(configMsg.Serialize())
        # REQ/RSP
        bin = self.mgrConnection.recv()
        return bin

    def sendInterestedNotificationsRspCb(self, rsp):
        """
        Receive a response message from the HAL for the notification rsp callback
        :param rsp:
        :return:
        """
        self.logger.debug("Receive a interest notification response message:" + str(rsp.msg))

    def recvHelloRspMsgCb(self, hello):
        """
        Call back for Hello Message
        :param hello:
        :return:
        """
        self.logger.debug("Recv a hello message:" + str(hello.msg))

    def connectionDisconnectCb(self, msg):
        """
        the connection has been detected disconnected , register it again
        We have reconenct, we have to assure the regiter message is received by the HAL
        :param msg:
        :return:
        """

        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return
        self.logger.debug("Detected disconnected, register again")
        # clean up the push and pull socket
        if 0:
            self.pushSock.close()
            self.pullSock.close()

            self.pushSock = None
            self.pullSock = None
            self.mgrConnection = None
            # self.clientID = None #will not set it to none since

            self.connectionSetup()

        self.mgrConnection.monitor.close()
        self.mgrConnection.close()

        # create the connection again
        self.connectionSetup()
        self.register(self.clientID)  # The zmq lower part will handle the reconnect

        self.disconnected = True

    def recvRegisterMsgCb(self, cfg):
        """
        the callback handler for the configuration message
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
            self.logger.error("Cannot get index from the path [%s]" % self.pushPath)
            return
        if self.index == -1:
            self.index = index
            self.pushSock = HalTransport(HalTransport.HalTransportClientAgentPull, HalTransport.HalClientMode,
                                         index=index, socketMode=HalTransport.HalSocketPushMode,
                                         disconnectHandlerCb=self.connectionDisconnectCb)

            self.pullSock = HalTransport(HalTransport.HalTransportClientAgentPush, HalTransport.HalClientMode,
                                         index=index, socketMode=HalTransport.HalSocketPullMode,
                                         disconnectHandlerCb=self.connectionDisconnectCb)

        self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def clientQuery(self):
        """
        Send a client query message to get all registered client info
        :return:
        """

        if self.disconnected:
            self.logger.error("The client is on disconencted state,"
                              " skip to send the message.")
            return None
        self.logger.debug("Send a client query message to Hal")
        clientQueryMsg = HalMessage("HalClientQuery", ClientID=self.clientID)
        self.mgrConnection.send(clientQueryMsg.Serialize())
        try:
            bin = self.mgrConnection.recv()
        except Exception as e:
            print("Got exception when receiving the msg, reason:%s" % str(e))
            return None
        rsp = HalMessage.DeSerialize(bin)
        if rsp.msg.MsgType != "HalClientQueryRsp":
            self.logger.error("Cannot Query client, "
                              "reason[msgType mismatch:%s]" % rsp.msg.MsgType)
            return None
        return rsp

    def getClientstats(self, clientId):
        """
        Send a client statistics request message
        :return:
        """

        if self.disconnected:
            self.logger.error("The client is on disconencted state,"
                              " skip to send the message.")
            return None
        self.logger.debug("Send a client statistics message to Hal")
        statsQueryMsg = HalMessage("HalAgentStatsReq", ClientID=clientId)
        self.mgrConnection.send(statsQueryMsg.Serialize())
        try:
            bin = self.mgrConnection.recv()
        except Exception as e:
            print("Got exception when receiving the msg, reason:%s" % str(e))
            return None
        rsp = HalMessage.DeSerialize(bin)
        if rsp.msg.MsgType != "HalAgentStatsRsp":
            self.logger.error("Cannot Query client statistics, "
                              "reason[msgType mismatch:%s]" % rsp.msg.MsgType)
            return None
        return rsp

    def _getIndexFromPath(self):
        rePattern = r"/(\d+)/"
        ret = re.search(rePattern, self.pushPath)

        if ret is not None:
            digitStr = ret.group(1)
            return int(digitStr)

        return -1
