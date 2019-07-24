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

from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalAgent import HalAgent
from rpd.common.rpd_logging import AddLoggerToClass


class HalAgentClient(HalAgent):
    """This class is the client agent class.

    the class will have the following API:

    * disconnectHandler:  the
      handler will be invoked when the transport layer get a disconnect
      event, the function will clean the agent
      resources, including the socket resource, remove it from the global
      runtime DB.
    * sendMsg: This API will send message via
      Agent's pushsock channel.
    * handleClientHello: The API will handle
      the Hello message
    * handleConfigRsp: This API will handle the
      configuration response HalMessage from client
    * handleNotification: This API will handle the notification HalMessage

    """
    ClientIndex = 0
    # self handle table
    HalGlobal.gHandleTable["HalClientHello"] = "handleClientHello"
    HalGlobal.gHandleTable["HalConfig"] = "handleConfig"
    HalGlobal.gHandleTable["HalConfigRsp"] = "handleConfigRsp"
    HalGlobal.gHandleTable["HalNotification"] = "handleNotification"

    __metaclass__ = AddLoggerToClass

    def __init__(self, poller, clientID, disconnectHandler, reuseIndex=None):
        """The function will generate the client agent object. the main
        function is to create the socket channel. for Hal the sock channel
        works at the server mode, it will listen at these sockets.

        :param poller: a global poller, the transport socket and the monitor socket will register into it.
        :param ClientID: a client  UUID
        :param disconnectHandler: the manager disconnect handler, will be called with agent gets a disconnect event.
        :param reuseIndex: for the client restart, it will provide it's previous ID, the agent will reuse
                            these ID and use the same transport path.
        :return: agent obj

        """
        super(HalAgentClient, self).__init__()

        if reuseIndex is None:
            # Generate the client index
            while True:
                index = HalAgentClient.ClientIndex
                HalAgentClient.ClientIndex += 1
                if str(index) not in HalGlobal.gClientIndex.values():
                    break
        else:
            index = reuseIndex

        self.index = index

        if clientID not in HalGlobal.gClientIndex:
            HalGlobal.gHalClientDbConnection.addMsgtoDB(
                "ClientIndex", {clientID: index}, expired=False)

        # Start the transport
        self.transportPush = HalTransport(
            HalTransport.HalTransportClientAgentPush, HalTransport.HalServerMode,
            index=index, socketMode=HalTransport.HalSocketPushMode,
            disconnectHandlerCb=self.disconnectHandler)

        # for the push, we don't need to register to the poller

        if self.transportPush.monitor:
            poller.register(self.transportPush.monitor)
            HalGlobal.gMonitorSocketMappingTable[
                self.transportPush.monitor] = self.transportPush

        # start the pull transport
        self.transportPull = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalServerMode,
            index=index, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=self.disconnectHandler)
        poller.register(self.transportPull.socket)
        # add the pull socket to the socket agent mapping table
        HalGlobal.gSocketAgentMappingTable[self.transportPull.socket] = self

        # process the monitor
        if self.transportPull.monitor:
            poller.register(self.transportPull.monitor)
            HalGlobal.gMonitorSocketMappingTable[
                self.transportPull.monitor] = self.transportPull

        # For other variables
        self.mgrDisconnectCb = disconnectHandler
        self.disconnectProcessed = False
        self.poller = poller
        self.clientID = clientID

        # put the message into the resend list
        self.logger.debug("Check the last unsuccessful message.%s for client[%s]" % (
            HalGlobal.gRestartResendMsg, self.clientID))
        if self.clientID:
            for key in HalGlobal.gRestartResendMsg:
                if key.startswith(self.clientID):
                    self.logger.debug("Add message[%s] to resend list" % key)
                    cfg = HalGlobal.gRestartResendMsg[key]
                    seqNum = cfg.msg.SeqNum if cfg.msg.HasField(
                        "SeqNum") else 0
                    self.addToResendList(seq=seqNum, sendagent=self, msg=cfg)

    def disconnectHandler(self, transport):
        """the function will be invoked when the transport layer get a
        disconnect event, the fucntion will clean the agent resources,
        including the socket resource, remove it from the global runtime DB.

        :param transport: the transport object, pull/push
        :return:

        """
        self.logger.info(
            "Got a client[%s] disconnect event, process it in client agent" % self.clientID)

        # we have two transport layer can trigger this handler, we only need one time to process,
        # this flag is used for this
        if self.disconnectProcessed:
            self.logger.info(
                "client disconnect event has been processed")
            return

        # unregister/close the monitor socket
        if self.transportPull.monitor:
            HalGlobal.gMonitorSocketMappingTable.pop(
                self.transportPull.monitor)
            self.poller.unregister(self.transportPull.monitor)
            self.transportPull.socket.disable_monitor()
            self.transportPull.monitor.close()
        if self.transportPush.monitor:
            HalGlobal.gMonitorSocketMappingTable.pop(
                self.transportPush.monitor)
            self.poller.unregister(self.transportPush.monitor)
            self.transportPush.socket.disable_monitor()
            self.transportPush.monitor.close()

        # call the mgr callback to process the disconnect event
        self.mgrDisconnectCb(self)

        # remove the transportPull from the poller
        self.poller.unregister(self.transportPull.socket)

        # remove from the socket agent mapping table
        HalGlobal.gSocketAgentMappingTable.pop(self.transportPull.socket)

        # Remove from the global Agent DB
        self.removeFromAgentDB()

        # close the push and pull, monitor socket
        self.transportPull.close()
        self.transportPush.close()

        self.disconnectProcessed = True

    def sendMsg(self, msg):
        """Send a message via the transport push socket.

        :param msg: a stringlized msg, not the HAlMessage
        :return:

        """
        if msg is None:
            self.logger.error(
                "The msg is None, skip invoking the low level function")
            return

        self.transportPush.send(msg)

    def handleClientHello(self, hello):
        """The Hello message handler.

        :param hello: which is a HalMessage, hold all the info about the hello message
        :return:  NA

        """
        self.logger.debug("Send out the hello rsp message")

        # update the stats
        self.stats.NrMsgs += 1
        self.stats.NrHelloMsgs += 1
        if hello is None:
            msg = "Cannot handle a none client hello message"
            self.logger.error(msg)
            self.stats.NrErrorMsgs += 1
            raise Exception(msg)

        rsp = HalMessage("HalClientHelloRsp",
                         ClientID=hello.msg.ClientID)
        # send out
        self.transportPush.send(rsp.Serialize())
        self.stats.NrHelloRspMsgs += 1

    def handleConfigRsp(self, cfgRsp):
        """This API will handle the configuration response HalMessage from
        client.

        :param cfgRsp:
        :return:

        """
        if cfgRsp is None:
            msg = "Cannot handle a none config response message"
            self.logger.error(msg)
            raise Exception(msg)

        HalGlobal.gHalMsgDbConnection.removeMsgFromDB(
            cfgRsp.msg.SrcClientID + "-" + str(cfgRsp.msg.SeqNum))
        HalGlobal.gDispatcher.dispatchCfgRspMessage(self, cfgRsp)

        self.stats.NrCfgRspMsgs += 1

    def handleNotification(self, notification):
        """This API will handle the notification HalMessage.

        :param notification: the notification HalMessage
        :return:

        """
        if notification is None:
            msg = "Cannot handle the notification since the msg is None"
            self.logger.error(msg)
            raise Exception(msg)
        # update the stats
        self.stats.NrNotifyMsgs += 1
        self.stats.NrMsgs += 1
        HalGlobal.gDispatcher.dispatchNotificationMsg(self, notification)

    def handleConfig(self, cfg):
        """The configuration HalMessage handler.

        :param cfg:  The Config message from the client
        :return:

        """
        if cfg is None:
            msg = "Cannot handle a none config message"
            self.logger.error(msg)
            raise Exception(msg)

        # Add the message to the DB
        seqNum = cfg.msg.SeqNum if cfg.msg.HasField("SeqNum") else 0
        msgBinary = cfg.originalBinary \
            if cfg.originalBinary else cfg.Serialize()
        # add the msg to DB
        HalGlobal.gHalMsgDbConnection.addMsgtoDB(
            msgKey=cfg.msg.SrcClientID + "-" + str(seqNum),
            msg={
                "ClientID": cfg.msg.SrcClientID,
                "Msg": msgBinary
            }
        )

        # Update the stats
        self.stats.NrMsgs += 1
        self.stats.NrCfgMsgs += 1

        # first, process the resendList
        self.processResendList()

        # Dispatch this message to the correct client
        ret = HalGlobal.gDispatcher.dispatchCfgMessage(self, cfg)
        if ret == -1:
            self.addToResendList(seq=seqNum, sendagent=self, msg=cfg)
