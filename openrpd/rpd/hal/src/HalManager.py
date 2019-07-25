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

import uuid
import logging
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.HalAgentClient import HalAgentClient
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.common.rpd_logging import AddLoggerToClass


class HalManager(object):
    """this is the base class of the manager class, this class will init some
    common variables.

    register the mgr socket to poller.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self, MgrType, poller):
        """
        :param MgrType: The manager type
        :param poller: a global poller, which we can register the manager to it
        :return: Manager object

        """

        if MgrType == HalTransport.HalTransportClientMgr:
            self.logger.info("Create the Hal client manager...")
        else:
            self.logger.error("Unexcepted MgrType got: %s" % str(MgrType))

        # create the Clinet manager
        self.transport = HalTransport(
            MgrType, HalTransport.HalServerMode, disconnectHandlerCb=self.disconnectHandler)

        self.poller = poller

        # register to the poller
        self.poller.register(self.transport.socket)

        # Add this socket to the socket agent mapping table
        HalGlobal.gSocketAgentMappingTable[self.transport.socket] = self

        # process the monitor socket
        if not (self.transport.monitor is None):
            HalGlobal.gMonitorSocketMappingTable[
                self.transport.monitor] = self.transport
            self.poller.register(self.transport.monitor)

    def disconnectHandler(self, monitorEvent):
        self.logger.debug("Got a Monitor event:%s" % str(monitorEvent))

    def disconnectCb(self, agent):
        """
        :param agent: The agent that will be disconnect
        :return: None

        """
        raise Exception("you need to implement this function")


class HalClientManager(HalManager):
    """The client Manager for Hal, responsible for process the request from the
    clients Client manager will handle the request from the clients, will
    handle the following HalMessages:

    * HalClientRegister
    * HalClientQuery
    * HalDriverQuery
    * HalClientInterestNo
    * HalGlobalStatsRe
    * HalClientStatsRe

    """
    __metaclass__ = AddLoggerToClass

    HalGlobal.gHandleTable["HalClientRegister"] = "handleRegisterRequest"
    HalGlobal.gHandleTable["HalClientQuery"] = "handleClientQuery"
    HalGlobal.gHandleTable[
        "HalClientInterestNotificationCfg"] = "handleClientInterestNotificationCfg"
    HalGlobal.gHandleTable["HalGlobalStatsReq"] = "handleGlobalStatsReq"
    HalGlobal.gHandleTable["HalAgentStatsReq"] = "handleAgentStatsReq"
    HalGlobal.gHandleTable["HalSetLoggingLevel"] = "handleHalSetLoggingLevel"

    def __init__(self, poller):
        """
        :param poller: Global poller, use to register the push and pull sockets
        :return:

        """
        super(HalClientManager, self).__init__(
            HalTransport.HalTransportClientMgr, poller)

    def handleRegisterRequest(self, register, test=False):
        """
        handle the client reigster request HalMessage, the process will be as following:
        1. if the HalMessage contains a valid ClientID, Hal will consider it as reconnect event, it will retrieve the
           index from gClientIndex and pass these variable to transport layer.
           Else, Hal will think it is a brand new register, and allocate a new UUID to client.
        2. Send a response message to client, with Pull/Push path, the client can connect to these paths
        :param register:the HalMessage register
        :return will send a response message to client

        """
        if register is None:
            msg = "Cannot handle the client register request since the register msg is None"
            self.logger.error(msg)
            raise Exception(msg)

        clientID = None
        index = None
        if register.msg.HasField("ClientID"):
            clientID = register.msg.ClientID
            if clientID in HalGlobal.gClientIndex:
                index = int(HalGlobal.gClientIndex[clientID])
                self.logger.info(
                    "*****Reuse the previous clientID[%s] and the index[%d]*****" % (clientID, index))

        # for brand new register
        if clientID is None or index is None:
            clientID = str(uuid.uuid4())
            self.logger.info(
                "Generate a new clientID for the the agent:%s" % clientID)

        # create the agent
        agent = HalAgentClient(self.poller, clientID, self.disconnectCb, index)

        # save the client register info to the internal DB
        self._addClientToDb(clientID, {
            "msg": register,
            "clientID": clientID,
            "agent": agent
        })

        # Update the states
        HalGlobalStats.NrClient += 1

        self.logger.info("Client[%s] is connected " % clientID)
        self.logger.info("register msg:" + str(register.msg))

        # we also need to parse the supported msg and make it more efficiency
        # change log:
        # Add the multiple client support, the msg can be send to multiple
        # clients
        for msgType in register.msg.ClientSupportedMessages:
            if msgType not in HalGlobal.gMsgTypeClientMapping:
                HalGlobal.gMsgTypeClientMapping[msgType] = list()

            HalGlobal.gMsgTypeClientMapping[
                msgType].append(HalGlobal.gClientDB[clientID])
        # send out the rsp
        regRsp = HalMessage("HalClientRegisterRsp",
                            Rsp={
                                "Status": HalCommon_pb2.SUCCESS,
                                "ErrorDescription": "Successful"
                            },
                            ClientID=clientID,
                            PathFromHalToClient=agent.transportPush.path,
                            PathFromClientToHal=agent.transportPull.path
                            )
        self.logger.debug(
            "Send register response to requester:%s" % regRsp.msg)
        # serialize and send out
        if not test:
            ret = self.transport.send(regRsp.Serialize())
            if ret is False:
                self.logger.error("Send client register response failed")

    def disconnectCb(self, agent):
        """This is he disconnect callback function from the agent. When some
        disconnect event happens on agent/push/pull, the disconnect event will
        be received by the agent, agent will process this event and then call
        the mgr to process it. the manager will remove the agent from the
        following global runtime DB:

        gClientDB --- The Db hold all the client info, including the name/version info, indexed by the clientID

        gNotificationMapping --- The mapping hold the notification messages and the client mapping

        :param agent: The agent that will be disconnect
        :return: None

        """
        self.logger.debug("Disconnecting a client agent from manager")

        client = None
        clientID = None
        for clientId in HalGlobal.gClientDB:
            if HalGlobal.gClientDB[clientId]['agent'] == agent:
                clientID = clientId
                client = HalGlobal.gClientDB[clientID]

        if client is None:
            self.logger.error(
                "Cannot find the client agent %s in global client table", agent)
            return

        if clientID is not None:
            HalGlobal.gClientDB.pop(clientID)

        self.logger.info(
            "Client[%s] is disconnected, recycle the resources " % clientID)

        # Process the notification handling.
        removeMsgList = list()
        for notiMsg in HalGlobal.gNotificationMapping:
            clientList = HalGlobal.gNotificationMapping[notiMsg]
            if client in clientList:
                clientList.remove(client)

            if len(clientList) == 0:
                removeMsgList.append(notiMsg)

        for msg in removeMsgList:
            HalGlobal.gNotificationMapping.pop(msg)

        # Process the MsgType handing
        msg = client["msg"]
        for msgType in msg.msg.ClientSupportedMessages:
            if msgType in HalGlobal.gMsgTypeClientMapping:
                client_list = HalGlobal.gMsgTypeClientMapping[msgType]
                if client in client_list:
                    client_list.remove(client)
                if len(HalGlobal.gMsgTypeClientMapping[msgType]) == 0:
                    HalGlobal.gMsgTypeClientMapping.pop(msgType)

        # Update the stats
        HalGlobalStats.NrClient -= 1

    def handleClientQuery(self, query):
        """handle the drivers query request. The handler will go through the
        gClientDB and find the all the drivers and send these info to client.

        :param query: the query message, we will use the clientID in this message
        :return return a message to client

        """
        if query is None:
            msg = "Cannot handle a none client query"
            self.logger.error(msg)
            raise Exception(msg)

        clientList = list()
        for clientID in HalGlobal.gClientDB:
            msg = HalGlobal.gClientDB[clientID]["msg"]
            retDict = dict()
            retDict["ClientID"] = clientID
            retDict["ClientName"] = msg.msg.ClientName
            retDict["ClientDescription"] = msg.msg.ClientDescription
            retDict["ClientVersion"] = msg.msg.ClientVersion

            retDict["ClientSupportedMessages"] = list()
            for item in msg.msg.ClientSupportedMessages:
                retDict["ClientSupportedMessages"].append(item)

            retDict["ClientSupportedNotificationMessages"] = list()
            for item in msg.msg.ClientSupportedNotificationMessages:
                retDict["ClientSupportedNotificationMessages"].append(item)
            clientList.append(retDict)

        rsp = HalMessage("HalClientQueryRsp",
                         ClientID=query.msg.ClientID,
                         Clients=clientList)
        self.logger.debug(
            "Send client query response to requester:%s" % rsp.msg)

        ret = self.transport.send(rsp.Serialize())
        if ret is False:
            self.logger.error("Send client query response failed")

    def handleClientInterestNotificationCfg(self, interest):
        """Client can send cfg message to specify which notification message it
        is interested in, this handler will handle this request. All the
        notification interest mapping are stored in a dict, the key is the
        notification type and value is a list, which hold all the clients.

        :param cfg: the interest message from the client
        :return: None

        """
        if interest is None:
            msg = "Cannot handle a none interest configuration."
            self.logger.error(msg)
            raise Exception(msg)

        # Get the interest msg types and put them in mapping tables
        cfgMsg = interest.msg
        self.logger.info(
            "handle client interest request from[%s]: %s" % (cfgMsg.ClientID, cfgMsg))
        for item in cfgMsg.ClientNotificationMessages:
            client = self._getClientFromDb(cfgMsg.ClientID)
            if client is None:
                self.logger.error(
                    "Cannot handle a message without client, msg:%s", cfgMsg)
                rspMsg = HalMessage(
                    "HalClientInterestNotificationCfgRsp", ClientID="",
                    Rsp={
                        "Status": HalCommon_pb2.FAILED,
                        "ErrorDescription": "No ClientID or no runtime client"
                    })
                self.logger.info(
                    "Send client interest response to requester:%s" % rspMsg.msg)
                ret = self.transport.send(rspMsg.Serialize())
                if ret is False:
                    self.logger.error("Send client interest response failed")
                return
            else:
                if item not in HalGlobal.gNotificationMapping:
                    HalGlobal.gNotificationMapping[item] = list()
                # check if we have register the message
                if client in HalGlobal.gNotificationMapping[item]:
                    pass
                else:
                    HalGlobal.gNotificationMapping[item].append(client)

        rspMsg = HalMessage(
            "HalClientInterestNotificationCfgRsp", ClientID=cfgMsg.ClientID,
            Rsp={
                "Status": HalCommon_pb2.SUCCESS,
                "ErrorDescription": "Successful"
            })
        self.logger.info(
            "Send client interest response to requester:%s" % rspMsg.msg)
        ret = self.transport.send(rspMsg.Serialize())
        if ret is False:
            self.logger.error("Send client interest response failed")

    def handleGlobalStatsReq(self, req):
        """handle the global stats message.

        :param req: request from the client, find it in message definition.
        :return:

        """
        # Get the Client ID for stats
        rspMsg = HalGlobalStats.generateHalMessage()
        self.logger.debug(
            "Send global stats  response to requester:%s" % rspMsg.msg)
        ret = self.transport.send(rspMsg.Serialize())
        if ret is False:
            self.logger.error("Send global statistics failed")

        return

    def handleAgentStatsReq(self, req):
        """handle the client stats message.

        :param req: request from the client, find it in message definition.
        :return:

        """
        clientID = None
        if req.msg.HasField("ClientID"):
            clientID = req.msg.ClientID

        error = False
        msg = ""
        if clientID is None:
            msg = "The requester must specify a client ID"
            error = True

        if clientID and not (clientID in HalGlobal.gClientDB):
            msg = "Cannot find the Client in DB"
            error = True

        if error:
            ret = self.transport.send(HalMessage("HalAgentStatsRsp",
                                                 Rsp={
                                                     "Status": HalCommon_pb2.FAILED,
                                                     "ErrorDescription": msg
                                                 }).Serialize())
            if ret is False:
                self.logger.error("Send hal agent statistics failure response failed")

            return

        client = HalGlobal.gClientDB[clientID]
        agent = client["agent"]
        msg = agent.stats.generateHalMessage()
        self.logger.debug(
            "Send Client stats  response to requester:%s" % msg.msg)
        ret = self.transport.send(msg.Serialize())
        if ret is False:
            self.logger.error("Send hal agent statistics response failed")

    def handleHalSetLoggingLevel(self, req):
        """handle the logging level change request, first, will find the module
        and then change the level based on the requirement.

        :param req: request from the client
        :return:

        """
        clientID = req.msg.ClientID
        level = req.msg.LoggingLevel
        module = req.msg.Module

        self.logger.info("Get a logging level change request from client[%s],set module[%s] to level[%s]" % (
            clientID, module, logging.getLevelName(level)
        ))

        if level not in (
            logging.CRITICAL, logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG
        ):
            self.logger.error(
                "Cannot set the module to level[%d], client:%s", level, clientID)
            ret = self.transport.send(HalMessage("HalSetLoggingLevelRsp",
                                                 ClientID=clientID,
                                                 Rsp={
                                                     "Status": HalCommon_pb2.FAILED,
                                                     "ErrorDescription": "Cannot set debug level since the debug level is "
                                                     "invalid"
                                                 }).Serialize())
            if ret is False:
                self.logger.error("Send logging level invalid response failed")

            return

        if module not in logging.Logger.manager.loggerDict:
            msg = "Cannot set the module[%s] level, since the module does not exist. client:%s" % (
                module, clientID)
            self.logger.error(msg)
            ret = self.transport.send(HalMessage("HalSetLoggingLevelRsp",
                                                 ClientID=clientID,
                                                 Rsp={
                                                     "Status": HalCommon_pb2.FAILED,
                                                     "ErrorDescription": msg
                                                 }).Serialize())
            if ret is False:
                self.logger.error("Send logging module invalid response failed")

            return

        # find the logger
        logger = logging.getLogger(module)
        logger.setLevel(level)

        ret = self.transport.send(HalMessage("HalSetLoggingLevelRsp",
                                             ClientID=clientID,
                                             Rsp={
                                                 "Status": HalCommon_pb2.SUCCESS,
                                                 "ErrorDescription": ""
                                             }).Serialize())
        if ret is False:
            self.logger.error("Send logging level success response failed")

    def handleClientTeardown(self, req):
        """handle the leave request from the client."""

    def handleInterestRequest(self, req):
        """handler the client interest request."""

    @staticmethod
    def _addClientToDb(clientID, content):
        HalGlobal.gClientDB[clientID] = content

    @staticmethod
    def _getClientFromDb(clientID):
        if clientID in HalGlobal.gClientDB:
            return HalGlobal.gClientDB[clientID]
        return None

    def _removeClientFromDb(self):
        pass
