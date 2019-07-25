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
import subprocess
import os
import time
import uuid
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.hal.src.HalDispatcher import HalDispatcher
from rpd.hal.src.HalAgentClient import HalAgentClient
from rpd.hal.src.HalManager import HalClientManager
from rpd.hal.src.transport.HalTransport import HalPoller
from rpd.hal.src.HalConfigMsg import RCP_TO_HAL_MSG_TYPE
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalAgent import HalAgent


timeStampSock = "/tmp/testHalDispatcherRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"

INVALID_MSGTYPE = 20600
# Setup DB


def setupDB():
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # Start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    filename = "/tmp/test_haldispatcher.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(timeStampSock):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")

    HalGlobal.gHalClientDbConnection = HalDatabase(timeStampSock, 30, 11)


class testHalDispatcher(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupDB()

        cls.clientID = str(uuid.uuid4())
        cls.poller = HalPoller()
        cls.halDispatcher = HalDispatcher()
        cls.halAgent = HalAgent()

    @classmethod
    def tearDownClass(cls):
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)

    def setUp(self):
        self.clientMgr = HalClientManager(self.poller)

    def tearDown(self):
        keys = HalGlobal.gClientDB.keys()
        for clientId in keys:
            self.clientMgr.disconnectCb(HalGlobal.gClientDB[clientId]['agent'])
        self.assertEqual(HalGlobalStats.NrClient, 0)

    # Create def for test
    def tmpCb(self, int):
        pass

    def test_cfgMsgTimeoutCb(self):
        """Construct client agent msg and original msg."""

        try:
            self.clientMgr.handleRegisterRequest(None)
        except Exception as e:
            self.assertEqual(
                "Cannot handle the client register "
                "request since the register msg is None", str(e))

        # Create a client msg
        agent = HalAgentClient(self.poller,
                               clientID="123",
                               disconnectHandler=None,
                               reuseIndex=None)

        # Create a original message
        oricfgMsg = HalMessage("HalConfig",
                               SrcClientID="123",
                               SeqNum=33,
                               CfgMsgType=1,
                               CfgMsgPayload="test HalDispatcher")

        # Test cfgMsgTimeoutCb
        currentErrorMsgs = HalGlobalStats.NrErrorMsgs
        self.halDispatcher.cfgMsgTimeoutCb(
            args={"agent": agent, "originalMsg": oricfgMsg})
        self.assertEqual(HalGlobalStats.NrErrorMsgs, currentErrorMsgs + 1)

    def test_dispatchCfgMessage(self):
        """Dispatch the client cfg msg. HalGlobal.gMsgTypeDriverMapping is
        expected to be in range(1024~2060). """

        # self.driverMgr = HalDriverManager(self.poller)

        # For integration test
        # if HalGlobalStats.NrDriver != 0:
        #    HalGlobalStats.NrDriver = 0

        try:
            self.clientMgr.handleRegisterRequest(None)
        except Exception as e:
            self.assertEqual(
                "Cannot handle the client register "
                "request since the register msg is None", str(e))

        # Construct a register message
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="testDriver",
                                 ClientDescription="test message",
                                 ClientVersion="1.0.1",
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        self.clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 1)

        # Create a sendAgent msg
        agent = HalAgentClient(self.poller,
                               clientID="8734hhfs",
                               disconnectHandler=None,
                               reuseIndex=None)

        cfgMsgInFirst = HalMessage("HalConfig",
                                   SrcClientID="123",
                                   SeqNum=1003,
                                   # The first cfg.msg.CfgMsgType is 1024
                                   CfgMsgType=1024,
                                   CfgMsgPayload="test HalDispatcher")

        # Test CfgMsgType=1024 in
        # HalGlobal.gMsgTypeDriverMapping(1024~2060--->HalConfigMsg)
        self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgInFirst)

        # Return 0 for normal process
        self.assertEqual(self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgInFirst), 0)

        cfgMsgInEnd = HalMessage("HalConfig",
                                 SrcClientID="123",
                                 SeqNum=1003,
                                 # The last cfg.msg.CfgMsgType is 2060
                                 CfgMsgType=2060,
                                 CfgMsgPayload="test HalDispatcher")

        # Test CfgMsgType=2060 in HalGlobal.gMsgTypeDriverMapping(1024~2060--->HalConfigMsg)
        # HalGlobal.gMsgTypeDriverMapping (1024~1033, 2048~2060)
        self.halDispatcher.dispatchCfgMessage(sendAgent=agent, cfg=cfgMsgInEnd)

        # Return 0 for normal process
        self.assertEqual(
            self.halDispatcher.dispatchCfgMessage(sendAgent=agent, cfg=cfgMsgInEnd), 0)

        cfgMsgNotIn = HalMessage("HalConfig",
                                 SrcClientID="123",
                                 SeqNum=122,
                                 CfgMsgType=INVALID_MSGTYPE,
                                 CfgMsgPayload="test HalDispatcher")

        # Test CfgMsgType=INVALID_MSGTYPE not in HalGlobal.gMsgTypeDriverMapping
        self.halDispatcher.dispatchCfgMessage(sendAgent=agent, cfg=cfgMsgNotIn)

        # Return -1 for error
        self.assertEqual(self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgNotIn), -1)

        cfgMsgNotInF = HalMessage("HalConfig",
                                  SrcClientID="123",
                                  SeqNum=122,
                                  # cfg.msg.CfgMsgType <1024
                                  CfgMsgType=1023,
                                  CfgMsgPayload="test HalDispatcher")

        # Test CfgMsgType=1023(<1024) not in HalGlobal.gMsgTypeDriverMapping
        self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgNotInF)

        # Return -1 for error
        self.assertEqual(self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgNotInF), -1)

        # Test CfgMsgType=2059 that is in HalGlobal.gMsgTypeDriverMapping
        # System configure message type
        MsgTypeRpdCapabilities = 0
        MsgTypeCcapCoreIdentification = 1
        MsgTypeSsd = 2

        cfgMsgInEndx = HalMessage("HalConfig",
                                  SrcClientID="123",
                                  SeqNum=1003,
                                  # The last cfg.msg.CfgMsgType is
                                  CfgMsgType=MsgTypeCcapCoreIdentification,
                                  CfgMsgPayload="test HalDispatcher")

        # Test CfgMsgType= in
        # HalGlobal.gMsgTypeDriverMapping(1024~2060--->HalConfigMsg)
        self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgInEndx)

        # Return 0 for normal process
        self.assertEqual(self.halDispatcher.dispatchCfgMessage(
            sendAgent=agent, cfg=cfgMsgInEndx), 0)

        # send to itself
        if (1024 in HalGlobal.gMsgTypeClientMapping
            and isinstance(HalGlobal.gMsgTypeClientMapping[1024], list)
                and len(HalGlobal.gMsgTypeClientMapping[1024]) >= 1):
            tmpagent = HalGlobal.gMsgTypeClientMapping[1024][0]["agent"]
            self.halDispatcher.dispatchCfgMessage(
                sendAgent=tmpagent, cfg=cfgMsgInFirst)

    def test_dispatchCfgRspMessage(self):
        """Dispatch the message from the driver clientID whether in
        HalGlobal.gClientDB."""

        # self.clientMgr = HalClientManager(self.poller)

        HalGlobal.gClientIndex[self.clientID] = 3

        # Create a client register msg
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="testClient",
                                 ClientDescription="test Clientmessage ",
                                 ClientVersion="1.0.1",
                                 ClientID=self.clientID)
        self.clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 1)

        tmpDriverID = str(uuid.uuid4())
        HalGlobal.gClientIndex[tmpDriverID] = 2

        # Create a driver register msg
        registerMsg = HalMessage("HalClientRegister",

                                 ClientName="testDriver",
                                 ClientDescription="test Drivermessage",
                                 ClientVersion="1.0.1",
                                 ClientID=tmpDriverID,
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        self.clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 2)

        sendAgent = HalGlobal.gClientDB[tmpDriverID]["agent"]
        agent = HalGlobal.gClientDB[self.clientID]["agent"]

        cfgMsg = HalMessage("HalConfigRsp",

                            # client is in HalGlobal.gClientDB(as:
                            # ClientID=self.clientID)
                            SrcClientID=self.clientID,
                            SeqNum=1003,
                            Rsp={
                                "Status": HalCommon_pb2.SUCCESS,
                                "ErrorDescription": ""
                            },
                            CfgMsgType=1025,
                            CfgMsgPayload="hello")

        cfgMsg2 = HalMessage("HalConfigRsp",

                             # client is in HalGlobal.gClientDB(as:
                             # ClientID=self.clientID)
                             SrcClientID=self.clientID,
                             SeqNum=1004,
                             Rsp={
                                 "Status": HalCommon_pb2.FAILED,
                                 "ErrorDescription": ""
                             },
                             CfgMsgType=1025,
                             CfgMsgPayload="hello")

        # Test clientID in HalGlobal.gClientDB
        self.halDispatcher.dispatchCfgRspMessage(sendAgent, cfgMsg)
        # Confirm clientID in HalGlobal.gClientDB
        self.assertEqual(agent.stats.NrTimeoutMsgs, 1)
        self.assertEqual(sendAgent.stats.NrErrorMsgs, 0)

        agent.addToRuntimeObjList(1003, 5, (self.tmpCb, 1))
        self.halDispatcher.dispatchCfgRspMessage(agent, cfgMsg)
        agent.addToRuntimeObjList(1004, 5, (self.tmpCb, 1))
        agent.addToRuntimeObjList(1004, 5, (self.tmpCb, 1))
        self.halDispatcher.dispatchCfgRspMessage(agent, cfgMsg2)
        self.halDispatcher.dispatchCfgRspMessage(agent, cfgMsg2)

        # Test clientID not in HalGlobal.gClientDB
        cfgMsgno = HalMessage("HalConfigRsp",

                              # clientID is not in HalGlobal.gClientDB(Random
                              # value)
                              SrcClientID="clientID is not in HalGlobal.gClientDB",
                              SeqNum=122,
                              Rsp={
                                  "Status": HalCommon_pb2.SUCCESS,
                                  "ErrorDescription": ""
                              },
                              CfgMsgType=1025,
                              CfgMsgPayload="hello")
        self.halDispatcher.dispatchCfgRspMessage(sendAgent, cfgMsgno)

        # Confirm clientID not in HalGlobal.gClientDB
        self.assertEqual(sendAgent.stats.NrErrorMsgs, 1)
        # Test is not timeout

    def test_dispatchNotificationMsg(self):
        """Dispatch a notification msg to interested clients client whether
        in HalGlobal.gNotificationMapping."""
        # self.clientMgr = HalClientManager(self.poller)

        HalGlobal.gClientIndex[self.clientID] = 7

        # Create a client register msg
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="testNotification",
                                 ClientDescription="test Notimessage ",
                                 ClientVersion="1.0.1",
                                 ClientID=self.clientID)
        self.clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 1)

        # self.driverMgr = HalDriverManager(self.poller)

        tmpDriverID = str(uuid.uuid4())
        HalGlobal.gClientIndex[tmpDriverID] = 2

        # Create a driver register msg
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="testDriver",
                                 ClientDescription="test Driver message",
                                 ClientVersion="1.0.1",
                                 ClientID=tmpDriverID,
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        self.clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 2)

        sendAgent = HalGlobal.gClientDB[tmpDriverID]["agent"]

        # Create a HalNotification msg
        cfgMsgNoti = HalMessage("HalNotification",
                                ClientID=self.clientID,
                                HalNotificationType=3,
                                HalNotificationPayLoad="hello")

        # Test notificationMsg.HalNotificationType not in
        # HalGlobal.gNotificationMapping
        self.halDispatcher.dispatchNotificationMsg(sendAgent, cfgMsgNoti)
        self.assertEqual(sendAgent.stats.NrDroppedMsgs, 1)

        # Test client in HalGlobal.gNotificationMapping
        # Create a client interest notification
        configMsg = HalMessage("HalClientInterestNotificationCfg",
                               # client in HalGlobal.gNotificationMapping
                               ClientID=self.clientID,
                               ClientNotificationMessages=list((2, 3, 4)))

        # Invoke handleClientInterestNotificationCfg for add
        # notificationMsg.HalNotificationType to HalGlobal.gNotificationMapping
        self.clientMgr.handleClientInterestNotificationCfg(configMsg)

        configMsg = HalMessage("HalClientInterestNotificationCfg",
                               # client in HalGlobal.gNotificationMapping
                               ClientID=tmpDriverID,
                               ClientNotificationMessages=list((2, 3, 4)))
        self.clientMgr.handleClientInterestNotificationCfg(configMsg)

        # Check the point of client in HalGlobal.gNotificationMapping
        sendAgent.stats.NrDroppedMsgs = 0
        self.halDispatcher.dispatchNotificationMsg(sendAgent, cfgMsgNoti)

        # sendAgent.stats.NrDroppedMsgs != 1
        self.assertNotEqual(sendAgent.stats.NrDroppedMsgs, 1)


if __name__ == '__main__':
    unittest.main()
