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
import uuid
import time
import unittest
import subprocess
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalDispatcher import HalDispatcher
from rpd.hal.src.HalAgentClient import HalAgentClient
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalPoller
from rpd.hal.src.HalStats import HalGlobalStats

timeStampSock = "/tmp/testHalAgentDRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"


def setupDB():
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    filename = "/tmp/test_halagentd.conf"
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

    HalGlobal.gHalClientDbConnection = HalDatabase(timeStampSock, 30, 1)
    HalGlobal.gHalMsgDbConnection = HalDatabase(timeStampSock, 30, 0)


class TestHalAgentDriver(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global timeStampSock
        cls.poller = HalPoller()
        cls.clientId = cls.driverID = str(uuid.uuid4())
        # set the redis server
        setupDB()
        # setup the Dispatcher
        HalGlobal.gDispatcher = HalDispatcher()

    @classmethod
    def tearDownClass(cls):
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)

    def setUp(self):
        self.halAgentClient = HalAgentClient(
            self.poller, self.driverID, self.disconnectHandler, None)

    def tearDown(self):
        self.halAgentClient.disconnectHandler(None)

    def disconnectHandler(self, agent):
        pass

    def test_register(self):
        cfgMsg = HalMessage("HalConfig",
                            SrcClientID="1",
                            DstClientID="1",
                            SeqNum=0,
                            CfgMsgType=2,
                            CfgMsgPayload="")

        HalGlobal.gRestartResendMsg[self.clientId] = cfgMsg
        halAgentClient = HalAgentClient(
            self.poller, self.driverID, self.disconnectHandler, None)
        self.assertEqual(len(halAgentClient.resendList), 1)
        HalGlobal.gRestartResendMsg.clear()

    def test_HandleConfig(self):
        """test the method of halAgentClient#HandleConfig check the HalConfig
        HalMessage can be handle without exception, check the HalConfig
        HalMessage status, if status is correct case pass.

        :keyword:halAgentClient#HandleConfig
        :exception:assertIsNone(str(e)), halAgentClient.stats.NrCfgMsgs

        """
        cfgMsg = HalMessage("HalConfig", SrcClientID=self.clientId, SeqNum=0,
                            CfgMsgType=123,
                            CfgMsgPayload="Hello")
        try:
            self.halAgentClient.handleConfig(cfgMsg)
        except Exception as e:
            self.assertIsNone(str(e))
        self.assertEqual(self.halAgentClient.stats.NrCfgMsgs, 1)

    def test_HandleUnnormalConfig(self):
        """test the method of halAgentClient#HandleConfig check the HalConfig
        HalMessage can be handle with specific exception, once catch the error
        message, case pass.

        :keyword:halAgentClient#HandleConfig
        :exception:"Cannot create a msg since we can not find the msg definition"

        """
        try:
            self.halAgentClient.handleConfig(None)
        except Exception as e:
            self.assertEqual(
                str(e), "Cannot handle a none config message")

        # try:
        tmp = self.halAgentClient.stats.NrErrorMsgs
        cfgMsg = HalMessage(
            "HalConfig", SrcClientID="0123456789", SeqNum=0,
            CfgMsgType=123,
            CfgMsgPayload="Hello")
        self.halAgentClient.handleConfig(cfgMsg)
        self.assertEqual(self.halAgentClient.stats.NrErrorMsgs, tmp + 1)

    def test_HandleConfigRsp(self):
        """test the method of halAgentClient#HandleConfigRsp check the
        HalConfigRsp HalMessage can be handle without exception, check the
        HalConfigRsp HalMessage status, if status is correct case pass.

        :keyword:halAgentClient#HandleConfigRsp
        :exception:assertIsNone(str(e)), halAgentClient.stats.NrCfgRspMsgs

        """
        cfgMsg = HalMessage(
            "HalConfigRsp", SrcClientID=self.clientId, SeqNum=0,
            Rsp={
                "Status": HalCommon_pb2.SUCCESS,
                "ErrorDescription": ""
            },
            CfgMsgType=123,
            CfgMsgPayload="Hello")
        try:
            self.halAgentClient.handleConfigRsp(cfgMsg)
        except Exception as e:
            self.assertIsNone(str(e))
        self.assertEqual(self.halAgentClient.stats.NrCfgRspMsgs, 1)

    def test_HandleUnnormalConfigRsp(self):
        """test the method of halAgentClient#HandleConfigRsp check the
        HalConfigRsp HalMessage can be handle with specific exception, once
        catch the error message, case pass.

        :keyword:halAgentClient#HandleConfigRsp
        :exception:"Cannot create a msg since we can not find the msg definition"

        """
        try:
            self.halAgentClient.handleConfigRsp(None)
        except Exception as e:
            self.assertEqual(
                str(e), "Cannot handle a none config response message")

        # try:
        tmp = HalGlobalStats.NrErrorMsgs
        cfgMsg = HalMessage(
            "HalConfigRsp", SrcClientID="0123456789", SeqNum=0,
            Rsp={
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": "test"
            },
            CfgMsgType=123,
            CfgMsgPayload="Hello")
        self.halAgentClient.handleConfigRsp(cfgMsg)
        self.assertEqual(HalGlobalStats.NrErrorMsgs, tmp + 1)

    def test_handleClientHello(self):
        """test the method of halAgentClient#handleDriverHello check the hello
        HalMessage can be handle without exception, check the hello HalMessage
        status, once status isn't correct case fail.

        :keyword:halAgentClient#handleDriverHello
        :exception:assertIsNone(str(e)), halAgentClient.stats.NrHelloRspMsgs

        """
        hello = HalMessage("HalClientHello", ClientID=self.driverID)
        try:
            self.halAgentClient.handleClientHello(hello)
        except Exception as e:
            self.assertIsNone(str(e))
        self.assertEqual(self.halAgentClient.stats.NrHelloRspMsgs, 1)

    def test_handleUnmormalClientHello(self):
        """test the method of halAgentClient#handleNoneDriverHello check the
        none hello HalMessage can be handle with specific exception, check the
        none hello HalMessage status, if it's correct case pass.

        :keyword:halAgentClient#handleNoneDriverHello
        :exception:"Cannot handle a NULL Driver Driver message", halAgentClient.stats.NrErrorMsgs

        """
        hello = None
        tmp = self.halAgentClient.stats.NrErrorMsgs
        try:
            self.halAgentClient.handleClientHello(hello)
        except Exception as e:
            self.assertRegexpMatches(
                str(e), "Cannot handle a none client hello message")
        self.assertEqual(self.halAgentClient.stats.NrErrorMsgs, tmp + 1)

    def test_handleNotification(self):
        """test the method of halAgentClient#handleNotification check the
        normall notification HalMessage can be handle without exception, check
        the normall notification HalMessage status, once status isn't correct
        case fail.

        :keyword:halAgentClient#handleNotification
        :exception:assertIsNone(str(e)), halAgentClient.stats.NrNotifyMsgs

        """
        notfication = HalMessage("HalNotification",
                                 ClientID=self.driverID,
                                 HalNotificationType=10,
                                 HalNotificationPayLoad="test")
        try:
            self.halAgentClient.handleNotification(notfication)
        except Exception as e:
            self.assertIsNone(str(e))
        self.assertEqual(self.halAgentClient.stats.NrNotifyMsgs, 1)

    def test_handleUnnormalNotification(self):
        """test the method of halAgentClient#handleNotification check the none
        notification HalMessage can be handle with specific exception, once
        catch the error message, case pass.

        :keyword:halAgentClient#handleNotification
        :exception:"Cannot handle the notification since the msg is NOne"

        """
        notfication = None
        try:
            self.halAgentClient.handleNotification(notfication)
        except Exception as e:
            self.assertRegexpMatches(
                str(e), "Cannot handle the notification since the msg is None")

    def test_sendMsg(self):
        """test the method of halAgentClient#sendMsg if the normall halmessage
        can be send without exception, this case pass.

        :keyword:halAgentClient#sendMsg
        :exception:assertIsNone(str(e))

        """
        # construct the Hello message
        try:
            helloMsg = HalMessage(
                "HalClientRegister", ClientName="abc", ClientDescription="abc",
                ClientVersion="1.2.3", ClientSupportedMessages=[1, 2, 3],
                ClientSupportedNotificationMessages=[])
            self.halAgentClient.sendMsg(helloMsg.Serialize())
        except Exception as e:
            self.assertIsNone(str(e))

    def test_sendNoneMsg(self):
        """test the method of halAgentClient#sendMsg if the halmessage is none,
        method throw the specific exception, once the exception match the error
        msg, case pass.

        :keyword:halAgentClient#sendMsg
        :exception:"The msg is None, skip to invoke the low level function"

        """
        # construct the Hello message
        helloMsg = None
        try:
            self.halAgentClient.sendMsg(helloMsg)
        except Exception as e:
            self.assertRegexpMatches(
                str(e), "The msg is None, skip to invoke the low level function")

    def test_sendUnnormalMsg(self):
        """test the method of halAgentClient#sendMsg construct unnormal
        message, method throw exception, once the exception match the error
        msg, case pass.

        :keyword:halAgentClient#sendMsg
        :exception:assertIsNone(str(e))

        """

        # construct the Hello message
        msgTypes = [111222, {'key': 'value'}]
        index = 0
        for msgType in msgTypes:
            if index == 0:
                try:
                    index += 1
                    self.halAgentClient.sendMsg(msgType)
                except Exception as e:
                    self.assertRegexpMatches(
                        str(e), "does not provide a buffer interface.")
            if index == 1:
                try:
                    index += 1
                    self.halAgentClient.sendMsg(msgType)
                except Exception as e:
                    self.assertRegexpMatches(
                        str(e), "does not provide a buffer interface.")

    def test_Disconnect(self):
        """test the method halAgentClient#disconnectHandler, handle the
        transportPush modem event, if the method throw a exception when
        running, case fail if the method can running normally, check the
        disconnectProcessed status, once the disconnectProcessed status isn't
        correct, cases fail.

        :keyword:halAgentClient#disconnectHandler
        :exception:assertIsNone(str(e)), halAgentClient.disconnectProcessed

        """
        agentDriver = HalAgentClient(
            self.poller, "12345", self.disconnectHandler, 7)
        self.assertIsNotNone(agentDriver)
        self.assertIn(agentDriver, HalGlobal.gAgentDB)
        self.assertFalse(agentDriver.disconnectProcessed)
        agentDriver.disconnectHandler(None)
        self.assertTrue(agentDriver.disconnectProcessed)
        self.assertNotIn(agentDriver, HalGlobal.gAgentDB)
        agentDriver.disconnectHandler(None)
        self.assertTrue(agentDriver.disconnectProcessed)

if __name__ == '__main__':
    unittest.main()
