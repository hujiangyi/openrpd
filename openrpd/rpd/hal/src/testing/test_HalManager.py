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

import unittest
import subprocess
import os
import time
import logging
from rpd.hal.src.transport.HalTransport import HalPoller
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalManager import HalManager, HalClientManager
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.hal.src.HalConfigMsg import RCP_TO_HAL_MSG_TYPE
from rpd.hal.src.transport.HalTransport import HalTransport

timeStampSock = "/tmp/testHalMgrRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"


def setupDB():
    """first, create and start the redis server, sencond, set up the DB.

    :parameter:None
    :return:None

    """
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    filename = "/tmp/test_halmgr.conf"
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


class TestHalManager(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupDB()

    @classmethod
    def tearDownClass(cls):
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_CreateHalClientManager(self):
        """test create the HalClientManager,

        check whether the HalClientManager
        created, if not case fail

        check whether the HalClientManager socket in
        the socketAgentMapping, if not case fail

        check whether the
        HalClientManager monitor in the monitorSocketMapping, if not case fail.

        :keyword:CreateHalClientManager
        :exception:assertIsNotNone(clientMgr), assertIn(clientMgr.transport.socket,
                   HalGlobal.gSocketAgentMappingTable),
                   assertIn(clientMgr.transport.monitor,
                   HalGlobal.gMonitorSocketMappingTable)
        :parameter:
        :return:

        """
        poller = HalPoller()
        clientMgr = HalClientManager(poller)

        self.assertIsNotNone(clientMgr)
        self.assertIn(clientMgr.transport.socket,
                      HalGlobal.gSocketAgentMappingTable)
        self.assertIn(clientMgr.transport.monitor,
                      HalGlobal.gMonitorSocketMappingTable)
        clientMgr._removeClientFromDb()

        faultflag = False
        try:
            mgr = HalManager(999, poller)
        except Exception:
            faultflag = True
        self.assertTrue(faultflag)

        mgr = HalManager(HalTransport.HalTransportClientMgr, poller)
        mgr.disconnectHandler(0x1)
        try:
            mgr.disconnectCb(None)
        except Exception:
            pass


    def test_HandleClientRegister(self):
        """test HalDriverManager#handleRegisterRequest,

        check whether the none
        HalMessage can be handle, throw a specific exception, if don't catch
        the exception case fail

        check whether the normal HalMessage can be
        handle, if isn't correct, case fail

        check the status when disconnect
        the invalid agent, if isn't correct, case fail

        check the status when
        disconnect the agent, if isn't correct, case fail

        check whether the
        reuse HalMessage can be handle, if isn't correct, case fail.

        :keyword:HalDriverManager#handleRegisterRequest
        :exception:"Cannot handle the register request since the register msg is None",
                    assertEqual(HalGlobalStats.NrDriver, 1), assertEqual(HalGlobalStats.NrDriver, 0)
        :parameter:
        :return:

        """
        poller = HalPoller()
        clientMgr = HalClientManager(poller)

        try:
            clientMgr.handleRegisterRequest(None)
        except Exception as e:
            self.assertEqual(
                "Cannot handle the client register "
                "request since the register msg is None", str(e))

        # construct a register message
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="test",
                                 ClientDescription="test message",
                                 ClientVersion="1.0.1",
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 1)

        # disconnect invalid agent
        clientMgr.disconnectCb(0)
        self.assertEqual(HalGlobalStats.NrClient, 1)

        # disconnect
        keys = HalGlobal.gClientDB.keys()
        for clientId in keys:
            clientMgr.disconnectCb(HalGlobal.gClientDB[clientId]['agent'])
        self.assertEqual(HalGlobalStats.NrClient, 0)

        HalGlobalStats.NrClient = 0
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="test",
                                 ClientDescription="test message",
                                 ClientVersion="1.0.1",
                                 ClientID=clientId,
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 1)

        # construct a reuse register message
        HalGlobal.gClientIndex[clientId] = 0
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="test",
                                 ClientDescription="test message",
                                 ClientVersion="1.0.1",
                                 ClientID=clientId,
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        clientMgr.handleRegisterRequest(registerMsg, True)
        self.assertEqual(HalGlobalStats.NrClient, 2)

        clientMgr.disconnectCb(HalGlobal.gClientDB[clientId]['agent'])
        self.assertEqual(HalGlobalStats.NrClient, 1)

        keys = HalGlobal.gClientDB.keys()
        for clientId in keys:
            clientMgr.disconnectCb(HalGlobal.gClientDB[clientId]['agent'])
        self.assertEqual(HalGlobalStats.NrClient, 0)

    def test_HandleClient(self):
        """test HandleClientRegister#handleClientInterestNotificationCfg, test
        HandleClientRegister#handleClientQuery, test
        HandleClientRegister#handleDriverQuery, test
        HandleClientRegister#handleHalSetLoggingLevel.

        check whether the none
        HalMessage can be handle, throw a specific exception, if don't catch
        the exception case fail

        check whether the interested notification
        HalMessage can be handle, if isn't correct, case fail

        check whether the
        none client query message can be handle, throw a specific exception, if
        don't catch the exception case fail

        check whether the none driver query
        message can be handle, throw a specific exception, if don't catch the
        exception case fail

        check whether the logging level change request can
        be handle, if not case fail.

        :keyword:HandleClientRegister#handleClientInterestNotificationCfg
                 HandleClientRegister#handleClientQuery
                 HandleClientRegister#handleDriverQuery
                 HandleClientRegister#handleHalSetLoggingLevel
        :exception:"Cannot handle a NULL interest configuration",
                    assertNotIn(1, HalGlobal.gNotificationMapping.keys()),
                    "Cannot handle a NULL query",
                    "Cannot handle a NULL Driver query",
                    assertEqual(logger.level, logging.INFO)
        :parameter:
        :return:

        """
        poller = HalPoller()
        clientMgr = HalClientManager(poller)
        HalGlobal.gClientIndex["123"] = 1
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="test",
                                 ClientDescription="test message ",
                                 ClientVersion="1.0.1",
                                 ClientID="123")
        clientMgr.handleRegisterRequest(registerMsg)

        HalGlobal.gClientIndex["321"] = 2
        registerMsg = HalMessage("HalClientRegister",
                                 ClientName="test",
                                 ClientDescription="test message",
                                 ClientVersion="1.0.1",
                                 ClientID="321",
                                 ClientSupportedMessages=list(
                                     tuple(RCP_TO_HAL_MSG_TYPE.values())),
                                 ClientSupportedNotificationMessages=list((2, 3, 4)))
        clientMgr.handleRegisterRequest(registerMsg)

        try:
            clientMgr.handleClientInterestNotificationCfg(None)
        except Exception as e:
            self.assertEqual(
                "Cannot handle a none interest configuration.", str(e))

        interesteMsg = HalMessage("HalClientInterestNotificationCfg",
                                  ClientNotificationMessages=[1, 2, 3])
        clientMgr.handleClientInterestNotificationCfg(interesteMsg)
        self.assertNotIn(1, HalGlobal.gNotificationMapping.keys())

        interesteMsg = HalMessage(
            "HalClientInterestNotificationCfg", ClientID="123",
            ClientNotificationMessages=[1, 2])
        clientMgr.handleClientInterestNotificationCfg(interesteMsg)
        self.assertIn(1, HalGlobal.gNotificationMapping.keys())

        interesteMsg = HalMessage(
            "HalClientInterestNotificationCfg", ClientID="123",
            ClientNotificationMessages=[1])
        clientMgr.handleClientInterestNotificationCfg(interesteMsg)
        self.assertIn(1, HalGlobal.gNotificationMapping.keys())

        clientMgr.handleGlobalStatsReq(None)

        statsMsg = HalMessage("HalAgentStatsReq")
        clientMgr.handleAgentStatsReq(statsMsg)

        statsMsg = HalMessage("HalAgentStatsReq", ClientID="321")
        clientMgr.handleAgentStatsReq(statsMsg)

        statsMsg = HalMessage("HalAgentStatsReq", ClientID="123")
        clientMgr.handleAgentStatsReq(statsMsg)

        statsMsg = HalMessage("HalAgentStatsReq", ClientID="456")
        clientMgr.handleAgentStatsReq(statsMsg)

        statsMsg = HalMessage("HalAgentStatsReq", )
        clientMgr.handleAgentStatsReq(statsMsg)

        try:
            clientMgr.handleClientQuery(None)
        except Exception as e:
            self.assertEqual("Cannot handle a none client query", str(e))
        queryMsg = HalMessage("HalClientQuery", ClientID="123")
        clientMgr.handleClientQuery(queryMsg)

        queryMsg = HalMessage("HalClientQuery", )
        clientMgr.handleClientQuery(queryMsg)

        logger = logging.getLogger("HalClientManager")
        setLogMsg = HalMessage("HalSetLoggingLevel", ClientID="123",
                               Module="HalClientManager", LoggingLevel=logging.INFO)
        clientMgr.handleHalSetLoggingLevel(setLogMsg)
        self.assertEqual(logger.level, logging.INFO)

        setLogMsg = HalMessage("HalSetLoggingLevel", ClientID="123",
                               Module="HalClientManager", LoggingLevel=logging.NOTSET)
        clientMgr.handleHalSetLoggingLevel(setLogMsg)
        self.assertEqual(logger.level, logging.INFO)

        setLogMsg = HalMessage("HalSetLoggingLevel", ClientID="123",
                               Module="HalNotSet", LoggingLevel=logging.DEBUG)
        clientMgr.handleHalSetLoggingLevel(setLogMsg)
        self.assertEqual(logger.level, logging.INFO)

        setLogMsg = HalMessage("HalSetLoggingLevel", ClientID="123",
                               Module="HalClientManager", LoggingLevel=logging.DEBUG)
        clientMgr.handleHalSetLoggingLevel(setLogMsg)
        self.assertEqual(logger.level, logging.DEBUG)

        clientMgr.disconnectCb(HalGlobal.gClientDB["321"]['agent'])
        clientMgr.disconnectCb(HalGlobal.gClientDB["123"]['agent'])
        clientMgr.disconnectCb(None)

if __name__ == '__main__':
    unittest.main()
