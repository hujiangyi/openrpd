#!/usr/bin/python
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

import sys
import os
import json
import zmq
import argparse
import logging
import signal
from time import time
from rpd.hal.src.HalGlobal import HalGlobal
from zmq.utils.monitor import recv_monitor_message
from rpd.hal.src.HalManager import HalClientManager
from rpd.hal.src.transport.HalTransport import HalPoller
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalDispatcher import HalDispatcher
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.rpd_logging import setup_logging

# logger we can use it in local file
logger = None


def _mainLoop():
    """This fucntion create the HalClient manager, and then will loop the
    poller.

    Also this function will dispatch the following events to
    corresponding handler:
    * timeout:
      * will process the agent timeout list
      * will process the agent resend list
    * HalMessage events:
      * the function will decode
        all the incoming events and invoke the corresponding agent, and invoke
        corresponding handler.
    * monitor Events:
      * These messages are from the low
        level queue events, such as the reconnect/close/disconnect. These messages
        are handled by the corresponding agents.

    Please note that, in Hal design, everything are in a single thread, it is stateless and trigger by the events.

    :return:

    """
    if logger is None:
        sys.exit(-1)

    logger.info("Start the poller...")
    HalGlobal.gPoller = HalPoller()

    logger.info("Start the client manager...")
    HalGlobal.gClientMgr = HalClientManager(HalGlobal.gPoller)

    logger.info("Staring poll all the events...")

    lastcalledTime = time()

    while not HalGlobal.StopHal:
        socks = HalGlobal.gPoller.poll(HalGlobal.gTimeout)

        # for timeout events
        if time() - lastcalledTime > HalGlobal.gTimeout / 1000:
            lastcalledTime = time()
            logger.debug("Got a timeout event")

            # for timeout list
            for agent in HalGlobal.gAgentDB:
                handler = getattr(agent, "processTimeoutObjs")
                handler()

            # for resend
            for clientID in HalGlobal.gClientDB:
                handler = getattr(HalGlobal.gClientDB[clientID]["agent"],
                                  "processResendList")
                handler()

        if socks is None:
            continue

        # For the HalMessage path
        for sock in socks:

            # For the low-level queue events
            if sock in HalGlobal.gMonitorSocketMappingTable:
                logger.debug("Got a monitor event...")
                handler = getattr(
                    HalGlobal.gMonitorSocketMappingTable[sock], "monitorHandler")
                handler(recv_monitor_message(sock))
                continue
            # For Halmessages
            if socks[sock] == HalPoller.POLLIN:
                try:
                    bin = sock.recv(flags=zmq.NOBLOCK)
                    msg = HalMessage.DeSerialize(bin)
                    # logger.debug("Got a zmq msg:for remote, msg %s" % msg.msg)
                    if msg.type in HalGlobal.gHandleTable and sock in HalGlobal.gSocketAgentMappingTable:
                        func = getattr(HalGlobal.gSocketAgentMappingTable[
                                       sock], HalGlobal.gHandleTable[msg.type])
                        func(msg)
                    else:
                        logger.warn(
                            "Cannot handle the POLLIN events for message:%s",
                            msg)
                        if sock == HalGlobal.gClientMgr.transport.socket:
                            sock.send("dummy")
                        HalGlobalStats.NrErrorMsgs += 1
                except zmq.ZMQError as e:
                    logger.debug(
                        "Got an error when trying with non-block read:" + str(e))
                except Exception as e:
                    logger.warn("Get an unhandled exception:%s" % str(e))
            else:
                logger.warn(
                    "Cannot handle the event, No handler for it:%s" % str(socks[sock]))


def _parseConfiguraion(default_path='hal.conf'):
    """Loads the configuration from the configuration file and  put them in
    the runtime configuration.

    :param default_path: the configuration path
    :return:

    """
    envKey = "HAL_CFG"
    confPath = default_path
    value = os.getenv(envKey, None)
    config = None
    if value:
        confPath = value
    if confPath and os.path.exists(confPath):
        with open(confPath, 'rt') as f:
            config = json.load(f)

    return config


def main():
    """Everything starts here."""
    global logger
    parser = argparse.ArgumentParser("Hal args parser")
    parser.add_argument(
        "--conf", metavar='C', type=str, help="Hal configuration path")
    args = parser.parse_args()

    config = _parseConfiguraion(args.conf)
    if config is None:
        sys.stderr.write(
            "Cannot load the configuration or the configuration format is not correct")
        sys.exit(-1)

    # setup the log
    setup_logging('HAL', filename="hal.log")
    # setup the logger
    logger = logging.getLogger("HalMain")

    # setup the Dispatcher
    HalGlobal.gDispatcher = HalDispatcher()

    # setup the database
    if "db" not in config:
        sys.stderr.write(
            "Cannot find the redis config information, using the default configuration")
        HalGlobal.gHalMsgDbConnection = HalDatabase("/tmp/redis.sock", 30, 12)
        HalGlobal.gHalClientDbConnection = HalDatabase(
            "/tmp/redis.sock", 30, 11)
    else:
        dbConf = config["db"]
        logger.info("Setting up the Hal database:\n\tPath:%s\n\tmsgDB:%d\n\tindexDB:%d" %
                    (dbConf["address"], dbConf["msgDB"], dbConf["indexDB"]))
        HalGlobal.gHalMsgDbConnection = HalDatabase(
            dbConf["address"], dbConf["timeout"], dbConf["msgDB"])
        HalGlobal.gHalClientDbConnection = HalDatabase(
            dbConf["address"], dbConf["timeout"], dbConf["indexDB"])

    # Getting the un-handled message from the DB, we don't need to clean up
    # the DB since we have set the expire for keys
    if not HalGlobal.gHalMsgDbConnection.isDatabaseEmpty():
        logger.info("Start to load all the resend messages to runtime memory")
        msgs = HalGlobal.gHalMsgDbConnection.listAllMsgs()
        for msg in msgs:
            logger.info("Loading message %s" % msg["Key"])
            key = msg["Key"]
            gpbMsg = msg["Msg"]
            try:
                HalMsg = HalMessage.DeSerialize(gpbMsg)
                logger.debug("Got a zmq msg:%s" % HalMsg.msg)
                HalGlobal.gRestartResendMsg[key] = HalMsg
            except Exception as e:
                logger.error(
                    "Error happened when handling msg, error info:%s", str(e))

    # get all the contents and put it in gClientIndex
    if not HalGlobal.gHalClientDbConnection.isDatabaseEmpty("ClientIndex"):
        logger.info(
            "Start to getting previous registered client ID and index... ")
        msgs = HalGlobal.gHalClientDbConnection.listAllMsgs("ClientIndex")
        for key in msgs:
            HalGlobal.gClientIndex[key] = msgs[key]

    _mainLoop()


def handle_interrrupt_signal(signum, frame):
    sys.exit(0)


# register the ctrl C to handle this signal
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrrupt_signal)
    main()
