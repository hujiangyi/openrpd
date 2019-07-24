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

import logging
from sortedcontainers import SortedListWithKey
from time import time
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalStats import HalAgentStats
from rpd.common.rpd_logging import AddLoggerToClass


class HalTimeoutCallback(object):
    """This class is callback class for processing the timeout events."""
    def __init__(self, seq, timeout, cbObj):
        self.cbObj = cbObj
        self.seq = seq
        self.timeout = time() + timeout
        self.ref_count = 1

    def isTimeout(self):
        """The timeout variable holds the exact time for timeout, we just need
        to compare the timeout and the current time.

        :return:

        """
        if self.timeout < time():
            return True
        return False


class HalAgent(object):
    """The class is the base class to hold the common part of the agent, mainly
    contains a resend list and a timeout list.

    For timeout list, we uses a sorted container, and the key is time when will be timeout. the reason to use a
    sorted container, is we just check the first values until we encounter the first un-timeout value, we don't need
    to check all the values. As to the sorted container, it is the b-tree, so the insert time will be o(lgn)

    For the resend list, we use a dict, the reason we use sorted container.
    resend list is used to hold two type messages:

        1. restart messages. when HAL restart, it will read messages from the DB and put these messages into this
           list. when the client is online, it will resend these message to driver.
        2. For some reason, the driver will offline, so we will put message to this list and resend it when the
           driver is online resend will be triggered with following events:
           1. timeout
           2. when the agent receive a message

    """

    TIMEOUT_30S = 30

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        """setup the logger, create the timeout list and the resend list.The
        msgCache is use to hold a seq to msg mapping this is used by the driver
        send a late response to client, if we can not find the seq in this
        cache, we think the timeout mechanism has processed this message, so we
        we would send the rsp to client.

        :return:

        """
        self.logger.debug("Add the client to the global DB")
        HalGlobal.gAgentDB[self] = 1

        self.runtimeTimeoutList = SortedListWithKey(key=lambda x: x.timeout)
        self.timeout = self.TIMEOUT_30S
        self.msgCache = dict()

        self.rsp_msg = dict()

        self.resendList = SortedListWithKey(key=lambda x: x["seq"])

        # stats
        self.stats = HalAgentStats()

    def removeFromAgentDB(self):
        """Remove the agent from the AgentDB, AgentDB is used to hold all the
        agents, the loop function use it to process the timeout list and the
        resend list.

        :return:

        """
        self.logger.debug("Remove the client from the global DB")
        HalGlobal.gAgentDB.pop(self)

    def processTimeoutObjs(self):
        """Check the runtimeTimeoutList and find the times-out ones to send
        a timeout rsp to client.

        :return:

        """
        if len(self.runtimeTimeoutList) <= 0:
            return

        self.logger.debug(
            "Processing the timeout Objs[%d]" % len(self.runtimeTimeoutList))

        while len(self.runtimeTimeoutList):
            timeoutObj = self.runtimeTimeoutList[0]

            if timeoutObj.isTimeout():
                self.logger.debug("timeout!, call the handler")
                # Execute the callback
                cbFunc = timeoutObj.cbObj[0]
                cbArgs = timeoutObj.cbObj[1]

                cbFunc(cbArgs)
                self.runtimeTimeoutList.pop(0)

                if timeoutObj.seq in self.msgCache:
                    self.msgCache.pop(timeoutObj.seq)

                # clean up the rsp msg cache
                if timeoutObj.seq in self.rsp_msg:
                    self.rsp_msg.pop(timeoutObj.seq)
            else:
                break

    def addToRuntimeObjList(self, seq, timeout, (cb, args)):
        """Add the events to the timeout list.

        :param seq: the HalMessage seq number
        :param timeout: time out value, not "timeout at" value
        :return:

        """
        if seq in self.msgCache:
            self.msgCache[seq].ref_count += 1
            if hasattr(self, "clientID"):
                client_id = self.clientID
            else:
                client_id = "NA"
            self.logger.debug(
                "Agent %s: seq %d has been in runtime object list, adjust it's ref count to %d",
                client_id, seq, self.msgCache[seq].ref_count)
            return

        # Create a HalTimeoutCallback
        self.logger.debug(
            "add msg seq [%d ] to the runtime Msg List for agent %s" % (seq, self))
        htcb = HalTimeoutCallback(seq, timeout, (cb, args))
        self.runtimeTimeoutList.add(htcb)

        self.msgCache[seq] = htcb

    def addToResendList(self, seq, sendagent, msg):
        """Add the resend msg to the resend list.

        :param seq: the seq number of the Hal message
        :param sendagent: the send agent, which will be a client agent
        :param msg: the Hal message
        :return:

        """
        self.logger.debug("add msg seq [%d ] to the resend list" % seq)

        self.resendList.add({
            "seq": seq,
            "sendAgent": sendagent,
            "msg": msg,
            "time": time() + 5  # FIXME we should add a configure value?
        })

    def processResendList(self, test=False):
        """go through the resend list, find the timeout ones and send a
        unsupported message to client.

        for the un-timeout ones, we will send the message to the dispatcher, if the dispatch successfully process the
        message, we will remove from the list
        :return:

        """
        if len(self.resendList) <= 0:
            return

        self.logger.debug(
            "Process the resend list, and send the msg to driver")

        removeList = list()
        for i in xrange(len(self.resendList)):
            msg = self.resendList[i]
            seq = msg["seq"]
            if msg["time"] < time():
                # send a timeout msg to the original sender
                cfgMsg = msg["msg"].msg
                unSupportedMsg = HalMessage(
                    "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=seq,
                    Rsp={
                        "Status": HalCommon_pb2.NOTSUPPORTED,
                        "ErrorDescription": 'No Driver can handle this message, please check '
                        'if the driver has registered, or if the registered'
                        ' driver can supported this message type'
                    },
                    CfgMsgType=cfgMsg.CfgMsgType,
                    CfgMsgPayload=cfgMsg.CfgMsgPayload)
                if not test:
                    msg["sendAgent"].transportPush.send(
                        unSupportedMsg.Serialize())
                removeList.append(msg)
                continue

            # invoke dispatcher
            ret = HalGlobal.gDispatcher.dispatchCfgMessage(
                msg["sendAgent"], msg["msg"])
            if ret == 0:
                removeList.append(msg)

        # Process the removeList
        for msg in removeList:
            self.resendList.remove(msg)

    def removeFromRuntimeObjList(self, seq):
        """remove from the timetout lsit.

        :param seq: the HAL message seq number field for configure message and for configure response message
        :return: 0 and rsp msg list if we have receive all the msgs, otherwise if we have not receive all the msgs.

        """
        if hasattr(self, "clientID"):
            client_id = self.clientID
        else:
            client_id = "NA"

        self.logger.debug(
            "Agent %s: seq %d, remove the timeout obj from the list.", client_id, seq)

        if seq in self.msgCache:
            tObj = self.msgCache[seq]
            tObj.ref_count -= 1

            if tObj.ref_count <= 0:
                self.runtimeTimeoutList.remove(tObj)
                self.msgCache.pop(seq)
                return 0, self.rsp_msg.pop(seq)
            else:
                return tObj.ref_count, None

    def isMsgTimeout(self, seq):
        """to judge if a message is timeout.

        :param seq:
        :return:

        """
        self.logger.debug(
            "Test if the seq[%d] in sent packets for agent [%s]" % (seq, self))
        if seq in self.msgCache:
            return False

        return True

    # For the part the sub-class should be implemented
    def disconnectHandler(self, transport):
        raise Exception("the sub class should implement this function")

    # Save cfg rsp messages
    def save_cfg_rsp_msg(self, seq, rsp_msg):
        """Save configuration response message in sending agent. the reason is
        simple, we need to cache all the rsp messages and check the status.
        then send rsp to sender.

        :param seq: the seq number
        :param rsp_msg: rsp_msg
        :return: None

        """
        if seq not in self.rsp_msg:
            self.rsp_msg[seq] = list()

        if rsp_msg in self.rsp_msg[seq]:
            return

        self.rsp_msg[seq].append(rsp_msg)
