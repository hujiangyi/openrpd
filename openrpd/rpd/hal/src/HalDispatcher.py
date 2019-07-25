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
# Change log
# 2016/08/03 Add the multiple receiver support

import logging

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage


class HalDispatcher(object):

    """This class is responsible to dispath a message, including the cfg msg
    and the notification msg.

    it is a bit like the msg broker in some msg queue

    """
    __metaclass__ = AddLoggerToClass

    def cfgMsgTimeoutCb(self, args):
        """
        :param args: the callback parameters, we need the srcClient agent, original message
        :return:

        """
        agent = args["agent"]
        cfgMsg = args["originalMsg"].msg

        self.logger.warn(
            "Send a timeout message to client [%s] for message %s" % (agent.clientID, cfgMsg))

        seqNum = cfgMsg.SeqNum if hasattr(cfgMsg, "SeqNum") else 0
        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=seqNum,
            Rsp={
                "Status": HalCommon_pb2.TIMEOUT,
                "ErrorDescription": 'timeout happened when sending the msg to dstClient, is dstClient dead :(?'
            },
            CfgMsgType=cfgMsg.CfgMsgType,
            CfgMsgPayload=cfgMsg.CfgMsgPayload)

        # Do some stats here
        agent.stats.NrErrorMsgs += 1
        agent.stats.NrCfgRspMsgs += 1
        agent.stats.NrTimeoutMsgs += 1

        agent.transportPush.send(msg.Serialize())

    def dispatchCfgMessage(self, sendAgent, cfg):
        """Dispatch the client cfg msg.

        :param sendAgent: the agent that sends the configuration message.
        :param cfg: the HalMessage type.
        :return: -1 for error, should add it to resend list;
                 0 for normal process

        """
        # check the CfgMsgType and routing it to the correct dstClient
        cfgMsg = cfg.msg
        if cfg.msg.CfgMsgType not in HalGlobal.gMsgTypeClientMapping:
            self.logger.warn(
                "There is no client support this config message currently, will resend it later: %s.", cfgMsg)
            sendAgent.stats.NrErrorMsgs += 1  # the message cannot be supported, will resend it later
            return -1

        agent_list = HalGlobal.gMsgTypeClientMapping[cfgMsg.CfgMsgType]
        cfgMsg.SeqNum = cfgMsg.SeqNum if cfgMsg.HasField("SeqNum") else 0
        cfgMsg.SrcClientID = sendAgent.clientID

        for agent_obj in agent_list:
            agent = agent_obj["agent"]

            if agent is sendAgent:
                self.logger.warn(
                    "agent %s: Cannot send seq %d to itself", agent.clientID, cfgMsg.SeqNum)
                msg = HalMessage(
                    "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=cfgMsg.SeqNum,
                    Rsp={
                        "Status": HalCommon_pb2.FAILED,
                        "ErrorDescription": 'Cannot send configuration msg to itself'
                    },
                    CfgMsgType=cfgMsg.CfgMsgType,
                    CfgMsgPayload=cfgMsg.CfgMsgPayload
                )

                agent.transportPush.send(msg.Serialize())
                continue

            client_id = agent_obj["clientID"]

            cfgMsg.DstClientID = client_id
            # we should rewrite the srcClientID
            agent.transportPush.send(cfg.Serialize())
            sendAgent.addToRuntimeObjList(
                cfgMsg.SeqNum, sendAgent.timeout,
                (self.cfgMsgTimeoutCb, {"agent": sendAgent, "originalMsg": cfg}))

            agent.stats.NrCfgMsgs += 1
            self.logger.debug(
                "Dispatching the msg[%d] from srcClient[%s] to dstClient[%s]" % (cfgMsg.CfgMsgType,
                                                                                 cfgMsg.SrcClientID,
                                                                                 cfgMsg.DstClientID))

        return 0

    def get_available_rsp(self, rsp_list):
        for rsp in rsp_list:
            if rsp.msg.Rsp.Status == HalCommon_pb2.SUCCESS:
                return rsp
        return None

    def dispatchCfgRspMessage(self, sendAgent, rsp):
        """Dispatch the message from the dstClient. Rsp function will not check
        it's self since it's passive function in most cases.

        :param sendAgent: the dstClient agent
        :param rsp: rsp HalMessage
        :return:

        """
        cfgRspMsg = rsp.msg
        srcClientID = cfgRspMsg.SrcClientID

        seq = cfgRspMsg.SeqNum
        if srcClientID not in HalGlobal.gClientDB:
            self.logger.warn(
                "Cannot find the client [%s] for config response message, %s.", srcClientID, cfgRspMsg)
            HalGlobalStats.NrErrorMsgs += 1
            sendAgent.stats.NrErrorMsgs += 1
            return

        agent = HalGlobal.gClientDB[srcClientID]["agent"]

        # Check if the msg has been timeout
        if agent.isMsgTimeout(seq):
            self.logger.warn(
                "A timeout msg has been sent to client, you are a slow client? clientID:%s, seq:%s", srcClientID, seq)
            agent.stats.NrTimeoutMsgs += 1
            return

        # save the configuration message
        agent.save_cfg_rsp_msg(seq, rsp)
        self.logger.debug("Recv rsp cfg msg type: %d seq %d" % (rsp.msg.CfgMsgType, seq))
        # update the timeout processing
        ref_count, rsp_list = agent.removeFromRuntimeObjList(seq)
        if ref_count == 0:
            for rsp in rsp_list:
                if rsp.msg.Rsp.Status != HalCommon_pb2.SUCCESS and rsp.msg.Rsp.Status != HalCommon_pb2.SUCCESS_IGNORE_RESULT:
                    self.logger.warn(
                        "Agent %s: seq %d, msg rsp failure found, send it to original sender.",
                        agent.clientID, seq)
                    # send the msg to srcClient
                    agent.transportPush.send(rsp.Serialize())
                    # do some stats
                    agent.stats.NrCfgRspMsgs += 1
                    break
            else:
                self.logger.debug(
                    "Agent %s:seq %d, all the rsp messages are(is) good, send rsp to original sender.",
                    agent.clientID, seq)
                rsp = self.get_available_rsp(rsp_list)
                if rsp is None:
                    self.logger.debug("Not get available rsp")
                    return
                self.logger.debug("Send rsp to src client")
                # send the msg to srcClient
                agent.transportPush.send(rsp.Serialize())
                # do some stats
                agent.stats.NrCfgRspMsgs += 1

    def dispatchNotificationMsg(self, sendAgent, notification):
        """Dispatch a notification msg to interested clients."""
        notificationMsg = notification.msg
        if notificationMsg.HalNotificationType not in HalGlobal.gNotificationMapping:
            self.logger.warn(
                "There is no client interested in this notification message, drop it! msg:%s", notificationMsg)
            HalGlobalStats.NrErrorMsgs += 1
            sendAgent.stats.NrDroppedMsgs += 1
            return
        msgStr = notification.Serialize()
        for client in HalGlobal.gNotificationMapping[notificationMsg.HalNotificationType]:
            self.logger.debug(
                "Send the notification[%d] to client[%s]" % (notificationMsg.HalNotificationType, client["clientID"]))
            agent = client["agent"]
            if agent is sendAgent:
                self.logger.debug(
                    "Skip sending the notification[%d] to the sender[%s]" % (
                        notificationMsg.HalNotificationType, sendAgent.clientID))
                continue
            # push the message to client
            agent.transportPush.send(msgStr)

            # Add some stats
            agent.stats.NrNotifyMsgs += 1
