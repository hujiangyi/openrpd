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
import zmq
import hexdump
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalOperation_pb2 import HalNotification
from rpd.hal.src.msg.ClientProvision_pb2 import HalClientRegister

if __name__ == "__main__":
    trans = HalTransport(
        HalTransport.HalTransportClientMgr, HalTransport.HalClientMode)
    trans.connects()

    registerMsg = HalClientRegister()
    registerMsg.MsgType = "HalClientRegister"
    registerMsg.ClientName = "Test"
    registerMsg.ClientDescription = "This is a test msg"
    registerMsg.ClientVersion = "1.0"
    registerMsg.ClientSupportedMessages.append(1)
    registerMsg.ClientSupportedMessages.append(123)
    registerMsg.ClientSupportedNotificationMessages.append(11)
    registerMsg.ClientSupportedNotificationMessages.append(12)

    strMsg = registerMsg.SerializeToString()

    # dump the message
    hexdump.hexdump(strMsg)
    trans.send(strMsg)
    bin = trans.recv()

    rsp = HalMessage.DeSerialize(bin)

    ClientID = rsp.msg.ClientID

    push = rsp.msg.PathFromHalToClient
    pull = rsp.msg.PathFromClientToHal

    print ClientID
    print pull
    print push

    # Create the Pull interface
    context = HalTransport.context

    pullSock = context.socket(zmq.PULL)
    pushSock = context.socket(zmq.PUSH)

    pushSock.connect("ipc://" + pull)
    pullSock.connect("ipc://" + push)

    # construct the Hello message
    helloMsg = HalMessage("HalClientHello", ClientID=ClientID)
    pushSock.send(helloMsg.Serialize())

    bin = pullSock.recv()
    rsp = HalMessage.DeSerialize(bin)

    print rsp.msg

    """
	notfication = HalNotification()
	notfication.ClientID = ClientID
	notfication.HalNotificationType = 10
	notfication.HalNotificationPayLoad = "hello"
	"""
    notfication = HalMessage("HalNotification", ClientID=ClientID,
                             HalNotificationType=10, HalNotificationPayLoad="hello")
    pushSock.send(notfication.Serialize())
    print notfication.msg

    # create the
    while True:
        bin = pullSock.recv()
        rsp = HalMessage.DeSerialize(bin)
        cfgMsg = rsp.msg
        print cfgMsg
        if rsp.msg.MsgType == "HalConfig":
            seqNum = cfgMsg.SeqNum if hasattr(cfgMsg, "SeqNum") else 0
            msg = HalMessage(
                "HalConfigRsp", ClientID=cfgMsg.ClientID, SeqNum=seqNum,
                Rsp={
                    "Status": HalCommon_pb2.SUCCESS,
                    "ErrorDescription": ""
                },
                CfgMsgType=cfgMsg.CfgMsgType,
                CfgMsgPayload=cfgMsg.CfgMsgPayload)
            # time.sleep(10)
            pushSock.send(msg.Serialize())
