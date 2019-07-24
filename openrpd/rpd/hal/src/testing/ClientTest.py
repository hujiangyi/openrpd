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
import random
# from msg.USpaceDriverProvison_pb2 import HalUSDriverRegister,
# HalUSDriverRegisterRsp
from rpd.hal.src.msg.ClientProvision_pb2 import HalClientRegister
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg.HalMessage import HalMessage

trans = HalTransport(
    HalTransport.HalTransportClientMgr, HalTransport.HalClientMode)
trans.connects()


def ClientRegisterRandom():
    registerMsg = HalClientRegister()
    registerMsg.MsgType = "HalClientRegister"
    registerMsg.ClientName = "Test" + str(random.randint(1, 100))
    registerMsg.ClientDescription = "This is a test msg"
    registerMsg.ClientVersion = "1.0"

    strMsg = registerMsg.SerializeToString()

    # dump the message
    hexdump.hexdump(strMsg)
    trans.send(strMsg)
    bin = trans.recv()

    rsp = HalMessage.DeSerialize(bin)

    print rsp.msg

    push = rsp.msg.PathFromHalToClient
    pull = rsp.msg.PathFromClientToHal

    context = HalTransport.context

    pullSock = context.socket(zmq.PULL)
    pushSock = context.socket(zmq.PUSH)

    pushSock.connect("ipc://" + pull)
    pullSock.connect("ipc://" + push)

    return (rsp.msg.ClientID, pullSock, pushSock)


if __name__ == "__main__":

    (ClientID, pullSock, pushSock) = ClientRegisterRandom()

    # generate many clients

    # for i in xrange(1):
    #    ClientRegisterRandom()

    # send out the query issue
    queryMsg = HalMessage("HalClientQuery", ClientID=ClientID)
    binQueryMsg = queryMsg.Serialize()
    hexdump.hexdump(binQueryMsg)

    trans.send(binQueryMsg)
    bin = trans.recv()

    rsp = HalMessage.DeSerialize(bin)

    print rsp.msg

    # send out the driver query
    queryMsg = HalMessage("HalClientQuery", ClientID=ClientID)
    binQueryMsg = queryMsg.Serialize()
    hexdump.hexdump(binQueryMsg)

    trans.send(binQueryMsg)
    bin = trans.recv()

    rsp = HalMessage.DeSerialize(bin)

    print rsp.msg

    # send the hello msg

    helloMsg = HalMessage("HalClientHello", ClientID=ClientID)
    pushSock.send(helloMsg.Serialize())

    bin = pullSock.recv()
    rsp = HalMessage.DeSerialize(bin)

    print rsp.msg
    """
	cfgMsg = HalMessage("HalConfig",
	                    CfgMsgType=123,
	                    CfgMsgPayload="Hello"
	                    )
	
	pushSock.send(cfgMsg.Serialize())
	bin = pullSock.recv()
	rsp = HalMessage.DeSerialize(bin)
	
	print rsp.msg
	"""
    # send the ineterest message
    interesteMsg = HalMessage(
        "HalClientInterestNotificationCfg", ClientID=ClientID,
        ClientNotificationMessages=[1, 2, 3])
    trans.send(interesteMsg.Serialize())
    bin = trans.recv()
    rsp = HalMessage.DeSerialize(bin)
    print rsp.msg

    # stats msg
    statsMsg = HalMessage("HalGlobalStatsReq", ClientID=ClientID)
    trans.send(statsMsg.Serialize())
    bin = trans.recv()
    rsp = HalMessage.DeSerialize(bin)
    print rsp.msg

    statsMsg = HalMessage(
        "HalAgentStatsReq", ClientID='0be5b45c-0348-4e7c-b967-e0c613d912a4')
    trans.send(statsMsg.Serialize())
    bin = trans.recv()
    rsp = HalMessage.DeSerialize(bin)
    print rsp.msg
    """
	cfgMsg = HalMessage("HalConfig",
	                    CfgMsgType=100,
	                    CfgMsgPayload="Hello"
	                    )
	
	pushSock.send(cfgMsg.Serialize())
	bin = pullSock.recv()
	rsp = HalMessage.DeSerialize(bin)
	print rsp.msg
	import time
	"""
    """
	bin = pullSock.recv()
	rsp = HalMessage.DeSerialize(bin)
	print rsp.msg
	
	"""
