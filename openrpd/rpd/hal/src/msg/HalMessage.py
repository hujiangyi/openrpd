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
from rpd.hal.src.msg import ClientProvision_pb2
from rpd.hal.src.msg import HalOperation_pb2
from rpd.hal.src.msg import HalStats_pb2
from rpd.hal.src.msg import HalControl_pb2


class HalMessage(object):
    """handle the message serialization/deserialization."""
    MsgTypeMapping = {
        "HalClientRegister": ClientProvision_pb2.HalClientRegister,
        "HalClientRegisterRsp": ClientProvision_pb2.HalClientRegisterRsp,
        "HalClientQuery": ClientProvision_pb2.HalClientQuery,
        "HalClientQueryRsp": ClientProvision_pb2.HalClientQueryRsp,
        "HalClientHello": HalOperation_pb2.HalClientHello,
        "HalClientHelloRsp": HalOperation_pb2.HalClientHelloRsp,
        "HalConfig": HalOperation_pb2.HalConfig,
        "HalConfigRsp": HalOperation_pb2.HalConfigRsp,
        "HalClientInterestNotificationCfg": ClientProvision_pb2.HalClientInterestNotificationCfg,
        "HalClientInterestNotificationCfgRsp": ClientProvision_pb2.HalClientInterestNotificationCfgRsp,
        "HalNotification": HalOperation_pb2.HalNotification,
        "HalGlobalStatsReq": HalStats_pb2.HalGlobalStatsReq,
        "HalGlobalStats": HalStats_pb2.HalGlobalStats,
        "HalAgentStatsReq": HalStats_pb2.HalAgentStatsReq,
        "HalAgentStatsRsp": HalStats_pb2.HalAgentStatsRsp,
        "HalSetLoggingLevel": HalControl_pb2.HalSetLoggingLevel,
        "HalSetLoggingLevelRsp": HalControl_pb2.HalSetLoggingLevelRsp,

    }

    def __init__(self, MsgType, **MsgParametr):
        self.msg = None
        self.type = None
        self.originalBinary = None

        if "binary" in MsgParametr:
            self.originalBinary = MsgParametr["binary"]

        if MsgType == "__General__":
            self.type = MsgParametr["type"]
            self.msg = MsgParametr["msg"]
            return
        if MsgType in self.MsgTypeMapping:
            self.type = MsgType
            msgCLass = self.MsgTypeMapping[MsgType]
            self.msg = msgCLass()
            self.msg.MsgType = MsgType
            # init the parameters
            for para in MsgParametr:
                if isinstance(MsgParametr[para], tuple):
                    MsgParametr[para] = list(MsgParametr[para])
                if isinstance(MsgParametr[para], list):

                    if len(MsgParametr[para]) <= 0:
                        continue

                    array = getattr(self.msg, para)
                    # test the MsgParameter type
                    if isinstance(MsgParametr[para][0], dict):
                        for item in MsgParametr[para]:
                            obj = array.add()
                            for field in item:
                                if isinstance(item[field], list):
                                    innerArray = getattr(obj, field)
                                    for innerField in item[field]:
                                        innerArray.append(innerField)
                                else:
                                    setattr(obj, field, item[field])
                    else:
                        for item in MsgParametr[para]:
                            # compose the msg now
                            array.append(item)

                elif isinstance(MsgParametr[para], dict):
                    innerInstance = getattr(self.msg, para)
                    for paraInner in MsgParametr[para]:
                        if isinstance(MsgParametr[para][paraInner], list):
                            array = getattr(innerInstance, paraInner)
                            for item in MsgParametr[para][paraInner]:
                                array.append(item)
                        else:
                            setattr(
                                innerInstance, paraInner, MsgParametr[para][paraInner])
                else:
                    if MsgParametr[para] is not None:
                        setattr(self.msg, para, MsgParametr[para])
        else:
            raise Exception(
                "Cannot create a msg since we can not find the msg definition")

    def Serialize(self):
        """Invoke the SerializeToString to change the msg to string, this
        function can resue the msg."""
        if self.msg:
            return self.msg.SerializeToString()

        raise Exception("Cannot serializing the msg since the msg is None")

    @staticmethod
    def DeSerialize(binary):
        """Unserialize a binay to a."""
        # first we should get teh msg type from the msg
        if binary is None or len(binary) < 2:
            raise Exception("The input binary is None")

        # get the second byte for the length
        lenth = ord(binary[1])
        msgType = binary[2:2 + lenth]

        if msgType in HalMessage.MsgTypeMapping:
            msgClass = HalMessage.MsgTypeMapping[msgType]

            msg = msgClass()
            msg.ParseFromString(binary)

            return HalMessage("__General__", msg=msg, type=msgType, binary=binary)
        else:
            raise Exception(
                "Cannot parse the message since the msgType[%s] is unknown" % msgType)
