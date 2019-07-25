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
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2


class TestHalDatabase(unittest.TestCase):

    def test_createHalMessage(self):
        """test create HalMessage.

        check the HalUSDriverRegisterRsp message can
        be serialized, if not case fail

        check the unnormal message can't be
        created, if not case fail

        check the none message can't be serialized,
        if not case fail.

        :keyword:createHalMessage
        :exception:assertEqual(regRsp.Serialize(), regRsp1.Serialize()),
                   "Cannot create a msg since we can not find the msg definition",
                   "Cannot serializing the msg since the msg is None",
        :parameter:
        :return:

        """
        msg = HalMessage(
            "HalClientRegister", ClientName="abc", ClientDescription="abc",
            ClientVersion="1.2.3", ClientSupportedMessages=[1, 2, 3],
            ClientSupportedNotificationMessages=[1, 2, 3])
        msg = HalMessage(
            "HalClientRegister", ClientName="abc", ClientDescription="abc",
            ClientVersion="1.2.3", ClientSupportedMessages=[1, 2, 3],
            ClientSupportedNotificationMessages=[])
        msg.Serialize()
        regRsp = HalMessage("HalClientRegisterRsp",
                            Rsp={
                                "Status": HalCommon_pb2.SUCCESS,
                                "ErrorDescription": "Successful"
                            },
                            ClientID="123",
                            PathFromHalToClient="123",
                            PathFromClientToHal="abc'"
                            )

        bin = regRsp.Serialize()
        regRsp1 = HalMessage.DeSerialize(bin)

        self.assertEqual(regRsp.Serialize(), regRsp1.Serialize())

        # test line 85
        rsp = HalMessage("HalClientQueryRsp",
                         ClientID="123",
                         Clients=[
                             {
                                 "ClientID": "clientID",
                                 "ClientName": "msg.msg.ClientName",
                                 "ClientDescription": "msg.msg.ClientDescription",
                                 "ClientVersion": "msg.msg.ClientVersion",
                                 "ClientSupportedMessages": [12, 3],
                                 "ClientSupportedNotificationMessages": [1, 2]
                             },
                             {
                                 "ClientID": "clientID",
                                 "ClientName": "msg.msg.ClientName",
                                 "ClientDescription": "msg.msg.ClientDescription",
                                 "ClientVersion": "msg.msg.ClientDriverVersion",
                                 "ClientSupportedMessages": [12, 3],
                                 "ClientSupportedNotificationMessages": [1, 2]
                             }
                         ])
        try:
            rsp = HalMessage("HalClientInterestNotificationCfgRsp",
                             ClientID="123",
                             Rsp={"Status": 1, "ErrorDescription": []})
            rsp = HalMessage("HalClientInterestNotificationCfgRsp",
                             ClientID="123",
                             Rsp={"Status": 1, "ErrorDescription": [1, 2, 3]})
        except AttributeError:
            pass

        try:
            msg = HalMessage("test")
        except Exception as e:
            self.assertEqual(
                str(e), "Cannot create a msg since we can not find the msg definition")

        try:
            rsp.msg = None
            rsp.Serialize()
        except Exception as e:
            self.assertEqual(
                str(e), "Cannot serializing the msg since the msg is None")
        """
        msg = HalMessage("HalClientRegister", )
        msg = HalMessage("HalClientRegisterRsp", )
        msg = HalMessage("HalClientQuery", )
        msg = HalMessage("HalClientQueryRsp", )
        msg = HalMessage("HalClientHello", )
        msg = HalMessage("HalClientHelloRsp", )
        msg = HalMessage("HalConfig", )
        msg = HalMessage("HalConfigRsp", )
        msg = HalMessage("HalClientInterestNotificationCfg", )
        msg = HalMessage("HalClientInterestNotificationCfgRsp", )
        msg = HalMessage("HalNotification", )
        msg = HalMessage("HalGlobalStatsReq", )
        msg = HalMessage("HalGlobalStats", )
        msg = HalMessage("HalClientStatsReq", )
        msg = HalMessage("HalClientStats", )
        """

    def test_Deserialize(self):
        """test HalMessage#DeSerialize,

        check the string message can't be
        deserialized, if not case fail

        check the unnormal binary HalMessage
        can't be deserialized, if not case fail.

        :keyword:HalMessage#DeSerialize
        :exception:"The input binary is None",
                   "Cannot parse the message since the msgType"
        :parameter:
        :return:

        """
        try:
            mas = HalMessage.DeSerialize("a")
        except Exception as e:
            self.assertEqual("The input binary is None", str(e))

        try:
            msg = HalMessage.DeSerialize("00000))))))00000))))))00000))))))00000))))))00000))))))00000))))))00000)))))"
                                         ")00000))))))00000))))))")
        except Exception as e:
            self.assertEqual(
                str(e).startswith("Cannot parse the message since the msgType"), True)


if __name__ == '__main__':
    unittest.main()
