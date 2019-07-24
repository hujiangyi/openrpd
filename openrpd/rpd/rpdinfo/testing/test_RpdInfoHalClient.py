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

from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.hal.src.HalConfigMsg import MsgTypeRpdInfo
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.rpdinfo.src.RpdInfoHalClient import RpdInfoHalClient


class testRpdInfoHalClient(unittest.TestCase):
    def setUp(self):
        self.rpdinfo = RpdInfoHalClient(
            "RpdInfo_hal", "This is RPDInfo hal client",
            "1.0.0", (MsgTypeRpdInfo,), ())

    def test_recvCfgMsgCb(self):
        cfg = t_RcpMessage()
        cfg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        cfg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
        # cfg.RpdMacAddress = "111111111111"
        payload = cfg.SerializeToString()
        print payload
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="435qwert22",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdInfo,
                                 CfgMsgPayload=payload)
        self.assertEqual(None, self.rpdinfo.recvCfgMsgCb(self.cfgMsg))

if __name__ == '__main__':
    unittest.main()
