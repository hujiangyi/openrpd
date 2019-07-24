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
from rpd.hal.src.msg.HalMessage import HalMessage


class HalGlobalStats(object):
    NrClient = 0
    NrErrorMsgs = 0  # Error messages, such as the message can not find the driver or client

    @staticmethod
    def generateHalMessage():
        return HalMessage(
            "HalGlobalStats",
            NrClient=HalGlobalStats.NrClient,
            NrErrorMsgs=HalGlobalStats.NrErrorMsgs
        )


class HalAgentStats(object):

    def __init__(self):
        self.NrMsgs = 0
        self.NrCfgMsgs = 0
        self.NrDroppedMsgs = 0
        self.NrTimeoutMsgs = 0
        self.NrNotifyMsgs = 0
        self.NrHelloMsgs = 0
        self.NrCfgRspMsgs = 0
        self.NrHelloRspMsgs = 0
        self.NrErrorMsgs = 0

    def generateHalMessage(self):
        return HalMessage("HalAgentStatsRsp",
                          NrMsgs=self.NrMsgs,
                          NrCfgMsgs=self.NrCfgMsgs,
                          NrDroppedMsgs=self.NrDroppedMsgs,
                          NrTimeoutMsgs=self.NrTimeoutMsgs,
                          NrNotifyMsgs=self.NrNotifyMsgs,
                          NrHelloMsgs=self.NrHelloMsgs,
                          NrCfgRspMsgs=self.NrCfgRspMsgs,
                          NrHelloRspMsgs=self.NrHelloRspMsgs,
                          NrErrorMsgs=self.NrErrorMsgs,
                          )
