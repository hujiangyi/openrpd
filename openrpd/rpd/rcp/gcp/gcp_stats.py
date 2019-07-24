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
# from rpd.hal.src.msg.HalMessage import HalMessage


class GcpSessionStats(object):

    def __init__(self):
        self.Rx = 0
        self.RxRunt = 0
        self.RxFrag = 0
        self.RxInvalidLen = 0
        self.RxDecodeFail = 0
        self.RxDecodeFrag = 0
        self.RxSessionErr = 0
        self.RxSessionClose = 0
        self.RxNoData = 0
        self.RxSockErr = 0
        self.RxQEmpty = 0

        self.Tx = 0
        self.TxQEmpty = 0
        self.TxQFull = 0
        self.TxFrag = 0
        self.TxEncodeErr = 0
        self.TxEncodeFail = 0
        self.TxSessionErr = 0
        self.TxSockErr = 0
