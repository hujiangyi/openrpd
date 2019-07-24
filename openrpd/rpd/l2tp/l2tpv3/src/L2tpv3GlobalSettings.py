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


class L2tpv3GlobalSettings(object):
    """This is the place to hold all the l2tp configurations."""
    LocalIPAddress = "127.0.0.1"
    Dispatcher = None
    l2tp_hal_client = None
    APITransportPath = "ipc:///tmp/l2tpDaemonSock"

    # Debug file dir, this is used for large scale test
    DebugFileDir = "./"
    # daemon related files, used for large scale test
    DaemonFileDir = "/tmp/"

    # Some system infomation
    Hostname = "OpenRPD"
    VendorName = "Cisco"

    # For connection setting
    HelloMsgTimeout = 60
    ConnectionTimeout = 5 * HelloMsgTimeout
    SendZlbTimeout = 1
    ReceiveWindowSize = 16
    SendTimeout = 18
    MustAvpsCheck = False
    # for unit test
    UnitTest_StopL2tp = False

    #for RFC 4951
    failoverCapofCC = True
    failoverCapofDC = False
    recoveryTime = 0
