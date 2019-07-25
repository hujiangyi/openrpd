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


class HalGlobal(object):
    # please note that all the duplicated import file will only executed once
    # This is the main logic for Hal
    StopHal = False

    # we need a global name to mgr
    gClientMgr = None

    # we need a global poller
    gPoller = None

    # the msgtype and the handler mapping table
    gHandleTable = dict()

    # the monitor socket table
    gMonitorSocketMappingTable = dict()
    # the socket and agent mspping table
    gSocketAgentMappingTable = dict()

    # the msg type and destination agent mapping
    gMsgTypeClientMapping = dict()

    # The clientID and the client mapping
    gClientIndex = dict()
    # the dict hold all the client and the index, will not
    # clear

    # The client DB, which hold the clientID and client agent mapping
    gClientDB = dict()

    # The interest notification and the client mapping
    gNotificationMapping = dict()

    # global Timeout setting
    gTimeout = 1000  # The unit is ms

    # The gAgentDb hold all the agents, including the client agent and the
    # driver agents
    gAgentDB = dict()

    # the database object
    # gHalMsgDbConnection = HalDatabase.HalDatabase("/tmp/redis.sock", 30, 12)
    # gHalClientDbConnection = HalDatabase.HalDatabase("/tmp/redis.sock", 30,
    # 11)
    gHalMsgDbConnection = None
    gHalClientDbConnection = None

    # The global dispatcher, which is used to dispatch the message from client
    # to driver, or from the driver to client
    gDispatcher = None

    # restart resend messages
    gRestartResendMsg = dict()

    @classmethod
    def reinit(cls):
        cls.StopHal = False

        cls.gClientMgr = None

        cls.gPoller = None

        for sock in cls.gMonitorSocketMappingTable:
            sock.close()
        cls.gMonitorSocketMappingTable = dict()

        for sock in cls.gSocketAgentMappingTable:
            sock.close()
        cls.gSocketAgentMappingTable = dict()

        cls.gMsgTypeClientMapping = dict()

        cls.gClientIndex = dict()

        cls.gClientDB = dict()

        cls.gNotificationMapping = dict()

        cls.gTimeout = 1000  # The unit is ms

        cls.gAgentDB = dict()

        cls.gHalMsgDbConnection = None
        cls.gHalClientDbConnection = None

        cls.gDispatcher = None

        cls.gRestartResendMsg = dict()
