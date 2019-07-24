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
import zmq
import threading
import time

from rpd.rcp.rcp_process import RcpProcess, RcpHalProcess
from rpd.rcp.gcp import gcp_sessions
from rpd.rcp.rcp_sessions import RCPMasterCapabilities, RCPMasterDescriptor
from rpd.rcp.rcp_master_orchestrator import RCPMasterOrchestrator
from rpd.gpb.it_api_msgs_pb2 import t_ItApiRpdMessage
from rpd.it_api.manager import RpdITManager
from rpd.it_api.it_api import ItApiClientOpenRPD


class TestItApiMgr(unittest.TestCase):

    def _disp_stop(self, _):
        self.disp.end_loop()

    def _client_connect(self, _):
        self.t_client.connect("127.0.0.1")
        # send get MSG to the testing manager
        msg = t_ItApiRpdMessage()
        msg.ItApiRpdMessageType = msg.IT_API_RPD_GET

        response = self.t_client.it_api_send_msg(msg)

        self.assertEqual(t_ItApiRpdMessage.IT_API_RPD_GET,
                         response.ItApiRpdMessageType,
                         "Invalid testing message type received")
        self.disp.end_loop()

    def test_mgr_it_api(self):
        self.t_mgr = RpdITManager()
        self.disp = self.t_mgr.it_api_server.disp

        t = threading.Thread(target=self._client_worker)
        t.start()

        self.disp.loop()
        self.t_mgr.testing_cleanup()

    def _client_worker(self):
        self.t_client = ItApiClientOpenRPD()
        time.sleep(3)
        self._client_connect(None)

if __name__ == "__main__":
    unittest.main()
