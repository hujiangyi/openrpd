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
import threading
import time

from rpd_service_suite.service_suite_mgr import ServiceConfigAdapter, ServiceSuiteManager
from rpd.it_api.it_api import ItApiClientServiceSuite
from rpd.common.rpd_syslog import log
from rpd.gpb.it_api_msgs_pb2 import t_ItApiServiceSuiteMessage


class UtServiceConfig(ServiceConfigAdapter):

    def _enable(self, gpb_params):
        log.debug("SERVICE_UT: Enabled: %s", self.name)
        if None is not gpb_params:
            self._service_configure(gpb_params)
        return True

    def _disable(self):
        log.debug("SERVICE_UT: Disabled: %s", self.name)
        return True

    def _service_configure(self, gpb_params):
        log.debug("SERVICE_UT: Configured: %s; %s", self.name, gpb_params)
        return True


class TestSuiteManager(unittest.TestCase):

    def _client_send_thread(self):
        time.sleep(2)
        gpb_msg = self.client.it_api_send_msg(self.gpb_msg)

        self.assertTrue(gpb_msg.HasField("MessageResult"),
                        "Response without result set")

        self.assertEqual(
            gpb_msg.MessageResult,
            gpb_msg.IT_API_SERVICE_SUITE_RESULT_OK,
            "Invalid ServiceSuite message result: %s".format(
                gpb_msg.t_ItApiServiceSuiteMessageResult.Name(
                    gpb_msg.MessageResult)
            ))

        self.disp.end_loop()

    def test_mgr_mock_services(self):
        mgr = ServiceSuiteManager()

        # use mock services instead of real
        new_services = []
        for serv in mgr.services:
            new_services.append(UtServiceConfig(name=serv.name))
        mgr.services = new_services

        self.client = ItApiClientServiceSuite()
        self.client.connect("127.0.0.1")

        self.assertIsNotNone(self.client.it_api_socket,
                             "Client is not connected to ServiceSuiteManager"
                             "instance")

        self.gpb_msg = t_ItApiServiceSuiteMessage()
        self.gpb_msg.MessageType = self.gpb_msg.IT_API_SERVICE_SUITE_CONFIGURE
        self.gpb_msg.ServiceConfigureMessage.DHCPv4.enable = True

        t = threading.Thread(target=self._client_send_thread)
        t.start()
        self.disp = mgr.disp
        self.disp.loop()
        self.client.cleanup()
        mgr.cleanup()

    def test_mgr_ccap_services(self):
        mgr = ServiceSuiteManager()

        # use mock services instead of real
        new_services = []
        for serv in mgr.services:
            if serv.name in ("DHCPv4", "DHCPv6", "TPv4", "TPv6"):
                new_services.append(UtServiceConfig(name=serv.name))
            else:
                new_services.append(serv)
        mgr.services = new_services

        self.client = ItApiClientServiceSuite()
        self.client.connect("127.0.0.1")

        self.assertIsNotNone(self.client.it_api_socket,
                             "Client is not connected to ServiceSuiteManager"
                             "instance")

        self.gpb_msg = t_ItApiServiceSuiteMessage()
        self.gpb_msg.MessageType = self.gpb_msg.IT_API_SERVICE_SUITE_CONFIGURE
        self.gpb_msg.ServiceConfigureMessage.CcapCoreV4.enable = True

        v4_scenario = \
            self.gpb_msg.ServiceConfigureMessage.CcapCoreV4.ClientScenarios.add()
        v4_scenario.ScenarioType = v4_scenario.SCENARIO_REDIRECT
        v4_scenario.client_ip = "127.0.0.1"

        t = threading.Thread(target=self._client_send_thread)
        t.start()
        self.disp = mgr.disp
        self.disp.loop()

        self.assertEqual(len(mgr.orchestrator.sessions_active), 1,
                         "Invalid number of active sessions in master "
                         "orchestrator: {}".format(
                             len(mgr.orchestrator.sessions_active)))

        # disable the CcapCore service
        self.gpb_msg = t_ItApiServiceSuiteMessage()
        self.gpb_msg.MessageType = self.gpb_msg.IT_API_SERVICE_SUITE_CONFIGURE
        self.gpb_msg.ServiceConfigureMessage.CcapCoreV4.enable = False

        t = threading.Thread(target=self._client_send_thread_ccap_services)
        t.start()
        self.disp.loop()

        self.assertEqual(len(mgr.orchestrator.sessions_active), 0,
                         "Invalid number of active sessions in master "
                         "orchestrator: {}".format(
                             len(mgr.orchestrator.sessions_active)))

        self.client.cleanup()
        mgr.cleanup()

    def _client_send_thread_ccap_services(self):
        time.sleep(2)
        gpb_msg = self.client.it_api_send_msg(self.gpb_msg)

        self.assertTrue(gpb_msg.HasField("MessageResult"),
                        "Response without result set")

        self.assertEqual(
            gpb_msg.MessageResult,
            gpb_msg.IT_API_SERVICE_SUITE_RESULT_OK,
            "Invalid ServiceSuite message result: %s".format(
                gpb_msg.t_ItApiServiceSuiteMessageResult.Name(
                    gpb_msg.MessageResult)
            ))

        self.disp.end_loop()

if __name__ == "__main__":
    unittest.main()
