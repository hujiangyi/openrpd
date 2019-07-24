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

import unittest
from rpd.provision.manager.src.manager_main import AgentsStarter
import os, time
import subprocess
import signal
from rpd.common.rpd_logging import setup_logging


class TestAgentsStarter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging("PROVISION", filename="provision_mgr_process.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')

    def test_starter_init(self):
        print '#'*80
        print 'test main init'
        starter = AgentsStarter(simulator=False)
        agent_process = {}
        agent_id = None
        for agent_id in starter.agent_dict:
            agent_process[agent_id] = starter.start_process(starter.agent_dict[agent_id])

        # input parameter is Popen object
        starter.check_process_status(agent_process[agent_id])

        # input parameter is not Popen object
        starter.check_process_status(1)

        for idx in agent_process:
            agent_process[idx].terminate()

        process_obj = starter.start_process(starter.fake_driver_cmd_line)
        starter.fake_driver_process = {
            "process": process_obj,
            "retries": 0,
        }
        starter.cleanup()

        # not simulator
        AgentsStarter(simulator=True)


if __name__ == '__main__':
    unittest.main()
    setup_logging("PROVISION", "test.log")
