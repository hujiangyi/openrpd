#
# Copyright (c) 2018 Cisco and/or its affiliates, and
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
from rpd.gpb.cfg_pb2 import config
from rpd.resource.src.RpdHostResourceHandler import HostResourceHandler
from rpd.common.rpd_logging import AddLoggerToClass


class testRpdInfoHalClient(unittest.TestCase):

    __metaclass__ = AddLoggerToClass

    def setUp(self):
        self.hostRes = HostResourceHandler()
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_getMemorySize(self):
        self.logger.info("test_getMemorySize")
        memsize = self.hostRes.getMemorySize()
        self.assertTrue(memsize != 0)

    def test_getProcessorLoad(self):
        self.logger.info("test_getProcessorLoad")
        cpuload = self.hostRes.getProcessorLoad()
        self.assertTrue(cpuload > 0)

    def test_getStorages(self):
        self.logger.info("test_getStorages")
        cfg_msg = config()
        hr = cfg_msg.HostResources
        hr.hrMemorySize = self.hostRes.getMemorySize()
        self.hostRes.getStorages(hr.hrStorages)
        self.assertTrue(hr.hrStorages)

    def test_getProcesses(self):
        self.logger.info("test_getProcesses")
        cfg_msg = config()
        hr = cfg_msg.HostResources
        hr.hrProcessorLoad = self.hostRes.getProcessorLoad()
        self.hostRes.getProcesses(hr.hrProcesses)
        self.assertTrue(hr.hrProcesses)


if __name__ == '__main__':
    unittest.main()
