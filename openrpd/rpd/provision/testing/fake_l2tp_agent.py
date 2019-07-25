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
from rpd.provision.process_agent.agent.fake_agent import FakeAgent
import rpd.provision.process_agent.agent.agent as agent
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass


class L2TP(FakeAgent):
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        super(L2TP, self).__init__(agent.ProcessAgent.AGENTTYPE_L2TP)


if __name__ == "__main__":
    setup_logging("PROVISION", filename="provision_l2tp.log")
    pagent = L2TP()
    pagent.start()
