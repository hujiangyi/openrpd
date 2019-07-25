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


# from rpd.provision.process_agent.agent.agent import ProcessAgent
# from rpd.provision.process_agent.interface_status.interface_status_agent import InterfaceStatus
from rpd.provision.process_agent.tod.tod_agent import TimeOfDay
# from rpd.provision.process_agent.rcp.rcp_agent import RcpOverGcp

import logging
logging.basicConfig(level=logging.DEBUG)
# process_agent = ProcessAgent(ProcessAgent.AGENTTYPE_INTERFACE_STATUS, "ipc:///tmp/p1sock", "ipc:///tmp/p3sock")
# process_agent = InterfaceStatus()
#
# process_agent.start()

if __name__ == "__main__":
    process_agent = TimeOfDay()
    process_agent.start()

    # process_agent = RcpOverGcp()
    # process_agent.start()
