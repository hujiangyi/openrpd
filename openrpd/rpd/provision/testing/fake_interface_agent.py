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
import zmq

from rpd.common.rpd_logging import setup_logging
import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.provision.process_agent.agent.fake_agent import FakeAgent


class InterfaceStatus(FakeAgent):

    SCAN_INTERFACE_TIMEOUT = 5

    def __init__(self):
        super(InterfaceStatus, self).__init__(agent.ProcessAgent.AGENTTYPE_INTERFACE_STATUS)
        self.dispatcher.timer_register(self.SCAN_INTERFACE_TIMEOUT, self.scan_available_interface)

    def scan_available_interface(self, _):
        self.logger.debug("Scanning available interface ...")
        for idx in self.mgrs:
            event_request_rsp = protoDef.msg_event_notification()
            event_request_rsp.mgr_event.mgr_id = idx
            event_request_rsp.mgr_event.event_id = self.id
            event_request_rsp.mgr_event.data = self.Fake_Parameter[self.id]
            try:
                self.mgrs[idx]['transport'].sock.send(
                    event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
            except zmq.ZMQError as ex:
                self.logger.error("failed to send to manager: %s" % str(ex))


if __name__ == "__main__":
    setup_logging("PROVISION", filename="provision_interface_status.log")
    pagent = InterfaceStatus()
    print pagent.agent_status
    pagent.start()
