# Copyright (c) VECTOR TECHNOLOGIES SA Gdynia, Poland, and
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
from interactive_simulator.Scenario import Scenario


class ReadNotifyScenario(Scenario):
    DESCRIPTION = "This scenario is used internally for checking if first message received from rpd is notify.\
                  Don't use this scenario."

    def __init__(self, kwargs={}):
        super(ReadNotifyScenario, self).__init__()
        self.add_next_step(self.check_if_notify, True)

    def check_if_notify(self, connection, s_buffer):
        packet = Scenario.read_pkt(s_buffer)
        is_notify = False
        for msg in packet.msgs:
            if msg.message_name == "NotifyREQ":
                is_notify = True
        if is_notify:
            print "-- received notify frame! --"
        else:
            print "-- this is not notify frame, closing connection! --"
            connection.close()
