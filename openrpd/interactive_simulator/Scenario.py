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
from rpd.rcp.rcp_lib.rcp import RCPPacket
from time import time
from interactive_simulator.FrameGenerator import FrameGenerator


class Scenario(object):
    generator = FrameGenerator()
    STATE_DESCRIPTION = "Scenario: name={}, state={}, remaining steps={}"
    DESCRIPTION = ""
    REQUIRED_ARGS = []

    def __init__(self, name=None):
        name = name if name is not None else self.__class__.__name__
        self.name = name
        self.steps = []
        self.sent_frames = []
        self.current_status = ""

    def add_next_step(self, s_function, s_type, *args):
        self.steps.append([s_function, s_type, args])

    def get_name(self):
        return self.name

    def has_next_step(self, read=False):
        steps = self.steps
        steps_len = len(steps)
        if read:
            return steps_len > 0 and self.steps[0][1] == True
        if not read and steps_len > 0:
            for step in steps:
                if step[1] == False:
                    return True
            return False
        return False

    def get_remaining_steps(self):
        return len(self.steps)

    def update_scenario_status(self, status, slave_addr="unknown"):
        if status == 0:
            self.current_status = Scenario.STATE_DESCRIPTION.format(
                self.name, "starting", self.get_remaining_steps()
            )
        elif status == 1:
            self.current_status = Scenario.STATE_DESCRIPTION.format(
                self.name, "executing", self.get_remaining_steps()
            )
        elif status == 2:
            self.current_status = "Scenario has been executed"

    def get_status(self):
        return self.current_status

    @staticmethod
    def read_pkt(s_buffer):
        packet = RCPPacket(s_buffer, buf_data_len=len(s_buffer))
        packet.decode()
        return packet

    def call_function(self, step, kwargs):
        s_function, s_type, args = step
        if s_type and "buffer" in kwargs and "connection" in kwargs:
            s_function(kwargs["connection"], kwargs["buffer"], *args)
        elif "connection" in kwargs:
            s_function(kwargs["connection"], *args)

    def execute_next_step(self, **kwargs):
        self.call_function(self.steps.pop(0), kwargs)

    def execute_next_async_step(self, **kwargs):
        step_index = None
        steps = self.steps
        for index, step in enumerate(steps):
            if step[1] == False:
                step_index = index
                break
        if step_index is not None:
            self.call_function(self.steps.pop(step_index), kwargs)

    def recv_frame(self, connection, s_buffer):
        packet = Scenario.read_pkt(s_buffer)
        current_time = time()
        for index, frame in enumerate(self.sent_frames):
            if frame.id == packet.transaction_identifier:
                print "-- received response after {} s --".format(current_time - frame.send_time)
                self.sent_frames.remove(frame)
                break
        else:
            print "-- received response tranasaction indentifier doesn't exist in sent requests --"

    def check_if_exist_timeouted_frame(self, connection, timeout):
        current_time = time()
        sent_frames = self.sent_frames
        for frame in sent_frames:
            if current_time - frame.send_time > timeout:
                print "There is timeout frame!"

        print "There is no timeouted frames!"

    def send_frame(self, connection, frame):
        print "-- sent frame --"
        frame.prepare_to_send()
        connection.send(frame.content)
        self.sent_frames.append(frame)

    def send_multiple_frames(self, connection, frames):
        for frame in frames:
            frame.prepare_to_send()
            connection.send(frame.content)
            self.sent_frames.append(frame)

    @classmethod
    def get_scenario_description(cls):
        return cls.DESCRIPTION

    @classmethod
    def get_missing_attributes(cls, p_args):
        missing_attrs = []
        for arg in cls.REQUIRED_ARGS:
            if arg not in p_args:
                missing_attrs.append(arg)
        return missing_attrs
