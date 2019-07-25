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
from threading import Thread
from array import array
import struct
import socket
from Queue import LifoQueue


class Connection(Thread):
    MAX_PACKET_LEN = 65535
    MIN_PACKET_LEN = 7

    def __init__(self, conn, addr, s_container):
        Thread.__init__(self)
        self.conn = conn
        self.conn.settimeout(1.0)
        self.addr = addr
        self.scenarios = LifoQueue()
        self.current_scenario = None
        self.stop = False
        self.scenario_stop = False
        self.buffer = array("B")
        self.packet_len = 0

    def get_packet_len(self):
        self.get_data_from_socket(self.MIN_PACKET_LEN)
        if len(self.buffer) >= self.MIN_PACKET_LEN:
            self.packet_len = struct.unpack("!H", self.buffer[4:6])[0]
            return True
        return False

    def get_packet_payload(self):
        self.get_data_from_socket(self.packet_len)

    def get_addr(self):
        return self.addr

    def is_stopped(self):
        return self.stop

    def get_data_from_socket(self, data_len):
        data = self.conn.recv(data_len)
        if not data:
            self.stop = True
            return
        self.buffer.extend(array("B", data))

    def clear_socket_recv(self):
        try:
            while True:
                self.conn.recv(1024)
        except socket.timeout:
            return "Socket has been cleared"

    def break_executing_scenario(self):
        self.scenario_stop = True
        while not self.scenarios.empty():
            self.scenarios.get()
        self.current_scenario = None
        self.clear_socket_recv()

    def reset_state(self):
        self.buffer = array("B")
        self.packet_len = 0

    def run(self):
        while not self.stop:
            self.current_scenario = None
            scenario = self.scenarios.get()
            self.current_scenario = scenario
            scenario.update_scenario_status(0)
            self.execute_scenario(scenario)
        print "killed process ", self.addr

    def execute_scenario(self, scenario):
        while not self.stop and not self.scenario_stop:
            scenario.update_scenario_status(1)
            try:
                if scenario.has_next_step(True):
                    if self.get_packet_len():
                        self.get_packet_payload()
                        scenario.execute_next_step(
                            connection=self.conn, buffer=self.buffer)
                        self.reset_state()
                elif scenario.has_next_step():
                    scenario.execute_next_async_step(connection=self.conn)
                else:
                    scenario.update_scenario_status(2)
                    break
            except socket.timeout:
                if scenario.has_next_step() and not self.scenario_stop:
                    scenario.execute_next_async_step(connection=self.conn)

    def stop_thread(self):
        self.stop = True
        self.conn.close()
