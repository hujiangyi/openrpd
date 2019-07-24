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
from interactive_simulator.Connection import Connection
import socket
import interactive_simulator.scenarios as scenarios
from interactive_simulator.FrameGenerator import RequiredAttributeNotPresent


class ConnectionManager(object):

    def __init__(self, host, port):
        self.connections = []
        self.initialize_socket(host, port)
        self.default_scenario = None

    def initialize_socket(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        self.soc = s

    def listen(self):
        print "-- simulator is listening for connections --"
        while True:
            self.soc.listen(5)
            conn, addr = self.soc.accept()
            t = Connection(conn, addr, None)
            t.daemon = True
            self.connections.append(t)
            t.start()
            t.scenarios.put(self.get_notify_scenario())
            if self.default_scenario is not None:
                self.execute_default_scenario(t)

    def execute_default_scenario(self, connection):
        scen = self.default_scenario
        try:
            connection.scenarios.put(scen["scenario"](scen["attrs"]))
        except RequiredAttributeNotPresent as ex:
            print "-- Default scenario can't be executed because of missing attributes: {} --".format(ex)

    def get_notify_scenario(self):
        return scenarios.get("readnotifyscenario")()

    def set_default_scenario(self, scenario, attrs):
        self.default_scenario = {"scenario": scenario, "attrs": attrs}

    def remove_default_scenario(self):
        self.default_scenario = None

    def remove_closed_connections(self):
        for conn in list(self.connections):
            if conn.is_stopped():
                self.connections.remove(conn)

    def execute_scenario(self, scenario_cls, attrs):
        scenarios = {}
        for conn in self.connections:
            address = "{}:{}".format(conn.get_addr()[0], conn.get_addr()[1])
            scenario_obj = scenario_cls(attrs)
            conn.scenarios.put(scenario_obj)
            conn.scenario_stop = False
            scenarios[address] = "Added {0} to execute for slave {1}".format(scenario_obj.get_name(), address)
        return scenarios

    def check_scenarios_statuses(self):
        statuses = {}
        for conn in self.connections:
            addr = "{}:{}".format(conn.addr[0], conn.addr[1])
            if conn.current_scenario is not None:
                statuses[addr] = conn.current_scenario.get_status()
            else:
                statuses[addr] = "Waiting for scenario"
        return statuses

    def break_executing_scenarios(self):
        if len(self.connections) == 0:
            return False
        for conn in self.connections:
            conn.break_executing_scenario()
        return True

    def stop_all_threads(self):
        self.soc.shutdown(socket.SHUT_RDWR)
        for t in self.connections:
            t.stop_thread()
        self.soc.close()
