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
from interactive_simulator.ConnectionManager import ConnectionManager
import threading
import pickle
import zmq
import interactive_simulator.scenarios as scenarios
import traceback
from interactive_simulator.TesterExceptions import *
from interactive_simulator.helper_methods import *
from interactive_simulator.FrameGenerator import RequiredAttributeNotPresent


class Simulator(object):

    MGMT_SOCK = "ipc:///tmp/rpd_tester.ipc"

    def __init__(self, host, port):
        self.connection_manager = ConnectionManager(host, port)
        self.ctx = zmq.Context()
        self.control_socket = self.ctx.socket(zmq.REP)
        self.control_socket.bind(Simulator.MGMT_SOCK)

    def start(self):
        t = threading.Thread(target=self._control_loop, args=())
        t.daemon = True
        t.start()
        self.connection_manager.listen()

    def stop(self):
        self.connection_manager.stop_all_threads()

    def _control_loop(self):
        while True:
            raw_request = self.control_socket.recv()
            request = pickle.loads(raw_request)
            try:
                response = self.handle_request(request)
            except ScenarioNotFound:
                response = {"result": "Scenario: scenario not found"}
            except Exception as e:
                response = {"result": "Scenario: unknown exception"}
                traceback.print_exc()
            raw_response = pickle.dumps(response)
            self.control_socket.send(raw_response)

    def handle_request(self, request):
        attrs = {}
        scns = request["scenarios"]
        command_attrs = handle_prefixes(request["attrs"])
        file_attrs = handle_prefixes(request["file"])
        if command_attrs:
            attrs = parse_scenario_attrs(command_attrs)
        if file_attrs:
            overwrite_file_attrs(command_attrs, file_attrs)
            file_attrs = parse_scenario_attrs(file_attrs)
            attrs = merge_attributes(attrs, file_attrs)
        if scns:
            action = scns.pop(0)
            return self.process_scenario_command(action, scns, attrs)
        return {}

    def process_scenario_command(self, action, action_args, attrs=None):
        self.connection_manager.remove_closed_connections()
        if action == "select":
            response = {}
            for single_scenario in action_args:
                scenario = scenarios.get(single_scenario)
                try:
                    merge_statuses(response, self.connection_manager.execute_scenario(scenario, attrs))
                except RequiredAttributeNotPresent as ex:
                    return {"status": "Scenario can't be executed because of missing attributes: {}".format(ex)}
            if not response:
                return {"status": "There are no connected slaves..."}
            return response
        elif action == "set_default":
            scen_name = action_args.pop(0)
            scen = scenarios.get(scen_name)
            self.connection_manager.set_default_scenario(scen, attrs)
            return {"status": "{} has been set as connection default scenario".format(scen_name)}
        elif action == "remove_default":
            self.connection_manager.remove_default_scenario()
            return {"status": "Default scenario has been removed"}
        elif action == "status":
            response = self.connection_manager.check_scenarios_statuses()
            if not response:
                return {"status": "There are no connected slaves..."}
            else:
                return response
        elif action == "break":
            result = self.connection_manager.break_executing_scenarios()
            if not result:
                return {"status": "There are no connected slaves..."}
            else:
                return {"status": "Executing scenarios has been stopped"}
        elif action == "help":
            descriptions = {}
            if action_args:
                scenario_name = action_args.pop(0)
                scenario = scenarios.get(scenario_name)
                descriptions[scenario_name] = scenario.get_scenario_description()
                return descriptions
            else:
                return {"available scenarios": scenarios.get_all_scenarios()}
        else:
            return {"response": "Unknown command"}


if __name__ == "__main__":
    sim = None
    try:
        sim = Simulator("0.0.0.0", 8190)
        sim.start()
    except KeyboardInterrupt:
        sim.stop()
        print "program has been closed"
