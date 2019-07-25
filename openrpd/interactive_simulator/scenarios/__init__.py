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
from os.path import dirname, basename, isfile
import glob
from importlib import import_module
from interactive_simulator.TesterExceptions import *

_modules = glob.glob(dirname(__file__) + "/*.py")
_scenarios_names = [basename(
    f)[:-3] for f in _modules if isfile(f) and basename(f)[:-3].endswith("Scenario")]
all_scenarios = {}
for scenario in _scenarios_names:
    all_scenarios[scenario.lower()] = getattr(
        import_module("interactive_simulator.scenarios.{0}".format(scenario)), scenario)


def get(scenario_name):
    try:
        return all_scenarios[scenario_name]
    except KeyError:
        raise ScenarioNotFound


def get_all_scenarios():
    return [basename(f)[:-3].lower() for f in _modules if isfile(f) and basename(f)[:-3].endswith("Scenario")]
