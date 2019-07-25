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
from interactive_simulator.FrameGenerator import RequiredAttributeNotPresent


class RfChannelScenario(Scenario):
    DESCRIPTION = "This scenario is used for configuring rf channel. It sends single frame and wait for response. \
        Every attribute from RfChannel.proto can be set. \
        Required attributes: RfChannelSelector.RfPortIndex, RfChannelSelector.RfChannelType, RfChannelSelector.RfChannelIndex"

    REQUIRED_ARGS = ["RfChannelSelector.RfPortIndex", "RfChannelSelector.RfChannelType", "RfChannelSelector.RfChannelIndex"]

    def __init__(self, args={}):
        super(RfChannelScenario, self).__init__()
        missing_attributes = self.get_missing_attributes(args.pop("passed_attrs", []))
        if len(missing_attributes) == 0:
            self.add_next_step(self.send_frame, False, Scenario.generator.rfchannel_config(**args))
            self.add_next_step(self.recv_frame, True)
        else:
            raise RequiredAttributeNotPresent(str(missing_attributes))
