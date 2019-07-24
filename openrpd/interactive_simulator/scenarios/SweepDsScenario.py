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
from interactive_simulator.helper_methods import *


class SweepDsScenario(Scenario):
    DESCRIPTION = "This scenario is used for make downstream QAM channel up and down 100 times."
    up_params = [
        "RfChannelSelector.RfChannelType=1",
        "RfChannelSelector.RfPortIndex=0",
        "DsScQamChannelConfig.AdminState=2",
        "DsScQamChannelConfig.RfMute=1",
        "DsScQamChannelConfig.TSID=2",
        "DsScQamChannelConfig.OperationalMode=2",
        "DsScQamChannelConfig.Modulation=4",
        "DsScQamChannelConfig.InterleaverDepth=1",
        "DsScQamChannelConfig.Annex=4",
        "DsScQamChannelConfig.SyncInterval=10",
        "DsScQamChannelConfig.SymbolFrequencyDenominator=4",
        "DsScQamChannelConfig.SymbolFrequencyNumerator=250",
        "DsScQamChannelConfig.SymbolRateOverride=260",
        "DsScQamChannelConfig.SpectrumInversionEnabled=0",
        "DsScQamChannelConfig.PowerAdjust=17",
    ]

    down_params = [
        "RfChannelSelector.RfChannelType=2",
        "RfChannelSelector.RfPortIndex=0",
        "DsScQamChannelConfig.AdminState=3",
        "DsScQamChannelConfig.RfMute=-1",
        "DsScQamChannelConfig.TSID=-1",
        "DsScQamChannelConfig.CenterFrequency=-1",
        "DsScQamChannelConfig.OperationalMode=-1",
        "DsScQamChannelConfig.Modulation=-1",
        "DsScQamChannelConfig.InterleaverDepth=-1",
        "DsScQamChannelConfig.Annex=-1",
        "DsScQamChannelConfig.SymbolFrequencyDenominator=-1",
        "DsScQamChannelConfig.SymbolFrequencyNumerator=-1",
        "DsScQamChannelConfig.SymbolRateOverride=-1",
        "DsScQamChannelConfig.SpectrumInversionEnabled=-1",
        "DsScQamChannelConfig.PowerAdjust=-1"
    ]

    def __init__(self, args={}):
        super(SweepDsScenario, self).__init__()
        self.get_missing_attributes(args.pop("passed_attrs", []))
        steps = []
        start_freq = 98000000

        for i in range(1, 100):
            up_params = list(self.up_params)
            down_params = list(self.down_params)
            freq = start_freq+(i*8*(10**6))
            up_params += ["RfChannelSelector.RfChannelIndex={}".format(i), "DsScQamChannelConfig.CenterFrequency={}".format(freq)]
            down_params += ["RfChannelSelector.RfChannelIndex={}".format(i)]
            up_attrs = parse_scenario_attrs(up_params)
            down_attrs = parse_scenario_attrs(down_params)
            steps += [Scenario.generator.rfchannel_config(**up_attrs), Scenario.generator.rfchannel_config(**down_attrs)]

        for step in steps:
            self.add_next_step(self.send_frame, False, step)
            self.add_next_step(self.recv_frame, True)