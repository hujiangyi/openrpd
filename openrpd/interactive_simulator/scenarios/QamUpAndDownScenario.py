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
from interactive_simulator.helper_methods import *


class QamUpAndDownScenario(Scenario):
    DESCRIPTION = "This scenario is used for configuring upstream and downstream qam channel. Parameterization is not supported."

    down_params = [
        "RfChannelSelector.RfChannelType=1",
        "RfChannelSelector.RfPortIndex=0",
        "RfChannelSelector.RfChannelIndex=1",
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
        "DsScQamChannelConfig.CenterFrequency=98000000"
    ]

    up_params = [
        "RfChannelSelector.RfChannelType=5",
        "RfChannelSelector.RfPortIndex=1",
        "RfChannelSelector.RfChannelIndex=2",
        "UsScQamChannelConfig.AdminState=2",
        "UsScQamChannelConfig.Type=1",
        "UsScQamChannelConfig.CenterFrequency=90000000",
        "UsScQamChannelConfig.Width=200000",
        "UsScQamChannelConfig.IntervalUsageCode[0].Code=2",
        "UsScQamChannelConfig.IntervalUsageCode[0].DifferentialEncoding=1",
        "UsScQamChannelConfig.IntervalUsageCode[0].PreambleModType=1",
        "UsScQamChannelConfig.IntervalUsageCode[0].Scrambler=1",
        "UsScQamChannelConfig.IntervalUsageCode[0].ByteInterleaverDepth=1"
    ]

    def __init__(self, args={}):
        super(QamUpAndDownScenario, self).__init__()
        missing_attributes = self.get_missing_attributes(args.pop("passed_attrs", []))
        if len(missing_attributes) == 0:
            up_attrs = parse_scenario_attrs(list(self.up_params))
            down_attrs = parse_scenario_attrs(list(self.down_params))
            self.add_next_step(self.send_frame, False, Scenario.generator.rfchannel_config(**up_attrs))
            self.add_next_step(self.recv_frame, True)
            self.add_next_step(self.send_frame, False, Scenario.generator.rfchannel_config(**down_attrs))
            self.add_next_step(self.recv_frame, True)
        else:
            raise RequiredAttributeNotPresent(str(missing_attributes))