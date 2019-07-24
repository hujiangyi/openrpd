Copyright (c) VECTOR TECHNOLOGIES SA Gdynia, Poland, and Cable Television Laboratories, Inc. ("CableLabs")

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Theory of operation
=====================
Ccap core simulator is used to communicate with rpd and simulate requests/responses.
                                                  
                                                ____________         __________                    
                                               |    core    |       |          |                   
                                               |  simulator |<----->|   RPD    |                   
                                               |____________|       |__________|

It has two main and third optional component. First is sim.py, which handles incoming connections from RPD and it is a server for second simulator component: client.by. Third and optional is clish client, which only calls client.py with proper parameters. On sim.py are implemented several scenarios, which can be invoked by client.py.

Client.py can start particular scenario, interrupt its execution, ask for current status of execution. There can be also set/unset default scenario, which will be executed after rpd connect with simulator. Scenario can be parameterized. It can be done from file or from console. When the same attribute is set in file and console - console attribute overwrites file attribute. When setting a lot of nested attributes, for convenience, prefix can be set.
How passed parameters will be used depends of senario implementation. For example RfChannelScenario and RfPortScenario can receive parameters which set content of frame, which will be send to rpd. It is described in scenario description, which you can invoke with help command. Convention is that capitalized attributes are used in building frame and lowercase attributes are for simulator inernal usage.

Default scenario, which is executed for every incoming from rpd connection, is ReadNotifyScenario. It checks if first received from RPD frame is notify and closes connection if not. Optionally, next is executed default scenario, if it is set.

Frame parametrization is made on base of coresponding proto files. For example, for RfPortScenario RfPort.proto can be used. It is important to use exactly the same name, e.g. `RfPortType` and not `rfporttype`. Nesting attributes is handled by dot. For example to set RfPortIndex for RfPort: RfPortSelector.RfPortIndex=2. There are also repeated attributes, which can be more than one. To set repeated attribute use [] with index. E.g. DsRfPort.DedicatedToneConfig[0].ToneIndex=1, for another repeated: DsRfPort.DedicatedToneConfig[1].ToneIndex=2. Don't use spaces before and after "=".

When setting attributes in console, type it after --attrs, separating using spaces. E.g.:
	python client.py --scenarios select rfchannelscenario --attrs RfChannelSelector.RfPortIndex=5 RfChannelSelector.RfChannelType=2

When setting attributes in file, type file path after --file:
Parameters in file should be separated by new lines:

File parameters example:
	prefix=RfChannelSelector
	RfPortIndex=5
	RfChannelType=2
	RfChannelIndex=1
	prefix=DsOfdmChannelConfig.DsOfdmSubcarrierType[0]
	StartSubcarrierId=1
	EndSubcarrierId=2

How to start simulator:
	First step is execute command:
		python -m interactive_simulator/sim

	Next rpd can connect with simulator.
	Now commands from client.py can be send.

Some examples (in first line using client.py, in second line using clish):

To execute scenario:
	console: python client.py --scenarios select sweepdsscenario
	clish: s-select sweepdsscenario

To execute scenario with parameters from console:
	console: python client.py --scenarios select rfchannelscenario --attrs prefix=RfChannelSelector RfPortIndex=5 RfChannelType=2 RfChannelIndex=1
	clish: s-select rfchannelscenario attrs "prefix=RfChannelSelector RfPortIndex=5 RfChannelType=2 RfChannelIndex=2"
or:
	python client.py --scenarios select rfchannelscenario --attrs RfChannelSelector.RfPortIndex=5 RfChannelSelector.RfChannelType=2 RfChannelSelector.RfChannelIndex=1
	clish: s-select rfchannelscenario attrs "RfChannelSelector.RfPortIndex=5 RfChannelSelector.RfChannelType=2 RfChannelSelector.RfChannelIndex=2"

To execute scenario with parameters loaded from file:
	console: python client.py --scenarios select rfchannelscenario --file /tmp/test.txt
	clish: s-select rfchannelscenario file /tmp/test.txt

To execute scenario with parameters loaded from file and console (console attributes overwrites file attributes in case of conflict):
	console: python client.py --scenarios select rfchannelscenario --attrs prefix=RfChannelSelector RfPortIndex=5 --file /tmp/test.txt
	clish: in current moment not supported

Using prefixes:

	console: python client.py --scenarios select rfchannelscenario --attrs prefix=RfChannelSelector RfPortIndex=5 RfChannelType=2 RfChannelIndex=1 prefix=DsOfdmChannelConfig.DsOfdmSubcarrierType[0] StartSubcarrierId=1 EndSubcarrierId=2
	clish: s-select rfchannelscenario attrs "prefix=RfChannelSelector RfPortIndex=5 RfChannelType=2 RfChannelIndex=1 prefix=DsOfdmChannelConfig.DsOfdmSubcarrierType[0] StartSubcarrierId=1 EndSubcarrierId=2"


To set default scenario use the same command as for select, but instead of `select` type `set_default`:
	console: python client.py --scenarios set_default rfchannelscenario --file /tmp/test.txt
	clish: s-default-set rfchannelscenario file /tmp/test.txt

To remove default:
	console: python client.py --scenarios remove_default
	clish: s-default-rm

Parametrizing works the same as for selecting scenario.

Current execution status can be checked (e.g. for long executing scenarios- how many steps left):
	console: python client.py --scenarios status
	clish: s-status

Scenario execution can be interrupted:
	console: python client.py --scenarios break
	clish: s-break

To list all available scenarios:
	console: python client.py --scenarios help
	clish: s-help 

To get particular scenario description:
	console: python client.py --scenarios help `scenario name`
	clish: s-help `scenario name`
