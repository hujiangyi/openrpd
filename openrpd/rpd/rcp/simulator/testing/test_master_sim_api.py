#
# Copyright (c) 2016 Cisco and/or its affiliates, and
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

import unittest

import zmq

import rpd.gpb.cfg_pb2 as Config
from rpd.gpb import master_sim_pb2 as master_sim_def
from rpd.rcp.simulator.rcp_master_sim import MasterAPI


class TestMasterSimApi(unittest.TestCase):

    # def setUpClass(cls):
        # pass

    # def tearDownClass(cls):
        # pass

    def testMasterRedirect(self):
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.connect(MasterAPI.MasterZMQPath)

        # construct the message
        msg = master_sim_def.t_MasterSimApiMessage()
        slave_desc = master_sim_def.t_SlaveDescriptor()
        slave_desc.addr_master = "0.0.0.0"
        slave_desc.port_master = 8190
        slave_desc.interface_master = "eth0"
        slave_desc.addr_local = "127.0.0.1"
        slave_desc.port_local = 8190
        slave_desc.interface_local = "eth0"
        slave_desc.addr_family = 2

        msg.operation = msg.WRITE

        cfg = Config.config()

        redirect = cfg.RpdRedirect.add()
        redirect.RedirectIpAddress = "127.0.0.1"
        # binascii.a2b_hex("7F000001")

        msg.slave_descriptor.CopyFrom(slave_desc)
        msg.cfg.CopyFrom(cfg)

        print msg
        data = msg.SerializeToString()

        socket.send(data)
        socket.close()
        del context

    def testMasterApiConnectionSetup(self):
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.connect(MasterAPI.MasterZMQPath)

        # construct the message
        msg = master_sim_def.t_MasterSimApiMessage()
        slave_desc = master_sim_def.t_SlaveDescriptor()
        slave_desc.addr_master = "0.0.0.0"
        slave_desc.port_master = 8190
        slave_desc.interface_master = "lo"
        slave_desc.addr_local = "127.0.0.1"
        slave_desc.port_local = 8191
        slave_desc.interface_local = "lo"
        slave_desc.addr_family = 2

        msg.operation = msg.WRITE

        cfg = Config.config()

        cfg.RpdCapabilities.NumBdirPorts = 10

        cfg.RpdCapabilities.NumBdirPorts = 1
        cfg.RpdCapabilities.NumDsRfPorts = 2
        cfg.RpdCapabilities.NumUsRfPorts = 3
        cfg.RpdCapabilities.NumTenGeNsPorts = 4
        cfg.RpdCapabilities.NumOneGeNsPorts = 5
        cfg.RpdCapabilities.NumDsScQamChannels = 6
        cfg.RpdCapabilities.NumDsOfdmChannels = 7
        cfg.RpdCapabilities.NumUsScQamChannels = 8
        cfg.RpdCapabilities.NumUsOfdmaChannels = 9
        cfg.RpdCapabilities.NumDsOob55d1Channels = 10
        cfg.RpdCapabilities.NumUsOob55d1Channels = 11
        cfg.RpdCapabilities.NumDsOob55d2Channels = 12
        cfg.RpdCapabilities.NumUsOob55d2Channels = 13
        cfg.RpdCapabilities.NumNdfChannels = 14
        cfg.RpdCapabilities.NumNdrChannels = 15
        cfg.RpdCapabilities.SupportsUdpEncap = True
        cfg.RpdCapabilities.NumDsPspFlows = 17
        cfg.RpdCapabilities.NumUsPspFlows = 18
        cfg.RpdCapabilities.RpdIdentification.VendorName = "Cisco"
        cfg.RpdCapabilities.RpdIdentification.VendorId = "aa"
        cfg.RpdCapabilities.RpdIdentification.ModelNumber = "aa"
        cfg.RpdCapabilities.RpdIdentification.DeviceMacAddress = "11:22:33:44:55:66"
        cfg.RpdCapabilities.RpdIdentification.CurrentSwVersion = "V1.0.0"
        cfg.RpdCapabilities.RpdIdentification.BootRomVersion = "V0.1.0"
        cfg.RpdCapabilities.RpdIdentification.DeviceDescription = "Cisco NODE"
        cfg.RpdCapabilities.RpdIdentification.DeviceAlias = "Node"
        cfg.RpdCapabilities.RpdIdentification.SerialNumber = "123412"
        cfg.RpdCapabilities.RpdIdentification.UsBurstReceiverVendorId = "12"
        cfg.RpdCapabilities.RpdIdentification.UsBurstReceiverModelNumber = "cisco123"
        cfg.RpdCapabilities.RpdIdentification.UsBurstReceiverDriverVersion = "V123"
        cfg.RpdCapabilities.RpdIdentification.UsBurstReceiverSerialNumber = "cisco123"
        cfg.RpdCapabilities.RpdIdentification.RpdRcpProtocolVersion = "V1.0.0"
        cfg.RpdCapabilities.RpdIdentification.RpdRcpSchemaVersion = "V1.0.10"
        reachAbility = cfg.RpdCapabilities.LcceChannelReachability.add()
        reachAbility.EnetPortIndex = 1
        reachAbility.ChannelType = 2
        reachAbility.RfPortIndex = 3
        reachAbility.StartChannelIndex = 4
        reachAbility.EndChannelIndex = 5
        cfg.RpdCapabilities.PilotToneCapabilities.NumCwToneGens = 1
        cfg.RpdCapabilities.PilotToneCapabilities.LowestCwToneFreq = 2
        cfg.RpdCapabilities.PilotToneCapabilities.HighestCwToneFreq = 3
        cfg.RpdCapabilities.PilotToneCapabilities.MaxPowerDedCwTone = 4
        cfg.RpdCapabilities.PilotToneCapabilities.QamAsPilot = 5
        cfg.RpdCapabilities.PilotToneCapabilities.MinPowerDedCwTone = 5
        cfg.RpdCapabilities.PilotToneCapabilities.MaxPowerQamCwTone = 6
        cfg.RpdCapabilities.PilotToneCapabilities.MinPowerQamCwTone = 7

        allocDSResource = cfg.RpdCapabilities.AllocDsChanResources.add()
        allocDSResource.DsPortIndex = 1
        allocDSResource.AllocatedDsOfdmChannels = 2
        allocDSResource.AllocatedDsScQamChannels = 3
        allocDSResource.AllocatedDsOob55d1Channels = 4
        allocDSResource.AllocatedDsOob55d2Channels = 5
        allocDSResource.AllocatedNdfChannels = 6

        allocUSResource = cfg.RpdCapabilities.AllocUsChanResources.add()
        allocUSResource.UsPortIndex = 1
        allocUSResource.AllocatedUsOfdmaChannels = 2
        allocUSResource.AllocatedUsScQamChannels = 3
        allocUSResource.AllocatedUsOob55d1Channels = 4
        allocUSResource.AllocatedUsOob55d2Channels = 5
        allocUSResource.AllocatedNdrChannels = 6

        msg.slave_descriptor.CopyFrom(slave_desc)
        msg.cfg.CopyFrom(cfg)

        print msg
        data = msg.SerializeToString()

        socket.send(data)
        socket.close()
        del context


if __name__ == '__main__':
    unittest.main()
