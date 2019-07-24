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
import binascii

from rpd.common import utils
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_lib import gcp_packet
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.rcp_lib.rcp import Message, RCPSequence, RCPMessage,\
    RCP_SEQUENCE_MIN_LEN


class TestRCPSpecifics(unittest.TestCase):

    def test_rcp_message(self):
        msg = Message(gcp_msg_def.DataStructREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.Mode.set_val(0)
        msg.msg_fields.Port.set_val(11)
        msg.msg_fields.Channel.set_val(111)
        msg.msg_fields.VendorID.set_val(1111)
        msg.msg_fields.VendorIndex.set_val(254)

        # rcp_msg
        rcp_msg = RCPMessage(msg.message_id, rcp_tlv_def.RCP_MSG_TYPE_REX)
        msg.tlv_data.rcp_msgs.append(rcp_msg)

    def test_tlv_data(self):
        print "Test test_tlv_data...."
        seq = RCPSequence(gcp_msg_def.NotifyREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          1234,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print "Test test_tlv_data...."
        seq.RpdCapabilities.NumBdirPorts.set_val(4)
        alloc_ds =\
            seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        alloc_ds.DsPortIndex.set_val(1)
        alloc_ds.AllocatedDsOfdmChannels.set_val(11)
        alloc_ds.AllocatedDsScQamChannels.set_val(111)

        alloc_ds = \
            seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        alloc_ds.DsPortIndex.set_val(2)
        alloc_ds.AllocatedDsOfdmChannels.set_val(22)
        alloc_ds.AllocatedDsScQamChannels.set_val(222)

        alloc_ds = \
            seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        alloc_ds.DsPortIndex.set_val(3)
        alloc_ds.AllocatedDsOfdmChannels.set_val(33)
        alloc_ds.AllocatedDsScQamChannels.set_val(333)

        buf = seq.encode()
        self.assertIsNotNone(buf)

        seq_dec = RCPSequence(gcp_msg_def.NotifyREQ,
                              rcp_tlv_def.RCP_MSG_TYPE_NTF,
                              11,
                              rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        self.assertEqual(seq_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         seq_dec.DECODE_DONE)
        # self.assertTrue(seq._ut_compare(seq_dec))

    @unittest.skip('skip test for unsupport feature')
    def test_tlv_data_repeated_negative(self):
        seq = RCPSequence(gcp_msg_def.NotifyREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          1,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)

        seq.RpdCapabilities.NumBdirPorts.set_val(4)
        seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        buf = seq.encode()
        self.assertIsNotNone(buf)

        seq_dec = RCPSequence(gcp_msg_def.NotifyREQ,
                              rcp_tlv_def.RCP_MSG_TYPE_NTF,
                              2,
                              rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        self.assertEqual(seq_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         seq_dec.DECODE_DONE)
        self.assertFalse(seq._ut_compare(seq_dec))

    @unittest.skip('skip test for unsupport feature')
    def test_value_constraint(self):
        # Same like previous test, but we set TLV with limited range of values

        seq = RCPSequence(gcp_msg_def.NotifyREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          1,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)

        # Bool constraint
        with self.assertRaises(ValueError):
            seq.RpdCapabilities.SupportsUdpEncap.set_val(2)

        sub_tlv = \
            seq.RpdCapabilities.LcceChannelReachability.add_new_repeated()

        # Range constraint less than <1,10>
        with self.assertRaises(ValueError):
            sub_tlv.ChannelType.set_val(0)

        # Range constraint greater than <1,10>
        with self.assertRaises(ValueError):
            sub_tlv.ChannelType.set_val(15)

        buf = seq.encode()
        self.assertEqual(len(buf), RCP_SEQUENCE_MIN_LEN)
        self.assertIsNotNone(buf)

        seq.offset = 0
        seq.buf_data_len = 0
        seq.buffer = None

        # Range constraint <1,10> - valid value
        sub_tlv.ChannelType.set_val(10)

        buf = seq.encode()
        dec_seq = RCPSequence(gcp_msg_def.NotifyREQ,
                              rcp_tlv_def.RCP_MSG_TYPE_NTF,
                              2,
                              rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        self.assertEqual(dec_seq.decode(buf, offset=0, buf_data_len=len(buf)),
                         dec_seq.DECODE_DONE)
        self.assertTrue(dec_seq._ut_compare(seq))

    def test_msg_with_tlv(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(gcp_msg_def.NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)
        seq = RCPSequence(gcp_msg_def.NotifyREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        rcp_msg = RCPMessage(gcp_msg_def.NotifyREQ,
                             rcp_tlv_def.RCP_MSG_TYPE_NTF)
        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        seq.RpdCapabilities.NumBdirPorts.set_val(1)
        buf = msg.encode()
        self.assertIsNotNone(buf)

        msg_dec = Message(gcp_msg_def.NotifyREQ)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)
        # self.assertTrue(msg._ut_compare(msg_dec))

    def test_msg_with_unexpected_tlvs(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(gcp_msg_def.NotifyREQ)
        seq = RCPSequence(gcp_msg_def.NotifyREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          123,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        rcp_msg = RCPMessage(gcp_msg_def.NotifyREQ,
                             rcp_tlv_def.RCP_MSG_TYPE_NTF)
        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        # Try to fill TLV, which is not expected
        with self.assertRaises(AttributeError):
            seq.CcapCoreIdentification.Index.set_val(6)

    def test_msg_with_tlvs_of_all_classes_only_subTLV(self):
        seq = RCPSequence(gcp_msg_def.NotifyError,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)
        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('ABC')
        msg = Message(gcp_msg_def.NotifyError)

        rcp_msg = RCPMessage(gcp_msg_def.NotifyError,
                             rcp_tlv_def.RCP_MSG_TYPE_NTF)
        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.ReturnCode.set_val(
            gcp_msg_def.GCP_RC_MESSAGE_FAILURE.rc)

        buf = msg.encode()
        self.assertIsNotNone(buf)
        buf_str = binascii.hexlify(buf)

        # C_RpdCapabilities_2 C2_RpdIdentification_19
        vendor_name_pattern = "010003414243"
        self.assertNotEqual(buf_str.find(vendor_name_pattern), -1)

    def test_msg_with_tlvs_of_all_classes(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(gcp_msg_def.DataStructError)
        msg.msg_fields.TransactionID.set_val(5)

        msg.msg_fields.ExceptionCode.set_val(gcp_msg_def.
                                             GCP_RC_MESSAGE_FAILURE.rc)

        seq = RCPSequence(gcp_msg_def.DataStructError,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)

        rcp_msg = RCPMessage(gcp_msg_def.DataStructError,
                             rcp_tlv_def.RCP_MSG_TYPE_REX)
        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('ABC')
        seq.RpdCapabilities.NumBdirPorts.set_val(1)
        # TODO this can be uncommented when conflicting numbering is solved
        # seq.RpdCapabilities.NumAsyncVideoChannels.set_val(2)

        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('31')
        seq.RpdCapabilities.RpdIdentification.VendorId.set_val(9)
        seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
            (0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56))
        seq.RpdCapabilities.RpdIdentification.SerialNumber.set_val('33')

        sub_tlv =\
            seq.RpdCapabilities.LcceChannelReachability.add_new_repeated()
        sub_tlv.EnetPortIndex.set_val(4)
        sub_tlv.EndChannelIndex.set_val(5)

        seq.RpdCapabilities.PilotToneCapabilities.NumCwToneGens.set_val(6)
        seq.RpdCapabilities.PilotToneCapabilities.QamAsPilot.set_val(1)

        sub_tlv = seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        sub_tlv.DsPortIndex.set_val(8)
        sub_tlv.AllocatedNdfChannels.set_val(9)

        sub_tlv = seq.RpdCapabilities.AllocUsChanResources.add_new_repeated()
        sub_tlv.UsPortIndex.set_val(10)
        sub_tlv.AllocatedNdrChannels.set_val(11)

        sub_tlv = seq.CcapCoreIdentification.add_new_repeated()
        sub_tlv.Index.set_val(12)
        sub_tlv.CoreIpAddress.set_val((0x01, 0x02, 0x03, 0x04))
        sub_tlv.VendorId.set_val(13)

        sub_tlv = seq.RfPort.add_new_repeated()
        sub_tlv.RfPortSelector.RfPortIndex.set_val(0)
        # sub_tlv.DsRfPort.PortIndex.set_val(14)
        sub_tlv.DsRfPort.TiltMaximumFrequency.set_val(15)

        sub_tlv = seq.RfChannel.add_new_repeated()
        sub_tlv.RfChannelSelector.RfChannelIndex.set_val(0)
        sub_tlv.DsScQamChannelConfig.AdminState.set_val(1)
        sub_tlv.DsScQamChannelConfig.PowerAdjust.set_val(17)
        sub_tlv.DsOfdmChannelConfig.AdminState.set_val(2)
        sub_tlv.DsOfdmChannelConfig.SubcarrierSpacing.set_val(1)

        sub_tlv2 = sub_tlv.DsOfdmChannelConfig.DsOfdmSubcarrierType.add_new_repeated()
        sub_tlv2.StartSubcarrierId.set_val(21)
        sub_tlv2.EndSubcarrierId.set_val(22)
        sub_tlv2.SubcarrierUsage.set_val(1)

        sub_tlv2 = sub_tlv.DsOfdmProfile
        sub_tlv2.ProfileId.set_val(15)
        # sub_tlv3 = sub_tlv2.DsOfdmSubcarrierModulation.add_new_repeated()
        # sub_tlv3.StartSubcarrierId.set_val(21)
        # sub_tlv3.EndSubcarrierId.set_val(22)
        # sub_tlv3.Modulation.set_val(1)

        sub_tlv.UsScQamChannelConfig.AdminState.set_val(3)
        sub_tlv.UsScQamChannelConfig.TargetRxPower.set_val(24)
        sub_tlv2 = sub_tlv.UsScQamChannelConfig.IntervalUsageCode.\
            add_new_repeated()
        sub_tlv2.Code.set_val(14)
        sub_tlv2.GuardTime.set_val(26)

        sub_tlv.UsOfdmaChannelConfig.AdminState.set_val(4)
        sub_tlv.UsOfdmaChannelConfig.TargetRxPower.set_val(28)
        sub_tlv.UsOfdmaInitialRangingIuc.NumSubcarriers.set_val(10)
        sub_tlv.UsOfdmaInitialRangingIuc.Guardband.set_val(10)
        sub_tlv.UsOfdmaFineRangingIuc.NumSubcarriers.set_val(14)
        sub_tlv.UsOfdmaFineRangingIuc.Guardband.set_val(10)

        sub_tlv2 = sub_tlv.UsOfdmaDataIuc.add_new_repeated()
        sub_tlv2.DataIuc.set_val(5)
        sub_tlv2.DataSymbolModulation.set_val(1)

        sub_tlv2 = sub_tlv.UsOfdmaSubcarrierCfgState.add_new_repeated()
        sub_tlv2.StartingSubcarrierId.set_val(0)
        sub_tlv2.SubarrierUsage.set_val(4)

        sub_tlv2 = sub_tlv.SidQos.add_new_repeated()
        sub_tlv2.StartSid.set_val(100)
        sub_tlv2.NumSids.set_val(10)
        sub_tlv2.SidSfType.set_val(2)

        sub_tlv2 = sub_tlv.SidQos.add_new_repeated()
        sub_tlv2.StartSid.set_val(15800)
        sub_tlv2.NumSids.set_val(5)
        sub_tlv2.SidSfType.set_val(3)

        buf = msg.encode()
        self.assertNotEqual(buf, None)

        msg_dec = Message(gcp_msg_def.DataStructError)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)
        # self.assertTrue(msg._ut_compare(msg_dec))

    def test_msg_with_tlvs_of_all_classes_find_TVL(self):
        seq = RCPSequence(gcp_msg_def.NotifyError,
                          rcp_tlv_def.RCP_MSG_TYPE_NTF,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('ABC')
        msg = Message(gcp_msg_def.NotifyError)
        rcp_msg = RCPMessage(gcp_msg_def.NotifyError,
                             rcp_tlv_def.RCP_MSG_TYPE_NTF)
        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        msg.msg_fields.TransactionID.set_val(10)
        msg.msg_fields.ReturnCode.set_val(
            gcp_msg_def.GCP_RC_MESSAGE_FAILURE.rc)

        seq.RpdCapabilities.NumBdirPorts.set_val(11)
        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('ABC')
        seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
            (0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56))

        sub_tlv = seq.CcapCoreIdentification.add_new_repeated()
        sub_tlv.Index.set_val(0x34)
        sub_tlv.CoreIpAddress.set_val((0xA1, 0xA2, 0xA3, 0xA4,
                                       0xB1, 0xB2, 0xB3, 0xB4,
                                       0xC1, 0xC2, 0xC3, 0xC4,
                                       0xD1, 0xD2, 0xD3, 0xD4))

        buf3 = msg.encode()
        self.assertIsNotNone(buf3)
        buf3_str = binascii.hexlify(buf3)

        num_bidir_ports_pattern = "010002000b"
        vendor_name_pattern = "010003414243"
        device_mac_address_pattern = "040006abcdef123456"
        index_pattern = "01000134"
        core_ip_address_pattern = "030010a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4"

        self.assertNotEqual(buf3_str.find(num_bidir_ports_pattern), -1)
        self.assertNotEqual(buf3_str.find(vendor_name_pattern), -1)
        self.assertNotEqual(buf3_str.find(device_mac_address_pattern), -1)
        self.assertNotEqual(buf3_str.find(index_pattern), -1)
        self.assertNotEqual(buf3_str.find(core_ip_address_pattern), -1)

    @staticmethod
    def create_testing_ds_cfg_sequence(gcp_message_id, rcp_message_id):
        seq = RCPSequence(gcp_message_id, rcp_message_id,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)

        seq.RpdCapabilities.NumBdirPorts.set_val(1)
        # TODO this can be uncommented when conflicting numbering is solved
        # seq.RpdCapabilities.NumAsyncVideoChannels.set_val(2)
        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('31')
        seq.RpdCapabilities.RpdIdentification.VendorId.set_val(32)
        seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
            (0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56))
        seq.RpdCapabilities.RpdIdentification.SerialNumber.set_val('33')

        sub_tlv =\
            seq.RpdCapabilities.LcceChannelReachability.add_new_repeated()
        sub_tlv.EnetPortIndex.set_val(4)
        sub_tlv.ChannelType.set_val(
            rcp_tlv_def.CHANNEL_TYPE_1_DsScQa_downstream_QAM[0])
        sub_tlv.EndChannelIndex.set_val(5)
        sub_tlv.RfPortIndex.set_val(6)

        seq.RpdCapabilities.PilotToneCapabilities.NumCwToneGens.set_val(6)
        seq.RpdCapabilities.PilotToneCapabilities.QamAsPilot.set_val(1)

        sub_tlv = seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        sub_tlv.DsPortIndex.set_val(8)
        sub_tlv.AllocatedNdfChannels.set_val(9)

        sub_tlv = seq.RpdCapabilities.AllocUsChanResources.add_new_repeated()
        sub_tlv.UsPortIndex.set_val(10)
        sub_tlv.AllocatedNdrChannels.set_val(11)

        sub_tlv = seq.RfPort.add_new_repeated()
        sub_tlv.RfPortSelector.RfPortIndex.set_val(0)
        sub_tlv.DsRfPort.AdminState.set_val(1)
        sub_tlv.DsRfPort.BasePower.set_val(30)
        sub_tlv.DsRfPort.RfMute.set_val(0)
        sub_tlv.DsRfPort.TiltSlope.set_val(8)
        sub_tlv.DsRfPort.TiltMaximumFrequency.set_val(15)

        sub_tlv = seq.RfChannel.add_new_repeated()
        sub_tlv.RfChannelSelector.RfChannelIndex.set_val(0)
        sub_tlv.DsScQamChannelConfig.AdminState.set_val(1)
        sub_tlv.DsScQamChannelConfig.RfMute.set_val(1)
        sub_tlv.DsScQamChannelConfig.TSID.set_val(2)
        sub_tlv.DsScQamChannelConfig.CenterFrequency.set_val(98000000)
        sub_tlv.DsScQamChannelConfig.OperationalMode.set_val(2)
        sub_tlv.DsScQamChannelConfig.Modulation.set_val(4)
        sub_tlv.DsScQamChannelConfig.InterleaverDepth.set_val(1)
        sub_tlv.DsScQamChannelConfig.Annex.set_val(4)
        sub_tlv.DsScQamChannelConfig.SyncInterval.set_val(10)
        sub_tlv.DsScQamChannelConfig.SymbolFrequencyDenominator.set_val(4)
        sub_tlv.DsScQamChannelConfig.SymbolFrequencyNumerator.set_val(250)
        sub_tlv.DsScQamChannelConfig.SymbolRateOverride.set_val(260)
        sub_tlv.DsScQamChannelConfig.SpectrumInversionEnabled.set_val(0)
        sub_tlv.DsScQamChannelConfig.PowerAdjust.set_val(17)

        return seq

    @staticmethod
    def create_testing_cfg_sequence(gcp_message_id, rcp_message_id):
        seq = RCPSequence(gcp_message_id, rcp_message_id,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)

        seq.RpdCapabilities.NumBdirPorts.set_val(1)
        # TODO this can be uncommented when conflicting numbering is solved
        # seq.RpdCapabilities.NumAsyncVideoChannels.set_val(2)
        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('31')
        seq.RpdCapabilities.RpdIdentification.VendorId.set_val(32)
        seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
            (0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56))
        seq.RpdCapabilities.RpdIdentification.SerialNumber.set_val('33')

        sub_tlv =\
            seq.RpdCapabilities.LcceChannelReachability.add_new_repeated()
        sub_tlv.EnetPortIndex.set_val(4)
        sub_tlv.ChannelType.set_val(
            rcp_tlv_def.CHANNEL_TYPE_1_DsScQa_downstream_QAM[0])
        sub_tlv.EndChannelIndex.set_val(5)
        sub_tlv.RfPortIndex.set_val(6)

        seq.RpdCapabilities.PilotToneCapabilities.NumCwToneGens.set_val(6)
        seq.RpdCapabilities.PilotToneCapabilities.QamAsPilot.set_val(1)

        sub_tlv = seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        sub_tlv.DsPortIndex.set_val(8)
        sub_tlv.AllocatedNdfChannels.set_val(9)

        sub_tlv = seq.RpdCapabilities.AllocUsChanResources.add_new_repeated()
        sub_tlv.UsPortIndex.set_val(10)
        sub_tlv.AllocatedNdrChannels.set_val(11)

        sub_tlv = seq.RfPort.add_new_repeated()
        sub_tlv.RfPortSelector.RfPortIndex.set_val(0)
        # sub_tlv.DsRfPort.PortIndex.set_val(14)
        sub_tlv.DsRfPort.TiltMaximumFrequency.set_val(15)

        sub_tlv = seq.RfChannel.add_new_repeated()
        sub_tlv.RfChannelSelector.RfChannelIndex.set_val(0)

        # dMsg = binascii.a2b_hex("c200016af52b01e02f00000100219f7b66380158000003010200010d0401010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000042501010101020102030200260402018c050100060110070201520801000901160a01010b01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101")
        # sub_tlv.DocsisMsg.set_val(dMsg)

        sub_tlv.DsScQamChannelConfig.AdminState.set_val(1)
        sub_tlv.DsScQamChannelConfig.PowerAdjust.set_val(17)
        sub_tlv.DsOfdmChannelConfig.AdminState.set_val(2)
        sub_tlv.DsOfdmChannelConfig.SubcarrierSpacing.set_val(1)

        sub_tlv2 = sub_tlv.DsOfdmChannelConfig.DsOfdmSubcarrierType.add_new_repeated()
        sub_tlv2.StartSubcarrierId.set_val(21)
        sub_tlv2.EndSubcarrierId.set_val(22)
        sub_tlv2.SubcarrierUsage.set_val(1)

        sub_tlv2 = sub_tlv.DsOfdmProfile
        sub_tlv2.ProfileId.set_val(15)
        # sub_tlv3 = sub_tlv2.DsOfdmSubcarrierModulation.add_new_repeated()
        # sub_tlv3.StartSubcarrierId.set_val(21)
        # sub_tlv3.EndSubcarrierId.set_val(22)
        # sub_tlv3.Modulation.set_val(1)

        sub_tlv.UsScQamChannelConfig.AdminState.set_val(3)
        sub_tlv.UsScQamChannelConfig.TargetRxPower.set_val(24)
        sub_tlv2 = sub_tlv.UsScQamChannelConfig.IntervalUsageCode.add_new_repeated(
        )
        sub_tlv2.Code.set_val(14)
        sub_tlv2.GuardTime.set_val(26)

        sub_tlv.UsOfdmaChannelConfig.AdminState.set_val(4)
        sub_tlv.UsOfdmaChannelConfig.TargetRxPower.set_val(28)
        sub_tlv.UsOfdmaInitialRangingIuc.NumSubcarriers.set_val(10)
        sub_tlv.UsOfdmaInitialRangingIuc.Guardband.set_val(10)
        sub_tlv.UsOfdmaFineRangingIuc.NumSubcarriers.set_val(14)
        sub_tlv.UsOfdmaFineRangingIuc.Guardband.set_val(10)

        sub_tlv2 = sub_tlv.UsOfdmaDataIuc.add_new_repeated()
        sub_tlv2.DataIuc.set_val(5)
        sub_tlv2.DataSymbolModulation.set_val(1)

        sub_tlv2 = sub_tlv.UsOfdmaSubcarrierCfgState.add_new_repeated()
        sub_tlv2.StartingSubcarrierId.set_val(0)
        sub_tlv2.SubarrierUsage.set_val(4)
        return seq

    @staticmethod
    def create_testing_sequence_from_gpb(gcp_message_id, rcp_message_id,
                                         gpb_message):
        return RCPSequence(gcp_message_id, rcp_message_id, 0,
                           rcp_tlv_def.RCP_OPERATION_TYPE_WRITE, gpb_message)

    def test_rcp_message_in_gcp_msg(self):
        msg = Message(gcp_msg_def.DataStructREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.Mode.set_val(0)
        msg.msg_fields.Port.set_val(11)
        msg.msg_fields.Channel.set_val(111)
        msg.msg_fields.VendorID.set_val(1111)
        msg.msg_fields.VendorIndex.set_val(254)

        rcp_msg = RCPMessage(msg.message_id, rcp_tlv_def.RCP_MSG_TYPE_REX)
        msg.tlv_data.rcp_msgs.append(rcp_msg)

        seq = self.create_testing_cfg_sequence(msg.message_id,
                                               rcp_msg.rcp_message_id)

        rcp_msg.sequences.append(seq)
        buf_enc = msg.encode()

        msg_dec = Message()
        msg_dec.decode(buf_enc, 0, len(buf_enc))
        # self.assertTrue(msg._ut_compare(msg_dec))

    def test_default_gpb(self):
        cap = t_RpdCapabilities()
        value = getattr(cap, "NumBdirPorts")
        GCPObject.default_gpb(cap)
        self.assertEqual(cap.NumBdirPorts, value)

    def test_msg_with_tlvs_of_multi_core(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(gcp_msg_def.DataStructError)
        msg.msg_fields.TransactionID.set_val(5)

        msg.msg_fields.ExceptionCode.set_val(gcp_msg_def.
                                             GCP_RC_MESSAGE_FAILURE.rc)

        seq = RCPSequence(gcp_msg_def.DataStructError,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)

        rcp_msg = RCPMessage(gcp_msg_def.DataStructError,
                             rcp_tlv_def.RCP_MSG_TYPE_REX)
        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        resSet = seq.MultiCore.ResourceSet.add_new_repeated()
        resSet.ResourceSetIndex.set_val(1)
        resSet.CcapCoreOwner.set_val(\
            utils.Convert.mac_to_tuple_of_bytes("00:00:00:00:00:00"))
        resSet.DsRfPortStart.set_val(0)
        resSet.DsRfPortEnd.set_val(0)
        dsChanGroup = resSet.DsChanGroup.add_new_repeated()
        dsChanGroup.DsChanGroupIndex.set_val(1)
        dsChanGroup.DsChanType.set_val(3)
        dsChanGroup.DsChanIndexStart.set_val(0)
        dsChanGroup.DsChanIndexEnd.set_val(10)
        dsChanGroup = resSet.DsChanGroup.add_new_repeated()
        dsChanGroup.DsChanGroupIndex.set_val(2)
        dsChanGroup.DsChanType.set_val(4)
        dsChanGroup.DsChanIndexStart.set_val(11)
        dsChanGroup.DsChanIndexEnd.set_val(12)
        resSet.UsRfPortStart.set_val(0)
        resSet.UsRfPortEnd.set_val(1)
        usChanGroup = resSet.UsChanGroup.add_new_repeated()
        usChanGroup.UsChanGroupIndex.set_val(0)
        usChanGroup.UsChanType.set_val(5)
        usChanGroup.UsChanIndexStart.set_val(0)
        usChanGroup.UsChanIndexEnd.set_val(2)
        usChanGroup = resSet.UsChanGroup.add_new_repeated()
        usChanGroup.UsChanGroupIndex.set_val(1)
        usChanGroup.UsChanType.set_val(6)
        usChanGroup.UsChanIndexStart.set_val(3)
        usChanGroup.UsChanIndexEnd.set_val(4)

        buf = msg.encode()
        self.assertNotEqual(buf, None)

        msg_dec = Message(gcp_msg_def.DataStructError)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)

if __name__ == '__main__':
    unittest.main()
