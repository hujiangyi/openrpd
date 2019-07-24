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
import time
from rpd.rcp.rcp_packet_director import RCPSlavePacketBuildDirector, RCPPacketBuildError
from rpd.rcp.rcp_sessions import RCPSlaveSession
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib.rcp import RCPPacket, RCPSequence
from rpd.rcp.rcp_hal import RcpHalIpc, DataObj
from rpd.gpb.VendorSpecificExtension_pb2 import t_VendorSpecificExtension
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
from rpd.common.rpd_logging import setup_logging



def create_test_sequence(operation=rcp_tlv_def.RCP_OPERATION_TYPE_WRITE, seq_num=0):

    seq = RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX,
                      seq_num, operation, unittest=True)

    seq.RpdCapabilities.NumBdirPorts.set_val(1)
    # TODO this can be uncommented when conflicting numbering is solved
    # seq.RpdCapabilities.NumAsyncVideoChannels.set_val(2)
    seq.RpdCapabilities.RpdIdentification.VendorName.set_val('31')
    seq.RpdCapabilities.RpdIdentification.VendorId.set_val(9)
    seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
        (0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56))
    seq.RpdCapabilities.RpdIdentification.SerialNumber.set_val('33')

    sub_tlv = \
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

    seq.RdtiConfig.RpdRdtiMode.set_val(2)
    seq.RdtiConfig.RpdPtpDefDsDomainNumber.set_val(44)
    seq.RdtiConfig.RpdPtpProfileVersion.set_val('10-11-12')
    sub_tlv = seq.RdtiConfig.RpdPtpPortConfig.add_new_repeated()
    sub_tlv.RpdEnetPortIndex.set_val(0)
    sub_tlv.RpdPtpPortIndex.set_val(0)
    sub_tlv.RpdPtpPortAdminState.set_val(4)
    sub_tlv.RpdPtpPortClockSource.set_val((10, 74, 21, 216))
    sub_tlv.RpdPtpPortDsLogSyncInterval.set_val(-7)
    sub_tlv.RpdPtpPortDsLogAnnounceInterval.set_val(-3)
    sub_tlv.RpdPtpPortDsAnnounceReceiptTimeout.set_val(60)

    return seq

def create_test_pkt(pkt_director, slave,
                    gcp_id=gcp_msg_def.NotifyREQ,
                    rcp_id=rcp_tlv_def.RCP_MSG_TYPE_NTF,
                    rcp_operation=rcp_tlv_def.RCP_OPERATION_TYPE_WRITE):

    if None is pkt_director:
        return None

    pkt_director.builder.clear()
    transaction_id = slave.get_next_trans_id()
    rcp_sequence_id = slave.get_next_seq_id()

    pkt_director.builder.add_packet(transaction_id=transaction_id)
    pkt_director.builder.add_gcp_msg(gcp_id, transaction_id)
    pkt_director.builder.add_rcp_msg(rcp_id)
    pkt_director.builder.add_rcp_seq(rcp_sequence_id,
                                     rcp_operation,
                                     gpb_config=None)

    # Fill some hardcoded data now
    seq = pkt_director.builder.last_rcp_sequence
    pkt_director._set_rpd_identification(seq, slave.get_descriptor().interface_local)
    pkt_director._set_rpd_identification(seq, slave.get_descriptor().interface_local, seq.parent_gpb.RpdCapabilities)
    pkts = pkt_director.builder.get_packets()
    if len(pkts) != 1:
        return None
    return pkts[0]

def fake_cb():
    print "fake cb handled"

class RcpPktDirectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_logging('GCP', filename="provision_rcp.log")
        cls.dispatcher = Dispatcher()
        cls.desc = GCPSlaveDescriptor(addr_master='localhost')
        cls.session = RCPSlaveSession(cls.desc, cls.dispatcher,
                                        fake_cb, fake_cb, fake_cb)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def setUp(self):
        self.pktDirector = RCPSlavePacketBuildDirector()

    def tearDown(self):
        pass

    def test_handle_fm_nty(self):
        event_dict = dict()
        current_t = time.time()
        event_dict["FirstTime"] = current_t
        event_dict['LastTime'] = current_t
        event_dict["Counts"] = 1
        event_dict["text"] = "test_handle_fm_nty"
        event_dict["PENDING_LOCAL"] = rcp_tlv_def.RPD_EVENT_NOTIFICATION_PENDING_LOG[0]
        event_dict["Level"] = 6
        pkt = self.pktDirector.get_fault_management_notify_packet(self.session,
                                                                  66070211,
                                                                  "test_handle_fm_nty",
                                                                  event_dict)
        self.assertIsInstance(pkt, RCPPacket)
        faultflag = False
        try:
            self.pktDirector.get_fault_management_notify_packet(None,
                                                                66070211,
                                                                "test_handle_fm_nty",
                                                                event_dict)
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)

    def test_handle_ipv6_nty_exception(self):
        faultflag = False
        try:
            pkt = self.pktDirector.get_ipv6_notify_packet('', "ipv6")
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)
        faultflag = False
        try:
            pkt = self.pktDirector.get_ipv6_notify_packet(None, "ipv6")
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)


    def test_handle_ipv6_nty(self):
        ipv6_msg = t_VendorSpecificExtension()
        sub_tlv_ipv6_addr = ipv6_msg.Ipv6Address.add()
        sub_tlv_ipv6_addr.EnetPortIndex = 0
        sub_tlv_ipv6_addr.IpAddress = "2001:93:3:1::0"
        sub_tlv_ipv6_addr.AddrType = 1
        sub_tlv_ipv6_addr.PrefixLen = 128 
        payload = ipv6_msg.SerializeToString()
        pkt = self.pktDirector.get_ipv6_notify_packet(self.session, payload)
        self.assertIsInstance(pkt, RCPPacket)

    def test_handle_ptp_nty(self):
        pkt = self.pktDirector.get_ptp_notify_packet(self.session, "ALIGNED")
        self.assertIsInstance(pkt, RCPPacket)
        faultflag = False
        try:
            self.pktDirector.get_ptp_notify_packet(None, "ALIGNED")
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)

    def test_get_nty_req(self):
        pkt = self.pktDirector.get_notify_request_packet(self.session)
        self.assertIsInstance(pkt, RCPPacket)
        faultflag = False
        try:
            self.pktDirector.get_notify_request_packet(None)
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)

    def test_get_rsp(self):
        req_pkt = self.pktDirector.get_notify_request_packet(self.session)
        self.pktDirector.get_positive_rsp_packets(self.session, req_pkt)
        faultflag = False
        try:
            self.pktDirector.get_positive_rsp_packets(None, req_pkt)
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)

        self.pktDirector.get_gcp_err_rsp_packet(self.session, req_pkt)

        faultflag = False
        try:
            self.pktDirector.get_resulting_rsp_packets(None, req_pkt, [])
        except AttributeError:
            faultflag = True
        self.assertTrue(faultflag)

        for operation in [rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          rcp_tlv_def.RCP_OPERATION_TYPE_DELETE,
                          rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE]:
            req_pkt = create_test_pkt(self.pktDirector, self.session,
                                      rcp_operation=operation)
            self.pktDirector.get_resulting_rsp_packets(self.session, req_pkt, [])

        faultflag = False
        try:
            req_pkt = create_test_pkt(self.pktDirector, self.session,
                                      rcp_operation=rcp_tlv_def.RCP_OPERATION_TYPE_NONE)
            self.pktDirector.get_resulting_rsp_packets(self.session, req_pkt, [])
        except RCPPacketBuildError:
            faultflag = True
        self.assertTrue(faultflag)

        for gcp_id in [gcp_msg_def.NotifyREQ,
                       gcp_msg_def.ManagementREQ,
                       gcp_msg_def.DataStructREQ]:
            req_pkt = create_test_pkt(self.pktDirector, self.session, gcp_id=gcp_id)
            self.pktDirector.get_resulting_rsp_packets(self.session, req_pkt, [])

        faultflag = False
        try:
            req_pkt = create_test_pkt(self.pktDirector, self.session,
                                      gcp_id=gcp_msg_def.NotifyRSP)
            self.pktDirector.get_resulting_rsp_packets(self.session, req_pkt, [])
        except RCPPacketBuildError:
            faultflag = True
        self.assertTrue(faultflag)

        req_pkt = create_test_pkt(self.pktDirector, self.session,
                                  gcp_id=gcp_msg_def.NotifyREQ)
        seq_num = self.session._sequence_id
        seq = create_test_sequence(seq_num=seq_num)
        data = DataObj(seq, RcpHalIpc.RPD_DATA_OPER_RD, seq.seq_number)
        self.pktDirector.get_resulting_rsp_packets(self.session, req_pkt, [data, ])

        aw_req_pkt = create_test_pkt(self.pktDirector, self.session,
                                     gcp_id=gcp_msg_def.DataStructREQ)
        seq_num = self.session._sequence_id
        seq = create_test_sequence(seq_num=seq_num)
        data = DataObj(seq, RcpHalIpc.RPD_DATA_OPER_AW, seq.seq_number)
        self.pktDirector.get_resulting_rsp_packets(self.session, aw_req_pkt, [data, ])


    def test_send_eds(self):
        seq = create_test_sequence()
        self.pktDirector.send_eds_response_directly(self.session, 1, 1, seq)
        seq = create_test_sequence(rcp_tlv_def.RCP_OPERATION_TYPE_READ)
        self.pktDirector.send_eds_response_directly(self.session, 1, 1, seq, result=False)
        seq = create_test_sequence(rcp_tlv_def.RCP_OPERATION_TYPE_DELETE)
        self.pktDirector.send_eds_response_directly(self.session, 1, 1, seq, result=False)
        seq = create_test_sequence(rcp_tlv_def.RCP_OPERATION_TYPE_NONE)
        self.pktDirector.send_eds_response_directly(self.session, 1, 1, seq)
        self.pktDirector.send_eds_response_directly(None, 1, 1, seq)


if __name__ == '__main__':
    unittest.main()
