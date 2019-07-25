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
from os import EX_DATAERR
from rpd.rcp.rcp_sessions import RCPSlaveSession
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib.rcp import RCPSequence
from rpd.rcp.rcp_process import RcpProcess, RcpHalProcess
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.proto import GcpMsgType
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor
from rpd.common.utils import Convert
from rpd.rcp.rcp_lib import rcp

from rpd.rcp.rcp_orchestrator import *
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, stop_test_redis
from rpd.rcp.rcp_hal import RcpHalClientError
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities


def notification_mgr_cb(seq, args=None):
    pass


def fake_cb(data):
    print "fake cb handled"


class RcpProcessTest(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("GCP", filename="rcp.log")

        cls.dispatcher = Dispatcher()
        cls.desc = GCPSlaveDescriptor(addr_master='localhost', interface_local='local')
        cls.session = RCPSlaveSession(cls.desc, cls.dispatcher,
                                      fake_cb, fake_cb, fake_cb)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def setUp(self):
        setup_test_redis()
        self.process = RcpHalProcess("ipc:///tmp/_test_rcp.tmp",
                                     notify_mgr_cb=notification_mgr_cb)

    def tearDown(self):
        self.process.cleanup()
        stop_test_redis()

    def test_init(self):
        process = RcpProcess("ipc:///tmp/_test_rcp_2.tmp")
        process.register_ipc_msg_rx_callback("string")
        process.cleanup()

        faultflag = False
        try:
            process = RcpProcess("http:///tmp/_test_rcp_2.tmp")
        except RuntimeError:
            faultflag = True
        self.assertTrue(faultflag)

        self.process.add_ccap_cores(["lo;127.0.0.1", "lo;127.0.0.1.1"])

    def test_cli(self):
        self.process.orchestrator.sessions_active_fd[self.desc.get_uniq_id()] = self.session
        self.process.orchestrator.sessions_failed[self.desc.get_uniq_id()] = self.session
        self.process.orchestrator.principal.append(self.session)
        self.process.orchestrator.non_principals.append(self.session)
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = GcpMsgType.ShowGcpSession
        rsp_msg = t_CliMessage()
        rsp_msg.CliMsgType = msg.CliMsgType
        rsp_msg.CliDataOperation = msg.CliDataOperation
        self.process.show_gcp_session(msg, rsp_msg)
        print rsp_msg

        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = GcpMsgType.ShowGcpSessionDetail
        rsp_msg = t_CliMessage()
        rsp_msg.CliMsgType = msg.CliMsgType
        rsp_msg.CliDataOperation = msg.CliDataOperation
        self.process.show_gcp_session_detail(msg, rsp_msg)
        print rsp_msg

        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_WRITE
        msg.CliMsgType = GcpMsgType.ChangeGcpLoggingLevel
        msg.CliGcp.GcpLogging.module = GcpMsgType.GcpGDM
        msg.CliGcp.GcpLogging.level = 'debug'
        rsp_msg = t_CliMessage()
        rsp_msg.CliMsgType = msg.CliMsgType
        rsp_msg.CliDataOperation = msg.CliDataOperation
        ret = self.process.change_gcp_logging_level(msg, rsp_msg)
        self.assertTrue(ret)
        print rsp_msg

        msg.CliGcp.GcpLogging.level = 'notsupported'
        ret = self.process.change_gcp_logging_level(msg, rsp_msg)
        self.assertFalse(ret)

        msg.CliGcp.GcpLogging.module = GcpMsgType.GcpAll
        msg.CliGcp.GcpLogging.level = 'debug'
        ret = self.process.change_gcp_logging_level(msg, rsp_msg)
        self.assertFalse(ret)

    def test_msg_dispatch(self):
        try:
            self.process.send_ipc_msg('error')
        except SystemExit as e:
            self.assertEqual(e.code, EX_DATAERR)

        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": None,
                                   "req_data": "error"})

        timeout_msg = t_RcpMessage()
        timeout_msg.RcpMessageType = timeout_msg.CONNECT_CLOSE_NOTIFICATION
        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": None,
                                   "req_data": timeout_msg})

        data_list = []
        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)
        seq.RpdCapabilities.NumBdirPorts.set_val(1)
        seq.RpdCapabilities.RpdIdentification.VendorName.set_val('31')
        seq.RpdCapabilities.RpdIdentification.VendorId.set_val(9)
        data_list.append(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)
        sub_tlv = seq.RfPort.add_new_repeated()
        sub_tlv.RfPortSelector.RfPortIndex.set_val(0)
        sub_tlv.DsRfPort.AdminState.set_val(1)
        sub_tlv.DsRfPort.BasePower.set_val(30)
        sub_tlv.DsRfPort.RfMute.set_val(0)
        sub_tlv.DsRfPort.TiltSlope.set_val(8)
        sub_tlv.DsRfPort.TiltMaximumFrequency.set_val(15)
        data_list.append(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)
        seq.RpdConfigurationDone.set_val(1)
        data_list.append(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        seq.ipc_msg = None
        data_list.append(seq)

        self.process.hal_ipc.disconnected = False
        self.process.hal_ipc.clientID = '12345'
        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": 'tmp',
                                   "gcp_msg": "tmp",
                                   "req_data": data_list})

    def test_msg_dispatch_I08(self):
        print("##################test_msg_dispatch_I08##################")
        try:
            self.process.send_ipc_msg('error')
        except SystemExit as e:
            self.assertEqual(e.code, EX_DATAERR)

        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": None,
                                   "req_data": "error"})

        timeout_msg = t_RcpMessage()
        timeout_msg.RcpMessageType = timeout_msg.CONNECT_CLOSE_NOTIFICATION
        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": None,
                                   "req_data": timeout_msg})

        data_list = []
        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                          unittest=True)
        sub_tlv = seq.CcapCoreIdentification.add_new_repeated()
        sub_tlv.Index.set_val(1)
        sub_tlv.CoreId.set_val('1234567890')
        sub_tlv.CoreIpAddress.set_val(Convert.ipaddr_to_tuple_of_bytes("127.0.0.1"))
        sub_tlv.IsPrincipal.set_val(False)
        sub_tlv.CoreMode.set_val(1)
        sub_tlv.InitialConfigurationComplete.set_val(True)
        sub_tlv.MoveToOperational.set_val(True)
        sub_tlv.CoreFunction.set_val(1)
        sub_tlv.ResourceSetIndex.set_val(2)
        data_list.append(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE,
                          unittest=True)
        sub_tlv = seq.RfPort.add_new_repeated()
        sub_tlv.RfPortSelector.RfPortIndex.set_val(0)
        sub_tlv.DsRfPort.AdminState.set_val(1)
        sub_tlv.DsRfPort.BasePower.set_val(30)
        sub_tlv.DsRfPort.RfMute.set_val(0)
        sub_tlv.DsRfPort.TiltSlope.set_val(8)
        sub_tlv.DsRfPort.TiltMaximumFrequency.set_val(15)
        data_list.append(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE,
                          unittest=True)
        seq.RpdConfigurationDone.set_val(1)
        data_list.append(seq)

        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE)
        seq.ipc_msg = None
        data_list.append(seq)

        self.process.hal_ipc.disconnected = False
        self.process.hal_ipc.clientID = '12345'
        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": 'tmp',
                                   "gcp_msg": "tmp",
                                   "req_data": data_list})

    def test_msg_dispatch_coreident_read(self):
        print("########test_msg_dispatch_null_coreident_read##########")
        try:
            self.process.send_ipc_msg('error')
        except SystemExit as e:
            self.assertEqual(e.code, EX_DATAERR)

        data_list = []
        seq = RCPSequence(gcp_msg_def.DataStructREQ,
                          rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0, rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                          unittest=True)
        sub_tlv = seq.CcapCoreIdentification.add_new_repeated()
        seq.ipc_msg = None
        data_list.append(seq)

        self.process.hal_ipc.disconnected = False
        self.process.hal_ipc.clientID = '12345'
        self.process.send_ipc_msg({"session": self.session,
                                   "req_packet": 'tmp',
                                   "gcp_msg": "tmp",
                                   "req_data": data_list})

    def construct_rcp_pkt(self, buffer):
        packet = rcp.RCPPacket(buffer, buf_data_len=len(buffer))
        result = packet.decode()
        self.assertEqual(result, GCPObject.DECODE_DONE)
        return packet

    def construct_eds_pkt_invalid_tlv_under_rfchannel(self):
        # write rfchannel with invalid tlv 99
        s_buffer = "\x00\x00\x00\x01\x00\x55\x00\x06\x00\x51\x05\x69\x00\x00" \
                   "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\x42\x09\x00\x3f\x0a\x00" \
                   "\x02\x05\x6a\x0b\x00\x01\x02\x10\x00\x33\x0c\x00\x0c\x01\x00\x01" \
                   "\x00\x02\x00\x01\x05\x03\x00\x01\x02\x63\x00\x21\x01\x00\x02\x1f" \
                   "\xff\x02\x00\x04\x00\x00\x39\x08\x03\x00\x01\x04\x04\x00\x04\x00" \
                   "\x00\x00\x04\x05\x00\x02\x00\x06\x06\x00\x02\x00\x1a"

        packet = rcp.RCPPacket(s_buffer, buf_data_len=len(s_buffer))
        result = packet.decode()
        self.assertEqual(result, GCPObject.DECODE_DONE)
        return packet

    def construct_eds_first_ira_tlv(self):
        # read capabilities and write identification
        s_buffer = "\x00\x00\x00\x01\x01\x82\x00\x06\x01\x7e" \
            "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x11\x8b\x01\x01\x01\x6f\x09" \
            "\x01\x1a\x0a\x00\x02\x00\x01\x0b\x00\x01\x01\x32\x01\x0e\x01\x00" \
            "\x00\x02\x00\x00\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00" \
            "\x07\x00\x00\x08\x00\x00\x09\x00\x00\x0a\x00\x00\x0b\x00\x00\x0c" \
            "\x00\x00\x0d\x00\x00\x0e\x00\x00\x0f\x00\x00\x10\x00\x00\x11\x00" \
            "\x00\x12\x00\x00\x13\x00\x30\x01\x00\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x05\x00\x00\x06\x00\x00\x07\x00\x00\x08\x00\x00\x09" \
            "\x00\x00\x0a\x00\x00\x0b\x00\x00\x0c\x00\x00\x0d\x00\x00\x0e\x00" \
            "\x00\x0f\x00\x00\x10\x00\x00\x14\x00\x0f\x01\x00\x00\x02\x00\x00" \
            "\x03\x00\x00\x04\x00\x00\x05\x00\x00\x15\x00\x18\x01\x00\x00\x02" \
            "\x00\x00\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00\x07\x00" \
            "\x00\x08\x00\x00\x16\x00\x12\x01\x00\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x05\x00\x00\x06\x00\x00\x17\x00\x12\x01\x00\x00\x02" \
            "\x00\x00\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00\x18\x00" \
            "\x09\x01\x00\x00\x02\x00\x00\x03\x00\x00\x19\x00\x00\x1a\x00\x00" \
            "\x1b\x00\x00\x1c\x00\x00\x1d\x00\x00\x1e\x00\x00\x1f\x00\x00\x20" \
            "\x00\x00\x21\x00\x00\x23\x00\x00\x24\x00\x00\x26\x00\x00\x27\x00" \
            "\x00\x28\x00\x00\x29\x00\x00\x2a\x00\x00\x2b\x00\x00\x2c\x00\x00" \
            "\x2d\x00\x00\x2e\x00\x00\x2f\x00\x00\x30\x00\x00\x09\x00\x4f\x0a" \
            "\x00\x02\x00\x02\x0b\x00\x01\x02\x3c\x00\x43\x01\x00\x01\x01\x02" \
            "\x00\x04\x31\x32\x33\x34\x03\x00\x10\x20\x01\x00\x60\x00\x10\x00" \
            "\x13\x00\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x01\x05\x00\x08" \
            "\x43\x43\x41\x50\x43\x4f\x52\x45\x06\x00\x02\x11\x8b\x07\x00\x01" \
            "\x01\x08\x00\x01\x00\x0a\x00\x02\x00\x00\x0b\x00\x01\x00"

        packet = rcp.RCPPacket(s_buffer, buf_data_len=len(s_buffer))
        result = packet.decode()
        self.assertEqual(result, GCPObject.DECODE_DONE)
        return packet

    def test_msg_invalid_tlv_under_rfchannel(self):
        pkt = self.construct_eds_pkt_invalid_tlv_under_rfchannel()
        try:
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    def test_msg_valid_tlv_hal_connect_false(self):
        pkt = self.construct_eds_first_ira_tlv()
        try:
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    def test_msg_valid_tlv_hal_connect_true(self):
        pkt = self.construct_eds_first_ira_tlv()
        try:
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 1)

    def construct_eds_pkt_vendor_specific(self):
        # write vendor specific tlv
        msg_buff = "\x00\x00\x00\x01\x00\x52\x00\x06\x00\x4e\x00\xc5\x00\x00" \
            "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\x3f\x09\x00\x3c\x0a\x00" \
            "\x02\x00\xc6\x0b\x00\x01\x02\x15\x00\x30\x01\x00\x02\x00\x09\x08" \
            "\x00\x28\x01\x00\x02\x1f\xff\x02\x00\x04\x00\x00\x2c\x88\x03\x00" \
            "\x01\x04\x04\x00\x04\x00\x00\x00\x04\x05\x00\x02\x00\x06\x06\x00" \
            "\x01\x00\x07\x00\x01\x05\x08\x00\x01\x01"
        pkt = self.construct_rcp_pkt(buffer=msg_buff)
        return pkt

    def test_hal_timeout_tlv(self):
        pkt = self.construct_eds_pkt_vendor_specific()
        try:
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 1)
        msg_record = self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping[1]
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.MSG_TIMEOUT = 0
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record._timeout_check_cb(arg="None")
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    def test_rpd_info(self):
        # read rpd info
        msg_buff = "\x00\x00\x00\x01\x01\x12\x00\x06\x00\xbd\xb6\x0e\x00\x00" \
            "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\xae\x09\x00\xab\x0a\x00" \
            "\x02\xb6\x0f\x0b\x00\x01\x01\x64\x00\x9f\x01\x00\x06\x01\x00\x00" \
            "\x02\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
            "\x04\x00\x00\x0f\x00\x20\x01\x00\x01\x01\x02\x00\x04\x5d\x03\x28" \
            "\x54\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00\x07\x00\x00" \
            "\x08\x00\x00\x09\x00\x00\x0f\x00\x20\x01\x00\x01\x01\x02\x00\x04" \
            "\x5d\x03\x28\x54\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00" \
            "\x07\x00\x00\x08\x00\x00\x09\x00\x00\x06\x00\x4e\xb6\x0f\x00\x00" \
            "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\x3f\x09\x00\x3c\x0a\x00" \
            "\x02\xb6\x10\x0b\x00\x01\x02\x15\x00\x30\x01\x00\x02\x00\x09\x08" \
            "\x00\x28\x01\x00\x02\x1f\xff\x02\x00\x04\x00\x00\x52\x08\x03\x00" \
            "\x01\x04\x04\x00\x04\x00\x00\x00\x04\x05\x00\x02\x00\x06\x06\x00" \
            "\x01\x00\x07\x00\x01\x05\x08\x00\x01\x04"

        pkt = self.construct_rcp_pkt(buffer=msg_buff)
        try:
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.req_msg_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 2)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 2)
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.MSG_TIMEOUT = 0
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record._timeout_check_cb(arg="None")
        self.assertEquals(len(self.process.orchestrator.req_msg_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    def test_rpd_info_2(self):
        # read rpd info and write vendor-specific
        msg_buff = "\x00\x00\x00\x01\x01\x12\x00\x06\x00\xbd\xb6\x0e\x00\x00" \
                   "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\xae\x09\x00\xab\x0a\x00" \
                   "\x02\xb6\x0f\x0b\x00\x01\x01\x64\x00\x9f\x01\x00\x06\x01\x00\x00" \
                   "\x02\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
                   "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
                   "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
                   "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
                   "\x04\x00\x00\x0c\x00\x0d\x01\x00\x01\x00\x02\x00\x00\x03\x00\x00" \
                   "\x04\x00\x00\x0f\x00\x20\x01\x00\x01\x01\x02\x00\x04\x5d\x03\x28" \
                   "\x54\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00\x07\x00\x00" \
                   "\x08\x00\x00\x09\x00\x00\x0f\x00\x20\x01\x00\x01\x01\x02\x00\x04" \
                   "\x5d\x03\x28\x54\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00" \
                   "\x07\x00\x00\x08\x00\x00\x09\x00\x00\x06\x00\x4e\xb6\x0f\x00\x00" \
                   "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\x3f\x09\x00\x3c\x0a\x00" \
                   "\x02\xb6\x10\x0b\x00\x01\x02\x15\x00\x30\x01\x00\x02\x00\x09\x08" \
                   "\x00\x28\x01\x00\x02\x1f\xff\x02\x00\x04\x00\x00\x52\x08\x03\x00" \
                   "\x01\x04\x04\x00\x04\x00\x00\x00\x04\x05\x00\x02\x00\x06\x06\x00" \
                   "\x01\x00\x07\x00\x01\x05\x08\x00\x01\x04"

        pkt = self.construct_rcp_pkt(buffer=msg_buff)
        try:
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.req_msg_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 2)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 2)
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.MSG_TIMEOUT = 0
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record._timeout_check_cb(arg="None")
        self.assertEquals(len(self.process.orchestrator.req_msg_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    def test_rpd_read_cap(self):
        # read cap
        msg_buff = "\x00\x00\x00\x01\x00\x99\x00\x06\x00\x95" \
            "\x00\x00\x00\xff\xff\xff\xff\x00\x00\x11\x8b\x01\x01\x00\x86\x09" \
            "\x00\x2f\x0a\x00\x02\x00\x00\x0b\x00\x01\x01\x32\x00\x18\x02\x00" \
            "\x00\x03\x00\x00\x04\x00\x00\x05\x00\x00\x06\x00\x00\x07\x00\x00" \
            "\x08\x00\x00\x14\x00\x00\x15\x00\x08\x01\x00\x02\x06\x1b\x32\x00" \
            "\x00\x09\x00\x51\x0a\x00\x02\x00\x01\x0b\x00\x01\x02\x3c\x00\x45" \
            "\x01\x00\x01\x01\x02\x00\x06\x00\x01\x02\x03\x04\x05\x03\x00\x10" \
            "\x20\x01\x05\x58\xff\x40\x0e\x15\x00\x00\x00\x00\x00\x00\x01\x00" \
            "\x04\x00\x01\x00\x05\x00\x0c\x48\x61\x72\x6d\x6f\x6e\x69\x63\x43" \
            "\x6f\x72\x65\x06\x00\x02\x06\x1b\x07\x00\x01\x01\x08\x00\x01\x00" \
            "\x0a\x00\x02\x00\x03"
        pkt = self.construct_rcp_pkt(buffer=msg_buff)
        self.process.orchestrator.rcp_process_channel.hal_ipc.rpd_cap = t_RpdCapabilities()
        GCPObject.default_gpb(self.process.orchestrator.rcp_process_channel.hal_ipc.rpd_cap)
        self.process.orchestrator.rcp_process_channel.hal_ipc.rpd_cap.NumDsRfPorts = 2
        for portidx in range(1, 3):
            entry = self.process.orchestrator.rcp_process_channel.hal_ipc.rpd_cap.LcceChannelReachability.add()
            entry.EnetPortIndex = 0
            entry.ChannelType = entry.CHANNEL_TYPE_2_DSOFDM_DOWNSTREAM_OFDM
            entry.RfPortIndex = portidx
            entry.StartChannelIndex = 0
            entry.EndChannelIndex = 0

        try:
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 2)
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.MSG_TIMEOUT = 0
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record._timeout_check_cb(arg="None")
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    def test_rpd_read_rpdinfo_mcast(self):
        msg_buff = "\x00\x00\x00\x01\x00\x2A\x00\x06\x00\x26\x31\xf0\x00\x00" \
                   "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\x17\x09\x00\x14\x0a\x00" \
                   "\x02\x31\xf1\x0b\x00\x01\x01\x1a\x00\x02\x00\x03\x64\x00\x03\x05\x00\x00"

        pkt = self.construct_rcp_pkt(buffer=msg_buff)

        try:
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 1)
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.MSG_TIMEOUT = 0
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record._timeout_check_cb(arg="None")
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)

    @unittest.skip("only for integration environment")
    def test_rpd_read_rpdinfo_mcast_1(self):
        msg_buff = "\x00\x00\x00\x01\x00\x2d\x00\x06\x00\x29\x31\xf0\x00\x00" \
                   "\x00\x00\x00\x00\x00\x11\x8b\x01\x02\x00\x1a\x09\x00\x17\x0a\x00" \
                   "\x02\x31\xf1\x0b\x00\x01\x01\x1a\x00\x02\x00\x03\x64\x00\x06\x05\x00\x03\x01\x00\x00"

        pkt = self.construct_rcp_pkt(buffer=msg_buff)

        try:
            self.process.dispatcher.handle_one_event()
            self.process.orchestrator.rcp_process_channel.hal_ipc.disconnected = False
            self.process.orchestrator.pkt_handler.handle_pkt(pkt=pkt, slave=self.session)
            self.process.dispatcher.handle_one_event()
        except RcpHalClientError:
            pass
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 1)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 1)
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.MSG_TIMEOUT = 0
        self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record._timeout_check_cb(arg="None")
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.pkt_db), 0)
        self.assertEquals(len(self.process.orchestrator.rcp_process_channel.hal_ipc.msg_record.seq_num_mapping), 0)


if __name__ == '__main__':
    setup_logging("GCP", filename="rcp.log")
    unittest.main()
