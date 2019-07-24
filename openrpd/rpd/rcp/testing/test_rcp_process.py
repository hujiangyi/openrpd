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

def fake_cb(data):
    print "fake cb handled"


class RcpProcessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dispatcher = Dispatcher()
        cls.desc = GCPSlaveDescriptor(addr_master='localhost', interface_local='local')
        cls.session = RCPSlaveSession(cls.desc, cls.dispatcher,
                                      fake_cb, fake_cb, fake_cb)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def setUp(self):
        self.process = RcpHalProcess("ipc:///tmp/_test_rcp.tmp",
                                     notify_mgr_cb=fake_cb)

    def tearDown(self):
        self.process.cleanup()

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

if __name__ == '__main__':
    unittest.main()
