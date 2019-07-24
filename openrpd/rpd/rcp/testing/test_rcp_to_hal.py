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
import os
import time
import subprocess
import threading
import binascii
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.rcp.rcp_hal import RcpHalIpc, RcpHalClientError, RcpMessageRecord, RcpMessageRecordElem, DataObj
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalDispatcher import HalDispatcher
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalConfigMsg import *
import logging
import json
import rpd.hal.src.HalMain as HalMain
from rpd.rcp.rcp_lib.rcp import RCPSequence
from rpd.rcp.rcp_lib import docsis_message
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.hal.src.HalConfigMsg import RCP_TO_HAL_MSG_TYPE
from rpd.gpb.cfg_pb2 import config
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.rcp.rcp_process import RcpHalProcess, RcpProcess
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.gpb.monitor_pb2 import t_LED
from rpd.provision.proto.MonitorMsgType import MsgTypeSetLed
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor
from rpd.rcp.rcp_sessions import RCPSlaveSession
import socket
from rpd.common.utils import Convert
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.gpb.CcapCoreIdentification_pb2 import t_CcapCoreIdentification


def create_cfg_sequence():

    seq = RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX,
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


def create_empty_cfg_sequence():

    seq = RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX,
                      0,
                      rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                      unittest=True)
    return seq


def create_full_cfg_sequence():

    seq = RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX,
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

    sub_tlv = seq.CcapCoreIdentification.add_new_repeated()
    sub_tlv.Index.set_val(1)
    sub_tlv.CoreId.set_val("1234567890")

    sub_tlv = seq.RedundantCoreIpAddress.add_new_repeated()
    sub_tlv.ActiveCoreIpAddress.set_val(
        Convert.ipaddr_to_tuple_of_bytes("1.1.1.1"))
    sub_tlv.StandbyCoreIpAddress.set_val(
        Convert.ipaddr_to_tuple_of_bytes("1.1.1.2"))

    seq.RpdConfigurationDone.set_val(1)

    seq.Ssd.SsdServerAddress.set_val(
        Convert.ipaddr_to_tuple_of_bytes("1.1.1.1"))
    seq.Ssd.SsdTransport.set_val(2)

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

    sub_tlv = seq.RfChannel.add_new_repeated()
    sub_tlv.RfChannelSelector.RfChannelIndex.set_val(0)
    sub_tlv.DsScQamChannelConfig.AdminState.set_val(1)
    sub_tlv.DsScQamChannelConfig.RfMute.set_val(1)
    sub_tlv.DsScQamChannelConfig.TSID.set_val(2)
    ucd_pkt = "c200016af52b01e02f00000100219f7b6638020e000003010200010d0401010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000042501010101020102030200260402018c050100060110070201520801000901160a01010b01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101"
    ucd_buf = binascii.a2b_hex(ucd_pkt)
    sub_tlv.DocsisMsg.set_val(ucd_buf)

    sub_tlv = seq.RfChannel.add_new_repeated()
    sub_tlv.RfChannelSelector.RfChannelIndex.set_val(0)
    sub_tlv.DsScQamChannelConfig.AdminState.set_val(1)
    sub_tlv.DsScQamChannelConfig.RfMute.set_val(1)
    sub_tlv.DsScQamChannelConfig.TSID.set_val(2)
    err_pkt = "c200002261fc01e02f00000100cae53ca4e900100000030542009fff0205052400000fff"
    err_buf = binascii.a2b_hex(err_pkt)
    sub_tlv.DocsisMsg.set_val(err_buf)

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


class RcpMessageRecordTest(unittest.TestCase):
    def setUp(self):
        self.dispatcher = Dispatcher()

    def tearDown(self):
        self.dispatcher.end_loop()

    def create_data_obj_from_seq(self, seq):
        if not isinstance(seq, RCPSequence):
                raise TypeError(
                    "RCPSequences are expected in tuple of RCP data")

        try:
            operation = RcpHalIpc.RCP_OPER_TO_RPD_DATA_OPER[seq.operation]
        except:
            raise AttributeError(
                "Invalid RCP operation set in sequence: %u" % seq.operation)

        data = DataObj(seq, operation, seq.seq_number)
        print data
        data.ipc_req_msg = seq.ipc_msg
        RfData = seq.ipc_msg.RpdDataMessage.RpdData
        for RfCh in RfData.RfChannel:
            if RfCh.HasField("DocsisMsg"):
                docsis_buf = RfCh.DocsisMsg
                docsis_msg = docsis_message.DocsisMsgMacMessage()
                docsis_msg.decode(docsis_buf, 0, len(docsis_buf))
                RfChMsg = docsis_msg.convert_to_RCPSequence(
                    gcp_msg_def.NotifyREQ,
                    rcp_tlv_def.RCP_MSG_TYPE_IRA,
                    RfCh,
                    rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        return data

    def recv_cb(self, arg):
        print "===================================================="
        print arg['session']
        print arg['req_packet']
        print arg['gcp_msg']
        dataObjs = arg['req_data']

        data_obj_num = 0
        for dataObj in dataObjs:
            print dataObj.rsp_data
            data_obj_num += 1
        self.fired = True
        self.data_obj_num = data_obj_num

    def test_create_rcp_msg_record(self):
        msg_record = RcpMessageRecord(
            self.dispatcher, event_fire_cb=self.recv_cb, unittest = {
                "enable":True,
                "runtimes":1,
            })
        self.dispatcher.loop()

        self.assertIsInstance(msg_record, RcpMessageRecord)

    def _add_req_to_internal(self, seq_num_start, data_objs, msg_record, session, pkt, gcp_msg):
        seq_num = seq_num_start
        # Add the rsp list
        for data_obj in data_objs:
            record_elem = RcpMessageRecordElem(data_obj)
            req_msg = data_obj.ipc_req_msg
            cfg_data = req_msg.RpdDataMessage.RpdData
            op = req_msg.RpdDataMessage.RpdDataOperation

            for desc, value in cfg_data.ListFields():
                if desc.name in ['RfChannel']:
                    for rf_channel in cfg_data.RfChannel:
                        for rf_desc, rf_value in rf_channel.ListFields():
                            if rf_desc.name in RCP_TO_HAL_MSG_TYPE:
                                data = config()
                                msg = data.RfChannel.add()
                                msg.CopyFrom(rf_channel)
                                if op == t_RpdDataMessage.RPD_CFG_READ:
                                    data_rsp = config()
                                    data_rsp.CopyFrom(data)
                                msg_record.add_req_to_internal_db(
                                    session, pkt, gcp_msg, seq_num, record_elem)
                                seq_num += 1
                elif desc.name in ['RfPort']:
                    for rf_port in cfg_data.RfPort:
                        for rf_desc, rf_value in rf_port.ListFields():
                            if rf_desc.name in RCP_TO_HAL_MSG_TYPE:
                                data = config()
                                msg = data.RfPort.add()
                                msg.CopyFrom(rf_port)
                                if op == t_RpdDataMessage.RPD_CFG_READ:
                                    data_rsp = config()
                                    data_rsp.CopyFrom(data)
                                msg_record.add_req_to_internal_db(
                                    session, pkt, gcp_msg, seq_num, record_elem)
                                seq_num += 1

        msg_record.set_send_procedure_done(session, pkt, gcp_msg)
        # Done the message receive part
        return seq_num

    def test_add_pkt_to_internal_db(self):

        # construct the pkt and session
        session = "test-session"
        pkt = "test-pkt" # we will not touch this pkt, just return back, so we don't need to construct the pkt
        gcp_msg = "gcp_msg"
        seq1 = create_cfg_sequence()
        seq2 = create_cfg_sequence()
        seq3 = create_cfg_sequence()
        seqs = [seq1, seq2, seq3]

        data_objs = []
        for seq in seqs:
            data_objs.append(self.create_data_obj_from_seq(seq))

        msg_record = RcpMessageRecord(self.dispatcher, event_fire_cb=self.recv_cb)
        msg_record.add_pkt_to_internal_db(session, pkt, gcp_msg, data_objs)
        self.assertIn((session, pkt, gcp_msg), msg_record.pkt_db)

        # test_remove
        record_elem = RcpMessageRecordElem(seq1)
        msg_record.add_req_to_internal_db(session, pkt, gcp_msg, 1, record_elem)
        self.assertIn(1, msg_record.seq_num_mapping)
        self.assertIn(1, record_elem.seq_nums)

        msg_record.remove_req_from_internal_db(1, record_elem)
        self.assertNotIn(1, msg_record.seq_num_mapping)
        self.assertNotIn(1, record_elem.seq_nums)

        # remove_req else branch
        msg_record.remove_req_from_internal_db(1, record_elem)

        seq_num = self._add_req_to_internal(10, data_objs, msg_record, session, pkt, gcp_msg)

        # Receive part
        self.fired = False
        switch = 0
        for seq_num_tmp in range(10, seq_num):
            cfg = HalMessage("HalConfigRsp")
            cfg.msg.SeqNum = seq_num_tmp
            if switch % 3 == 0:
                cfg.msg.Rsp.Status = HalCommon_pb2.FAILED
            else:
                cfg.msg.Rsp.Status = HalCommon_pb2.SUCCESS

            rcp_msg = t_RcpMessage()
            if switch % 3 == 1:
                rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            else:
                rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            cfg.msg.CfgMsgPayload = rcp_msg.SerializeToString()
            switch += 1
            try:
                msg_record.recv_fragment_msg(cfg)
            except AttributeError:
                # we use fake session
                pass

        self.assertEqual(self.fired, True)

    def test_req_message_timeout(self):
        # construct the pkt and session
        pkt = "test-pkt" # we will not touch this pkt, just return back, so we don't need to construct the pkt
        session = "test-session"
        gcp_msg = "gcp_msg"
        seq1 = create_cfg_sequence()
        seq2 = create_cfg_sequence()
        seqs = [seq1, seq2]

        data_objs = []
        for seq in seqs:
            data_objs.append(self.create_data_obj_from_seq(seq))

        msg_record = RcpMessageRecord(
            self.dispatcher, event_fire_cb=self.recv_cb, unittest = {
                "enable":True,
                "runtimes":5,
            })
        msg_record.add_pkt_to_internal_db(session, pkt, gcp_msg, data_objs)
        self.assertIn((session, pkt, gcp_msg), msg_record.pkt_db)

        seq_num = self._add_req_to_internal(
            10, data_objs, msg_record, session, pkt, gcp_msg)

        # Do not recv
        self.fired = False
        try:
            self.dispatcher.loop()
        except Exception:
            # we use fake session
            pass

        self.assertEqual(self.fired, True)

    def test_compose_rsp_msg(self):

        # construct the pkt and session
        pkt = "test-pkt" # we will not touch this pkt, just return back, so we don't need to construct the pkt
        session = "test-session"
        gcp_msg = "gcp_msg"
        seq1 = create_cfg_sequence()
        seq2 = create_cfg_sequence()
        seqs = [seq1, seq2]

        data_objs = []
        for seq in seqs:
            data_objs.append(self.create_data_obj_from_seq(seq))

        msg_record = RcpMessageRecord(self.dispatcher, event_fire_cb=self.recv_cb)
        msg_record.add_pkt_to_internal_db(session, pkt, gcp_msg, data_objs)
        self.assertIn((session, pkt, gcp_msg), msg_record.pkt_db)

        seq_num = self._add_req_to_internal(
            10, data_objs, msg_record, session, pkt, gcp_msg)
        self.data_obj_num = 0
        for seq_num_tmp in range(10, seq_num):
            cfg = HalMessage("HalConfigRsp")
            cfg.msg.SeqNum = seq_num_tmp
            cfg.msg.Rsp.Status = HalCommon_pb2.SUCCESS

            rcp_msg = t_RcpMessage()
            rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rpd_data_msg = t_RpdDataMessage()
            rpd_data_msg.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
            rcp_cfg = config()
            sub_tlv =rcp_cfg.RfChannel.add()
            sub_tlv.RfChannelSelector.RfPortIndex = 10
            sub_tlv = rcp_cfg.RfPort.add()
            sub_tlv.RfPortSelector.RfPortIndex = 10
            sub_tlv = rcp_cfg.RpdCapabilities
            sub_tlv.NumBdirPorts = 1
            sub_tlv = rcp_cfg.CcapCoreIdentification.add()
            sub_tlv.Index = 1
            sub_tlv = rcp_cfg.RpdRedirect.add()
            sub_tlv.RedirectIpAddress = '1.1.1.1'
            rcp_cfg.RpdPTPClockStatus = 1
            rcp_cfg.Ssd.SsdServerAddress = '1.1.1.1'
            rpd_data_msg.RpdData.CopyFrom(rcp_cfg)
            rcp_msg.RpdDataMessage.CopyFrom(rpd_data_msg)
            cfg.msg.CfgMsgPayload = rcp_msg.SerializeToString()
            try:
                msg_record.recv_fragment_msg(cfg)
            except AttributeError:
                # we use fake session
                pass

        self.assertEqual(self.data_obj_num, 2)

    def test_negative(self):
        try:
            dat = DataObj(None, RcpHalIpc.RPD_DATA_OPER_WR, 1)
            self.assertEqual("should hit AttributeError", 0)
        except AttributeError:
            pass
        try:
            dat = DataObj(None, None, 1)
            self.assertEqual("should hit AttributeError", 0)
        except AttributeError:
            pass

    def test_recv_bypass_msg(self):
        msg_record = RcpMessageRecord(self.dispatcher)
        msg_record.recv_bypass_msg(RcpMessageRecordElem('test'), '')


timeStampSock = "/tmp/testRcpToHalRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"
json_dic = dict()
json_dic["CFG_DB_NUM"] = 1
json_dic["DB_SOCKET_PATH"] = timeStampSock
json_dic["ShadowLayerEnable"] = True
json_dic["ConfigFilterEnable"] = True
json_dic["InternalPolicyEnable"] = True
json_dic["InternalPolicy"] = dict()
json_dic["ExternalPolicyEnable"] = False
TMP_CFG_PATH = "/tmp/test_rcpHal_shadow_layer.conf"
with open(TMP_CFG_PATH, "w") as f:
    f.write(json.dumps(json_dic, indent=4))


def setupDB():
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    filename = "/tmp/HaldatabaseUT.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(timeStampSock):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")

    HalGlobal.reinit()
    HalGlobal.gHalClientDbConnection = HalDatabase(timeStampSock, 30, 11)
    HalGlobal.gHalMsgDbConnection = HalDatabase(timeStampSock, 30, 12)


def demoHalmain():
    print "demoHalmain thread start!"
    HalGlobal.StopHal = False
    setup_logging('HAL', filename="hal.log")
    HalMain.logger = logging.getLogger("HalMain")
    HalMain.logger.info("hello demo HalMain Log")
    HalGlobal.gDispatcher = HalDispatcher()
    HalMain._mainLoop()
    print "clear Manager status!"
    keys = HalGlobal.gClientDB.keys()
    for clientId in keys:
        HalGlobal.gClientMgr.disconnectCb(HalGlobal.gClientDB[clientId]['agent'])
    if HalGlobalStats.NrClient != 0:
        raise Exception(
            "Cannot destroy the hal Main, reason: clients is not cleared")
    HalGlobal.StopHal = False
    print "demoHalmain thread done!"


class RcpHalError(unittest.TestCase):

    def setUp(self):
        self.dispatcher = Dispatcher()
        process = RcpProcess("ipc:///tmp/_test_rcp_to_hal.tmp")

        self.hal_ipc = RcpHalIpc(
            "HalClient", "This is a test application",
            "1.9.0", (1, 100, 102), process,
            "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)
        self.hal_ipc.start(self.rcp_cfg_rsp_handle, None)
        time.sleep(2)
        self.hal_ipc.rcp_hal_cb(self.hal_ipc.mgrConnection.socket, None)
        print("************************************************************")

    def tearDown(self):
        self.hal_ipc.channel.cleanup()
        self.hal_ipc.connection_cleanup(self.dispatcher)
        self.dispatcher.end_loop()

    def rcp_cfg_rsp_handle(self, cb):
        print "cfg response cb handled"

    def test_err_ntf(self):
        try:
            RcpHalIpc(
                "HalClient", "This is a test application",
                "1.9.0", 1, self,
                "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)
        except RcpHalClientError as e:
            self.assertEqual(
                e.msg, "supportedMsgType should be a tuple or list")

    def test_err_version(self):
        try:
            RcpHalIpc(
                "HalClient", "This is a test application",
                1.9, 1, self,
                "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)
        except RcpHalClientError as e:
            self.assertEqual(
                e.msg, "Driver name/desc/version should be a str type")

    def test_err_recv(self):
        self.hal_ipc.start(None, None)
        try:
            self.hal_ipc.rcp_hal_cb(self.hal_ipc.pushSock.monitor, mask=0)
            self.hal_ipc.rcp_hal_cb(self.hal_ipc.pullSock.monitor, mask=0)
            self.hal_ipc.rcp_hal_cb(self.hal_ipc.mgrConnection.monitor, mask=0)
            self.hal_ipc.register(self.hal_ipc.clientID)
        except AttributeError as a:
            pass

    def test_err_path(self):
        try:
            self.hal_ipc._getIndexFromPath()
        except AttributeError as a:
            pass

    def test_err_send(self):
        self.hal_ipc.send("")
        self.assertIsNone(self.hal_ipc.sendCfgMsg(1025, None))

    def test_send_err_ntf(self):
        self.hal_ipc.sendInterestedNotifications(1)

    def test_err_register(self):
        self.hal_ipc.connection_cleanup(self.dispatcher)
        self.hal_ipc.mgrConnection = None
        try:
            self.hal_ipc.register(self.hal_ipc.clientID)
        except RcpHalClientError as e:
            self.assertEqual(
                e.msg,
                "Cannot send the register since the mgr connection is not setup")

    def test_err_recv_register_cb(self):
        self.assertTrue(self.hal_ipc.disconnected)
        cfg_rsp_msg = HalMessage("HalClientRegisterRsp")
        cfg_rsp_msg.msg.Rsp.Status = 2
        self.hal_ipc.recvRegisterMsgCb(cfg_rsp_msg)
        self.assertTrue(self.hal_ipc.disconnected)

    def test_err_connection_cb(self):
        self.hal_ipc.connectionDisconnectCb(None)


@unittest.skip('skip')
class RcpHalConfigTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        #subprocess.call(["killall", "python"])
        setupDB()
        time.sleep(2)
        cls.stop = False
        HalGlobal.gClientMgr = None
        HalGlobal.gPoller = None
        t = threading.Thread(target=demoHalmain)
        t.start()
        time.sleep(5)
        if not HalGlobal.gClientMgr or not HalGlobal.gPoller:
            raise Exception("Cannot start the demo halMain")

    @classmethod
    def tearDownClass(cls):
        HalGlobal.StopHal = True
        time.sleep(4)
        # os.system("ps ax |grep HalMain|awk '{print $1}'|xargs kill -9")
        # time.sleep(2)
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)

    def setUp(self):
        # self.orchestrator = RCPSlaveOrchestrator(disp=self.dispatcher,
        #                                          cfg_ipc_channel=None,
        # TODO we need reboot IPC msg
        #                                          reboot_cb=None)
        process = RcpProcess("ipc:///tmp/_test_rcp_to_hal.tmp")

        self.hal_ipc = RcpHalIpc(
            "HalClient", "This is a test application",
            "1.9.0", (1, 100, 102), process,
            "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)
        self.hal_ipc.start(self.rcp_cfg_rsp_handle, None)
        time.sleep(2)
        self.hal_ipc.rcp_hal_cb(self.hal_ipc.mgrConnection.socket, None)
        print("************************************************************")

    def ntf_cb_handle(self, a, b):
        pass

    def rcp_cfg_rsp_handle(self, cb):
        print "cfg response cb handled"

    def test_send_cfg(self):

        timeOut = time.time() + 10
        while self.hal_ipc.disconnected and time.time() < timeOut:
            pass
        ipc_msg = {
            'session':"dummy-session",
            'req_packet':"dummy-packet",
            'gcp_msg':"dummy-message",
            'req_data':[create_cfg_sequence(), ],
        }
        self.hal_ipc.rcp_cfg_req(ipc_msg)

    def test_send_ntf(self):
        self.hal_ipc.sendInterestedNotifications((1, 2, 3))

    def test_ntf_rsp(self):
        ntf = HalMessage("HalClientInterestNotificationCfgRsp",
                         ClientID=self.hal_ipc.clientID)
        self.hal_ipc.recvInterestedNotificationsRspCb(ntf)

    def test_ptp_ntf(self):
        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeRoutePtpStatus,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)
        self.hal_ipc.rcp_notification_cb = self.ntf_cb_handle
        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeRoutePtpStatus,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

        ntf.msg.HalNotificationType = 0
        self.hal_ipc.recvNotificationCb(ntf)

        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeFaultManagement,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)
        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeInvalid,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

    def test_I07_ptp_ntf(self):
        gen_ntf_msg = t_GeneralNotification()
        gen_ntf_msg.NotificationType = t_GeneralNotification.PTPRESULTNOTIFICATION
        gen_ntf_msg.PtpResult = t_GeneralNotification.PTPHOOUTOFSPEC
        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeGeneralNtf,
                         HalNotificationPayLoad=gen_ntf_msg.SerializeToString())
        self.hal_ipc.recvNotificationCb(ntf)
        self.hal_ipc.rcp_notification_cb = self.ntf_cb_handle
        gen_ntf_msg.PtpResult = t_GeneralNotification.PTPSYNCHRONIZED
        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeGeneralNtf,
                         HalNotificationPayLoad=gen_ntf_msg.SerializeToString())
        self.hal_ipc.recvNotificationCb(ntf)

        ntf.msg.HalNotificationType = 0
        self.hal_ipc.recvNotificationCb(ntf)

        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeFaultManagement,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)
        ntf = HalMessage("HalNotification", ClientID=self.hal_ipc.clientID,
                         HalNotificationType=MsgTypeInvalid,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

    def test_hello_msg(self):
        self.hal_ipc.sayHelloToHal()
        hello = HalMessage("HalClientHelloRsp", ClientID=self.hal_ipc.clientID)
        self.hal_ipc.recvHelloRspMsgCb(hello)

    def test_recv_cfg_msg_cb(self):
        cfg_rsp = HalMessage("HalConfigRsp", SeqNum=12,
                             SrcClientID=self.hal_ipc.clientID)
        # cfg_rsp.msg.RcpDataResult = 2
        self.hal_ipc.recvCfgMsgRspCb(cfg_rsp)

    def test_rcv_cfg_msg_cb_ok(self):
        cfg_rsp = HalMessage("HalConfigRsp", SeqNum=15,
                             SrcClientID=self.hal_ipc.clientID)
        cfg = t_RcpMessage()
        cfg.RcpDataResult = 1
        cfg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        cfg_rsp.msg.CfgMsgPayload = cfg.SerializeToString()
        self.hal_ipc.rcp_req_done = True
        self.hal_ipc.recvCfgMsgRspCb(cfg_rsp)

    def test_rcv_cfg_msg_cb_fail(self):
        rsp = {"Status": HalCommon_pb2.SUCCESS,
               "ErrorDescription": "test success"}
        cfg_rsp = HalMessage("HalConfigRsp", SeqNum=16, Rsp=rsp,
                             SrcClientID=self.hal_ipc.clientID)
        cfg = t_RcpMessage()
        cfg.RcpDataResult = 2
        cfg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        cfg_rsp.msg.CfgMsgPayload = cfg.SerializeToString()
        self.hal_ipc.rcp_req_done = True
        self.hal_ipc.recvCfgMsgRspCb(cfg_rsp)

    def test_rcv_cfg_msg_cb_no_seq(self):
        cfg_rsp = HalMessage("HalConfigRsp", SeqNum=13,
                             SrcClientID=self.hal_ipc.clientID)
        self.hal_ipc.recvCfgMsgRspCb(cfg_rsp)

    def test_send_mgr_msg(self):
        led_msg = t_LED()
        self.hal_ipc.send_mgr_cfg_msg(MsgTypeSetLed, led_msg)
        self.hal_ipc.send_mgr_cfg_msg(None, led_msg)
        self.hal_ipc.connection_cleanup(self.hal_ipc.channel.dispatcher)
        self.hal_ipc.send_mgr_cfg_msg(MsgTypeSetLed, led_msg)

    def test_send_None_ctx(self):
        self.hal_ipc.sendCfgMsg(1025, None)
        self.hal_ipc.connectionDisconnectCb("")

    def tearDown(self):
        self.hal_ipc.channel.cleanup()
        self.hal_ipc.connection_cleanup(self.hal_ipc.channel.dispatcher)
        self.hal_ipc.channel.dispatcher.end_loop()


class RcpHalConfigReq(unittest.TestCase):
    def fake_cb(self, cb):
        print "fake cb handled"

    def test_cfg_req(self):
        process = RcpProcess("ipc:///tmp/_test_rcp_to_hal.tmp")

        desc = GCPSlaveDescriptor(
            "127.0.0.1", port_master=9999, addr_local="127.0.0.1",
            interface_local="lo",
            addr_family=socket.AF_INET)
        dummy_session = RCPSlaveSession(desc, process.dispatcher,
                                        self.fake_cb,
                                        self.fake_cb,
                                        self.fake_cb)
        self.hal_ipc = RcpHalIpc(
            "HalClient", "This is a test application",
            "1.9.0", (1, 100, 102), process,
            "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)
        self.hal_ipc.disconnected = False
        self.hal_ipc.clientID = 'dummy-clientId'

        # fault
        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': {},
        }
        try:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        except TypeError as e:
            self.assertIn("must be a list", str(e))

        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': ["dummy_data", ],
        }
        try:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        except TypeError as e:
            self.assertIn("RCPSequences are expected", str(e))

        seq = RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX,
                          0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_NONE,
                          unittest=True)
        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': [seq, ],
        }
        try:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        except AttributeError as e:
            self.assertIn("Invalid RCP operation", str(e))

        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': [],
        }
        try:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        except Exception as e:
            self.assertIn("contains nothing", str(e))

        # empty
        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': [create_empty_cfg_sequence(), ],
        }
        self.hal_ipc.rcp_cfg_req(ipc_msg)


        # full
        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': [create_full_cfg_sequence(), ],
        }
        self.assertEqual(self.hal_ipc.seqNum, 1)
        self.hal_ipc.rcp_cfg_req(ipc_msg)
        self.assertEqual(self.hal_ipc.seqNum, 13)

        self.hal_ipc.disconnected = True
        try:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        except RcpHalClientError:
            self.assertEqual(self.hal_ipc.seqNum, 13)
            pass

        self.hal_ipc.connection_cleanup(process.dispatcher)
        process.dispatcher.end_loop()


class RcpHalFuncTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging('GCP', filename="provision_rcp.log")
        process = RcpProcess("ipc:///tmp/_test_rcp_to_hal.tmp")
        cls.hal_ipc = RcpHalIpc(
            "HalClient", "This is a test application",
            "1.9.0", (1, 100, 102), process,
            "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)

    @classmethod
    def tearDownClass(cls):
        cls.hal_ipc.channel.cleanup()
        cls.hal_ipc.connection_cleanup(cls.hal_ipc.channel.dispatcher)
        cls.hal_ipc.channel.dispatcher.end_loop()

    def setUp(self):
        self.hal_ipc.msg_record = RcpMessageRecord(
            self.hal_ipc.channel.dispatcher,
            self.hal_ipc.channel.orchestrator.config_operation_rsp_cb)
        self.hal_ipc.rpd_cap = None
        self.hal_ipc.clientID = None
        self.hal_ipc.disconnected = True
        self.hal_ipc.seqNum = 1

    def tearDown(self):
        self.hal_ipc.msg_record = RcpMessageRecord(
            self.hal_ipc.channel.dispatcher,
            self.hal_ipc.channel.orchestrator.config_operation_rsp_cb)
        self.hal_ipc.rpd_cap = None
        self.hal_ipc.clientID = None
        self.hal_ipc.disconnected = True
        self.hal_ipc.seqNum = 1

    def ntf_cb_handle(self, a, b):
        pass

    def test_register(self):
        try:
            self.hal_ipc.register('NotNone')
        except Exception as e:
            self.assertEqual(type(e), RcpHalClientError)

    def test_sayHelloToHal(self):
        self.hal_ipc.sayHelloToHal()

    def test_sendInterestedNotifications(self):
        try:
            self.hal_ipc.sendInterestedNotifications((1, 2))
        except Exception as e:
            self.assertEqual(type(e), TypeError)

    def test_sendNotificationMsg(self):
        self.hal_ipc.disconnected = False
        self.hal_ipc.sendNotificationMsg(None, '')

    def test_sendCfgMsg(self):
        self.hal_ipc.disconnected = False
        self.hal_ipc.sendCfgMsg(None, None)
        self.assertEqual(self.hal_ipc.seqNum, 1)
        self.hal_ipc.clientID = "123"
        ret = self.hal_ipc.sendCfgMsg(MsgTypeRpdCapabilities, "")
        self.assertEqual(self.hal_ipc.seqNum, 2)

    def test_recvInterestedNotificationsRspCb(self):
        self.hal_ipc.regDoneTimer = self.hal_ipc.channel.dispatcher.timer_register(
            self.hal_ipc.REG_PERIOD, self.hal_ipc._check_register_done)
        self.hal_ipc.recvInterestedNotificationsRspCb(HalMessage("HalConfigRsp"))

    def test_recvCfgMsgRspCb(self):
        cfg_rsp = HalMessage("HalConfigRsp", SeqNum=12,
                             SrcClientID='1234567890')
        self.hal_ipc.recvCfgMsgRspCb(cfg_rsp)

        cfg_rsp = HalMessage("HalConfigRsp", SeqNum=12,
                             SrcClientID='1234567890', )

    def test_recvHelloRspMsgCb(self):
        self.hal_ipc.recvHelloRspMsgCb(HalMessage("HalClientHelloRsp"))

    def test_connectionDisconnectCb(self):
        self.hal_ipc.disconnected = False
        self.hal_ipc.retryNr = 0
        self.hal_ipc.connectionDisconnectCb(None)

    def test_send_mgr_cfg_msg(self):
        self.hal_ipc.clientID = "123"
        led_msg = t_LED()
        led_msg.setLed.ledType = led_msg.LED_TYPE_STATUS
        led_msg.setLed.color = led_msg.LED_COLOR_GREEN
        led_msg.setLed.action = led_msg.LED_ACTION_LIT
        self.hal_ipc.send_mgr_cfg_msg(MsgTypeSetLed, led_msg)

    def test_sendRpdCapReq(self):
        ret = self.hal_ipc.sendRpdCapReq()
        self.assertFalse(ret)
        self.hal_ipc.clientID = "123"
        ret = self.hal_ipc.sendRpdCapReq()
        self.assertTrue(ret)

    def test_recvRegisterMsgCb(self):
        try:
            # get index as -1
            regRsp = HalMessage("HalClientRegisterRsp",
                                Rsp={
                                    "Status": HalCommon_pb2.SUCCESS,
                                    "ErrorDescription": "Successful"
                                },
                                ClientID="123",
                                PathFromHalToClient="/tmp/1",
                                PathFromClientToHal="/tmp/2"
                                )
            self.hal_ipc.recvRegisterMsgCb(regRsp)

            # interestedNotification is not None
            regRsp = HalMessage("HalClientRegisterRsp",
                                Rsp={
                                    "Status": HalCommon_pb2.SUCCESS,
                                    "ErrorDescription": "Successful"
                                },
                                ClientID="123",
                                PathFromHalToClient="/tmp/1",
                                PathFromClientToHal="/tmp/2/"
                                )
            self.hal_ipc.recvRegisterMsgCb(regRsp)
        except Exception as e:
            self.assertEqual(type(e), AttributeError)

        try:
            # interestedNotification is not None
            self.hal_ipc.interestedNotification = None
            regRsp = HalMessage("HalClientRegisterRsp",
                                Rsp={
                                    "Status": HalCommon_pb2.SUCCESS,
                                    "ErrorDescription": "Successful"
                                },
                                ClientID="123",
                                PathFromHalToClient="/tmp/1",
                                PathFromClientToHal="/tmp/2/"
                                )
            self.hal_ipc.recvRegisterMsgCb(regRsp)
        except Exception as e:
            self.assertEqual(type(e), TypeError)

    def test_getIndexFromPath(self):
        path = '/tmp/client/'
        self.hal_ipc.pushPath = path
        # return -1
        self.hal_ipc._getIndexFromPath()

        path = '/tmp/client/1/pull'
        self.hal_ipc.pushPath = path
        print self.hal_ipc._getIndexFromPath()
        os.system('rm -rf /tmp/client')

    def test_recvNotificationCb(self):
        # cb is None
        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeRoutePtpStatus,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

        # cb not None
        self.hal_ipc.rcp_notification_cb = self.ntf_cb_handle

        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeRoutePtpStatus,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeFaultManagement,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeInvalid,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

    def test_I07_recvNotificationCb(self):
        gen_ntf_msg = t_GeneralNotification()
        gen_ntf_msg.NotificationType = \
            t_GeneralNotification.PTPRESULTNOTIFICATION
        gen_ntf_msg.PtpResult = t_GeneralNotification.PTPHOOUTOFSPEC
        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeGeneralNtf,
                         HalNotificationPayLoad=gen_ntf_msg.SerializeToString())
        self.hal_ipc.recvNotificationCb(ntf)

        # cb not None
        self.hal_ipc.rcp_notification_cb = self.ntf_cb_handle
        gen_ntf_msg.PtpResult = t_GeneralNotification.PTPSYNCHRONIZED
        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeGeneralNtf,
                         HalNotificationPayLoad=gen_ntf_msg.SerializeToString())
        self.hal_ipc.recvNotificationCb(ntf)

        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeFaultManagement,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)

        ntf = HalMessage("HalNotification", ClientID='12345567890',
                         HalNotificationType=MsgTypeInvalid,
                         HalNotificationPayLoad=self.hal_ipc.LOS)
        self.hal_ipc.recvNotificationCb(ntf)
    def test_notification_rpd_cap(self):
        self.hal_ipc.rpd_cap = None
        rpd_cap = t_RpdCapabilities()
        GCPObject.default_gpb(rpd_cap)
        self.hal_ipc.notification_rpd_cap(rpd_cap.SerializeToString())
        self.assertIsNone(self.hal_ipc.rpd_cap)
        rpd_cap = t_RpdCapabilities()
        rpd_cap.NumBdirPorts = 1
        self.hal_ipc.notification_rpd_cap(rpd_cap.SerializeToString())
        self.assertIsNotNone(self.hal_ipc.rpd_cap)
        self.assertEqual(self.hal_ipc.rpd_cap.NumBdirPorts, 1)


    def test_recMsgTypeRpdCapabilitiesCb(self):
        old_cap = self.hal_ipc.rpd_cap
        cfgMsgType = MsgTypeRpdCapabilities
        rcp_msg = t_RcpMessage()
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        data = config()
        cap = t_RpdCapabilities()
        GCPObject.default_gpb(cap)
        data.RpdCapabilities.CopyFrom(cap)
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig", SrcClientID='1',
                         SeqNum=self.hal_ipc.seqNum,
                         CfgMsgType=cfgMsgType,
                         CfgMsgPayload=payload)
        record_req_elem = self.hal_ipc.msg_record
        record_req_elem.ref_count = 0
        self.hal_ipc.msg_record.seq_num_mapping[0] = record_req_elem
        record_req_elem.rsp_list = []
        ret = self.hal_ipc.recMsgTypeRpdCapabilitiesCb(msg)
        self.assertTrue(ret)

    def test_recMsgTypeRpdCapabilitiesRspCb(self):

        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rpd_data_msg = t_RpdDataMessage()
        rpd_data_msg.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
        rcp_cfg = config()
        sub_tlv = rcp_cfg.RpdCapabilities
        self.hal_ipc._set_rpd_identification(sub_tlv.RpdIdentification)
        ret = Convert.mac_to_tuple_of_bytes(sub_tlv.RpdIdentification.DeviceMacAddress)
        self.assertEqual(ret, (0, 0, 0, 0, 0, 0))
        rpd_data_msg.RpdData.CopyFrom(rcp_cfg)
        rcp_msg.RpdDataMessage.CopyFrom(rpd_data_msg)

        CfgMsgPayload = rcp_msg.SerializeToString()
        rsp_msg = {"Status": HalCommon_pb2.SUCCESS,
                   "ErrorDescription": "Receive RpdCapabilities success"}

        msg = HalMessage("HalConfigRsp", SrcClientID="123",
                         SeqNum=12, Rsp=rsp_msg,
                         CfgMsgType=MsgTypeRpdCapabilities,
                         CfgMsgPayload=CfgMsgPayload)
        ret = self.hal_ipc.recMsgTypeRpdCapabilitiesRspCb(msg)
        self.assertTrue(ret)

        rsp_msg = {"Status": HalCommon_pb2.FAILED,
                   "ErrorDescription": "Receive RpdCapabilities failed"}
        msg = HalMessage("HalConfigRsp", SrcClientID="123",
                         SeqNum=12, Rsp=rsp_msg,
                         CfgMsgType=MsgTypeRpdCapabilities,
                         CfgMsgPayload=CfgMsgPayload)

        ret = self.hal_ipc.recMsgTypeRpdCapabilitiesRspCb(msg)
        self.assertFalse(ret)

        # to cover the exception case

        ret = self.hal_ipc.recMsgTypeRpdCapabilitiesRspCb(rsp_msg)
        self.assertFalse(ret)

    def test_recMsgTypesCcapCoreIdentificationCb(self):
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE
        cfg_msg = config()
        sub_tlv = cfg_msg.CcapCoreIdentification.add()
        sub_tlv.Index = 1
        sub_tlv.CoreId = "1234567890"

        sub_tlv.IsPrincipal= True
        sub_tlv.CoreMode = 1
        sub_tlv.CoreId = 'CoreId'
        sub_tlv.CoreIpAddress = '1.1.1.1'
        sub_tlv.CoreName = 'CoreName'
        sub_tlv.VendorId = 12
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        CoreIdIdentMsg = HalMessage("HalConfig",
                                    SrcClientID="testGCPPL2Static",
                                    SeqNum=325,
                                    CfgMsgType=MsgTypeCcapCoreIdentification,
                                    CfgMsgPayload=cfg_payload)
        ret = self.hal_ipc.recMsgTypeRpdCapabilitiesRspCb(CoreIdIdentMsg)
        self.assertFalse(ret)

    def test_valid_rpd_cap(self):
        test = "test"
        ret = self.hal_ipc.valid_rpd_cap(test)
        self.assertFalse(ret)
        test = t_RpdCapabilities()
        GCPObject.default_gpb(test)
        ret = self.hal_ipc.valid_rpd_cap(test)
        self.assertFalse(ret)
        test = t_RpdCapabilities()
        ret = self.hal_ipc.valid_rpd_cap(test)
        self.assertTrue(ret)


if __name__ == "__main__":
    unittest.main()
