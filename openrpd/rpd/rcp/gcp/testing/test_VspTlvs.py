#
# Copyright (c) 2017 MaxLinear, Inc. ("MaxLinear") and
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

from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_lib import gcp_packet
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.rcp_lib.rcp import Message, RCPSequence, RCPMessage,\
    RCP_SEQUENCE_MIN_LEN

import subprocess
import threading
from rpd.rcp.rcp_hal import RcpHalIpc, RcpHalClientError, RcpMessageRecord, RcpMessageRecordElem, DataObj
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalDispatcher import HalDispatcher
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalConfigMsg import *
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient
import logging
import json
import rpd.hal.src.HalMain as HalMain
from rpd.hal.lib.drivers.open_rpd_drv import OpenRpdDriver
from rpd.rcp.rcp_lib.rcp import RCPSequence
#from rpd.rcp.rcp_lib import ucd
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_lib import gcp_packet

import rpd.gpb.VendorSpecificExtension_pb2 as VendorSpecificExtension_pb2
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.rcp.rcp_process import RcpHalProcess
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor
from rpd.rcp.rcp_sessions import RCPSlaveSession
from rpd.rcp.vendorTLVs.src.RcpVspTlv import RcpVendorTlv, DEFAULT_VENDOR_ID
import socket

"""
Global variables:
"""
drv_logger = None
threads_list = []


class RcpGlobalSettings(object):
    hal_ipc = None
    gDispatcher = None
    rcpProcess = None


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

    HalGlobal.gHalClientDbConnection = HalDatabase(timeStampSock, 30, 11)
    HalGlobal.gHalMsgDbConnection = HalDatabase(timeStampSock, 30, 12)


"""
demoHalmain: Bring HAL layer up as single thread.  All logs go to hal.log
"""


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


"""
demoDrvmain: Bring OpenRpdDriver driver up as single thread.  All logs go to hal.log
"""


def demoDrvmain():
    print "demoDrvmain thread start!"
    setup_logging('HAL', filename="hal.log", logging_level=logging.DEBUG)
    drv_logger = logging.getLogger("DrvMain")
    drv_logger.info("hello demo DrvMain Log")
    driver = OpenRpdDriver("openrpd_generic_driver", "This is a Generic OpenRPD Driver", "1.0.0",
                           (0, MsgTypeRcpVendorSpecific), (2, 3, 4))
    driver.start()
    print "demoDrvmain thread done!"


def demoRCP():
    print "demoRCP thread start!"
    setup_logging('HAL', filename="hal.log", logging_level=logging.DEBUG)
    drv_logger = logging.getLogger("demoRCP")
    drv_logger.info("hello demoRCP Log")
    RcpGlobalSettings.gDispatcher = Dispatcher()
    rcpProcess = RcpHalProcess("ipc:///tmp/_test_rcp_to_hal.tmp", RcpGlobalSettings.gDispatcher)

    RcpGlobalSettings.hal_ipc = RcpHalIpc("RCP-HalClient", "This is a RCP test application",
                                          "1.9.0", (1, 100, 102), rcpProcess,
                                          "../hal/conf/ClientLogging.conf", shadowLayerConf=TMP_CFG_PATH)

    try:
        if None is not RcpGlobalSettings.hal_ipc:
            RcpGlobalSettings.hal_ipc.start(rcpProcess.orchestrator.config_operation_rsp_cb,
                                            rcpProcess.orchestrator.notification_process_cb)
            RcpGlobalSettings.rcpProcess = rcpProcess
            RcpGlobalSettings.gDispatcher.loop()
        else:
            print ("demoRCP: hal_ipc is NONE")
    except Exception:
        print ("socket is destroyed, demoRCP terminated")

    print "demoRCP thread done!"


#@unittest.skip('skip RcpVspTlvTest')
class RcpVspTlvTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupDB()
        time.sleep(2)
        cls.stop = False
        HalGlobal.gClientMgr = None
        HalGlobal.gPoller = None
        t = threading.Thread(target=demoHalmain)
        t.daemon = True
        t.start()
        threads_list.append(t)
        time.sleep(2)
        t = threading.Thread(target=demoRCP)
        t.daemon = True
        t.start()
        threads_list.append(t)
        time.sleep(2)
        if not HalGlobal.gClientMgr or not HalGlobal.gPoller:
            raise Exception("Cannot start the demo halMain")
        t = threading.Thread(target=demoDrvmain)
        t.daemon = True
        t.start()
        threads_list.append(t)
        time.sleep(2)

        cls.hal_ipc = RcpGlobalSettings.hal_ipc
        cls.dispatcher = RcpGlobalSettings.gDispatcher
        cls.rcpProcess = RcpGlobalSettings.rcpProcess

        # Create a VSP TLV Sequence
        cls.vsp_tlv_seq = RcpVendorTlv()

        # Create a VSP TLV Sequence (unmatched Vendor ID.  OpenRpdDriver will reject this)
        cls.vsp_tlv_seq_unmatched_vid = RcpVendorTlv(vendorID=(DEFAULT_VENDOR_ID - 1000))

    @classmethod
    def tearDownClass(cls):
        if None is not RcpGlobalSettings.hal_ipc:
            RcpGlobalSettings.hal_ipc.connection_cleanup(RcpGlobalSettings.gDispatcher)
        else:
            print ("tearDown: RcpGlobalSettings.hal_ipc is None!")
        if None is not RcpGlobalSettings.gDispatcher:
            RcpGlobalSettings.gDispatcher.end_loop()
        else:
            print ("tearDown: RcpGlobalSettings.gDispatcher is None!")

        HalGlobal.StopHal = True

        #os.system("ps ax |grep python|awk '{print $1}'|xargs kill -9")
        # time.sleep(2)
        subprocess.call(["killall", "redis-server"])
        time.sleep(4)
        for t in threads_list:
            if (t is not None and t.isAlive):
                t.join(2)

    def fake_cb(self, cb):
        print "fake cb handled"

    # GANG OF FIVE SKIP
    @unittest.skip('skip test_send_vsp_tlv_to_drv')
    def test_send_vsp_tlv_to_drv(self):
        """
        Send 2 RCP Sequences: 1 with READ, 1 with WRITE
        """
        print "test_send_vsp_tlv_to_drv\n"

        timeOut = time.time() + 5
        while self.hal_ipc is not None and self.hal_ipc.disconnected and time.time() < timeOut:
            pass

        desc = GCPSlaveDescriptor(
            "127.0.0.1", port_master=9999, addr_local="127.0.0.1",
            interface_local="lo",
            addr_family=socket.AF_INET)
        dummy_session = RCPSlaveSession(desc, self.dispatcher,
                                        self.fake_cb,
                                        self.fake_cb,
                                        self.fake_cb)

        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': [self.vsp_tlv_seq.create_vendor_tlvs_sequence(
                gcp_msg_def.NotifyREQ,
                rcp_tlv_def.RCP_MSG_TYPE_NTF,
                rcp_tlv_def.RCP_OPERATION_TYPE_READ),
                self.vsp_tlv_seq.create_vendor_tlvs_sequence(
                gcp_msg_def.NotifyREQ,
                rcp_tlv_def.RCP_MSG_TYPE_NTF,
                rcp_tlv_def.RCP_OPERATION_TYPE_WRITE), ],
        }
        if None is not self.hal_ipc:
            self.hal_ipc.rcp_cfg_req(ipc_msg)

        time.sleep(1)
        pkt_db = self.hal_ipc.msg_record.pkt_db
        pkt_db_len = len(pkt_db)

        # since the seq contains matched vendor id, so all RCP sequences should be sent to driver
        self.assertTrue(pkt_db_len == 0)

    # GANG OF FIVE SKIP
    @unittest.skip('skip test_send_vsp_tlv_unmatched_vid_to_drv')
    def test_send_vsp_tlv_unmatched_vid_to_drv(self):
        print "test_send_vsp_tlv_unmatched_vid_to_drv\n"

        timeOut = time.time() + 5
        while self.hal_ipc is not None and self.hal_ipc.disconnected and time.time() < timeOut:
            pass

        desc = GCPSlaveDescriptor(
            "127.0.0.1", port_master=9999, addr_local="127.0.0.1",
            interface_local="lo",
            addr_family=socket.AF_INET)
        dummy_session = RCPSlaveSession(desc, self.dispatcher,
                                        self.fake_cb,
                                        self.fake_cb,
                                        self.fake_cb)
        seq = self.vsp_tlv_seq_unmatched_vid.create_vendor_tlvs_sequence(
            gcp_msg_def.NotifyREQ,
            rcp_tlv_def.RCP_MSG_TYPE_NTF,
            rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        ipc_msg = {
            'session': dummy_session,
            'req_packet': "dummy-packet",
            'gcp_msg': "dummy-message",
            'req_data': [seq, ],
        }
        if None is not self.hal_ipc:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        time.sleep(1)

        pkt_db = self.hal_ipc.msg_record.pkt_db
        pkt_db_len = len(pkt_db)

        # since the seq contains unmatched vendor id, but there is no check for vid
        # so this VendorSpecificExtension TLV still sent to driver.
        self.assertTrue(pkt_db_len == 0)

    #@unittest.skip('skip test_add_avp')
    def test_create_vendor_tlv_seq(self):
        print "test_create_vendor_tlv_seq"
        seq = self.vsp_tlv_seq.create_vendor_tlvs_sequence(
            gcp_msg_def.NotifyREQ,
            rcp_tlv_def.RCP_MSG_TYPE_NTF,
            rcp_tlv_def.RCP_OPERATION_TYPE_DELETE)

        buf = seq.encode()
        self.assertIsNotNone(buf)
        # print str(buf) + ", len %d" %len(buf)

        seq_dec = self.vsp_tlv_seq.create_vendor_tlvs_sequence(
            gcp_msg_def.NotifyREQ,
            rcp_tlv_def.RCP_MSG_TYPE_NTF,
            rcp_tlv_def.RCP_OPERATION_TYPE_DELETE)

        self.assertEqual(seq_dec.decode(buf, offset=0, buf_data_len=len(buf)), seq_dec.DECODE_DONE)
        time.sleep(2)
        pass

    #@unittest.skip('skip test_msg_with_tlv')
    def test_msg_with_tlv(self):
        print "test_msg_with_tlv"
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(gcp_msg_def.NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)

        seq = self.vsp_tlv_seq.create_vendor_tlvs_sequence(
            gcp_msg_def.NotifyREQ,
            rcp_tlv_def.RCP_MSG_TYPE_NTF,
            rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)

        rcp_msg = RCPMessage(gcp_msg_def.NotifyREQ,
                             rcp_tlv_def.RCP_MSG_TYPE_NTF)

        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        buf = msg.encode()
        self.assertIsNotNone(buf)

        msg_dec = Message(gcp_msg_def.NotifyREQ)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)
        # self.assertTrue(msg._ut_compare(msg_dec))
        time.sleep(2)

    def test_msg_with_op_aw(self):
        print "test_msg_with_aw_tlv"
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(gcp_msg_def.NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)

        seq = self.vsp_tlv_seq.create_vendor_tlvs_sequence(
            gcp_msg_def.NotifyREQ,
            rcp_tlv_def.RCP_MSG_TYPE_IRA,
            rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE)

        rcp_msg = RCPMessage(gcp_msg_def.NotifyREQ,
                             rcp_tlv_def.RCP_MSG_TYPE_NTF)

        msg.tlv_data.rcp_msgs.append(rcp_msg)
        rcp_msg.sequences.append(seq)

        buf = msg.encode()
        self.assertIsNotNone(buf)

        msg_dec = Message(gcp_msg_def.NotifyREQ)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)


if __name__ == "__main__":
    unittest.main()
