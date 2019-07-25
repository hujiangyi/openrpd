#
# Copyright (c) 2016 Cisco and/or its affiliates,
#                    MaxLinear, Inc. ("MaxLinear"), and
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
import os
#import random as randint
import subprocess
import threading
import logging
import json
#import rpd.python_path_resolver
import rpd.hal.src.HalMain as HalMain
from random import randint

from rpd.dispatcher.dispatcher import Dispatcher
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.hal.src.db.HalDatabase import HalDatabase
from rpd.hal.src.HalDispatcher import HalDispatcher
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalConfigMsg import *
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient
from rpd.hal.lib.drivers.open_rpd_drv import OpenRpdDriver
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3Hal import L2tpHalClient
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
from rpd.l2tp.l2tpv3.src.L2tpv3AVP import l2tpv3AVP
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from vendorAVPs.src.L2tpv3VspAvps import *
from l2tpv3.src.L2tpv3Connection import L2tpConnection
from l2tpv3.src.L2tpv3Session import L2tpv3Session
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from l2tpv3.src.L2tpv3ControlPacket import L2tpv3ControlPacket
from l2tpv3.src.L2tpv3Fsm import L2tpv3SessionSenderFsm, L2tpv3SessionRecipientFsm
from l2tpv3.src.L2tpv3RFC3931AVPs import CallSerialNumber
from l2tpv3.src.L2tpv3RFC3931AVPs import ControlMessageAVP
from l2tpv3.src.L2tpv3RFC3931AVPs import LocalSessionID
from l2tpv3.src.L2tpv3RFC3931AVPs import RemoteSessionID
from l2tpv3.src.L2tpv3Session import L2tpv3Session


"""
Global variables:
"""
drv_logger = None
threads_list = []

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
    interestedNotification = list()
    interestedNotification.append(MsgTypeVspAvpExchange)
    driver = OpenRpdDriver("openrpd_generic_driver", "This is a Generic OpenRPD Driver", "1.0.0",
                           tuple((0, 5000)), (2, 3, 4), interestedNotification)
    driver.start()
    print "demoDrvmain thread done!"


"""
demoL2tp: Bring L2TP up as single thread.  All logs go to hal.log
"""


def demoL2tp():
    print "demoL2tp thread start!"
    setup_logging('HAL', filename="hal.log", logging_level=logging.DEBUG)
    drv_logger = logging.getLogger("demoL2tp")
    drv_logger.info("hello demoL2tp Log")

    dispatcher = Dispatcher()
    l2tp_dispatcher = L2tpv3Dispatcher(
        dispatcher,
        local_addr=None,
        # since we don't create global listen, set it to None
        create_global_listen=False)
    L2tpv3GlobalSettings.Dispatcher = l2tp_dispatcher

    # setup the halclient
    SupportedCfgMsg = list()
    SupportedCfgMsg.append(MsgTypeVspAvpExchange)
    notificationMsg = list()
    notificationMsg.append(MsgTypeL2tpv3SessionStatusNotification)
    hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                               "the HAL client of L2TP feature",
                               "1.0", tuple(notificationMsg), dispatcher, SupportedCfgMsg)
    L2tpv3GlobalSettings.l2tp_hal_client = hal_client
    hal_client.start(l2tp_dispatcher.receive_hal_message)
    if L2tpv3GlobalSettings.l2tp_hal_client:
        print ("setup l2tp hal client successfully")

    if L2tpv3GlobalSettings.Dispatcher:
        print ("l2tp_dispatcher is OK")
        print l2tp_dispatcher

    l2tp_dispatcher.dispatcher.loop()
    print "demoL2tp thread done!"

#@unittest.skip('skip L2tpHalDrvVspAvpTest')
# This is commented out due to it creates some errors
# when run together with .jenkins.  If run alone, it is OK.
# Will be activated later


class L2tpHalDrvVspAvpTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupDB()
        time.sleep(2)

        HalGlobal.gClientMgr = None
        HalGlobal.gPoller = None
        t = threading.Thread(target=demoHalmain)
        t.daemon = True
        t.start()
        time.sleep(2)
        threads_list.append(t)
        if not HalGlobal.gClientMgr or not HalGlobal.gPoller:
            raise Exception("Cannot start the demo halMain")
        t = threading.Thread(target=demoL2tp)
        t.daemon = True
        t.start()
        time.sleep(2)
        threads_list.append(t)
        t = threading.Thread(target=demoDrvmain)
        t.daemon = True
        t.start()
        threads_list.append(t)
        time.sleep(2)

        setup_logging('HAL', filename="hal.log", logging_level=logging.DEBUG)
        cls.logger = logging.getLogger("L2tpHalDrvVspAvpTest")
        cls.logger.info("hello L2tpHalDrvVspAvpTest Log")

        cls.stop = False
        cls.conn_address = '127.0.0.1'
        # Setup connection/session: set it here since global variables are already only after threads are up.
        cls.dispatcher = L2tpv3GlobalSettings.Dispatcher
        cls.hal_client = L2tpv3GlobalSettings.l2tp_hal_client
        # cls.conn = L2tpConnection.L2tpConnection(
        #    6661, 6662, cls.conn_address, cls.conn_address)
        #cls.session = L2tpv3Session.L2tpv3Session(6661, 6662, 'receiver',cls.conn)
        # cls.conn.addSession(cls.session)
        localSessionId = L2tpv3RFC3931AVPs.LocalSessionID(6661)
        remoteSessionId = L2tpv3RFC3931AVPs.RemoteSessionID(6662)
        remoteEnd = L2tpv3RFC3931AVPs.RemoteEndID(
            (((0, 3, 0), 0), ((0, 3, 1), 1), ((0, 3, 2), 2)))
        remoteEnd_1 = L2tpv3RFC3931AVPs.RemoteEndID(
            (((0, 3, 3), 3), ((0, 3, 4), 4), ((0, 3, 5), 5)))
        pw_type = L2tpv3RFC3931AVPs.L2SpecificSublayer(3)
        DepiL2SpecificSublayerSubtype = L2tpv3CableLabsAvps.DepiL2SpecificSublayerSubtype(3)
        LocalMTUCableLabs = L2tpv3CableLabsAvps.LocalMTUCableLabs(1500)

        cls.avps_icrq = []
        cls.avps_icrq.append(localSessionId)
        cls.avps_icrq.append(remoteSessionId)
        cls.avps_icrq.append(remoteEnd)
        cls.avps_icrq.append(remoteEnd_1)
        cls.avps_icrq.append(DepiL2SpecificSublayerSubtype)
        cls.avps_icrq.append(LocalMTUCableLabs)
        cls.avps_icrq.append(pw_type)

        cls.icrq_buf = struct.pack('!206B',
                                   0xc8, 0x03, 0x0, 206,
                                   0x0, 0x0, 0x0, 0x0,
                                   0x0, 0x3, 0x0, 0x4,
                                   0xc, 8, 0x0, 0x0,
                                   0x0, 0x0, 0x0, 10,
                                   0xc, 10, 0x0, 0x0,
                                   0, 15, 0, 0,
                                   0, 0,
                                   0xc, 10, 0x0, 0x0,
                                   0, 63, 0x40, 0x01,
                                   0x00, 0x01,
                                   0xc, 10, 0x0, 0x0,
                                   0, 64, 0x0, 0x0,
                                   0x0, 0x0,
                                   0xc, 40, 0x0, 0x0,
                                   0x0, 66, 0x0, 0x0,
                                   0x00, 0x03, 0x00, 0x00,
                                   0x00, 0x03, 0x01, 0x01,
                                   0x00, 0x03, 0x02, 0x02,
                                   0x00, 0x03, 0x03, 0x03,
                                   0x00, 0x03, 0x04, 0x04,
                                   0x00, 0x03, 0x05, 0x05,
                                   0x00, 0x03, 0x06, 0x06,
                                   0x00, 0x03, 0x07, 0x07,
                                   0xc, 8, 0, 0,
                                   0, 68, 0, 12,
                                   0xc, 8, 0, 0,
                                   0, 69, 0, 3,
                                   0xc, 8, 0, 0,
                                   0, 71, 0, 2,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 0x2, 0x1, 0x0,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 0x4, 0x7, 0xD0,
                                   0xc, 20, 0x11, 0x8b,
                                   0x0, 15, 0x0, 0x1,
                                   0x0, 0x2, 0x0, 0x3,
                                   0x0, 0x6, 0x0, 0x8,
                                   0x0, 11, 0x0, 13,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 16, 0x0, 0x3,
                                   0xc, 8, 0x11, 0x8b,
                                   0x0, 17, 0x0, 0x3,
                                   0xc, 40, 0x11, 0x8b,
                                   0x0, 11, 0, 0,
                                   0x5, 0x6, 0x7, 0x8,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   229, 1, 1, 255,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   0, 0, 0, 0,
                                   )

    @classmethod
    def tearDownClass(cls):
        HalGlobal.StopHal = True
        l2tp_dispatcher = L2tpv3GlobalSettings.Dispatcher
        if l2tp_dispatcher is not None:
            l2tp_dispatcher.dispatcher.end_loop()
        time.sleep(2)
        # os.system("ps ax |grep HalMain|awk '{print $1}'|xargs kill -9")
        # time.sleep(2)
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)
        for t in threads_list:
            if (t is not None and t.isAlive):
                t.join(1)

    #@unittest.skip('skip test_add_avp')
    def test_add_avp(self):
        print "test_add_avp"
        vsp_avp_attrType1 = 1
        vsp_avp_attrType2 = 2
        vsp_avp2_attrValue = "sample2"
        vsp_avp = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType1, attrValue="1234567890")
        vsp_avp2 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2, attrValue=vsp_avp2_attrValue)
        vsp_avps = l2tpv3VspAvps()
        self.assertTrue(vsp_avps is not None)
        l2tpv3VspAvps().add_VspAvp(vsp_avp)
        l2tpv3VspAvps().add_VspAvp(vsp_avp2)

        buf = vsp_avp.encode()
        print buf
        vsp_avp1 = vsp_avp.decodeAll(buf)
        for (vid, attr) in l2tpv3AVP.SubclassMapping.keys():
            vsp_avp = l2tpv3AVP.SubclassMapping[(vid, attr)]
            print vsp_avp

        # Get back vsp_avp2 using its vsp_avp_attrType2.
        vsp_avp2_ori = vsp_avps.get_VspAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2)
        self.assertTrue(vsp_avp2_attrValue == str(vsp_avp2_ori.attrValue))

    #@unittest.skip('skip test_get_VspAvp')
    def test_get_VspAvp(self):
        print "test_get_attrType: try to get a match for vendorID: (%d)" % (DEFAULT_VENDOR_ID)

        vsp_avps = l2tpv3VspAvps()
        for i in range(0, 1000):
            attr = randint(-50, 50)
            vspAvp = vsp_avps.get_VspAvp(DEFAULT_VENDOR_ID, attr)
            if (vspAvp) is not None and isinstance(vspAvp, l2tpv3SampleVendorAvp):
                print "Get a match Vendor AVP with (vid=%d,attr=%d)" % (DEFAULT_VENDOR_ID, attr)
                print vspAvp

    # GANG OF FIVE SKIP
    @unittest.skip('skip test_update_notify_avp')
    def test_update_notify_avp(self):
        print "test_update_notify_avp\n"

        vsp_avp_attrType1 = 10
        vsp_avp_attrType2 = 20
        vsp_avp_attrType3 = 30
        vsp_avp = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType1, notifyVendor=1, attrValue="29343230333")
        vsp_avp2 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2, UpdateOpt=1, attrValue="Sample2")
        vsp_avp3 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType3, UpdateOpt=1, attrValue="Sample3")
        vsp_avps = l2tpv3VspAvps()
        self.assertTrue(vsp_avps is not None)
        vsp_avps.add_VspAvp(vsp_avp)
        vsp_avps.add_VspAvp(vsp_avp2)
        vsp_avps.add_VspAvp(vsp_avp3)

        # sendupdate_VspAvp: should be called at boot time by l2tp_agent to update VSP AVPs in
        # l2tpv3AVP.SubclassMapping[].
        # In this test, only vsp_avp2/vsp_avp3 will get updated because it has UpdateOpt == 1
        vsp_avp2_attr_val = str(vsp_avp2.attrValue)
        vsp_avp3_attr_val = str(vsp_avp3.attrValue)
        # print "vsp_avp2 before:"
        # print vsp_avp2_attr_val
        # print "vsp_avp3 before:"
        # print vsp_avp3_attr_val
        vsp_avps.sendupdate_VspAvp()
        # it takes about 12ms to complete, so sleep for 1s.
        time.sleep(1)
        vsp_avp2_after = vsp_avps.get_VspAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2)
        vsp_avp3_after = vsp_avps.get_VspAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType3)
        # print "vsp_avp2 after:"
        # print str(vsp_avp2_after.attrValue)
        # print "vsp_avp3 after:"
        # print str(vsp_avp3_after.attrValue)

        # sendnotify_VspAvp: should be called in L2tpHalClient.fill_session_req_req_data()
        # In this test, OpenRPD driver gets notify about vsp_avp only because it has notifyVendor == 1
        # vsp_avps.sendnotify_VspAvp(DEFAULT_VENDOR_ID,20)

        # these 2 pairs of vsp_avp should NOT be equal since the driver has changed them
        self.assertTrue(vsp_avp2_attr_val != str(vsp_avp2_after.attrValue))
        self.assertTrue(vsp_avp3_attr_val != str(vsp_avp3_after.attrValue))
        time.sleep(1)

    # GANG OF FIVE SKIP
    @unittest.skip('skip test_notify_drv_of_vsp_avp')
    def test_notify_drv_of_vsp_avp(self):
        print "test_notify_drv_of_vsp_avp\n"

        vsp_avp_attrType1 = 10
        vsp_avp_attrType2 = 20
        vsp_avp = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType1, notifyVendor=NOTIFY_OPTION_ON, attrValue="11111111111")
        vsp_avp1 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2, notifyVendor=NOTIFY_OPTION_ON, attrValue="222222222222")
        vsp_avps = l2tpv3VspAvps()
        self.assertTrue(vsp_avps is not None)
        vsp_avps.add_VspAvp(vsp_avp)
        vsp_avps.add_VspAvp(vsp_avp1)
        # Add vsp_avp1 to session.avps_icrq
        self.avps_icrq.append(vsp_avp)
        self.avps_icrq.append(vsp_avp1)

        vsp_avps.sendnotify_VspAvps(self.avps_icrq)
        #req_msg = L2tpv3Hal_pb2.t_l2tpSessionReq()
        #ret = self.hal_client.fill_session_req_req_data(self.session, L2tpv3Session.ADD_SESSION, req_msg.req_data)
        # self.assertTrue(ret)

    #@unittest.skip('skip test_append_VspAvp')
    def test_append_VspAvp(self):
        print "test_append_VspAvp\n"

        vsp_avp_attrType1 = 10
        vsp_avp_attrType2 = 20
        vsp_avp1 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType1, attrValue="11111111111")
        vsp_avp2 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2, notifyVendor=1, attrValue="222222222222")

        # vsp_avp3 has OutCtrlPktList set to L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP, and it will be
        # appended to the avps list, and vsp_avp1 will not.
        ctrlIdsList = []
        ctrlIdsList.append(L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP)
        vsp_avp_attrType3 = 30
        vsp_avp3_attrValue = "3333333333"
        vsp_avp3 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType3,
                                         OutCtrlIds=ctrlIdsList,
                                         attrValue=vsp_avp3_attrValue)

        vsp_avps = l2tpv3VspAvps()
        self.assertTrue(vsp_avps is not None)
        vsp_avps.add_VspAvp(vsp_avp1)
        vsp_avps.add_VspAvp(vsp_avp2)
        vsp_avps.add_VspAvp(vsp_avp3)

        avps = list()
        avps.append(L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP))
        avps.append(L2tpv3RFC3931AVPs.SbfdVccv(
            L2tpv3RFC3931AVPs.SbfdVccv.VccvValue))

        vsp_avps.append_VspAvp(avps, L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP)
        # vsp_avp3 should be in avps list now
        found_vsp_avp_in_icrp = 0
        for avp in avps:
            if (isinstance(avp, l2tpv3SampleVendorAvp) and
                    avp.attrValue == vsp_avp3_attrValue):
                found_vsp_avp_in_icrp = 1
        self.assertEqual(found_vsp_avp_in_icrp, 1)

    #@unittest.skip('skip test_handleAvp')
    def test_handleAvp(self):
        vsp_avp_attrType1 = 10
        vsp_avp_attrType2 = 20
        vsp_avp1 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType1, attrValue="11111111111")
        vsp_avp2 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType2, notifyVendor=1, attrValue="222222222222")
        ctrlIdsList = []
        ctrlIdsList.append(L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP)
        vsp_avp_attrType3 = 30
        vsp_avp3_attrValue = "3333333333"
        vsp_avp3 = l2tpv3SampleVendorAvp(DEFAULT_VENDOR_ID, vsp_avp_attrType3,
                                         OutCtrlIds=ctrlIdsList,
                                         attrValue=vsp_avp3_attrValue)

        # Receive a good ICRQ, send a ICRP
        session_receiver = L2tpv3Session(0, 1, 'receiver')
        icrq = L2tpv3ControlPacket.decode(self.icrq_buf)
        # append couple VSP AVP
        icrq.avps.append(vsp_avp1)
        icrq.avps.append(vsp_avp2)
        icrq.avps.append(vsp_avp3)
        # print icrq

        # icrq.SetPktConnection(self.conn)
        # icrq.SetPktSession(session_receiver)
        #icrp = session_receiver.ReceiveICRQ(icrq)
        # Observe that only vsp_avp3 is appended to icrp
        # self.assertEqual(
        #    session_receiver.fsm.current, L2tpv3SessionRecipientFsm.StateWaitConn)
        #self.assertEqual(icrp.avps[0].messageType, ControlMessageAVP.ICRP)

        avps = list()
        avps.append(L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP))
        icrp = L2tpv3ControlPacket(6600, 0, 0, avps)
        for avp in icrq.avps:
            avp.handleAvp(icrq, icrp)

        # vsp_avp3 has non-None OutCtrlIds so it should be moved from icrq to icrp now
        found_vsp_avp_in_icrp = 0
        for avp in icrp.avps:
            if (isinstance(avp, l2tpv3SampleVendorAvp) and
                    avp.attrValue == vsp_avp3_attrValue):
                found_vsp_avp_in_icrp = 1

        self.assertEqual(found_vsp_avp_in_icrp, 1)


if __name__ == "__main__":
    unittest.main()
