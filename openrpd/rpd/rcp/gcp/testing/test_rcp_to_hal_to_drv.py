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
import subprocess
import threading
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
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
#from rpd.rcp.gcp.gcp_lib.ucd_pb2 import ucd as ucd_gpb
from rpd.hal.src.HalConfigMsg import RCP_TO_HAL_MSG_TYPE
from rpd.gpb.cfg_pb2 import config
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.rcp.rcp_process import RcpHalProcess
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor
from rpd.rcp.rcp_sessions import RCPSlaveSession
import socket

drv_logger = None
threads_list = []

class RcpGlobalSettings(object):
    hal_ipc = None
    gDispatcher = None

def create_cfg_read_sequence():

    seq = RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                      0,
                      rcp_tlv_def.RCP_OPERATION_TYPE_READ)

    # seq.RpdCapabilities.set_is_used()
    # seq.RpdCapabilities.NumBdirPorts.set_is_used()
    # seq.RpdCapabilities.NumAsyncVideoChannels.set_is_used()
    seq.RpdCapabilities.NumBdirPorts.set_val(1)
    # seq.RpdCapabilities.RpdIdentification.VendorName.set_val('31')
    # seq.RpdCapabilities.RpdIdentification.VendorId.set_val('32')
    # seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
        # (0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56))
    # seq.RpdCapabilities.RpdIdentification.SerialNumber.set_val('33')

    return seq


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

def demoDrvmain():
    print "demoDrvmain thread start!"
    setup_logging('HAL', filename="hal.log",logging_level=logging.DEBUG)
    drv_logger = logging.getLogger("DrvMain")
    drv_logger.info("hello demo DrvMain Log")
    driver = OpenRpdDriver("openrpd_generic_driver", "This is a Generic OpenRPD Driver", "1.0.0",
                             (0,10000), (2, 3, 4))
    driver.start()
    print "demoDrvmain thread done!"

def demoRCP():
    print "demoRCP thread start!"
    setup_logging('HAL', filename="hal.log",logging_level=logging.DEBUG)
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
            RcpGlobalSettings.gDispatcher.loop()
        else:
            print ("demoRCP: hal_ipc is NONE")
    except Exception:
        print ("socket is destroyed, demoRCP terminated")

    print "demoRCP thread done!"


class RcpHalConfigTest(unittest.TestCase):

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
        time.sleep(5)
        t = threading.Thread(target=demoRCP)
        t.daemon = True
        t.start()
        threads_list.append(t)
        time.sleep(5)
        if not HalGlobal.gClientMgr or not HalGlobal.gPoller:
            raise Exception("Cannot start the demo halMain")
        t = threading.Thread(target=demoDrvmain)
        t.daemon = True
        t.start()
        threads_list.append(t)        
        time.sleep(5)

    @classmethod
    def tearDownClass(cls):
        HalGlobal.StopHal = True
        time.sleep(4)
        #os.system("ps ax |grep python|awk '{print $1}'|xargs kill -9")
        #time.sleep(2)
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)
        for t in threads_list:
            if (t is not None and t.isAlive):
                t.join(2)


    def setUp(self):
        self.hal_ipc = RcpGlobalSettings.hal_ipc
        self.dispatcher = RcpGlobalSettings.gDispatcher

    def fake_cb(self, cb):
        print "fake cb handled" 

    def test_get_cfg(self):
        print "test_get_cfg\n"
        timeOut = time.time() + 10
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
            'req_data': [create_cfg_read_sequence(), ],
        }
        if None is not self.hal_ipc:
            self.hal_ipc.rcp_cfg_req(ipc_msg)
        else:
            print ("test_get_cfg: self.hal_ipc is None!")
        time.sleep(5)

    """
    def tearDown(self):
        print "tearDown\n"
        if None is not self.hal_ipc:
            self.hal_ipc.connection_cleanup(self.dispatcher)
        else:
            print ("tearDown: self.hal_ipc is None!")
        if None is not self.dispatcher:
            self.dispatcher.end_loop()
        else:
            print ("tearDown: self.dispatcher is None!")
    """

if __name__ == "__main__":
    unittest.main()
