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
import os
import time
import zmq
import tftpy
import unittest
import subprocess
import signal
import threading
from rpd.hal.src.HalConfigMsg import *
from zmq.utils.monitor import recv_monitor_message
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalPoller
from rpd.ssd.HalSsdDriver import *
from rpd.hal.simulator.start_hal import start_hal
from rpd.common.rpd_logging import setup_logging
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.gpb.cfg_pb2 import config

redis_sock_file = "/tmp/testHalSsdRedis" + \
                time.strftime("%d%H%M%S", time.localtime()) + ".sock"

hal_conf_content = """
{
    "db":{
        "address":"%s",
        "timeout":30,
        "msgDB":12,
        "indexDB":11
    }
}
""" % redis_sock_file

hal_conf_file_name = "/tmp/test_hal_ssd.conf"
hal_process = None


def setup_db():
    global hal_process
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
                           redis_sock_file + " \nunixsocketperm 700\n"
    filename = "/tmp/test_halagentd.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    # generate the hal_conf_file
    with open(hal_conf_file_name, "w") as f:
        f.write(hal_conf_content)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(redis_sock_file):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")

    hal_process = start_hal(hal_cfg_file=hal_conf_file_name)


class HalClientTest(HalSsdDriver):
    BOOT_ROOT_PATH = '/tmp/'
    BOOT_IMAGE_PATH = '/tmp/imagea'
    INIT_CODE_PATH = '/tmp/initcode'
    LOCAL_FILE_PATH = '/tmp/codefile.local'


    def connect_to_hal(self):
        self.connectionSetup()
        self.register(self.drvID)
        i = 0
        while i < 5:
            socks = self.poller.poll(1000)
            print socks
            i += 1
            if not socks:
                continue
            for sock in socks:
                if self.pushSock is not None and sock == self.pushSock.monitor:
                    self.pushSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if self.pullSock is not None and sock == self.pullSock.monitor:
                    self.pullSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if self.mgrConnection is not None and sock == self.mgrConnection.monitor:
                    self.mgrConnection.monitorHandler(
                        recv_monitor_message(sock))
                    continue
                if socks[sock] == HalPoller.POLLIN:
                    try:
                        bin = sock.recv(flags=zmq.NOBLOCK)
                        msg = HalMessage.DeSerialize(bin)
                        print msg.msg
                        self.logger.debug("Got a zmq msg:%s" % msg.msg)
                        if msg.type in self.HalMsgsHandler:
                            handler = self.HalMsgsHandler[msg.type]
                            handler(msg)
                        else:
                            self.logger.error("Unsupported msg type:%s" % msg.type)
                    except zmq.ZMQError as e:
                        self.logger.debug(
                            "Got an error when trying with non-block read:" + str(e))
                    except Exception as e:
                        self.logger.error(
                            "Error happens, reason:%s" % str(e))
                continue

    def close_connection(self):
        self.poller.unregister(self.pullSock.socket)
        self.poller.unregister(self.pullSock.monitor)
        self.poller.unregister(self.pushSock.monitor)
        self.poller.unregister(self.mgrConnection.socket)
        self.poller.unregister(self.mgrConnection.monitor)
        self.pullSock.close()
        self.pushSock.close()
        self.mgrConnection.socket.disable_monitor()
        self.mgrConnection.monitor.close()
        self.mgrConnection.close()


class HalClientTestErrorRsp(HalClientTest):
    def sendCfgRspMsg(self, cfg, rsp=None):
        """The configuration response routine, the driver implementor should fill sth into this function.

        :param cfg: The original configuration message
        :return:

        """
        cfgMsg = cfg.msg
        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=cfgMsg.SeqNum,
            Rsp={
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": ""
            },
            CfgMsgType=cfgMsg.CfgMsgType,
            CfgMsgPayload=cfgMsg.CfgMsgPayload)
        self.pushSock.send(msg.Serialize())


class TestSsdMgr(unittest.TestCase):

    def test_mgr(self):
        mgr = SsdManager()
        mgr.ipcEntry('')
        mgr.connectionSetup()
        mgr.ipcEntry(None)

        # ret = mgr.ssd_start(HalSsdDriver.TRIGGER_GCP)
        # self.assertFalse(ret)
        # ret = mgr.get_af_type()
        # self.assertFalse(ret)
        # ret = mgr.ssd_end('error')
        # self.assertFalse(ret)


class TestSsdDriver(unittest.TestCase):

    TFTP_PORT = 10086
    HTTP_PORT = 10087

    @classmethod
    def setUpClass(cls):
        setup_db()
        os.system("mkdir -p /tmp/ssd")
        time.sleep(1)
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") - 2
        cls.rootpath = "/".join(dirs[:rpd_index])
        cls.mgr_pid = subprocess.Popen("coverage run --parallel-mode --rcfile=" + cls.rootpath + "/.coverage.rc "
                                        + cls.rootpath +
                                        "/rpd/provision/manager/src/manager_main.py -s",
                                        executable='bash', shell=True)
        time.sleep(1)
        cls.tftp_pid = subprocess.Popen("coverage run --parallel-mode --rcfile=" + cls.rootpath + "/.coverage.rc "
                                         + cls.rootpath +
                                         "/rpd/ssd/testing/start_tftp_server.py --root "
                                         + cls.rootpath + " --server 127.0.0.1 --port "
                                         + str(cls.TFTP_PORT), executable='bash', shell=True)

        time.sleep(3)

    @classmethod
    def tearDownClass(cls):
        if hal_process is not None:
            hal_process.terminate()
        cls.mgr_pid.send_signal(signal.SIGINT)
        cls.mgr_pid.wait()
        cls.tftp_pid.send_signal(signal.SIGINT)
        cls.tftp_pid.wait()
        os.system('rm -rf /tmp/ProcessAgent_AGENTTYPE_*')
        subprocess.call(["killall", "python"])
        subprocess.call(["killall", "redis-server"])

    @unittest.skip('skip test_ssd_process')
    def test_ssd_process(self):
        if os.path.exists(HalClientTest.INIT_CODE_PATH):
            os.system('rm ' + HalClientTest.INIT_CODE_PATH)
        rootca = self.rootpath + '/rpd/ssd/testing/CABLELABS_ROOT_CA_PEM.CRT'
        driver = HalClientTest("SSD_Driver", "This is SSD Driver", "0.1.0",
                               (MsgTypeSsd,), None, rootca=rootca)
        driver.get_init_code()
        # driver.connect_to_hal()
        driver.start(simulate_mode=True)
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}
        # gcp: normal case
        driver.initCode = initcode
        driver.codeFile = CodeFileVerify(driver.initCode, rootca=rootca)

        cfgMsgPayload = t_RcpMessage()
        cfgMsgPayload.RcpMessageType = cfgMsgPayload.RPD_CONFIGURATION
        cfgMsgPayload.RpdDataMessage.RpdDataOperation = cfgMsgPayload.RpdDataMessage.RPD_CFG_WRITE
        cfg = config()
        ssd = cfg.Ssd
        ssd.SsdServerAddress = '127.0.0.1'
        ssd.SsdTransport = driver.TRANSPORT_TFTP
        ssd.SsdFilename = self.rootpath + '/rpd/ssd/testing/codefile'
        ssd.SsdStatus = 1
        ssd.SsdManufCvcChain = open(self.rootpath + '/rpd/ssd/testing/mfr_cvc.der', 'r').read()
        ssd.SsdCosignerCvcChain = open(self.rootpath + '/rpd/ssd/testing/mso_cvc.der', 'r').read()
        ssd.SsdControl = driver.START
        cfgMsgPayload.RpdDataMessage.RpdData.CopyFrom(cfg)

        # get ssd status when init
        cfgMsgPayload.RpdDataMessage.RpdDataOperation = cfgMsgPayload.RpdDataMessage.RPD_CFG_READ
        msg = HalMessage("HalConfig", SrcClientID='123456789',
                         SeqNum=1,
                         CfgMsgType=MsgTypeSsd,
                         CfgMsgPayload=cfgMsgPayload.SerializeToString())

        driver.recvCfgMsgCb(msg)

        # trigger ssd
        cfgMsgPayload.RpdDataMessage.RpdDataOperation = cfgMsgPayload.RpdDataMessage.RPD_CFG_WRITE
        msg = HalMessage("HalConfig", SrcClientID='123456789',
                         SeqNum=1,
                         CfgMsgType=MsgTypeSsd,
                         CfgMsgPayload=cfgMsgPayload.SerializeToString())

        driver.recvCfgMsgCb(msg)

        self.assertTrue('SsdServerAddress' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdServerAddress'], ssd.SsdServerAddress)
        self.assertTrue('SsdManufCvcChain' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdManufCvcChain'], ssd.SsdManufCvcChain)
        self.assertTrue('SsdCosignerCvcChain' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdCosignerCvcChain'], ssd.SsdCosignerCvcChain)
        self.assertEqual(driver.isProcessRunning, driver.TRIGGER_GCP)

        driver.ssdParam['SsdServerPort'] = self.TFTP_PORT
        # origin_size = os.stat(ssd.SsdFilename).st_size
        # if os.path.exists(driver.LOCAL_FILE_PATH):
        #     os.system('rm -f ' + driver.LOCAL_FILE_PATH)
        # driver._process_loop()
        start_time = time.time()
        while isinstance(driver.ssdProcess, threading.Thread) and \
                driver.ssdProcess.isAlive() and time.time() < start_time + 8:
            time.sleep(1)
        self.assertEqual(driver.isProcessRunning, driver.TRIGGER_NONE)
        # self.assertTrue(os.path.exists(driver.LOCAL_FILE_PATH))
        # self.assertEqual(os.stat(driver.LOCAL_FILE_PATH).st_size, origin_size)
        # print '*' * 40 + 'recv size same:' + str(origin_size) + '*' * 40
        # os.system('rm -f ' + driver.LOCAL_FILE_PATH)

        #get ssd status
        cfgMsgPayload.RpdDataMessage.RpdDataOperation = cfgMsgPayload.RpdDataMessage.RPD_CFG_READ
        msg = HalMessage("HalConfig", SrcClientID='123456789',
                         SeqNum=1,
                         CfgMsgType=MsgTypeSsd,
                         CfgMsgPayload=cfgMsgPayload.SerializeToString())

        driver.recvCfgMsgCb(msg)


        # api: normal case
        driver.get_init_code()
        # driver.initCode = initcode
        driver.codeFile = CodeFileVerify(driver.initCode, rootca=rootca)

        halApi = t_HalApi()
        ssd_api = halApi.ssdController
        ssd_api.action = ssd_api.SSD_START
        ssd_api.server = '127.0.0.1'
        ssd_api.file = self.rootpath + '/rpd/ssd/testing/codefile'
        ssd_api.transport = ssd_api.SSD_TRANSPORT_TFTP
        ssd_api.manufacturerCvc = open(self.rootpath + '/rpd/ssd/testing/mfr_cvc.der', 'r').read()
        ssd_api.cosignerCvc = open(self.rootpath + '/rpd/ssd/testing/mso_cvc.der', 'r').read()

        msg_api = HalMessage("HalConfig", SrcClientID='123456789',
                             SeqNum=2,
                             CfgMsgType=MsgTypeSsdApi,
                             CfgMsgPayload=halApi.SerializeToString())

        driver.recvCfgMsgCb(msg_api)

        self.assertTrue('SsdServerAddress' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdServerAddress'], ssd_api.server)
        self.assertTrue('SsdManufCvcChain' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdManufCvcChain'], ssd_api.manufacturerCvc)
        self.assertTrue('SsdCosignerCvcChain' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdCosignerCvcChain'], ssd_api.cosignerCvc)
        self.assertEqual(driver.isProcessRunning, driver.TRIGGER_API)

        driver.ssdParam['SsdServerPort'] = self.TFTP_PORT
        # origin_size = os.stat(ssd_api.file).st_size
        # if os.path.exists(driver.LOCAL_FILE_PATH):
        #     os.system('rm -f ' + driver.LOCAL_FILE_PATH)
        # driver._process_loop()
        start_time = time.time()
        while isinstance(driver.ssdProcess, threading.Thread) and \
                driver.ssdProcess.isAlive() and time.time() < start_time + 8:
            time.sleep(1)
        self.assertEqual(driver.isProcessRunning, driver.TRIGGER_NONE)
        # self.assertTrue(os.path.exists(driver.LOCAL_FILE_PATH))
        # self.assertEqual(os.stat(driver.LOCAL_FILE_PATH).st_size, origin_size)
        # print '*' * 40 + 'recv size same:' + str(origin_size) + '*' * 40
        # os.system('rm -f ' + driver.LOCAL_FILE_PATH)

        driver.codeFile.root_cert = None
        driver.recvCfgMsgCb(msg_api)
        time.sleep(4)
        driver.codeFile = CodeFileVerify(driver.initCode, rootca=rootca)

        # api: can not download the fixed codefile
        driver.get_init_code()
        # driver.initCode = initcode
        driver.codeFile = CodeFileVerify(driver.initCode, rootca=rootca)

        halApi = t_HalApi()
        ssd_api = halApi.ssdController
        ssd_api.action = ssd_api.SSD_START
        ssd_api.server = '127.0.0.1'
        ssd_api.file = self.rootpath + '/rpd/ssd/testing/codefile'
        ssd_api.transport = ssd_api.SSD_TRANSPORT_HTTP

        msg_api = HalMessage("HalConfig", SrcClientID='123456789',
                             SeqNum=2,
                             CfgMsgType=MsgTypeSsdApi,
                             CfgMsgPayload=halApi.SerializeToString())

        driver.recvCfgMsgCb(msg_api)

        self.assertTrue('SsdServerAddress' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdServerAddress'], ssd_api.server)

        driver.ssdParam['SsdServerPort'] = self.HTTP_PORT
        origin_size = os.stat(ssd_api.file).st_size
        # if os.path.exists(driver.LOCAL_FILE_PATH):
        #     os.system('rm -f ' + driver.LOCAL_FILE_PATH)
        # driver._process_loop()
        start_time = time.time()
        while isinstance(driver.ssdProcess, threading.Thread) and \
                driver.ssdProcess.isAlive() and time.time() < start_time + 16:
            time.sleep(1)
        self.assertEqual(driver.isProcessRunning, driver.TRIGGER_NONE)
        # self.assertFalse(os.path.exists(driver.LOCAL_FILE_PATH))

        #gcp: without required param
        driver.get_init_code()
        # driver.initCode = initcode
        driver.codeFile = CodeFileVerify(driver.initCode, rootca=rootca)

        halApi = t_HalApi()
        ssd_api = halApi.ssdController
        ssd_api.action = ssd_api.SSD_START
        ssd_api.server = 'fe80::204:9fff:fe03:115/64'
        ssd_api.file = self.rootpath + '/rpd/ssd/testing/codefile'
        ssd_api.transport = ssd_api.SSD_TRANSPORT_TFTP
        ssd_api.manufacturerCvc = '0000000000000000000000000000'
        ssd_api.status = 1

        msg_api = HalMessage("HalConfig", SrcClientID='123456789',
                             SeqNum=2,
                             CfgMsgType=MsgTypeSsdApi,
                             CfgMsgPayload=halApi.SerializeToString())

        driver.recvCfgMsgCb(msg_api)

        self.assertTrue('SsdServerAddress' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdServerAddress'], ssd_api.server)
        self.assertTrue('SsdManufCvcChain' in driver.ssdParam)
        self.assertEqual(driver.ssdParam['SsdManufCvcChain'], ssd_api.manufacturerCvc)
        self.assertFalse('SsdCosignerCvcChain' in driver.ssdParam)
        self.assertEqual(driver.isProcessRunning, driver.TRIGGER_API)

        driver.ssdParam['SsdServerPort'] = self.TFTP_PORT
        # origin_size = os.stat(ssd_api.file).st_size
        # if os.path.exists(driver.LOCAL_FILE_PATH):
        #     os.system('rm -f ' + driver.LOCAL_FILE_PATH)
        driver.ssdParam.pop('SsdTransport')
        # driver._process_loop()
        start_time = time.time()
        while isinstance(driver.ssdProcess, threading.Thread) and \
                driver.ssdProcess.isAlive() and time.time() < start_time + 8:
            time.sleep(1)

        driver._reporthook(0, 1024, 2048)
        driver._reporthook(1, 1024, -1)
        driver._reporthook(1, 1024, 2048)

        driver.ssdParam['SsdFilename'] = 'none'
        driver.ssdParam['SsdServerAddress'] = '0000::0000:0000:0000:0001'
        ret = driver.download_process(driver.TRANSPORT_TFTP, driver.ssdParam['SsdServerAddress'],
                                      driver.ssdParam['SsdFilename'])
        self.assertEqual(ret, None)
        # ret = driver.download_process(driver.TRANSPORT_HTTP, '127.0.0.1', 'none')
        # self.assertEqual(ret, None)
        driver.connection_cleanup()
        # driver.connection_cleanup()

    def test_ssd_negative(self):
        rootca = self.rootpath + '/rpd/ssd/testing/CABLELABS_ROOT_CA_PEM.CRT'

        driver = HalClientTest("SSD_Driver", "This is SSD Driver", "0.1.0",
                               (MsgTypeSsd,), None, rootca=rootca)
        driver.mgr = None
        driver.ssdParam["SsdFilename"] = '1'
        driver.ssdParam["SsdServerAddress"] = '1'
        driver.download_process(1, 1, 1)

        driver = HalClientTest("SSD_Driver", "This is SSD Driver", "0.1.0",
                               (MsgTypeSsd,), None, rootca=rootca)
        try:
            driver.register('100')
        except HalDriverClientError:
            pass

        # skip the new request when process is running
        driver.isProcessRunning = driver.TRIGGER_API
        self.assertEqual(driver.configSsdApi(None), t_SsdController.SSD_RESULT_GENERAL_ERROR)

        cfg = config()
        ssd = cfg.Ssd
        ssd.SsdServerAddress = '127.0.0.1'
        ssd.SsdTransport = driver.TRANSPORT_TFTP
        ssd.SsdFilename = self.rootpath + '/rpd/ssd/testing/codefile'
        self.assertEqual(driver.configSsd(cfg), t_SsdController.SSD_RESULT_GENERAL_ERROR)

        msg = HalMessage("HalConfig", SrcClientID='123456789',
                         SeqNum=2,
                         CfgMsgType=MsgTypeSsdApi)
        driver.recv_ssd_gcp(msg)
        driver.recv_ssd_api(msg)

        cfgMsgPayload = t_RcpMessage()
        cfgMsgPayload.RcpMessageType = cfgMsgPayload.RPD_CONFIGURATION
        cfgMsgPayload.RpdDataMessage.RpdDataOperation = cfgMsgPayload.RpdDataMessage.RPD_CFG_WRITE
        cfg = config()
        ssd = cfg.Ssd
        ssd.SsdServerAddress = '127.0.0.1'
        ssd.SsdTransport = driver.TRANSPORT_TFTP
        ssd.SsdFilename = self.rootpath + '/rpd/ssd/testing/codefile'
        ssd.SsdControl = driver.START
        cfgMsgPayload.RpdDataMessage.RpdData.CopyFrom(cfg)
        msg = HalMessage("HalConfig", SrcClientID='123456789',
                         SeqNum=1,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=cfgMsgPayload.SerializeToString())
        self.assertIsNone(driver._deSerializeConfigMsgPayload(msg, 'error'))
        # driver.recvCfgMsgCb(msg)

        os.system("touch /tmp/testimagename.itb.act")
        os.system("rm -rf " + driver.BOOT_IMAGE_PATH)
        os.system("ln -sf /tmp/testimagename.itb.act " + driver.BOOT_IMAGE_PATH)
        self.assertFalse(driver.is_same_img(None))
        self.assertFalse(driver.is_same_img('http://differenrname.itb'))
        self.assertTrue(driver.is_same_img('/tftpboot/test/testimagename.itb'))
        self.assertTrue(driver.is_same_img('testimagename.itb'))
        self.assertTrue(driver.is_same_img('testimagename.itb.act'))
        os.system("rm -rf " + driver.BOOT_IMAGE_PATH)
        self.assertFalse(driver.is_same_img('differenrname.itb'))
        self.assertFalse(driver.is_same_img('testimagename.itb.act'))
        os.system("touch " + driver.BOOT_IMAGE_PATH)
        self.assertFalse(driver.is_same_img('testimagename.itb.act'))

        driver.connection_cleanup()
        driver.connection_cleanup()

if __name__ == '__main__':
    setup_logging('HAL', filename="hal_client.log")
    unittest.main()
