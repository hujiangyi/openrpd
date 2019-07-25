#
# Copyright (c) 2016-2018 Cisco and/or its affiliates, and
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
"""This is the simulate peer file, Ut will not cover this packet."""

import unittest
import os
import time
import subprocess
import signal

from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.hal.src.HalConfigMsg import MsgTypeHostResources
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.common.rpd_logging import AddLoggerToClass
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, stop_test_redis
from rpd.gpb.cfg_pb2 import config
from rpd.resource.src.RpdResHalClient import RpdResHalClient,\
    MsgTypeRpdCtrl
from rpd.resource.src.RpdCrashFileHandler import CrashFileCtrlHandler, \
    CrashFileStatusInfo, CrashFileUploadProcess, CrashDataServerInfo
from rpd.dispatcher.dispatcher import Dispatcher


class testRpdCrashFileHandler(unittest.TestCase):
    TFTP_PORT = 8999
    HTTP_PORT = 8899

    FIVE_SECOND = 5
    ONE_SECOND = 1

    __metaclass__ = AddLoggerToClass
    nameList = ['temp1.core.gz', 'temp2.core.gz']
    nameList1 = ['temp1.core.gz']

    @classmethod
    def setUpClass(cls):
        cls.text = "00000000000000000"
        setup_test_redis()
        os.system("mkdir -p /tmp/crash/")
        global_dispatcher = Dispatcher()
        CrashFileStatusInfo.MAX_IDX = 20
        crashFileStatusInfo = CrashFileStatusInfo()
        CrashFileCtrlHandler.CORE_FILE_PATH = "/tmp/crash/"
        crashFileStatusInfo.CORE_FILE_PATH = "/tmp/crash/"
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") - 2
        cls.rootpath = "/".join(dirs[:rpd_index])
        cls.halClient = RpdResHalClient("RpdRes_hal",
                                        "This is RPD HostRes hal client",
                                        "1.0.0", global_dispatcher,
                                        (MsgTypeHostResources, MsgTypeRpdCtrl, ),
                                        ())
        cls.crashCtrlHandler = cls.halClient.crashFileCtrlHandler
        cls.crashCtrlHandler.CORE_FILE_PATH = "/tmp/crash/"

        cls.start_tftp_cmd = \
            "coverage run --parallel-mode --rcfile=" + \
            cls.rootpath + "/.coverage.rc " + \
            cls.rootpath + \
            "/rpd/resource/testing/tftp_server_sim.py --root " + \
            cls.rootpath + " --server 127.0.0.1 --port " + \
            str(cls.TFTP_PORT)
        cls.tftp_pid = subprocess.Popen(cls.start_tftp_cmd, executable='bash', shell=True)
        print(cls.tftp_pid)

    @classmethod
    def tearDownClass(cls):

        if cls.crashCtrlHandler and cls.crashCtrlHandler.is_upload_process_alive():
            cls.crashCtrlHandler.stop_upload_process()

        if cls.halClient.pushSock:
            cls.halClient.pushSock.close()
        del cls.halClient
        if cls.tftp_pid:
            cls.tftp_pid.send_signal(signal.SIGINT)
            cls.tftp_pid.wait()
        stop_test_redis()
        subprocess.call(["killall", "python"])
        pass

    def setUp(self):
        CrashFileStatusInfo.MAX_IDX = 20
        CrashFileCtrlHandler.CORE_FILE_PATH = "/tmp/crash/"
        os.system("mkdir -p /tmp/crash/")

    def tearDown(self):
        os.system("rm -rf /tmp/crash/*")
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.delete()
        if self.crashCtrlHandler.is_upload_process_alive():
            self.crashCtrlHandler.stop_upload_process()
        time.sleep(self.ONE_SECOND)

    def test_RpdCrashInfoQueueIndex(self):
        print("case: test_RpdCrashInfoQueueIndex")
        self.crashCtrlHandler.update_crash_file_table(None)
        CrashFileStatusInfo.MAX_IDX = 20
        record1 = CrashFileStatusInfo()
        freelist = []
        for i in range(0, 10):
            record1.allocateIndex()
            record1.write()
            if i % 2 == 0:
                record1.delete()
                freelist.append(record1.index)
                time.sleep(1)
        self.assertFalse(record1.allocateIndex() in freelist)

    def test_RpdCrashInfoRetriveIndex(self):
        print("case: test_RpdCrashInfoRetriveIndex")
        self.crashCtrlHandler.update_crash_file_table(None)
        CrashFileStatusInfo.MAX_IDX = 20
        fileName = "test"
        for i in range(0, 20):
            fileName1 = fileName + str(i) + ".core.gz"
            file_object = open(CrashFileCtrlHandler.CORE_FILE_PATH + fileName1, 'w')
            file_object.write(self.text)
            file_object.close()
            time.sleep(1)
        self.crashCtrlHandler.update_crash_file_table(None)

        fileName1 = fileName + str(21) + ".core.gz"
        file_object = open(CrashFileCtrlHandler.CORE_FILE_PATH + fileName1, 'w')
        file_object.write(self.text)
        file_object.close()
        fileName1 = fileName + str(22) + ".core.gz"
        file_object = open(CrashFileCtrlHandler.CORE_FILE_PATH + fileName1, 'w')
        file_object.write(self.text)
        file_object.close()
        self.crashCtrlHandler.update_crash_file_table(None)
        self.assertEquals(len(os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH)), 20)
        self.assertTrue(fileName1 in os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH))

    def test_add_crash_file(self):
        print("case: test_add_crash_file")
        self.crashCtrlHandler.update_crash_file_table(None)
        if self.crashCtrlHandler.is_upload_process_alive():
            self.crashCtrlHandler.stop_upload_process()

        for fileName in self.nameList:
            file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + fileName, 'w')
            file_object.write(self.text)
            file_object.close()
        time.sleep(self.ONE_SECOND)
        self.crashCtrlHandler.update_crash_file_table(None)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatsInfo = CrashFileStatusInfo(key)
            crashFileStatsInfo.read()
        self.assertNotEquals(len(os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH)), 20)

    def test_process(self):
        file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + "test1.core.gz", 'w')
        file_object.write(self.text)
        file_object.close()
        record1 = CrashFileStatusInfo()
        record1.index = 2
        record1.fileName = "test_1.core.gz"
        record1.write()
        uploadProcess = CrashFileUploadProcess(2)
        uploadProcess.run()
        record1 = CrashFileStatusInfo()
        record1.index = 3
        record1.fileName = ""
        record1.write()
        uploadProcess = CrashFileUploadProcess(3)
        uploadProcess.run()
        record1 = CrashFileStatusInfo()
        record1.index = 4
        record1.fileName = "test1.core.gz"
        record1.fileStatus = CrashFileCtrlHandler.CONTROL_CANCELUPLOAD
        record1.write()
        uploadProcess = CrashFileUploadProcess(4)
        uploadProcess.run()
        uploadProcess.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS, record1)
        uploadProcess = CrashFileUploadProcess(4)
        uploadProcess.run()

        print("step 2 TFTP upload")
        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = ""
        crashDataServerInfo.destPath = "/./"
        crashDataServerInfo.protocol = 2
        crashDataServerInfo.write()
        uploadProcess.upload_crash_file(record1)

        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "127.0.0.1"
        crashDataServerInfo.destPath = "/./"
        crashDataServerInfo.protocol = 3
        crashDataServerInfo.write()
        uploadProcess.upload_crash_file(record1)
        uploadProcess.upload_with_http(record1, crashDataServerInfo)

        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "127.0.0.1"
        crashDataServerInfo.destPath = ""
        crashDataServerInfo.protocol = 3
        crashDataServerInfo.write()
        uploadProcess.upload_crash_file(record1)
        uploadProcess.upload_with_http(record1, crashDataServerInfo)

        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "::"
        crashDataServerInfo.destPath = "/./"
        crashDataServerInfo.protocol = 1
        crashDataServerInfo.write()
        uploadProcess.upload_crash_file(record1)

        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "::"
        crashDataServerInfo.destPath = "/."
        crashDataServerInfo.protocol = 2
        crashDataServerInfo.write()
        record1.fileStatus = CrashFileCtrlHandler.STATUS_UPLOADCOMPLETED
        record1.fileControl = CrashFileCtrlHandler.CONTROL_UPLOADANDDELETE
        uploadProcess.upload_crash_file(record1)
        uploadProcess.upload_with_tftp(record1, crashDataServerInfo)
        self.assertNotEqual(record1.fileStatus, CrashFileCtrlHandler.STATUS_AVAILFORUPLOAD)
        self.assertNotEquals(len(os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH)), 20)

    def test_unexpect_process(self):
        print("case: test_unexpect_process")
        uploadProcess = CrashFileUploadProcess(2)
        file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + "test1.core.gz", 'w')
        print(self.crashCtrlHandler.CORE_FILE_PATH + "test1.core.gz")
        file_object.write(self.text)
        file_object.close()
        record1 = CrashFileStatusInfo()
        record1.index = 2
        record1.fileName = "test_1.core.gz"
        record1.fileStatus = CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS
        record1.write()
        uploadProcess.run()
        record1.fileName = "test1.core.gz"
        record1.fileStatus = CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS
        record1.write()

        uploadProcess.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADCANCELLED, record1)
        uploadProcess.run()
        record1.fileName = "test1.core.gz"
        record1.fileStatus = CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS
        record1.write()

        uploadProcess.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS, record1)
        uploadProcess.run()
        uploadProcess = CrashFileUploadProcess(2)
        uploadProcess.update_crash_file_status(CrashFileCtrlHandler.STATUS_AVAILFORUPLOAD, record1)
        uploadProcess.run()
        uploadProcess = CrashFileUploadProcess(None)
        uploadProcess.run()
        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "127.0.0.1"
        crashDataServerInfo.destPath = "/."
        crashDataServerInfo.protocol = 2
        crashDataServerInfo.write()
        uploadProcess.upload_with_tftp(record1, crashDataServerInfo)

        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "127.0.0.1"
        crashDataServerInfo.destPath = "/./"
        crashDataServerInfo.protocol = 2
        crashDataServerInfo.write()
        uploadProcess.upload_with_tftp(record1, crashDataServerInfo)

        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.destIpAddress = "ff02:0:0:0:0:0:0:2"
        crashDataServerInfo.destPath = "/./"
        crashDataServerInfo.protocol = 3
        crashDataServerInfo.write()
        uploadProcess.upload_with_http(record1, crashDataServerInfo)
        self.assertNotEqual(record1.fileStatus, CrashFileCtrlHandler.STATUS_AVAILFORUPLOAD)
        self.assertNotEquals(len(os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH)), 20)

    def test_del_crash_file(self):
        print("case: test_del_crash_file")

        self.crashCtrlHandler.check_file_valid("111.log")
        self.crashCtrlHandler.check_file_valid("111.core.gz")
        self.crashCtrlHandler.update_waiting_upload_list(True, None)
        self.crashCtrlHandler.update_crash_file_table(None)
        delFileName = ""
        for fileName in self.nameList:
            delFileName = fileName
            file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + fileName, 'w')
            file_object.write(self.text)
            file_object.close()

        self.crashCtrlHandler.update_crash_file_table(None)
        os.system("rm -rf /tmp/crash/%s" % delFileName)
        self.crashCtrlHandler.update_crash_file_table(None)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatsInfo = CrashFileStatusInfo(key)
            crashFileStatsInfo.read()
        self.assertNotEquals(len(os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH)), 20)

    def test_file_ctrl_set(self):
        print("case: test_file_ctrl_set")
        CrashFileCtrlHandler.delete_core_file("")

        os.system("rm -rf /tmp/crash/*")
        if self.crashCtrlHandler.is_upload_process_alive():
            self.crashCtrlHandler.stop_upload_process()
            time.sleep(self.ONE_SECOND)
        file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + "test1.core.gz", 'w')
        file_object.write(self.text)
        file_object.close()
        os.mkdir("/tmp/crash/test")
        CrashFileCtrlHandler.delete_core_file("test")
        self.crashCtrlHandler.update_crash_file_table(None)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_OTHER)
            crashFileStatusInfo.read()
            self.assertEquals(crashFileStatusInfo.fileControl, self.crashCtrlHandler.CONTROL_OTHER)
            self.assertEquals(crashFileStatusInfo.fileStatus, self.crashCtrlHandler.STATUS_AVAILFORUPLOAD)

    def test_file_delete(self):
        print("case: test_file_delete")
        file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + "test1.core.gz", 'w')
        file_object.write(self.text)
        file_object.close()
        self.crashCtrlHandler.update_crash_file_table(None)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_DELETEFILE)
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.assertNotEquals(crashFileStatusInfo, None)

    def test_file_upload(self):
        print("case: test_file_upload")
        self.crashCtrlHandler = self.halClient.crashFileCtrlHandler
        self.crashCtrlHandler.TFTP_PORT = self.TFTP_PORT
        time.sleep(1)
        self.assertEquals(self.crashCtrlHandler.is_upload_process_alive(), False)
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataServerCtrl
        rpdServerCtrlCfg.DestIpAddress = "127.0.0.1"
        rpdServerCtrlCfg.DestPath = "/./"
        rpdServerCtrlCfg.Protocol = CrashFileCtrlHandler.PROTOCOL_TFTP
        self.crashCtrlHandler.save_crash_data_server(rpdServerCtrlCfg)
        os.system("rm -rf /tmp/crash/*")
        for fileName in self.nameList:
            file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + fileName, 'w')
            file_object.write(self.text)
            file_object.close()
            break
        self.crashCtrlHandler.update_crash_file_table(None)

        print("step1: test upload=========\n")
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_UPLOAD)
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_UPLOAD)
            break

        time.sleep(self.ONE_SECOND)
        self.crashCtrlHandler.update_waiting_upload_list(True, 1)
        self.crashCtrlHandler.waitingUploadList.append(1)
        self.crashCtrlHandler.update_waiting_upload_list(False, 1)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            time.sleep(self.ONE_SECOND)

        time.sleep(self.ONE_SECOND)
        print("step2: test cancel upload")
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_CANCELUPLOAD)
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.assertEquals(crashFileStatusInfo.fileStatus, self.crashCtrlHandler.STATUS_UPLOADCANCELLED)

        self.crashCtrlHandler.waitingUploadList.append(crashFileStatusInfo.index)
        crashFileStatusInfo.read()
        self.crashCtrlHandler.update_waiting_upload_list(crashFileStatusInfo.index, self.crashCtrlHandler.CONTROL_CANCELUPLOAD)
        self.crashCtrlHandler.update_waiting_upload_list(crashFileStatusInfo.index, self.crashCtrlHandler.CONTROL_DELETEFILE)
        time.sleep(self.ONE_SECOND)
        print("step3: test upload and delete")
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_UPLOADANDDELETE)
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            time.sleep(self.ONE_SECOND)

    def test_tftp_fail_status(self):
        print("case:test_tftp_fail_status")
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataServerCtrl
        rpdServerCtrlCfg.DestPath = "/./"
        rpdServerCtrlCfg.Protocol = CrashFileCtrlHandler.PROTOCOL_TFTP
        self.crashCtrlHandler.save_crash_data_server(rpdServerCtrlCfg)
        if self.crashCtrlHandler.is_upload_process_alive():
            self.crashCtrlHandler.stop_upload_process()

        time.sleep(self.ONE_SECOND)
        self.assertEquals(self.crashCtrlHandler.is_upload_process_alive(), False)
        os.system("rm -rf /tmp/crash/*")
        for fileName in self.nameList1:
            file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + fileName, 'w')
            file_object.write(self.text)
            file_object.close()
        self.crashCtrlHandler.update_crash_file_table(None)

        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataServerCtrl
        rpdServerCtrlCfg.DestIpAddress = ""
        rpdServerCtrlCfg.DestPath = "/./"
        rpdServerCtrlCfg.Protocol = CrashFileCtrlHandler.PROTOCOL_TFTP
        self.crashCtrlHandler.save_crash_data_server(rpdServerCtrlCfg)
        print("step5: test upload=========\n")
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataServerCtrl
        rpdServerCtrlCfg.DestIpAddress = "128.0.0.1"
        rpdServerCtrlCfg.DestPath = "/./"
        rpdServerCtrlCfg.Protocol = CrashFileCtrlHandler.PROTOCOL_TFTP
        self.crashCtrlHandler.save_crash_data_server(rpdServerCtrlCfg)
        self.crashCtrlHandler.get_crash_data_server(rpdServerCtrlCfg)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.crashCtrlHandler.update_pending_file_idx_list(key, self.crashCtrlHandler.CONTROL_UPLOAD)

        time.sleep(self.FIVE_SECOND)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            self.assertNotEquals(crashFileStatusInfo.fileStatus, self.crashCtrlHandler.STATUS_AVAILFORUPLOAD)

    def test_tftp_ctrl_hal_msg(self):
        print("case:test_tftp_ctrl_hal_msg")
        self.assertEquals(self.crashCtrlHandler.is_upload_process_alive(), False)
        os.system("rm -rf /tmp/crash/*")
        for fileName in self.nameList:
            file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + fileName, 'w')
            file_object.write(self.text)
            file_object.close()
        file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + "111.txt", 'w')
        file_object.write(self.text)
        file_object.close()
        self.crashCtrlHandler.update_crash_file_table(None)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            rcp_msg = t_RcpMessage()
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rcp_msg.RpdDataMessage.RpdDataOperation = \
                t_RpdDataMessage.RPD_CFG_WRITE
            cfg_msg = config()
            rpdCtrl = cfg_msg.RpdCtrl
            dataFileCtrl = rpdCtrl.CrashDataFileCtrl.add()
            dataFileCtrl.Index = crashFileStatusInfo.index
            dataFileCtrl.FileControl = CrashFileCtrlHandler.CONTROL_UPLOAD
            rpdCtrl.CrashDataServerCtrl.DestIpAddress = "127.0.0.1"
            rpdCtrl.CrashDataServerCtrl.DestPath = "/tmp/crash/"
            rpdCtrl.CrashDataServerCtrl.Protocol = CrashFileCtrlHandler.PROTOCOL_TFTP

            rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
            cfg_payload = rcp_msg.SerializeToString()
            rdpCtrlMsg = HalMessage("HalConfig", SrcClientID="testRpdCtrlMsg",
                                    SeqNum=325,
                                    CfgMsgType=HalConfigMsg.MsgTypeRpdCtrl,
                                    CfgMsgPayload=cfg_payload)

        self.halClient.recvCfgMsgCb(rdpCtrlMsg)

    def test_http_ctrl_hal_msg(self):
        print("case: test_http_ctrl_hal_msg")
        if not self.tftp_pid:
            self.tftp_pid = subprocess.Popen(self.start_tftp_cmd, executable='bash', shell=True)
        if self.crashCtrlHandler.is_upload_process_alive():
            self.crashCtrlHandler.stop_upload_process()
        time.sleep(self.ONE_SECOND)
        self.assertEquals(self.crashCtrlHandler.is_upload_process_alive(), False)
        os.system("rm -rf /tmp/crash/*")
        for fileName in self.nameList:
            file_object = open(self.crashCtrlHandler.CORE_FILE_PATH + fileName, 'w')
            file_object.write(self.text)
            file_object.close()
        self.crashCtrlHandler.update_crash_file_table(None)
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            rcp_msg = t_RcpMessage()
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rcp_msg.RpdDataMessage.RpdDataOperation = \
                t_RpdDataMessage.RPD_CFG_WRITE
            cfg_msg = config()
            rpdCtrl = cfg_msg.RpdCtrl
            dataFileCtrl = rpdCtrl.CrashDataFileCtrl.add()
            dataFileCtrl.Index = crashFileStatusInfo.index
            dataFileCtrl.FileControl = CrashFileCtrlHandler.CONTROL_UPLOAD
            rpdCtrl.CrashDataServerCtrl.DestIpAddress = ""
            rpdCtrl.CrashDataServerCtrl.DestPath = "/tmp/crash/"
            rpdCtrl.CrashDataServerCtrl.Protocol = CrashFileCtrlHandler.PROTOCOL_HTTP

            rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
            cfg_payload = rcp_msg.SerializeToString()
            rdpCtrlMsg = HalMessage("HalConfig", SrcClientID="testRpdCtrlMsg",
                                    SeqNum=325,
                                    CfgMsgType=HalConfigMsg.MsgTypeRpdCtrl,
                                    CfgMsgPayload=cfg_payload)

        self.halClient.recvCfgMsgCb(rdpCtrlMsg)


if __name__ == '__main__':
    unittest.main()
