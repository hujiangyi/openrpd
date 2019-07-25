#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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
import unittest
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.provision.manager.src.manager_hal import ProvMgrHalDriver, ProvMgrHalDriverError
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.gpb.cfg_pb2 import config
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.HalConfigMsg import MsgTypeRpdCtrl
from rpd.hal.src.msg import HalCommon_pb2


class FakeManager(object):

    def __init__(self):
        self.desc = "This is a test manager."


class testProvMgrHalDriver(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("PROVISION", "test.log")
        cls.dispatcher = Dispatcher()
        cls.mgr = FakeManager()
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing") + 1
        cls.rootpath = "/".join(dirs[:rpd_index])

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.haldriver = ProvMgrHalDriver("ProvMgr_HAL_CLIENT", "This is provision manager hal driver", "1.0.0",
                                          ProvMgrHalDriver.cfgmsg_list,
                                          ProvMgrHalDriver.ntfmsg_list,
                                          ProvMgrHalDriver.ntfmsg_list,
                                          dispatcher=self.dispatcher,
                                          mgr=self.mgr
                                          )

    def tearDown(self):
        self.haldriver.connectionDisconnectCb(msg=None)
        if self.haldriver.poller and self.haldriver.mgrConnection:
            self.haldriver.poller.unregister(self.haldriver.mgrConnection.socket)
            self.haldriver.poller.unregister(self.haldriver.mgrConnection.monitor)
            self.haldriver.mgrConnection.socket.disable_monitor()
            self.haldriver.mgrConnection.monitor.close()
            self.haldriver.mgrConnection.close()

    def test_init(self):
        self.assertEqual(self.mgr, self.haldriver.mgr)
        self.assertEqual(self.dispatcher, self.haldriver.dispatcher)
        self.assertTrue(self.haldriver.disconnected)

    def test_connect(self):
        self.haldriver.start()
        self.assertTrue(self.haldriver.disconnected)
        self.assertIsNotNone(self.haldriver.mgrConnection)
        self.assertIsNotNone(self.haldriver.poller)

    def test_sendOperationalStatusNtf(self):
        self.haldriver.start()
        self.haldriver.disconnected = False
        self.haldriver.drvID = "test"
        try:
            self.haldriver.sendOperationalStatusNtf(operational=True)
        except Exception as e:
            self.fail("Exception happened: %s" % str(e))

        try:
            self.haldriver.sendOperationalStatusNtf(operational=False)
        except Exception as e:
            self.fail("Exception happened: %s" % str(e))

    def test_recvRpdResetCtrl(self):
        print("######test_recvRpdResetCtrl######")
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        self.haldriver.RESET_CTRL_FILENAME = self.rootpath + '/reset_ctrl'

        print("=====test case1: payload does not have RpdCtrl field=====")
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        return_str = self.haldriver.recvRpdResetCtrl(msg.msg)
        self.assertEquals(str(return_str),
                          "{'Status': %d, 'ErrorDescription': 'ProvMgr Do not Have RpdCtrl Filed.'}"
                          % HalCommon_pb2.SUCCESS_IGNORE_RESULT)

        print("=====test case2: payload operation neither read nor write=====")
        rpdresetcfg = config()
        rpdresetcfg.RpdCtrl.ResetCtrl.Reset = 4
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdresetcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 3
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        return_str = self.haldriver.recvRpdResetCtrl(msg.msg)
        self.assertEquals(str(return_str),
                          "{'Status': %d, 'ErrorDescription': 'Operation 3 for RpdResetCtrl is not supported'}" % HalCommon_pb2.FAILED)

        print("=====test case3: payload operation write=====")
        rpdresetcfg = config()
        rpdresetcfg.RpdCtrl.ResetCtrl.Reset = 2
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdresetcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 1
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)
        return_str = self.haldriver.recvRpdResetCtrl(msg.msg)
        self.assertTrue(os.path.exists(self.haldriver.RESET_CTRL_FILENAME))
        fp = open(self.haldriver.RESET_CTRL_FILENAME, 'r')
        reset_fp = fp.read()
        self.assertEqual(int(reset_fp.strip(":")[0]), 2)
        self.assertEquals(str(return_str),
                          "{'Status': %d, 'ErrorDescription': "
                          "'ProMgr handle RpdResetCtrl success for 1'}" % HalCommon_pb2.SUCCESS)

        print("=====test case4: payload operation read, reset file exists=====")
        rpdresetcfg = config()
        rpdresetcfg.RpdCtrl.ResetCtrl.Reset = 1
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdresetcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)

        return_str = self.haldriver.recvRpdResetCtrl(msg.msg)
        self.assertTrue(os.path.exists(self.haldriver.RESET_CTRL_FILENAME))
        fp = open(self.haldriver.RESET_CTRL_FILENAME, 'r')
        reset_fp = fp.read()
        self.assertEqual(int(reset_fp.strip(":")[0]), 2)
        self.assertEquals(str(return_str),
                          "{'Status': %d, 'ErrorDescription': "
                          "'ProMgr handle RpdResetCtrl success for 2'}" % HalCommon_pb2.SUCCESS)

        print("=====test case5: payload operation read, reset file not exists=====")
        if os.path.exists(self.haldriver.RESET_CTRL_FILENAME):
            os.remove(self.haldriver.RESET_CTRL_FILENAME)
        rpdresetcfg = config()
        rpdresetcfg.RpdCtrl.ResetCtrl.Reset = 1
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(rpdresetcfg)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdCtrl,
                         CfgMsgPayload=payload)

        return_str = self.haldriver.recvRpdResetCtrl(msg.msg)
        self.assertFalse(os.path.exists(self.haldriver.RESET_CTRL_FILENAME))
        self.assertEquals(str(return_str),
                          "{'Status': %d, 'ErrorDescription': "
                          "'ProMgr handle RpdResetCtrl success for 2'}" % HalCommon_pb2.SUCCESS)


if __name__ == '__main__':
    unittest.main()
    setup_logging("PROVISION", "test.log")
