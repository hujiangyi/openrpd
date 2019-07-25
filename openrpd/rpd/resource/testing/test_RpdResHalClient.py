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
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.hal.src.HalConfigMsg import MsgTypeHostResources, MsgTypeRpdCtrl, MsgTypeRpdState
from rpd.resource.src.RpdResHalClient import RpdResHalClient
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, stop_test_redis
from rpd.gpb.cfg_pb2 import config

from rpd.dispatcher.dispatcher import Dispatcher


class testRpdResHalClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_test_redis()
        global_dispatcher = Dispatcher()
        cls.rpdhostres = RpdResHalClient("RpdHostRes_hal",
                                         "This is RPD HostRes hal client",
                                         "1.0.0", global_dispatcher,
                                         (MsgTypeHostResources, MsgTypeRpdCtrl, ),
                                         ())

    @classmethod
    def tearDownClass(cls):
        stop_test_redis()
        if cls.rpdhostres.poller and cls.rpdhostres.mgrConnection:
            cls.rpdhostres.poller.unregister(cls.rpdhostres.mgrConnection.socket)
            cls.rpdhostres.poller.unregister(cls.rpdhostres.mgrConnection.monitor)
            cls.rpdhostres.mgrConnection.socket.disable_monitor()
            cls.rpdhostres.mgrConnection.monitor.close()
            cls.rpdhostres.mgrConnection.close()

    def test_recvCfgMsgCb(self):
        cfg = t_RcpMessage()
        cfg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        payload = cfg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeHostResources,
                                 CfgMsgPayload=payload)
        cfg_rsp_msg = HalMessage("HalClientRegisterRsp")
        cfg_rsp_msg.msg.Rsp.Status = 2
        self.rpdhostres.recvRegisterMsgCb(cfg_rsp_msg)
        self.assertTrue(self.rpdhostres.disconnected)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

    def test_recvRpdServerCtrlMsgCb(self):
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataServerCtrl
        rpdServerCtrlCfg.DestIpAddress = "127.0.0.1"
        rpdServerCtrlCfg.DestPath = "/bootflash/"
        rpdServerCtrlCfg.Protocol = 2
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        crashFileCtrl = self.rpdhostres.crashFileCtrlHandler
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))
        crashDataServerInfo = crashFileCtrl.get_server_info()
        self.assertEqual(crashDataServerInfo.destIpAddress,
                         rpdServerCtrlCfg.DestIpAddress)
        self.assertEqual(crashDataServerInfo.destPath,
                         rpdServerCtrlCfg.DestPath)
        self.assertEqual(crashDataServerInfo.protocol,
                         rpdServerCtrlCfg.Protocol)

    def test_recvRpdServerCtrlMsgCbRead(self):
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

        rpdCtrl = cfg_msg.RpdCtrl
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdState,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

        rpdCtrl = cfg_msg.RpdCtrl
        crashDataServerCtrl = rpdCtrl.CrashDataServerCtrl
        crashDataServerCtrl.DestIpAddress = "127.0.0.1"
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

    def test_recvRpdFileCtrlMsgCb(self):
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataFileCtrl.add()
        rpdServerCtrlCfg.Index = 254
        rpdServerCtrlCfg.FileControl = 2
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)

        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataFileCtrl.add()
        rpdServerCtrlCfg.FileControl = 2
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)

        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE
        cfg_msg = config()
        rpdCtrl = cfg_msg.RpdCtrl
        rpdServerCtrlCfg = rpdCtrl.CrashDataFileCtrl.add()
        rpdServerCtrlCfg.Index = 254
        rpdServerCtrlCfg.FileControl = 2
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)

        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE
        cfg_msg = config()
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)

        cfg_payload = rcp_msg.SerializeToString()
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdRes",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeRpdCtrl,
                                 CfgMsgPayload=cfg_payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))


if __name__ == '__main__':
    unittest.main()
