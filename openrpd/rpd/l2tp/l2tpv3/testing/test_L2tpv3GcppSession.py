#
# Copyright (c) 2017 Cisco and/or its affiliates,
# Cable Television Laboratories, Inc. ("CableLabs")
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
import l2tpv3.src.L2tpv3GcppConnection as L2tpv3GcppSession
import rpd.gpb.StaticPwConfig_pb2 as StaticPwConfig_pb2
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from l2tpv3.src.L2tpv3Hal import L2tpHalClient
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.hal.src.msg.HalMessage import HalMessage
import l2tpv3.src.L2tpv3_pb2 as l2tpMsg
from rpd.hal.src.transport.HalTransport import HalTransport
from l2tpv3.src.L2tpv3API import L2tpv3API
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
from rpd.gpb.cfg_pb2 import config
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.hal.src.msg import HalCommon_pb2

class StaticL2tpProvision():
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        return

    def add_dsStaticSession(self, staticPwCfg, index, is_MultiCast, is_IPV6, flag=True):
        fwdPwCfg = staticPwCfg.FwdStaticPwConfig
        fwdPwCfg.Index = index
        if flag:
            fwdPwCfg.CcapCoreOwner = "00:50:56:9A:22:18"
        else:
            fwdPwCfg.CcapCoreOwner = L2tpv3GcppSession.StaticL2tpSession.DEFAULT_MAC_ADDR
        if not is_IPV6:
            if is_MultiCast:
                fwdPwCfg.GroupAddress = "225.0.0.1"
            else:
                fwdPwCfg.GroupAddress = "127.0.0.1"
            fwdPwCfg.SourceAddress = "127.0.0.1"
        else:
            if is_MultiCast:
                fwdPwCfg.GroupAddress = "ff02:0:0:0:0:0:0:2"
            else:
                fwdPwCfg.GroupAddress = "2001:9:9:9::2"
            fwdPwCfg.SourceAddress = "::1"

    def add_commStaticSession(self, staticPwCfg, index,
                              sessionId, channelIndex, circuitStatus, direction):
        commPwCfg = staticPwCfg.CommonStaticPwConfig
        commPwCfg.Direction = direction
        commPwCfg.Index = index
        commPwCfg.PwType = 3
        commPwCfg.DepiPwSubtype = 3
        commPwCfg.L2SublayerType = 3
        commPwCfg.DepiL2SublayerSubtype = 3
        commPwCfg.SessionId = sessionId
        commPwCfg.CircuitStatus = circuitStatus
        commPwCfg.RpdEnetPortIndex = 0

        pwAssoc = commPwCfg.PwAssociation.add()
        pwAssoc.Index = index
        channelSelector = pwAssoc.ChannelSelector
        channelSelector.RfPortIndex = 0
        channelSelector.ChannelType = 3
        channelSelector.ChannelIndex = channelIndex
        commPwCfg.EnableStatusNotification = 0

    def add_usStaticSession(self, staticPwCfg, index, is_ipv6, flag=True):
        retPwCfg = staticPwCfg.RetStaticPwConfig
        retPwCfg.Index = index
        if is_ipv6:
            retPwCfg.DestAddress = "::1"
        else:
            retPwCfg.DestAddress = "127.0.0.1"
        retPwCfg.MtuSize = 65535
        if flag:
            retPwCfg.CcapCoreOwner = "00:50:56:9A:22:18"
        else:
            retPwCfg.CcapCoreOwner = L2tpv3GcppSession.StaticL2tpSession.DEFAULT_MAC_ADDR
        retPwCfg.UsPhbId = 0

    def check_StaticSession(self, staticPwCfg, staticL2tpDB):
        if staticPwCfg.HasField("CommonStaticPwConfig"):
            commPwCfg = staticPwCfg.CommonStaticPwConfig
            staticL2tpMsgBean = staticL2tpDB.get((commPwCfg.SessionId, commPwCfg.Direction))
            if not staticL2tpMsgBean:
                return False
            if staticL2tpMsgBean.direction != commPwCfg.Direction:
                return False
            if staticL2tpMsgBean.pwType != commPwCfg.PwType:
                return False
            if staticL2tpMsgBean.depiPwSubtype != commPwCfg.DepiPwSubtype:
                return False
            if staticL2tpMsgBean.l2SublayerType != commPwCfg.L2SublayerType:
                return False
            if staticL2tpMsgBean.depiL2SublayerSubtype != commPwCfg.DepiL2SublayerSubtype:
                return False
            if staticL2tpMsgBean.sessionId != commPwCfg.SessionId:
                return False
            if staticL2tpMsgBean.circuitStatus != commPwCfg.CircuitStatus:
                return False
            if staticL2tpMsgBean.rpdEnetPortIndex != commPwCfg.RpdEnetPortIndex:
                return False
            if staticL2tpMsgBean.enableNotifications != commPwCfg.EnableStatusNotification:
                return False
            PwAssociate = commPwCfg.PwAssociation
            for pwAssociate in PwAssociate:
                channelSelector = pwAssociate.ChannelSelector
                flag = False
                for index, channelBean in staticL2tpMsgBean.pwAssociation.items():
                    if channelSelector.RfPortIndex == channelBean.rfPortIndex \
                            and channelSelector.ChannelType == channelBean.channelType \
                            and channelSelector.ChannelIndex == channelBean.channelIndex:
                        flag = True
                        break
                if not flag:
                    return False
        else:
            return False

        if staticL2tpMsgBean.direction == L2tpv3GcppSession.StaticL2tpSession.DIRECTION_FORWARD:
            fwdStaticCfg = staticPwCfg.FwdStaticPwConfig
            if staticL2tpMsgBean.groupAddress != fwdStaticCfg.GroupAddress:
                return False
            if staticL2tpMsgBean.localAddress != \
                    L2tpv3GcppSession.L2tpv3GcppProvider.getLocalIp(fwdStaticCfg.SourceAddress):
                return False
            if not fwdStaticCfg.CcapCoreOwner:
                if staticL2tpMsgBean.ccapCoreOwner is not None:
                    return False
            else:
                if staticL2tpMsgBean.ccapCoreOwner != fwdStaticCfg.CcapCoreOwner:
                    return False

        if staticL2tpMsgBean.direction == L2tpv3GcppSession.StaticL2tpSession.DIRECTION_RETURN:
            retStaticCfg = staticPwCfg.RetStaticPwConfig
            if staticL2tpMsgBean.destAddress != retStaticCfg.DestAddress:
                return False
            if staticL2tpMsgBean.localAddress != \
                    L2tpv3GcppSession.L2tpv3GcppProvider.getLocalIp(retStaticCfg.DestAddress):
                return False
            if staticL2tpMsgBean.mtuSize != retStaticCfg.MtuSize:
                return False
            if staticL2tpMsgBean.usPhbId != retStaticCfg.UsPhbId:
                return False
            if not retStaticCfg.CcapCoreOwner:
                if staticL2tpMsgBean.ccapCoreOwner is not None:
                    return False
            else:
                if staticL2tpMsgBean.ccapCoreOwner != retStaticCfg.CcapCoreOwner:
                    return False
        return True


class TestGcppSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_logging("GCPP Unit test")
        cls.gcppSession = L2tpv3GcppSession.L2tpv3GcppProvider()
        cls.fwdCfg = StaticL2tpProvision()
        cls.ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        cls.api = L2tpv3API(cls.ApiPath)
        global_dispatcher = Dispatcher()
        cls.hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                       "the HAL client of L2TP feature",
                                       "1.0", tuple(L2tpHalClient.notification_list.keys()), global_dispatcher)
        cls.hal_client.pushSock = HalTransport(
                HalTransport.HalTransportClientAgentPull, HalTransport.HalClientMode,
                index=19, socketMode=HalTransport.HalSocketPushMode, disconnectHandlerCb=None)

    def test_ipv4SaveGcppSessionDB(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11,
                                          0x80001111, 3, 32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12, 0x80000001, 4, 32768, True)
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        ipv4 = self.gcppSession.getLocalIp("127.0.0.1")
        flag, sessionMsg = self.gcppSession.getStaticSessionBySesId(0x80000001, ipv4, "")
        self.assertTrue(flag)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2)

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13,
                                          0x80001121, 3, 32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 13, True, False)

        self.gcppSession.saveGcppSessionData(staticPwCfg)
        flag, sessionMsg = self.gcppSession.getStaticSessionBySesId(0x80001121, "127.0.0.2", "")
        self.assertFalse(flag)
        flag, sessionMsg = self.gcppSession.getStaticSessionBySesId(0x80001121, ipv4, "")
        self.assertTrue(flag)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 14, False)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14,
                                          0x80000021, 4, 32768, True)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 4)

        self.gcppSession.removeStaticSession(0x80001111, 0)
        self.gcppSession.removeStaticSession(0x80000001, 1)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2)
        self.gcppSession.removeStaticSession(0x80001111, 1)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2)
        self.assertTrue(((0x80001111, 0) not in self.gcppSession.staticPseudowireDB.keys()))
        self.assertTrue(((0x80000001, 1) not in self.gcppSession.staticPseudowireDB.keys()))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13,
                                          0x80001121, 3, 32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 13, True, False, False)

        self.gcppSession.saveGcppSessionData(staticPwCfg)
        flag, sessionMsg = self.gcppSession.getStaticSessionBySesId(0x80001121,
                                                                    ipv4, "")
        if flag and sessionMsg.ccapCoreOwner is None:
            self.gcppSession.removeStaticSession(0x80001121, 0)

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 14, False, False)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14,
                                          0x80000021, 4, 32768, True)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        flag, sessionMsg = self.gcppSession.getStaticSessionBySesId(0x80000021,
                                                                    ipv4, "")
        if flag and sessionMsg.ccapCoreOwner is None:
            self.gcppSession.removeStaticSession(0x80000021, 1)
        self.assertTrue(((0x80001121, 0) not in self.gcppSession.staticPseudowireDB.keys()))
        self.assertTrue(((0x80000021, 1) not in self.gcppSession.staticPseudowireDB.keys()))
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 0)

    def test_unexpect_ipv4SaveGcppSessionDB(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14,
                                          0x80000021, 4, 32768, True)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 0)

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14,
                                          0x80000021, 4, 32768, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 0)

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        commPwCfg = staticPwCfg.CommonStaticPwConfig
        commPwCfg.PwType = 3
        commPwCfg.DepiPwSubtype = 3
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 0)
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        fwdPwCfg = staticPwCfg.FwdStaticPwConfig
        fwdPwCfg.CcapCoreOwner = "00:50:56:9A:22:18"
        fwdPwCfg.GroupAddress = "127.0.0.1"
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13,
                                          0x80001121, 3, 32768, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 1)
        self.gcppSession.removeStaticSession(0x80001121, 0)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 0)

    def test_ipv6SaveGcppSessionDB(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11,
                                          0x80001111, 3, 32768, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12,
                                          0x80000001, 4, 32768, True)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2)

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 13, True, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13,
                                          0x80001121, 3, 32768, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 14, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14,
                                          0x80000021, 4, 32768, True)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 4)

        self.gcppSession.removeStaticSession(0x80001111, 0)
        self.gcppSession.removeStaticSession(0x80000001, 1)
        self.assertEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2)

    def test_staticGcppSession_ipv4(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        staticPwConfig = cfg_msg.StaticPwConfig
        self.fwdCfg.add_dsStaticSession(staticPwConfig, 11, False, False)
        self.fwdCfg.add_commStaticSession(staticPwConfig,
                                          11, 0x80001111, 3, 32768, False)
        self.fwdCfg.add_usStaticSession(staticPwConfig, 12, False)
        self.fwdCfg.add_commStaticSession(staticPwConfig,
                                          12, 0x80001112, 3, 32768, True)
        cfg_payload = rcp_msg.SerializeToString()

        staticL2tpMsg = HalMessage("HalConfig",
                                   SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        self.assertTrue(self.fwdCfg.check_StaticSession(cfg_msg.StaticPwConfig,
                                                        self.gcppSession.staticPseudowireDB))

    def test_staticGcppSession_ipv6(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        self.fwdCfg.add_dsStaticSession(cfg_msg.StaticPwConfig, 11, False, True)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig,
                                          11, 0x80001111, 3, 32768, False)
        self.fwdCfg.add_usStaticSession(cfg_msg.StaticPwConfig, 12, False)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig,
                                          12, 0x80001112, 3, 32768, True)
        cfg_payload = rcp_msg.SerializeToString()
        global_dispatcher = Dispatcher()
        staticL2tpMsg = HalMessage("HalConfig",
                                   SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        self.assertTrue(self.fwdCfg.check_StaticSession(cfg_msg.StaticPwConfig,
                                                        self.gcppSession.staticPseudowireDB))

    def test_MultiCastGcppSession_ipv4(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        self.fwdCfg.add_dsStaticSession(cfg_msg.StaticPwConfig, 13, True, False)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig,
                                          13, 0x80001111, 3, 32768, False)
        self.fwdCfg.add_usStaticSession(cfg_msg.StaticPwConfig, 14, False)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig,
                                          14, 0x80001112, 3, 32768, True)
        cfg_payload = rcp_msg.SerializeToString()
        global_dispatcher = Dispatcher()
        staticL2tpMsg = HalMessage("HalConfig",
                                   SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        self.assertTrue(self.fwdCfg.check_StaticSession(cfg_msg.StaticPwConfig,
                                                        self.gcppSession.staticPseudowireDB))

    def test_MultiCastGcppSession_ipv6(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        for index in range(162, 164):
            self.fwdCfg = StaticL2tpProvision()
            rcp_msg = t_RcpMessage()
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
            cfg_msg = config()
            staticPwConfig = cfg_msg.StaticPwConfig
            self.fwdCfg.add_dsStaticSession(staticPwConfig, index, True, True)
            self.fwdCfg.add_commStaticSession(staticPwConfig,
                                              index, 0x80001111 + index, index, 32768, False)
            rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
            cfg_payload = rcp_msg.SerializeToString()
            global_dispatcher = Dispatcher()
            staticL2tpMsg = HalMessage("HalConfig",
                                       SrcClientID="testGCPPL2Static",
                                       SeqNum=325,
                                       CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                       CfgMsgPayload=cfg_payload)
            self.hal_client.recvCfgMsgCb(staticL2tpMsg)
            self.assertTrue(self.fwdCfg.check_StaticSession(staticPwConfig,
                                                            self.gcppSession.staticPseudowireDB))


            rcp_msg = t_RcpMessage()
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
            cfg_msg = config()
            staticPwConfig = cfg_msg.StaticPwConfig
            self.retCfg = StaticL2tpProvision()
            self.retCfg.add_usStaticSession(staticPwConfig, index + 163, False)
            self.retCfg.add_commStaticSession(staticPwConfig,
                                              index + 163, 0x80007111 + index, index, 32768, True)
            rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
            cfg_payload = rcp_msg.SerializeToString()
            global_dispatcher = Dispatcher()
            staticL2tpMsg = HalMessage("HalConfig",
                                       SrcClientID="testGCPPL2Static",
                                       SeqNum=325,
                                       CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                       CfgMsgPayload=cfg_payload)

            self.hal_client.recvCfgMsgCb(staticL2tpMsg)
            self.assertTrue(self.fwdCfg.check_StaticSession(staticPwConfig,
                                                            self.gcppSession.staticPseudowireDB))

    def test_unexpectGcppSession(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        for index in range(0, 2):
            self.fwdCfg = StaticL2tpProvision()
            staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
            idx = 0
            self.fwdCfg.add_dsStaticSession(staticPwCfg, idx, False, False)
            self.fwdCfg.add_usStaticSession(staticPwCfg, idx, False)
            self.gcppSession.saveGcppSessionData(staticPwCfg)
            self.assertFalse(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                             self.gcppSession.staticPseudowireDB))
            self.assertNotEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2 * index + 2)
            staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
            self.fwdCfg = StaticL2tpProvision()
            self.fwdCfg.add_commStaticSession(staticPwCfg,
                                              index, 0x80001111 + index, index, 32768, False)
            self.fwdCfg.add_commStaticSession(staticPwCfg,
                                              (163 + index), 0x80002112 + index, (167 + index), 32768, True)
            self.gcppSession.saveGcppSessionData(staticPwCfg)
            self.assertFalse(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                             self.gcppSession.staticPseudowireDB))
            self.assertNotEqual(len(self.gcppSession.staticPseudowireDB.keys()), 2 * index + 2)
        return

    def test_showL2tpSessionCLI(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        self.ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11,
                                          0x80001111, 3, 32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12,
                                          0x80000001, 4, 32768, True)
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)

        self.gcppSession.saveGcppSessionData(staticPwCfg)

        self.api = L2tpv3API(self.ApiPath)
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO
        msg = self.api._handleMsg(cmd)
        # FAILURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the session parameter in session query msg")
        return

    def test_unexpctShowL2tpCLI(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11,
                                          0x80001111, 3, 32768, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.STATIC_SESSION_INFO
        sess = cmd.sess
        conn = sess.conn
        conn.remoteAddr = '127.0.0.1'
        conn.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress
        # Connection is not in connection DB
        conn.connectionID = 0
        # Local session is not in connection session
        # connection ------> session
        sess.localSessionID = 0x80001111
        msg = self.api._handleMsg(cmd)
        # FAILURE = 2
        self.assertEqual(msg.rsp, 1)
        return

    def test_getAllocatedIndex(self):
        for index in range(0, 0xFFFF):
            L2tpv3GcppSession.StaticL2tpSession.indexList.append(index)
        index = L2tpv3GcppSession.StaticL2tpSession.getAllocatedIndex()
        self.assertEqual(index, -1)


    def test_L2tpv3Hall_GCPP(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        index = 0
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = config()
        staticPwConfig = cfg_msg.StaticPwConfig
        self.retCfg = StaticL2tpProvision()
        self.retCfg.add_usStaticSession(staticPwConfig, index + 163, False, False)
        self.retCfg.add_commStaticSession(staticPwConfig,
                                        index + 163, 0x80007111 + index, index, 32768, True)
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        global_dispatcher = Dispatcher()
        staticL2tpMsg = HalMessage("HalConfig",
                                    SrcClientID="testGCPPL2Static",
                                    SeqNum=325,
                                    CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                    CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        self.assertFalse(self.fwdCfg.check_StaticSession(staticPwConfig,
                                                        self.gcppSession.staticPseudowireDB))

    def test_L2tpv3Hall_Unexpect_GCPP(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE

        cfg_msg = config()
        cfg_payload = rcp_msg.SerializeToString()
        staticL2tpMsg = HalMessage("HalConfig",
                                    SrcClientID="testGCPPL2Static",
                                    SeqNum=325,
                                    CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                    CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        self.assertTrue(len(self.gcppSession.staticPseudowireDB.keys())==0)

    def test_L2tpv3Hall_Unexpect_GCPP(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        index = 0
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = config()
        staticPwConfig = cfg_msg.StaticPwConfig
        self.retCfg = StaticL2tpProvision()
        self.retCfg.add_usStaticSession(staticPwConfig, index + 163, False)
        self.retCfg.add_commStaticSession(staticPwConfig,
                                        index + 163, 0x80007111 + index, index, 0, True)
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        global_dispatcher = Dispatcher()
        staticL2tpMsg = HalMessage("HalConfig",
                                    SrcClientID="testGCPPL2Static",
                                    SeqNum=325,
                                    CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                    CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwConfig,
                                                        self.gcppSession.staticPseudowireDB))


    def test_GCPP_recvCfgMsgRspCb(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11,
                                          0x80001111, 3, 32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))

        rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        rsp.session_selector.local_ip = self.gcppSession.getLocalIp("127.0.0.1")
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.lcce_id = 0
        rsp.session_selector.local_session_id = 0x80001111
        rsp.session_selector.remote_session_id = 0x80001111
        rsp.result = True
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=2,
                         Rsp={
                             "Status": HalCommon_pb2.SUCCESS,
                             "ErrorDescription": ""
                         },
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertTrue(ret)

    def test_GCPP_recvCfgMsgRspCb_FAILED(self):
        self.gcppSession.staticPseudowireDB.clear()
        L2tpv3GcppSession.StaticL2tpSession.indexList = []
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11,
                                          0x80001111, 3, 32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        self.gcppSession.saveGcppSessionData(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg,
                                                        self.gcppSession.staticPseudowireDB))
        print(self.gcppSession.staticPseudowireDB)

        rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        rsp.session_selector.local_ip = self.gcppSession.getLocalIp("127.0.0.1")
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.lcce_id = 0
        rsp.session_selector.local_session_id = 0x80001111
        rsp.session_selector.remote_session_id = 0x80001111
        rsp.result = True
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=2,
                         Rsp={
                             "Status": HalCommon_pb2.FAILED,
                             "ErrorDescription": ""
                         },
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertFalse(ret)

    @classmethod
    def tearDownClass(cls):
        if cls.hal_client.pushSock:
            cls.hal_client.pushSock.close()
        del cls.hal_client
        del cls.gcppSession

if __name__ == "__main__":
    unittest.main()
