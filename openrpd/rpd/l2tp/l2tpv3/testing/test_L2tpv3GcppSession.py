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
import rpd.python_path_resolver
import l2tpv3.src.L2tpv3GcppConnection as L2tpv3GcppSession
import rpd.gpb.StaticPwConfig_pb2 as StaticPwConfig_pb2
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from l2tpv3.src.L2tpv3Hal import L2tpHalClient
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalTransport
from l2tpv3.src.L2tpv3API import L2tpv3API
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
from rpd.gpb.cfg_pb2 import config
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.hal.src.msg import HalCommon_pb2
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, \
    stop_test_redis
from l2tpv3.src.L2tpv3GcppConnection import StaticL2tpSession
from l2tpv3.src.L2tpv3SessionDb import L2tpSessionRecord


class StaticL2tpProvision():
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        return

    def add_dsStaticSession(self, staticPwCfg, index, is_MultiCast, is_IPV6,
                            flag=True):
        fwdPwCfg = staticPwCfg.FwdStaticPwConfig
        fwdPwCfg.Index = index
        if flag:
            fwdPwCfg.CcapCoreOwner = "00:50:56:9A:22:18"
        else:
            fwdPwCfg.CcapCoreOwner = \
                L2tpv3GcppSession.StaticL2tpSession.DEFAULT_MAC_ADDR
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

    def add_commStaticSession(self, staticPwCfg, index, sessionId,
                              channelIndex, circuitStatus, direction):
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
            retPwCfg.CcapCoreOwner = \
                L2tpv3GcppSession.StaticL2tpSession.DEFAULT_MAC_ADDR
        retPwCfg.UsPhbId = 0

    def check_StaticSession(self, staticPwCfg, sess):
        if staticPwCfg.HasField("CommonStaticPwConfig"):
            commPwCfg = staticPwCfg.CommonStaticPwConfig
            if not sess:
                return False
            if sess.direction != commPwCfg.Direction:
                return False
            if sess.pwType != commPwCfg.PwType:
                return False
            if sess.depiPwSubtype != commPwCfg.DepiPwSubtype:
                return False
            if sess.l2SublayerType != commPwCfg.L2SublayerType:
                return False
            if sess.depiL2SublayerSubtype != commPwCfg.DepiL2SublayerSubtype:
                return False
            if sess.sessionId != commPwCfg.SessionId:
                return False
            if sess.circuitStatus != commPwCfg.CircuitStatus:
                return False
            if sess.rpdEnetPortIndex != commPwCfg.RpdEnetPortIndex:
                return False
            if sess.enableNotifications != commPwCfg.EnableStatusNotification:
                return False
            PwAssociate = commPwCfg.PwAssociation
            for pwAssociate in PwAssociate:
                channelSelector = pwAssociate.ChannelSelector
                flag = False
                for index, channelBean in sess.pwAssociation.items():
                    if channelSelector.RfPortIndex == channelBean.rfPortIndex \
                            and channelSelector.ChannelType == \
                            channelBean.channelType \
                            and channelSelector.ChannelIndex == \
                            channelBean.channelIndex:
                        flag = True
                        break
                if not flag:
                    return False
        else:
            return False

        if sess.direction == \
                L2tpv3GcppSession.StaticL2tpSession.DIRECTION_FORWARD:
            fwdStaticCfg = staticPwCfg.FwdStaticPwConfig
            if sess.groupAddress != fwdStaticCfg.GroupAddress:
                return False
            if sess.localAddress != \
                    L2tpv3GcppSession.L2tpv3GcppProvider.getLocalIp(
                    fwdStaticCfg.SourceAddress):
                return False
            if not fwdStaticCfg.CcapCoreOwner:
                if sess.ccapCoreOwner is not None:
                    return False
            else:
                if sess.ccapCoreOwner != fwdStaticCfg.CcapCoreOwner:
                    return False

        if sess.direction == \
                L2tpv3GcppSession.StaticL2tpSession.DIRECTION_RETURN:
            retStaticCfg = staticPwCfg.RetStaticPwConfig
            if sess.destAddress != retStaticCfg.DestAddress:
                return False
            if sess.localAddress != \
                    L2tpv3GcppSession.L2tpv3GcppProvider.getLocalIp(
                    retStaticCfg.DestAddress):
                return False
            if sess.mtuSize != retStaticCfg.MtuSize:
                return False
            if sess.usPhbId != retStaticCfg.UsPhbId:
                return False
            if not retStaticCfg.CcapCoreOwner:
                if sess.ccapCoreOwner is not None:
                    return False
            else:
                if sess.ccapCoreOwner != retStaticCfg.CcapCoreOwner:
                    return False
        return True


class TestGcppSession(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_logging("GCPP Unit test")
        setup_test_redis()
        cls.fwdCfg = StaticL2tpProvision()
        cls.ApiPath = \
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        cls.api = L2tpv3API(cls.ApiPath)
        global_dispatcher = Dispatcher()
        cls.hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                       "the HAL client of L2TP feature", "1.0",
                                       tuple(
                                           L2tpHalClient.notification_list.keys()),
                                       global_dispatcher)
        cls.hal_client.pushSock = HalTransport(
            HalTransport.HalTransportClientAgentPull,
            HalTransport.HalClientMode, index=19,
            socketMode=HalTransport.HalSocketPushMode,
            disconnectHandlerCb=None)

    @classmethod
    def tearDownClass(cls):
        if cls.hal_client.pushSock:
            cls.hal_client.pushSock.close()
        del cls.hal_client
        stop_test_redis()
    '''
    def test_ipv4SaveGcppSessionDB(self):
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11, 0x80001111, 3,
                                          32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        sess11 = L2tpv3GcppSession.StaticL2tpSession(11)
        sess11.updateRetstaticPseudowire(staticPwCfg)
        sess11.updateFwdStaticPseudowire(staticPwCfg)
        sess11.updateComStaticPseudowire(staticPwCfg)
        sess11.write()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess11))
        sess11 = None
        sess11 = L2tpv3GcppSession.StaticL2tpSession(11)
        sess11.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess11))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12, 0x80000001, 4,
                                          32768, True)
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)
        sess12 = L2tpv3GcppSession.StaticL2tpSession(12)
        sess12.updateRetstaticPseudowire(staticPwCfg)
        sess12.updateFwdStaticPseudowire(staticPwCfg)
        sess12.updateComStaticPseudowire(staticPwCfg)
        sess12.write()
        sess12 = None
        sess12 = L2tpv3GcppSession.StaticL2tpSession(12)
        sess12.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess12))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13, 0x80001121, 3,
                                          32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 13, True, False)

        sess13 = L2tpv3GcppSession.StaticL2tpSession(13)
        sess13.updateRetstaticPseudowire(staticPwCfg)
        sess13.updateFwdStaticPseudowire(staticPwCfg)
        sess13.updateComStaticPseudowire(staticPwCfg)
        sess13.write()

        sess13 = None
        sess13 = L2tpv3GcppSession.StaticL2tpSession(13)
        sess13.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess13))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 14, False)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14, 0x80000021, 4,
                                          32768, True)
        sess14 = L2tpv3GcppSession.StaticL2tpSession(14)
        sess14.updateRetstaticPseudowire(staticPwCfg)
        sess14.updateFwdStaticPseudowire(staticPwCfg)
        sess14.updateComStaticPseudowire(staticPwCfg)
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess14))
        sess14.write()
        sess14 = None
        sess14 = L2tpv3GcppSession.StaticL2tpSession(14)
        sess14.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess14))

        sess11 = L2tpv3GcppSession.StaticL2tpSession(11)
        sess11.delete()
        sess12 = L2tpv3GcppSession.StaticL2tpSession(12)
        sess12.delete()

        self.assertFalse(11 in StaticL2tpSession.get_keys())
        self.assertFalse(12 in StaticL2tpSession.get_keys())
        self.assertTrue(13 in StaticL2tpSession.get_keys())
        self.assertTrue(14 in StaticL2tpSession.get_keys())
        sess12 = StaticL2tpSession(12)
        sess12.delete()
        self.assertTrue(11 not in StaticL2tpSession.get_keys())
        self.assertTrue(12 not in StaticL2tpSession.get_keys())
        self.assertTrue(13 in StaticL2tpSession.get_keys())
        self.assertTrue(14 in StaticL2tpSession.get_keys())

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13, 0x80001121, 3,
                                          32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 13, True, False)

        sess13 = StaticL2tpSession(13)
        sess13.read()
        sess13.updateRetstaticPseudowire(staticPwCfg)
        sess13.write()
        sess13.updateFwdStaticPseudowire(staticPwCfg)
        sess13.write()
        sess13.updateComStaticPseudowire(staticPwCfg)
        sess13.write()
        sess13 = StaticL2tpSession(13)
        sess13.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, sess13))

    def test_unexpect_ipv4SaveGcppSessionDB(self):
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14, 0x80000021, 4,
                                          32768, True)
        ses14 = StaticL2tpSession(14)
        ses14.updateComStaticPseudowire(staticPwCfg)
        ses14.write()
        self.assertTrue(14 in StaticL2tpSession.get_keys())

    def test_ipv6SaveGcppSessionDB(self):
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11, 0x80001111, 3,
                                          32768, False)
        ses11 = StaticL2tpSession(11)
        ses11.updateFwdStaticPseudowire(staticPwCfg)
        ses11.updateComStaticPseudowire(staticPwCfg)
        ses11.write()
        ses11 = StaticL2tpSession(11)
        ses11.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, ses11))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12, 0x80000001, 4,
                                          32768, True)
        ses12 = StaticL2tpSession(12)
        ses12.updateRetstaticPseudowire(staticPwCfg)
        ses12.write()
        ses12.updateComStaticPseudowire(staticPwCfg)
        ses12.write()
        self.assertTrue(11 in StaticL2tpSession.get_keys())
        self.assertTrue(12 in StaticL2tpSession.get_keys())

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 13, True, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 13, 0x80001121, 3,
                                          32768, False)
        ses13 = StaticL2tpSession(13)
        ses13.updateFwdStaticPseudowire(staticPwCfg)
        ses13.write()
        ses13.updateComStaticPseudowire(staticPwCfg)
        ses13.write()
        ses13 = StaticL2tpSession(13)
        ses13.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, ses13))

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 14, True)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 14, 0x80000021, 4,
                                          32768, True)
        ses14 = StaticL2tpSession(14)
        ses14.updateRetstaticPseudowire(staticPwCfg)
        ses14.write()
        ses14.updateComStaticPseudowire(staticPwCfg)
        ses14.write()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, ses14))
        self.assertTrue(14 in StaticL2tpSession.get_keys())

        ses13.delete()
        ses14.delete()
        self.assertTrue(11 in StaticL2tpSession.get_keys())
        self.assertTrue(12 in StaticL2tpSession.get_keys())
        self.assertFalse(13 in StaticL2tpSession.get_keys())
        self.assertFalse(14 in StaticL2tpSession.get_keys())

    def test_staticGcppSession_ipv4(self):
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        staticPwConfig = cfg_msg.StaticPwConfig

        self.fwdCfg.add_usStaticSession(staticPwConfig, 12, False)
        self.fwdCfg.add_commStaticSession(staticPwConfig, 12, 0x80001112, 3,
                                          32768, True)
        cfg_payload = rcp_msg.SerializeToString()

        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        for key in StaticL2tpSession.get_keys():
            ses = StaticL2tpSession(key)
            ses.read()
            if ses.sessionId == 0x80001112:
                break
        self.assertTrue(
            self.fwdCfg.check_StaticSession(cfg_msg.StaticPwConfig, ses))

    def test_staticGcppSession_ipv6(self):
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        self.fwdCfg.add_dsStaticSession(cfg_msg.StaticPwConfig, 11, False,
                                        True)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig, 11,
                                          0x80001111, 3, 32768, False)
        self.fwdCfg.add_usStaticSession(cfg_msg.StaticPwConfig, 12, False)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig, 12,
                                          0x80001112, 3, 32768, True)
        cfg_payload = rcp_msg.SerializeToString()
        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        ses = StaticL2tpSession(11)
        ses.read()
        self.assertTrue(
            self.fwdCfg.check_StaticSession(cfg_msg.StaticPwConfig, ses))

    def test_MultiCastGcppSession_ipv4(self):
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        self.fwdCfg.add_dsStaticSession(cfg_msg.StaticPwConfig, 13, True,
                                        False)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig, 13,
                                          0x80001111, 3, 32768, False)
        self.fwdCfg.add_usStaticSession(cfg_msg.StaticPwConfig, 14, False)
        self.fwdCfg.add_commStaticSession(cfg_msg.StaticPwConfig, 14,
                                          0x80001112, 3, 32768, True)
        cfg_payload = rcp_msg.SerializeToString()
        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        ses = StaticL2tpSession(13)
        ses.read()
        self.assertTrue(
            self.fwdCfg.check_StaticSession(cfg_msg.StaticPwConfig, ses))

    def test_MultiCastGcppSession_ipv6(self):
        for index in range(162, 164):
            self.fwdCfg = StaticL2tpProvision()
            rcp_msg = t_RcpMessage()
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rcp_msg.RpdDataMessage.RpdDataOperation = \
                t_RpdDataMessage.RPD_CFG_WRITE
            cfg_msg = config()
            staticPwConfig = cfg_msg.StaticPwConfig
            self.fwdCfg.add_dsStaticSession(staticPwConfig, index, True, True)
            self.fwdCfg.add_commStaticSession(staticPwConfig, index,
                                              0x80001111 + index, index, 32768,
                                              False)
            rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
            cfg_payload = rcp_msg.SerializeToString()
            staticL2tpMsg = HalMessage("HalConfig",
                                       SrcClientID="testGCPPL2Static",
                                       SeqNum=325,
                                       CfgMsgType=
                                       HalConfigMsg.MsgTypeGcppToL2tp,
                                       CfgMsgPayload=cfg_payload)
            self.hal_client.recvCfgMsgCb(staticL2tpMsg)
            ses = StaticL2tpSession(index)
            ses.read()
            self.assertTrue(
                self.fwdCfg.check_StaticSession(staticPwConfig, ses))

            rcp_msg = t_RcpMessage()
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rcp_msg.RpdDataMessage.RpdDataOperation = \
                t_RpdDataMessage.RPD_CFG_WRITE
            cfg_msg = config()
            staticPwConfig = cfg_msg.StaticPwConfig
            self.retCfg = StaticL2tpProvision()
            self.retCfg.add_usStaticSession(staticPwConfig, index + 163, False)
            self.retCfg.add_commStaticSession(staticPwConfig, index + 163,
                                              0x80007111 + index, index, 32768,
                                              True)
            rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
            cfg_payload = rcp_msg.SerializeToString()
            staticL2tpMsg = HalMessage("HalConfig",
                                       SrcClientID="testGCPPL2Static",
                                       SeqNum=325,
                                       CfgMsgType=
                                       HalConfigMsg.MsgTypeGcppToL2tp,
                                       CfgMsgPayload=cfg_payload)

            self.hal_client.recvCfgMsgCb(staticL2tpMsg)
            ses = StaticL2tpSession(index + 163)
            ses.read()
            self.assertTrue(
                self.fwdCfg.check_StaticSession(staticPwConfig, ses))

    def test_unexpectGcppSession(self):
        for index in StaticL2tpSession.get_keys():
            ses = StaticL2tpSession(index)
            ses.delete()
        self.assertTrue(len(StaticL2tpSession.indexDBPool[
                        'StaticL2tpSession']) ==
                        StaticL2tpSession.MAX_STATIC_PWS)

        for index in range(0, 10):
            self.fwdCfg = StaticL2tpProvision()
            staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
            self.fwdCfg.add_dsStaticSession(staticPwCfg, index, False, False)
            self.fwdCfg.add_usStaticSession(staticPwCfg, index, False)
            ses = StaticL2tpSession(index)

            ses.updateFwdStaticPseudowire(staticPwCfg)
            ses.allocateIndex()
            ses.write()
            ses.updateRetstaticPseudowire(staticPwCfg)
            ses.allocateIndex()
            ses.write()

            self.assertFalse(self.fwdCfg.check_StaticSession(staticPwCfg, ses))

        for index in StaticL2tpSession.get_keys():
            ses = StaticL2tpSession(index)
            ses.read()
        self.assertTrue(len(StaticL2tpSession.indexDBPool[
                        'StaticL2tpSession']) ==
                        StaticL2tpSession.MAX_STATIC_PWS - 1)
        ses = StaticL2tpSession(0)
        self.assertTrue(ses.index == 0)
        ses.allocateIndex()
        self.assertFalse((ses.index == 0))
        return

    def test_showL2tpSessionCLI(self):
        self.fwdCfg = StaticL2tpProvision()
        self.ApiPath = \
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11, 0x80001111, 3,
                                          32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        ses = StaticL2tpSession(11)
        ses.updateComStaticPseudowire(staticPwCfg)
        ses.updateFwdStaticPseudowire(staticPwCfg)
        ses.write()

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12, 0x80000001, 4,
                                          32768, True)
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)

        ses = StaticL2tpSession(12)
        ses.updateComStaticPseudowire(staticPwCfg)
        ses.updateRetstaticPseudowire(staticPwCfg)
        ses.write()

        self.api = L2tpv3API(self.ApiPath)
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO
        msg = self.api._handleMsg(cmd)
        # FAILURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(msg.retMsg,
                         "Cannot find the session parameter in session "
                         "query msg")
        return

    def test_unexpctShowL2tpCLI(self):
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11, 0x80001111, 3,
                                          32768, False)
        ses11 = StaticL2tpSession(11)
        ses11.updateComStaticPseudowire(staticPwCfg)
        ses11.updateFwdStaticPseudowire(staticPwCfg)
        ses11.write()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)
        ses12 = StaticL2tpSession(12)
        ses12.updateRetstaticPseudowire(staticPwCfg)
        ses12.write()
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.STATIC_SESSION_INFO
        sess = cmd.sess
        conn = sess.conn
        conn.remoteAddr = '127.0.0.1'
        conn.localAddr = \
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress
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
        for key in StaticL2tpSession.get_keys():
            ses = StaticL2tpSession(key)
            ses.delete()

        for index in range(0, 0xFFFF):
            ses.allocateIndex()

        try:
            ses.allocateIndex()
        except IndexError:
            pass

        for key in StaticL2tpSession.get_keys():
            ses = StaticL2tpSession(key)
            ses.delete()
    '''

    def test_L2tpv3Hall_GCPP(self):
        index = 0
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = config()
        staticPwConfig = cfg_msg.StaticPwConfig
        self.retCfg = StaticL2tpProvision()
        self.retCfg.add_usStaticSession(staticPwConfig, index + 163, False,
                                        False)
        self.retCfg.add_commStaticSession(staticPwConfig, index + 163,
                                          0x80007111 + index, index, 32768,
                                          True)
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        ses = StaticL2tpSession(index + 163)
        ses.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwConfig, ses))

    def test_L2tpv3Hall_Unexpect_GCPP(self):
        index = 0
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = config()
        staticPwConfig = cfg_msg.StaticPwConfig
        self.retCfg = StaticL2tpProvision()
        self.retCfg.add_usStaticSession(staticPwConfig, index + 163, False)
        self.retCfg.add_commStaticSession(staticPwConfig, index + 163,
                                          0x80007111 + index, index, 0, True)
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(cfg_msg)
        cfg_payload = rcp_msg.SerializeToString()
        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)

        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        ses = StaticL2tpSession(index + 163)
        ses.read()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwConfig, ses))

    def test_GCPP_recvCfgMsgRspCb(self):
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11, 0x80001111, 3,
                                          32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        ses = StaticL2tpSession(11)
        ses.updateComStaticPseudowire(staticPwCfg)
        ses.updateFwdStaticPseudowire(staticPwCfg)
        ses.write()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, ses))

        rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        rsp.session_selector.local_ip = \
            L2tpv3GcppSession.L2tpv3GcppProvider.getLocalIp(
                "127.0.0.1")
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.lcce_id = 0
        rsp.session_selector.local_session_id = 0x80001111
        rsp.session_selector.remote_session_id = 0x80001111
        rsp.result = True
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=2,
                         Rsp={"Status": HalCommon_pb2.SUCCESS,
                              "ErrorDescription": ""},
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertTrue(ret)

    def test_GCPP_recvCfgMsgRspCb_FAILED(self):
        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 11, 0x80001111, 3,
                                          32768, False)
        self.fwdCfg.add_dsStaticSession(staticPwCfg, 11, False, False)
        ses = StaticL2tpSession(11)
        ses.updateFwdStaticPseudowire(staticPwCfg)
        ses.updateComStaticPseudowire(staticPwCfg)
        ses.write()
        self.assertTrue(self.fwdCfg.check_StaticSession(staticPwCfg, ses))

        rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        rsp.session_selector.local_ip = \
            L2tpv3GcppSession.L2tpv3GcppProvider.getLocalIp(
                "127.0.0.1")
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.lcce_id = 0
        rsp.session_selector.local_session_id = 0x80001111
        rsp.session_selector.remote_session_id = 0x80001111
        rsp.result = True
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=2,
                         Rsp={"Status": HalCommon_pb2.FAILED,
                              "ErrorDescription": ""},
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertFalse(ret)

    def test_staticGcppSession_CFG_WRITE_l2tpsessinfo_DB(self):
        sessRec = L2tpSessionRecord()
        sessRec.deleteAll()
        self.fwdCfg = StaticL2tpProvision()
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        rcp_msg.RpdDataMessage.RpdDataOperation = \
            t_RpdDataMessage.RPD_CFG_WRITE
        cfg_msg = rcp_msg.RpdDataMessage.RpdData
        staticPwConfig = cfg_msg.StaticPwConfig

        self.fwdCfg.add_usStaticSession(staticPwConfig, 12, False)
        self.fwdCfg.add_commStaticSession(staticPwConfig, 12, 0x80001112, 3,
                                          32768, True)
        cfg_payload = rcp_msg.SerializeToString()

        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        # cfg 2nd CFG_WRITE msg
        self.fwdCfg.add_usStaticSession(staticPwConfig, 12, False)
        self.fwdCfg.add_commStaticSession(staticPwConfig, 12, 0x80001113, 3,
                                          32768, True)
        cfg_payload = rcp_msg.SerializeToString()

        staticL2tpMsg = HalMessage("HalConfig", SrcClientID="testGCPPL2Static",
                                   SeqNum=325,
                                   CfgMsgType=HalConfigMsg.MsgTypeGcppToL2tp,
                                   CfgMsgPayload=cfg_payload)
        self.hal_client.recvCfgMsgCb(staticL2tpMsg)
        # check DB record
        sessRec = L2tpSessionRecord()
        retlist = sessRec.get_all()
        listlen = 0
        for sessRecord in retlist:
            listlen = listlen + 1
        self.assertEqual(listlen, 1)
        self.assertEqual(sessRecord.index.l2tpSessionId, 0x80001113)


if __name__ == "__main__":
    unittest.main()
