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
import struct

from rpd.dispatcher.dispatcher import Dispatcher
from l2tpv3.src.L2tpv3Hal import L2tpHalClient, L2tpv3HalStats
from l2tpv3.src.L2tpv3Hal import L2tpHalClientError
import rpd.hal.src.HalConfigMsg as HalConfigMsg
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from l2tpv3.src.L2tpv3Session import L2tpv3Session
from l2tpv3.src.L2tpv3Connection import L2tpConnection
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
import rpd.gpb.StaticPwConfig_pb2 as StaticPwConfig_pb2
import l2tpv3.src.L2tpv3GcppConnection as L2tpv3GcppSession
from l2tpv3.testing.test_L2tpv3GcppSession import StaticL2tpProvision
import time
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, stop_test_redis
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.gpb.cfg_pb2 import config
from rpd.hal.src.HalConfigMsg import MsgTypeRpdInfo
from rpd.mcast.src.DepiMcastSessionRecord import DepiMcastSessionRecord
from l2tpv3.src.L2tpv3SessionDb import L2tpSessionRecord
from rpd.common import utils


class TestExceptionError(Exception):
    pass


def fake_cb(data):
    print "fake cb handled"


def fake_cb_exception(data):
    raise TestExceptionError()


class testL2tpv3HalStats(unittest.TestCase):

    def test_init_clear(self):
        stats = L2tpv3HalStats()
        self.assertIsInstance(stats, L2tpv3HalStats)
        stats.error = 1
        stats.exception = 1
        stats.zmq_error = 1
        stats.clear()
        self.assertEqual(stats.error, 0)
        self.assertEqual(stats.exception, 0)
        self.assertEqual(stats.zmq_error, 0)


class testL2tpv3Hal(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        # open logger
        setup_logging("L2TP")
        setup_test_redis()

        cls.conn_address = '127.0.0.1'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(
            global_dispatcher, cls.conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        # setup the halclient

        notification_list = list()
        notification_list.append(
            HalConfigMsg.MsgTypeL2tpv3SessionStatusNotification)

        cls.hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                       "the HAL client of L2TP feature",
                                       "1.0", tuple(L2tpHalClient.notification_list.keys()), global_dispatcher)

        cls.hal_client.handler = dispatcher.receive_hal_message
        cls.conn = L2tpConnection(
            6661, 6662, cls.conn_address, cls.conn_address)
        cls.session = L2tpv3Session(6661, 6662, 'receiver', cls.conn)
        cls.conn.addSession(cls.session)
        localSessionId = L2tpv3RFC3931AVPs.LocalSessionID(6661)
        remoteSessionId = L2tpv3RFC3931AVPs.RemoteSessionID(6662)
        remoteEnd = L2tpv3RFC3931AVPs.RemoteEndID(
            (((0, 3, 0), 0), ((0, 3, 1), 1), ((0, 3, 2), 2)))
        remoteEnd_1 = L2tpv3RFC3931AVPs.RemoteEndID(
            (((0, 3, 3), 3), ((0, 3, 4), 4), ((0, 3, 5), 5)))
        pw_type = L2tpv3RFC3931AVPs.L2SpecificSublayer(3)
        DepiL2SpecificSublayerSubtype = L2tpv3CableLabsAvps.DepiL2SpecificSublayerSubtype(3)
        LocalMTUCableLabs = L2tpv3CableLabsAvps.LocalMTUCableLabs(1500)
        DepiRemoteMulticastJoin = L2tpv3CableLabsAvps.DepiRemoteMulticastJoin(("5.5.5.1", "229.1.1.255"))
        DepiResourceAllocReq = L2tpv3CableLabsAvps.DepiResourceAllocReq(((0, 1), (1, 2)))
        UpstreamFlow = L2tpv3CableLabsAvps.UpstreamFlow(((0, 1), (1, 2)))

        cls.session.avps_icrq.append(localSessionId)
        cls.session.avps_icrq.append(remoteSessionId)
        cls.session.avps_icrq.append(remoteEnd)
        cls.session.avps_icrq.append(remoteEnd_1)
        cls.session.avps_icrq.append(DepiL2SpecificSublayerSubtype)
        cls.session.avps_icrq.append(LocalMTUCableLabs)
        cls.session.avps_icrq.append(pw_type)
        cls.session.avps_icrq.append(DepiRemoteMulticastJoin)
        cls.session.avps_icrq.append(DepiResourceAllocReq)
        cls.session.avps_icrq.append(UpstreamFlow)

    @classmethod
    def tearDownClass(cls):
        cls.conn.CloseConnection()
        cls.conn.transport.network.close()
        L2tpv3GlobalSettings.Dispatcher._unregister_local_address(
            cls.conn_address)
        stop_test_redis()

    def setUp(self):
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

    def tearDown(self):
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()

    def test_get_route_table(self):
        route_table = L2tpHalClient.get_route_table()
        print route_table
        self.assertIsNotNone(route_table)

    def test_get_gateway(self):
        ipaddr = "127.0.0.1"
        ret = L2tpHalClient.get_gateway(ipaddr)
        self.assertEqual(ret, "127.0.0.1")
        ipaddr = "10.79.41.136"
        ret = L2tpHalClient.get_gateway(ipaddr)
        print ret
        ipaddr = "10.1.1.1"
        ret = L2tpHalClient.get_gateway(ipaddr)
        print ret

    def test_get_mac_of_ip(self):
        ipaddr = "127.0.0.1"
        ret = L2tpHalClient.get_mac_of_ip(ipaddr)
        self.assertEqual(ret, "00:00:00:00:00:00")
        ipaddr = "10.79.41.137"
        ret = L2tpHalClient.get_mac_of_ip(ipaddr)
        print ret
        ipaddr = "10.1.1.1"
        ret = L2tpHalClient.get_mac_of_ip(ipaddr)
        print ret
        ipaddr = "::1"
        ret = L2tpHalClient.get_mac_of_ip(ipaddr)
        self.assertEqual(ret, "00:00:00:00:00:00")
        ipaddr = "202:201:304:506::1"
        ret = L2tpHalClient.get_mac_of_ip(ipaddr)
        print ret

    def test_get_local_mac(self):
        ipaddr = "127.0.0.1"
        ret = L2tpHalClient.get_local_mac(ipaddr)
        self.assertIsNotNone(ret)

        ipaddr = "::1"
        ret = L2tpHalClient.get_local_mac(ipaddr)
        self.assertIsNotNone(ret)
        """
        ipaddr = "10.79.41.135"
        ret_mac_1 = "00:00:00:00:00:00"
        ret = L2tpHalClient.get_local_mac(ipaddr)
        self.assertEqual(ret, "00:50:56:9c:15:31")
        """

    def test_get_mac_bytes_from_ip(self):
        ipaddr = "10.1.1.1"
        ret = L2tpHalClient.get_mac_bytes_from_ip(ipaddr)
        mac = struct.unpack("!6B", ret)
        print mac

    def test_recvHalNotification(self):
        notification_status = L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus()
        notification_status.status = False
        notification_status.session_selector.local_ip = "127.0.0.1"
        notification_status.session_selector.remote_ip = "127.0.0.1"
        notification_status.session_selector.lcce_id = 1
        notification_status.session_selector.local_session_id = 1234
        notification_status.session_selector.remote_session_id = 1232556
        payload = notification_status.SerializeToString()
        notfication = HalMessage(
            "HalNotification", ClientID="1", HalNotificationType=HalConfigMsg.MsgTypeL2tpv3SessionStatusNotification,
            HalNotificationPayLoad=payload)

        ret = self.hal_client.recvHalNotification(notfication)
        self.assertTrue(ret)

        self.hal_client.handler = fake_cb
        ret = self.hal_client.recvHalNotification(notfication)
        self.assertTrue(ret)

        self.hal_client.handler = fake_cb_exception
        ret = self.hal_client.recvHalNotification(notfication)
        self.assertTrue(ret)

        notification_cap = L2tpv3Hal_pb2.t_l2tpCapability()
        payload = notification_cap.SerializeToString()
        notfication = HalMessage(
            "HalNotification", ClientID="1", HalNotificationType=HalConfigMsg.MsgTypeRpdCapabilities,
            HalNotificationPayLoad=payload)

        self.hal_client.handler = None
        ret = self.hal_client.recvHalNotification(notfication)
        self.assertTrue(ret)

        self.hal_client.handler = fake_cb
        ret = self.hal_client.recvHalNotification(notfication)
        self.assertTrue(ret)

        self.hal_client.handler = fake_cb_exception
        ret = self.hal_client.recvHalNotification(notfication)
        self.hal_client.handler = None
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        self.assertTrue(ret)

    def test_session_recvCfgMsgRspCb(self):
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        self.session.fsm.recvGoodICRQ()
        self.session.fsm.recvGoodICCN()
        rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        rsp.session_selector.local_ip = "127.0.0.1"
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.lcce_id = 1
        rsp.session_selector.local_session_id = 6661
        rsp.session_selector.remote_session_id = 6662
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

        # case exception
        self.hal_client.handler = None
        try:
            ret = self.hal_client.recvCfgMsgRspCb(msg)
        except L2tpHalClientError:
            pass

        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        # failed case
        rsp = L2tpv3Hal_pb2.t_l2tpSessionReq()
        rsp.msg_type = L2tpv3Session.ADD_SESSION
        rsp.session_selector.local_ip = "127.0.0.1"
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.local_session_id = 6661
        rsp.session_selector.remote_session_id = 6662
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=2,
                         Rsp={
                             "Status": HalCommon_pb2.TIMEOUT,
                             "ErrorDescription": ""
                         },
                         CfgMsgType=3073,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertFalse(ret)

    def test_del_session_recvCfgMsgRspCb(self):
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        self.session.fsm.recvGoodICRQ()
        rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
        rsp.session_selector.local_ip = "127.0.0.1"
        rsp.session_selector.remote_ip = "127.0.0.1"
        rsp.session_selector.lcce_id = 1
        rsp.session_selector.local_session_id = 6661
        rsp.session_selector.remote_session_id = 6662
        rsp.result = True
        rsp.req_data.circuit_status = False
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

    def test_lcceID_good_recvCfgMsgRspCb(self):
        self.conn.fsm.recvGoodSCCRQ()
        self.conn.fsm.recvGoodSCCCN()
        rsp = L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp()
        rsp.lcce_id = self.conn.localConnID
        rsp.lcce_info.local_ip = "10.79.41.138"
        rsp.lcce_info.remote_ip = "10.79.41.139"
        rsp.lcce_info.local_mac = L2tpHalClient.get_mac_of_ip(rsp.lcce_info.local_ip)
        rsp.lcce_info.remote_mac = L2tpHalClient.get_mac_of_ip(rsp.lcce_info.remote_ip)
        rsp.lcce_info.mtu = 2342
        rsp.result = True
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=3,
                         Rsp={
                             "Status": HalCommon_pb2.SUCCESS,
                             "ErrorDescription": ""
                         },
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertTrue(ret)

        # case exception
        self.hal_client.handler = None
        try:
            ret = self.hal_client.recvCfgMsgRspCb(msg)
            self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        except L2tpHalClientError as e:
            pass

    def test_lcceId_bad_recvCfgMsgRspCb(self):
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        self.conn.fsm.recvGoodSCCRQ()
        self.conn.fsm.recvGoodSCCCN()
        rsp = L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp()
        rsp.lcce_id = self.conn.localConnID
        rsp.lcce_info.local_ip = "10.79.41.138"
        rsp.lcce_info.remote_ip = "10.79.41.139"
        rsp.lcce_info.local_mac = L2tpHalClient.get_mac_of_ip(rsp.lcce_info.local_ip)
        rsp.lcce_info.remote_mac = L2tpHalClient.get_mac_of_ip(rsp.lcce_info.remote_ip)
        rsp.lcce_info.mtu = 2342
        rsp.result = False
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=3,
                         Rsp={
                             "Status": HalCommon_pb2.SUCCESS,
                             "ErrorDescription": ""
                         },
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertTrue(ret)

    def test_lcceId_bad_recvCfgMsgRspCb_NOTSUUPPORT(self):
        self.conn.fsm.recvGoodSCCRQ()
        self.conn.fsm.recvGoodSCCCN()
        rsp = L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq()
        rsp.lcce_id = self.conn.localConnID
        rsp.lcce_info.local_ip = "10.79.41.138"
        rsp.lcce_info.remote_ip = "10.79.41.139"
        rsp.lcce_info.local_mac = L2tpHalClient.get_mac_of_ip(rsp.lcce_info.local_ip)
        rsp.lcce_info.remote_mac = L2tpHalClient.get_mac_of_ip(rsp.lcce_info.remote_ip)
        rsp.lcce_info.mtu = 2342
        rsp.msg_type = L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq.ADD_L2TPv3_LCCE
        payload = rsp.SerializeToString()
        msg = HalMessage("HalConfigRsp", SrcClientID="123", SeqNum=3,
                         Rsp={
                             "Status": HalCommon_pb2.NOTSUPPORTED,
                             "ErrorDescription": ""
                         },
                         CfgMsgType=HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment,
                         CfgMsgPayload=payload)
        ret = self.hal_client.recvCfgMsgRspCb(msg)
        self.assertFalse(ret)

        # case exception
        fake_msg = HalMessage("HalClientRegisterRsp",
                              Rsp={
                                  "Status": HalCommon_pb2.NOTSUPPORTED,
                                  "ErrorDescription": ""
                              },
                              ClientID="214")
        ret = self.hal_client.recvCfgMsgRspCb(cfg=fake_msg)
        self.assertFalse(ret)

    def test_get_message_type_from_remote_end_id(self):
        # case 1
        remote_end_id_list = []
        for i in range(8):
            item = L2tpv3Hal_pb2.t_l2tpRemoteEndId()
            item.RfPortIndex = 0
            item.RfChannelType = L2tpHalClient.DS_SCQAM
            item.RfChannelIndex = i
            item.mpts_tag = i
            remote_end_id_list.append(item)
        ret_type = self.hal_client.get_message_type_from_remote_end_id(
            remote_end_id_list)
        self.assertEqual(ret_type, [L2tpHalClient.DS_SCQAM])

        # case 2
        item = L2tpv3Hal_pb2.t_l2tpRemoteEndId()
        item.RfPortIndex = 0
        item.RfChannelType = L2tpHalClient.US_ATDMA
        item.RfChannelIndex = 2
        item.mpts_tag = 0
        remote_end_id_list.append(item)
        try:
            self.hal_client.get_message_type_from_remote_end_id(
                remote_end_id_list)
        except L2tpHalClientError:
            pass

        # case 3
        ret_type = self.hal_client.get_message_type_from_remote_end_id(None)
        self.assertIsNone(ret_type)

        # case 4
        item = L2tpv3Hal_pb2.t_l2tpRemoteEndId()
        item.RfPortIndex = 0
        item.RfChannelType = L2tpHalClient.DS_OFDM
        item.RfChannelIndex = 1
        item.mpts_tag = 0
        remote_end_id_list.append(item)
        item = L2tpv3Hal_pb2.t_l2tpRemoteEndId()
        item.RfPortIndex = 0
        item.RfChannelType = L2tpHalClient.DS_OFDM_PLC
        item.RfChannelIndex = 0
        item.mpts_tag = 1
        remote_end_id_list.append(item)
        ret_type = self.hal_client.get_message_type_from_remote_end_id(remote_end_id_list)
        self.assertIn(L2tpHalClient.DS_OFDM, ret_type)
        self.assertIn(L2tpHalClient.DS_OFDM_PLC, ret_type)

    def test_fill_session_req_req_data(self):
        # case 1
        req_msg = L2tpv3Hal_pb2.t_l2tpSessionReq()
        ret = self.hal_client.fill_session_req_req_data(
            self.session, L2tpv3Session.ADD_SESSION, req_msg.req_data)
        self.assertTrue(ret)
        self.assertEquals(len(req_msg.req_data.remote_end_id), 6)
        self.assertEquals(req_msg.req_data.sublayer_type, 3)
        self.assertEquals(req_msg.req_data.remote_mtu, 1500)
        self.assertEquals(req_msg.req_data.pw_type, 3)
        self.assertNotEqual(req_msg.req_data.lcce_id, 0)
        self.assertEquals(len(req_msg.req_data.local_mac), 6)
        self.assertEquals(len(req_msg.req_data.remote_mac), 6)
        self.assertEqual(len(req_msg.req_data.phb_info), 4)
        self.assertEqual(len(req_msg.req_data.mcast_info), 1)

        # case 2
        try:
            ret = self.hal_client.fill_session_req_req_data(
                self.conn, L2tpv3Session.ADD_SESSION, req_msg.req_data)
        except L2tpHalClientError:
            pass

    def test_send_l2tp_session_req_msg(self):
        # case 1
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        ret = self.hal_client.send_l2tp_session_req_msg(
            self.session, L2tpv3Session.ADD_SESSION)
        self.assertTrue(ret)

        # case 2
        try:
            ret = self.hal_client.send_l2tp_session_req_msg(
                self.conn, L2tpv3Session.ADD_SESSION)
        except L2tpHalClientError:
            pass

        try:
            ret = self.hal_client.send_l2tp_session_req_msg(
                self.session, 5)
        except L2tpHalClientError:
            pass

    def test_send_l2tp_lcce_assignment_msg(self):
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        ret = self.hal_client.send_l2tp_lcce_assignment_msg(
            self.conn, L2tpConnection.ADD_LCCE)
        self.assertTrue(ret)

        try:
            self.hal_client.send_l2tp_lcce_assignment_msg(
                lcce=None, msg_type=L2tpConnection.ADD_LCCE)
        except Exception as e:
            self.assertIsInstance(e, L2tpHalClientError)

        try:
            ret = self.hal_client.send_l2tp_lcce_assignment_msg(
                self.conn, 5)
        except Exception as e:
            self.assertIsInstance(e, L2tpHalClientError)

    def test_l2tp_arp_learn(self):
        self.hal_client.arp_addr_dict["127.0.0.2"] = "00:00:00:00:00:00"
        self.hal_client.arp_addr_dict["127.0.0.1"] = "00:00:00:00:00:00"
        self.hal_client.startL2tpReCfgTimer()

        self.fwdCfg = StaticL2tpProvision()
        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12, 0x80000001, 4,
                                          32768, True)
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)
        session1 = L2tpv3GcppSession.StaticL2tpSession(12)
        session1.updateRetstaticPseudowire(staticPwCfg)
        session1.updateComStaticPseudowire(staticPwCfg)
        session1.destAddress = "127.0.0.1"
        session1.write()

        staticPwCfg = StaticPwConfig_pb2.t_StaticPwConfig()
        self.fwdCfg.add_commStaticSession(staticPwCfg, 12, 0x80000002, 5,
                                          32768, True)
        self.fwdCfg.add_usStaticSession(staticPwCfg, 12, False)
        session2 = L2tpv3GcppSession.StaticL2tpSession(12)
        session2.updateRetstaticPseudowire(staticPwCfg)
        session2.updateComStaticPseudowire(staticPwCfg)
        session2.destAddress = "127.0.0.2"
        session2.write()
        self.hal_client.update_us_l2tp_session_cfg(1)
        time.sleep(10)

        remoteMac = L2tpHalClient.get_mac_bytes_from_ip(session1.destAddress)
        self.assertNotEquals(remoteMac, "00:00:00:00:00:00")
        remoteMac = L2tpHalClient.get_mac_bytes_from_ip(session2.destAddress)
        self.assertNotEquals(remoteMac, "00:00:00:00:00:00")
        session1.delete()
        session2.delete()

    def test_start(self):
        self.hal_client.handler = None
        self.hal_client.dispatcher = None
        self.hal_client.start(cfg_cb=None)
        self.assertIsNone(self.hal_client.handler)
        self.hal_client.dispatcher = L2tpv3GlobalSettings.Dispatcher.dispatcher
        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        self.hal_client.start(cfg_cb=None)
        pass

    def test_connectionDisconnectCb(self):
        self.hal_client.disconnected = True
        self.hal_client.connectionDisconnectCb(None)
        self.hal_client.disconnected = False
        self.hal_client.connectionDisconnectCb(None)
        self.hal_client.disconnected = True
        pass

    def test_recvRpdInfo(self):
        # db support
        # clear db records
        sessRec = DepiMcastSessionRecord()
        sessRec.delete_all()
        sessRec = DepiMcastSessionRecord()
        test_count = 2
        for test_session in range(0, test_count):
            sessRec.updateDepiMcastSessionKey(IpAddrType=1,
                                              GroupIpAddr="10.79.31.1",
                                              SrcIpAddr="10.90.31.1",
                                              SessionId=test_session)
            sessRec.JoinTime = time.time()
            sessRec.write()

        print("######test_recvRpdInfo######")
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION

        print("=====test case1: payload operation read, # no read count, no key=====")
        data = config()
        data.RpdInfo.DepiMcastSession.add()
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        self.assertEqual(len(recv_rcp_msg.RpdInfo.DepiMcastSession), 2)
        self.assertEqual(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

        print("=====test case2: payload operation read, # read with keylist=====")
        data = config()
        for sessionId in range(0, 3):
            req = data.RpdInfo.DepiMcastSession.add()
            req.IpAddrType = 1
            req.GroupIpAddr = "10.79.31.1"
            req.SrcIpAddr = "10.90.31.1"
            req.SessionId = sessionId + 1

        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        for item in recv_rcp_msg.RpdInfo.DepiMcastSession:
            print item
        self.assertEqual(len(recv_rcp_msg.RpdInfo.DepiMcastSession), 3)
        self.assertEquals(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

        print("=====test case3: payload operation read, # read with readcount=====")
        data = config()
        data.ReadCount = 3
        req = data.RpdInfo.DepiMcastSession.add()
        req.IpAddrType = 1
        req.GroupIpAddr = "10.79.31.1"
        req.SrcIpAddr = "10.90.31.1"
        req.SessionId = 0

        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        for item in recv_rcp_msg.RpdInfo.DepiMcastSession:
            print item
        self.assertEqual(len(recv_rcp_msg.RpdInfo.DepiMcastSession), 2)
        self.assertEquals(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

    def test_recvRpdInfo_empty(self):
        # nothing in db
        sessRec = DepiMcastSessionRecord()
        ret = []
        for record in sessRec.get_next_n(count=100):
            ret.append(record)
        self.assertEquals(len(ret), 0)

        print("######test_recvRpdInfo with empty database######")
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION

        print("=====test case1: payload operation read, # no read count, no key=====")
        data = config()
        data.RpdInfo.DepiMcastSession.add()
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        self.assertEqual(len(recv_rcp_msg.RpdInfo.DepiMcastSession), 1)
        self.assertEqual(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

        print("=====test case2: payload operation read, # read with keylist=====")
        data = config()
        for sessionId in range(0, 3):
            req = data.RpdInfo.DepiMcastSession.add()
            req.IpAddrType = 1
            req.SessionId = sessionId + 1

        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        for item in recv_rcp_msg.RpdInfo.DepiMcastSession:
            print item
        self.assertEqual(len(recv_rcp_msg.RpdInfo.DepiMcastSession), 3)
        self.assertEquals(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

        print("=====test case3: payload operation read, # read with readcount=====")
        data = config()
        data.ReadCount = 3
        req = data.RpdInfo.DepiMcastSession.add()
        req.IpAddrType = 1
        req.SessionId = 0

        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        for item in recv_rcp_msg.RpdInfo.DepiMcastSession:
            print item
        self.assertEqual(len(recv_rcp_msg.RpdInfo.DepiMcastSession), 1)
        self.assertEquals(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

    def create_ipv4_ipv6_mcast(self, test_count):
        # create test_count records for ipv4 and test_count records for ipv6
        sessRec = DepiMcastSessionRecord()
        for test_session in range(0, test_count):
            sessRec.updateDepiMcastSessionKey(IpAddrType=1,
                                              GroupIpAddr="10.79.31.1",
                                              SrcIpAddr="10.79.31.1",
                                              SessionId=test_session)
            sessRec.LocalLcceIpAddr = "10.79.31.2"
            sessRec.RemoteLcceIpAddr = "10.79.31.1"
            sessRec.JoinTime = time.time()
            sessRec.write()
            sessRec.updateDepiMcastSessionKey(IpAddrType=2,
                                              GroupIpAddr="ff15:7079:7468:6f6e:6465:6d6f:6d63:6173",
                                              SrcIpAddr="2001::1",
                                              SessionId=test_session)
            sessRec.LocalLcceIpAddr = "2001::2"
            sessRec.RemoteLcceIpAddr = "2001::1"
            sessRec.JoinTime = time.time()
            sessRec.write()

    def test_recvRpdInfo_l2tpsessinfo(self):
        # db support
        # clear db records
        sessRec = L2tpSessionRecord()
        sessRec.deleteAll()
        sessRec = L2tpSessionRecord()
        test_count = 2
        for test_session in range(0, test_count):
            sessRec.updateL2tpSessionKey("10.79.31.1",
                                         "10.90.31.1",
                                         0,
                                         test_session)
            counterDiscTime = utils.Convert.pack_timestamp_to_string(
                int(time.time()))
            sessRec.updateL2tpSessionRecordData(
                coreId='1A2B3C4D5E6F',
                connCtrlId=0x12345678,
                udpPort=0,
                descr='(0:4:1)',
                sessionType=1,
                sessionSubType=4,
                maxPayload=1500,
                pathPayload=0,
                rpdIfMtu=9200,
                coreIfMtu=1500,
                errorCode=1,
                creationTime=300,
                operStatus=1,
                localStatus=0,
                lastChange=300,
                counterDiscontinuityTime=counterDiscTime)
            sessRec.write()

        print("######test_recvRpdInfo_l2tpsessinfo######")
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION

        print("=====test case1: payload operation read, # no read count, no key=====")
        data = config()
        data.RpdInfo.RpdL2tpSessionInfo.add()
        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        self.assertEqual(len(recv_rcp_msg.RpdInfo.RpdL2tpSessionInfo), 2)
        self.assertEqual(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

        print("=====test case2: payload operation read, # read with keylist=====")
        data = config()
        for sessionId in range(0, 3):
            req = data.RpdInfo.RpdL2tpSessionInfo.add()
            req.SessionIpAddrType = 1
            req.RemoteLcceIpAddr = "10.79.31.1"
            req.RpdLcceIpAddress = "10.90.31.1"
            req.Direction = 0
            req.LocalL2tpSessionId = sessionId

        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        for item in recv_rcp_msg.RpdInfo.RpdL2tpSessionInfo:
            print item
        self.assertEqual(len(recv_rcp_msg.RpdInfo.RpdL2tpSessionInfo), 3)
        self.assertEquals(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)

        print("=====test case3: payload operation read, # read with readcount=====")
        data = config()
        data.ReadCount = 3
        req = data.RpdInfo.RpdL2tpSessionInfo.add()
        req.SessionIpAddrType = 1
        req.RemoteLcceIpAddr = "10.79.31.1"
        req.RpdLcceIpAddress = "10.90.31.1"
        req.Direction = 0
        req.LocalL2tpSessionId = 0

        rcp_msg.RpdDataMessage.RpdData.CopyFrom(data)
        rcp_msg.RpdDataMessage.RpdDataOperation = 2
        payload = rcp_msg.SerializeToString()
        msg = HalMessage("HalConfig",
                         SrcClientID="testRpdFM",
                         SeqNum=322,
                         CfgMsgType=MsgTypeRpdInfo,
                         CfgMsgPayload=payload)
        return_str = self.hal_client.recvRpdInfo(msg.msg)
        config_data = t_RcpMessage()
        config_data.ParseFromString(msg.msg.CfgMsgPayload)
        recv_rcp_msg = config_data.RpdDataMessage.RpdData
        for item in recv_rcp_msg.RpdInfo.RpdL2tpSessionInfo:
            print item
        self.assertEqual(len(recv_rcp_msg.RpdInfo.RpdL2tpSessionInfo), 2)
        self.assertEquals(config_data.RcpDataResult, t_RcpMessage.RCP_RESULT_OK)


if __name__ == "__main__":
    unittest.main()
