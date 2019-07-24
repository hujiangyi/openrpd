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
import os
import struct
from rpd.dispatcher.dispatcher import Dispatcher
from l2tpv3.src.L2tpv3Hal import L2tpHalClient,L2tpv3HalStats
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
from rpd.common.rpd_logging import AddLoggerToClass

class TestExceptionError(Exception):
    pass

def fake_cb(data):
    print "fake cb handled"

def fake_cb_exception(data):
    raise TestExceptionError()

class testL2tpv3HalStats(unittest.TestCase):
    def test_init_clear(self):
        stats = L2tpv3HalStats()
        self.assertIsInstance(stats,L2tpv3HalStats)
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
        DepiResourceAllocReq = L2tpv3CableLabsAvps.DepiResourceAllocReq(((0, 1),(1,2)))
        UpstreamFlow = L2tpv3CableLabsAvps.UpstreamFlow(((0, 1), (1,2)))

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

        self.hal_client.handler= None
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

        #case exception
        self.hal_client.handler = None
        try:
            ret = self.hal_client.recvCfgMsgRspCb(msg)
        except L2tpHalClientError as e:
            pass

        self.hal_client.handler = L2tpv3GlobalSettings.Dispatcher.receive_hal_message
        #failed case
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

        #case exception
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

        #case exception
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
        except L2tpHalClientError as e:
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
        except L2tpHalClientError as e:
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
        except L2tpHalClientError as e:
            pass

        try:
            ret = self.hal_client.send_l2tp_session_req_msg(
                self.session, 5)
        except L2tpHalClientError as e:
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


if __name__ == "__main__":
    unittest.main()
