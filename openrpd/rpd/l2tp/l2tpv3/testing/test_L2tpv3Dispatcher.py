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

import sys
import os
import struct
import unittest
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.dispatcher.dispatcher import Dispatcher
from l2tpv3.src.L2tpv3Transport import L2tpv3Transport, L2tpv3Network
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher, L2tpv3DispatcherError,L2tpv3DispatcherStats
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3API import L2tpv3API
from l2tpv3.src.L2tpv3Connection import L2tpConnection
from l2tpv3.src.L2tpv3Session import L2tpv3Session


class testL2tpv3Dispatcher(unittest.TestCase):

    def setUp(self):
        self.local_addr="127.0.0.1"
        self.global_dispatcher = Dispatcher()
        self.l2tp_dispatcher = L2tpv3Dispatcher(dispatcher=self.global_dispatcher, create_global_listen=False,
                                                local_addr=self.local_addr)
        L2tpv3GlobalSettings.Dispatcher = self.l2tp_dispatcher

        self.local_addr = "::1"
        self.global_dispatcher = Dispatcher()
        self.l2tp_dispatcher = L2tpv3Dispatcher(dispatcher=self.global_dispatcher, create_global_listen=False,
                                                local_addr=self.local_addr)
        L2tpv3GlobalSettings.Dispatcher = self.l2tp_dispatcher

    def tearDown(self):
        self.l2tp_dispatcher._unregister_local_address(self.local_addr)
        for fd in self.l2tp_dispatcher.socketMapping.keys():
            trans_network = self.l2tp_dispatcher.socketMapping.pop(fd)
            # Close the socket
            trans_network.close()

    def test_init(self):
        local_addr = "test"
        try:
            dispatcher = L2tpv3Dispatcher(dispatcher=self.global_dispatcher, create_global_listen=True,
                                                local_addr=local_addr)
        except L2tpv3DispatcherError as e:
            pass

    def test_register_remote_address(self):
        remoteAddr = "127.0.0.1"
        self.l2tp_dispatcher.register_remote_address(remote_address=remoteAddr)
        self.assertIn(remoteAddr, self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 1)
        self.l2tp_dispatcher.register_remote_address(remote_address=remoteAddr)
        self.assertIn(remoteAddr, self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 1)

        self.l2tp_dispatcher.unregister_remote_address(remote_address="test")
        self.assertNotIn("test", self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 1)

        self.l2tp_dispatcher.unregister_remote_address(remote_address=remoteAddr)
        self.assertNotIn(remoteAddr, self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 0)

        remoteAddr = "::1"
        self.l2tp_dispatcher.register_remote_address(remote_address=remoteAddr)
        self.assertIn(remoteAddr, self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 1)
        self.l2tp_dispatcher.register_remote_address(remote_address=remoteAddr)
        self.assertIn(remoteAddr, self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 1)

        self.l2tp_dispatcher.unregister_remote_address(remote_address="test")
        self.assertNotIn("test", self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 1)

        self.l2tp_dispatcher.unregister_remote_address(remote_address=remoteAddr)
        self.assertNotIn(remoteAddr, self.l2tp_dispatcher.remoteAddrList)
        self.assertEqual(len(self.l2tp_dispatcher.remoteAddrList), 0)

    def test_register_local_address(self):
        local_addr="127.0.0.1"
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertTrue(ret)
        self.assertEqual(reason, "")
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertTrue(ret)
        self.assertRegexpMatches(
            reason, "Addr:%s has been bind" % local_addr)


        local_addr="test"
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertFalse(ret)

        ret, reason = self.l2tp_dispatcher._unregister_local_address(local_addr)
        self.assertFalse(ret)
        self.assertEqual(
                reason, "Cannot find the local address in l2tp interface bindings.")

        local_addr = "127.0.0.1"
        ret, reason = self.l2tp_dispatcher._unregister_local_address(local_addr)
        self.assertTrue(ret)
        self.assertEqual(reason, "")

        local_addr = "::1"
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertTrue(ret)
        self.assertEqual(reason, "")
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertTrue(ret)
        self.assertRegexpMatches(
            reason, "Addr:%s has been bind" % local_addr)

        local_addr = "::1"
        ret, reason = self.l2tp_dispatcher._unregister_local_address(local_addr)
        self.assertTrue(ret)
        self.assertEqual(reason, "")

    def test_register_transport(self):
        conn = L2tpConnection(localConnectionID = 0, remoteConnectionID=1, remoteAddr="127.0.0.1",
                 localAddr="127.0.0.1")
        self.l2tp_dispatcher.register_transport(conn.transport)
        self.assertEqual(self.l2tp_dispatcher.transportMapping[
            (conn.transport.localAddr, conn.transport.remoteAddr, conn.transport.connection.localConnID)],
                         conn.transport )

        self.l2tp_dispatcher._unregister_transport(conn.transport)
        self.assertNotIn((conn.transport.localAddr, conn.transport.remoteAddr, conn.transport.connection.localConnID),
                         self.l2tp_dispatcher.transportMapping)
        self.assertNotIn(conn.transport.network.fileno(), self.l2tp_dispatcher.socketMapping)

        conn.CloseConnection()

        trans = L2tpv3Transport(connection=conn)
        trans.network.close()
        trans.network = "test"
        try:
            self.l2tp_dispatcher.stats.clear()
            self.l2tp_dispatcher.register_transport(transport=trans)
        except L2tpv3DispatcherError as e:
            self.assertEqual(self.l2tp_dispatcher.stats.error,1)

        try:
            self.l2tp_dispatcher.stats.clear()
            self.l2tp_dispatcher._unregister_transport(transport=trans)
        except L2tpv3DispatcherError as e:
            self.assertEqual(self.l2tp_dispatcher.stats.error,1)
        conn.CloseConnection()

        self.l2tp_dispatcher.unregisterRequest = []
        conn = L2tpConnection(localConnectionID=0, remoteConnectionID=1, remoteAddr="127.0.0.1",
                              localAddr="127.0.0.1")
        conn.CloseConnection()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)

        self.l2tp_dispatcher._process_unregister_request()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)


        conn = L2tpConnection(localConnectionID=0, remoteConnectionID=1, remoteAddr="::1",
                              localAddr="::1")
        self.l2tp_dispatcher.register_transport(conn.transport)
        self.assertEqual(self.l2tp_dispatcher.transportMapping[
            (conn.transport.localAddr, conn.transport.remoteAddr, conn.transport.connection.localConnID)],
                         conn.transport )

        self.l2tp_dispatcher._unregister_transport(conn.transport)
        self.assertNotIn((conn.transport.localAddr, conn.transport.remoteAddr, conn.transport.connection.localConnID),
                         self.l2tp_dispatcher.transportMapping)
        self.assertNotIn(conn.transport.network.fileno(), self.l2tp_dispatcher.socketMapping)

        conn.CloseConnection()

        trans = L2tpv3Transport(connection=conn)
        trans.network.close()
        trans.network = "test"
        try:
            self.l2tp_dispatcher.stats.clear()
            self.l2tp_dispatcher.register_transport(transport=trans)
        except L2tpv3DispatcherError as e:
            self.assertEqual(self.l2tp_dispatcher.stats.error,1)

        try:
            self.l2tp_dispatcher.stats.clear()
            self.l2tp_dispatcher._unregister_transport(transport=trans)
        except L2tpv3DispatcherError:
            self.assertEqual(self.l2tp_dispatcher.stats.error, 1)
        conn.CloseConnection()

        self.l2tp_dispatcher.unregisterRequest = []
        conn = L2tpConnection(localConnectionID=0, remoteConnectionID=1, remoteAddr="::1",
                              localAddr="::1")
        conn.CloseConnection()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)

        self.l2tp_dispatcher._process_unregister_request()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

    def test_register_zmq(self):
        api_instance = None
        try:
            self.l2tp_dispatcher.register_zmq(api_instance)
        except L2tpv3DispatcherError as e:
            self.assertRegexpMatches(
                str(e), "parameter is None")
        try:
            self.l2tp_dispatcher.unregister_zmq(api_instance)
        except L2tpv3DispatcherError as e:
            self.assertRegexpMatches(
                str(e), "parameter is None")

        ApiPath = L2tpv3GlobalSettings.APITransportPath
        api = L2tpv3API(ApiPath)
        self.l2tp_dispatcher.register_zmq(api)
        self.assertEqual(self.l2tp_dispatcher.zmqMapping[api.transport.socket], api)

        self.l2tp_dispatcher.unregister_zmq(api)
        self.assertNotIn(api.transport.socket, self.l2tp_dispatcher.zmqMapping)

    def test_request_unregister(self):

        ret, reason = self.l2tp_dispatcher.request_unregister({
            "unregType": "test",
            "value": None
        })

        self.assertFalse(ret)
        self.assertEqual("unknown unregister type: test" ,reason)

        local_addr="127.0.0.1"
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)

        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": "test"})
        self.assertFalse(ret)

        self.l2tp_dispatcher.unregisterRequest = []

        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": local_addr})
        self.assertTrue(ret)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)

        self.l2tp_dispatcher._process_unregister_request()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

        # reg, unreg, reg

        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": local_addr})
        self.assertTrue(ret)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": local_addr})
        self.assertTrue(ret)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)

        self.l2tp_dispatcher._process_unregister_request()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

        local_addr = "::1"
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)

        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": "test"})
        self.assertFalse(ret)

        self.l2tp_dispatcher.unregisterRequest = []

        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": local_addr})
        self.assertTrue(ret)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)

        self.l2tp_dispatcher._process_unregister_request()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

        # reg, unreg, reg

        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": local_addr})
        self.assertTrue(ret)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)
        ret, reason = self.l2tp_dispatcher.register_local_address(local_addr)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

        ret, reason = self.l2tp_dispatcher.request_unregister(
            {"unregType": "localaddress", "value": local_addr})
        self.assertTrue(ret)
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 1)

        self.l2tp_dispatcher._process_unregister_request()
        self.assertEqual(len(self.l2tp_dispatcher.unregisterRequest), 0)

    def test_receive_hal_message(self):
        addr = "127.0.0.1"
        conn = L2tpConnection(localConnectionID=0, remoteConnectionID=1, remoteAddr=addr,
                              localAddr=addr)
        session_receiver = L2tpv3Session(1, 2, 'receiver', conn)
        conn.addSession(session_receiver)

        msg = L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus()

        msg.session_selector.local_ip = addr
        msg.session_selector.remote_ip = addr
        msg.session_selector.local_session_id = 1
        self.l2tp_dispatcher.receive_hal_message(msg)

        msg.session_selector.local_session_id = 2
        self.l2tp_dispatcher.receive_hal_message(msg)

        #case 2
        msg = L2tpv3Hal_pb2.t_l2tpSessionRsp()

        msg.session_selector.local_ip = addr
        msg.session_selector.remote_ip = addr
        msg.session_selector.local_session_id = 1
        conn.removeSession(session_receiver)
        self.l2tp_dispatcher.receive_hal_message(msg)

        addr = "::1"
        conn = L2tpConnection(localConnectionID=0, remoteConnectionID=1, remoteAddr=addr,
                              localAddr=addr)
        session_receiver = L2tpv3Session(1, 2, 'receiver', conn)
        conn.addSession(session_receiver)

        msg = L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus()

        msg.session_selector.local_ip = addr
        msg.session_selector.remote_ip = addr
        msg.session_selector.local_session_id = 1
        self.l2tp_dispatcher.receive_hal_message(msg)

        msg.session_selector.local_session_id = 2
        self.l2tp_dispatcher.receive_hal_message(msg)

        # case 4
        msg = L2tpv3Hal_pb2.t_l2tpSessionRsp()

        msg.session_selector.local_ip = addr
        msg.session_selector.remote_ip = addr
        msg.session_selector.local_session_id = 1
        conn.removeSession(session_receiver)
        self.l2tp_dispatcher.receive_hal_message(msg)


class testL2tpv3DispatcherStats(unittest.TestCase):

    def test_init_clear(self):
        stats = L2tpv3DispatcherStats()
        self.assertIsInstance(stats, L2tpv3DispatcherStats)
        stats.exception = 1
        stats.error = 1
        stats.pkt_error = 1
        stats.zmq_error = 1
        stats.unexpected_else = 1
        stats.clear()
        self.assertEqual(stats.exception, 0)
        self.assertEqual(stats.error, 0)
        self.assertEqual(stats.pkt_error, 0)
        self.assertEqual(stats.zmq_error, 0)
        self.assertEqual(stats.unexpected_else, 0)

if __name__ == '__main__':
    unittest.main()