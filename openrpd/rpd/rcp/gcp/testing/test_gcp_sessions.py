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
import ctypes
import Queue
import socket
import unittest
import select
import threading
import errno

import rpd.rcp.gcp.gcp_lib.gcp_object as gcp_object
from rpd.rcp.gcp.gcp_sessions import GCPMasterDescriptor, GCPMaster,\
    GCPSlaveDescriptor, GCPSlaveSession, GCPSession, GCPPacket, GCPSessionFull, GCPSlaveSessionError, \
    GCPSessionError, GCPSessionOrchestrator, GCPMasterSessionError, GCPSessionDescriptor


class TestGCPPacket_encode_exception(object):

    def encode(self, buffer=None, offset=None, buf_data_len=None):
        raise gcp_object.GCPEncodeError("test error")


class TestGCPPacket_encode_false(object):

    def encode(self, buffer=None, offset=None, buf_data_len=None):
        return False


class TestGCPPacket_encode_get_sub_buffer(object):

    def get_data_sub_buffer(self, offset=None):
        return None

    def encode(self, buffer=None, offset=None, buf_data_len=None):
        return True


class TestGCPSessions(unittest.TestCase):
    """Implements unit tests for GCPSlave and GCPMaster."""

    def test_master_init_close(self):
        try:
            GCPMasterDescriptor(addr_family=None)
        except Exception as e:
            self.assertIsInstance(e, GCPMasterSessionError)

        desc = GCPMasterDescriptor(addr=None, port=60001)
        master = GCPMaster(session_descriptor=desc)

        # check if not initiated
        self.assertFalse(master.is_initiated())

        # initiate the session
        master.initiate()

        # check if initiated
        self.assertTrue(master.is_initiated())

        # close the master
        master.close()
        self.assertTrue(master.is_session_failed())

    def __master_worker(self):
        """Accepts connections."""
        rd, wr, ex = select.select([self.master.get_socket()], [], [])
        for s in rd:
            if s is self.master.get_socket():
                if self.master.is_initiated():
                    self.master.accept_connection()

    def test_slave_init_close(self):
        # need to start master first
        desc = GCPMasterDescriptor(addr=None, port=60001)
        self.master = GCPMaster(session_descriptor=desc)
        self.master.initiate()
        self.assertTrue(self.master.is_initiated())

        # create slave
        desc = GCPSlaveDescriptor(addr_master='localhost', port_master=60001)
        slave = GCPSlaveSession(desc)
        self.assertFalse(slave.is_initiated())

        # start master working thread
        t = threading.Thread(target=self.__master_worker)
        t.start()

        # initiate slave
        slave.initiate()
        while slave.is_session_connecting():
            ret = slave.start_and_check_connect()
            if ret in [0, errno.EINPROGRESS, errno.EALREADY]:
                continue
            elif ret in [errno.EISCONN, ]:
                slave.session_state = slave.SESSION_STATE_GCP_SLAVE_INITIATED
                break
            else:
                break
        self.assertTrue(slave.is_initiated())

        # wait for the thread
        t.join()

        # close slave
        slave.close()
        self.assertTrue(slave.is_session_failed())

        # close master
        self.master.close()
        self.assertTrue(self.master.is_session_failed())

    def __master_worker_send_rec(self):
        """Accepts connections and sends back received packets."""
        inputs = [self.master.get_socket()]
        slave = None
        slave_fd = None
        self.master_rec_send_run = True
        count = 0
        while self.master_rec_send_run:
            count += 1
            if count > 60:
                break

            rd, vr, ex = select.select(inputs, [], [], 1)
            for r in rd:
                if r is self.master.get_socket():
                    fd = self.master.accept_connection()
                    ctx = self.master.get_fd_io_ctx(fd)
                    inputs.append(ctx.socket)
                    slave = ctx.socket
                    slave_fd = fd
                else:
                    if slave is not r:
                        continue

                    packet = self.master.read_pkt(r.fileno())

                    # send the same packet back
                    ctx = self.master.get_fd_io_ctx(slave_fd)
                    ctx.add_tx_packet(packet)
                    rd, wr, ex = select.select([], [slave], [], 1)
                    if not wr:
                        pass
                    else:
                        if wr[0] is not slave:
                            pass
                        else:
                            ret = self.master.send_pkt(slave_fd)
                            if ret[0] == GCPSession.PKT_SEND_DONE:
                                pass
                            else:
                                pass

    def test_rec_send(self):
        # need to start master first
        desc = GCPMasterDescriptor(addr=None, port=60001)
        self.master = GCPMaster(session_descriptor=desc)
        self.master.initiate()
        self.assertTrue(self.master.is_initiated())

        # slave init error case
        desc = "test"
        try:
            slave = GCPSlaveSession(desc)
        except Exception as e:
            self.assertIsInstance(e, GCPSlaveSessionError)

        try:
            slave = GCPSession(desc)
        except Exception as e:
            self.assertIsInstance(e, TypeError)

        # create slave
        desc = GCPSlaveDescriptor(addr_master='localhost', port_master=60001)
        slave = GCPSlaveSession(desc)
        self.assertFalse(slave.is_initiated())

        # start master working thread
        t = threading.Thread(target=self.__master_worker_send_rec)
        t.start()

        # initiate slave
        slave.initiate()
        while slave.is_session_connecting():
            ret = slave.start_and_check_connect()
            if ret in [0, errno.EINPROGRESS, errno.EALREADY]:
                continue
            elif ret in [errno.EISCONN, ]:
                slave.session_state = slave.SESSION_STATE_GCP_SLAVE_INITIATED
                break
            else:
                break
        self.assertTrue(slave.is_initiated())

        packet_send = GCPPacket()
        packet_send.transaction_identifier = 1
        packet_send.protocol_identifier = 2
        packet_send.length = 1  # just unit ID
        packet_send.unit_id = 255

        ctx = slave.get_fd_io_ctx(slave.get_socket_fd())
        ctx.add_tx_packet(packet_send)

        rd, wr, ex = select.select([], [slave.get_socket()], [])
        self.assertFalse(not wr, "No any socket for write")

        ret = slave.send_pkt(slave.get_socket_fd())
        self.assertTrue(ret[0] == GCPSession.PKT_SEND_DONE,
                        "Failed to send packet to master")

        rd, wr, ex = select.select([slave.get_socket()], [], [])
        self.assertFalse(not rd, "No any socket for read")

        packet_received = slave.read_pkt(slave.get_socket_fd())
        self.assertFalse(None is packet_received, "Packet receive failed")

        # self.failUnless(packet_received._ut_compare(packet_send),
        #                 "Received broken packet")

        # test add_tx_packet high queue case
        ctx.add_tx_packet(gcp_packet=packet_send, high_priority=True)
        rd, wr, ex = select.select([], [slave.get_socket()], [])
        self.assertFalse(not wr, "No any socket for write")

        ret = slave.send_pkt(slave.get_socket_fd())
        self.assertTrue(ret[0] == GCPSession.PKT_SEND_DONE,
                        "Failed to send packet to master")

        rd, wr, ex = select.select([slave.get_socket()], [], [])
        self.assertFalse(not rd, "No any socket for read")

        packet_received = slave.read_pkt(slave.get_socket_fd())
        self.assertFalse(None is packet_received, "Packet receive failed")

        # test add_tx_packet  low priority queue full case
        self.assertTrue(ctx.is_tx_empty())
        for i in range(0, GCPSession.TX_LOW_PRI_QUEUE_SIZE):
            ctx.add_tx_packet(packet_send)
            if i < GCPSession.TX_LOW_PRI_QUEUE_HIGH_WATERMARK - 1:
                self.assertFalse(ctx.is_tx_low_pri_queue_at_high_watermark())
            else:
                self.assertTrue(ctx.is_tx_low_pri_queue_at_high_watermark())

        self.assertTrue(ctx.packet_tx_low_pri_queue.full())
        try:
            ctx.add_tx_packet(packet_send)
        except Exception as e:
            self.assertIsInstance(e, GCPSessionFull)

        # test add_tx_packet  high priority queue full case
        for i in range(0, GCPSession.TX_HIGH_PRI_QUEUE_SIZE):
            ctx.add_tx_packet(gcp_packet=packet_send, high_priority=True)
        self.assertTrue(ctx.packet_tx_high_pri_queue.full())
        try:
            ctx.add_tx_packet(gcp_packet=packet_send, high_priority=True)
        except Exception as e:
            self.assertIsInstance(e, GCPSessionFull)

        # test add_tx_packet queue None
        ctx.packet_tx_high_pri_queue = None
        ctx.packet_tx_low_pri_queue = Queue.Queue(
            GCPSession.TX_LOW_PRI_QUEUE_SIZE)
        # pkt can not be added
        ret = ctx.add_tx_packet(packet_send)
        self.assertFalse(ret)

        # low queue is none
        ctx.packet_tx_high_pri_queue = Queue.Queue(
            GCPSession.TX_HIGH_PRI_QUEUE_SIZE)
        ctx.packet_tx_low_pri_queue = None
        # pkt can not be added
        ret = ctx.add_tx_packet(packet_send)
        self.assertFalse(ret)

        # high queue is none
        ctx.packet_tx_high_pri_queue = Queue.Queue(
            GCPSession.TX_HIGH_PRI_QUEUE_SIZE)
        ctx.packet_tx_low_pri_queue = Queue.Queue(
            GCPSession.TX_LOW_PRI_QUEUE_SIZE)

        ret = ctx.get_tx_packet()
        self.assertIsNone(ret)

        # wait for the thread
        self.master_rec_send_run = False
        t.join()

        # close slave
        slave.close()
        self.assertTrue(slave.is_session_failed())

        # close master
        self.master.close()
        self.assertTrue(self.master.is_session_failed())

    def test_add_rx_packet(self):
        ctx = GCPSession.GCP_IO_CTX(None)
        packet_rvd = GCPPacket()
        ctx.packet_rx_high_pri_queue = None
        ctx.packet_rx_low_pri_queue = Queue.Queue(
            GCPSession.RX_LOW_PRI_QUEUE_SIZE)
        ret = ctx.add_rx_packet(packet_rvd)
        self.assertFalse(ret)

        ctx.packet_rx_high_pri_queue = Queue.Queue(
            GCPSession.RX_HIGH_PRI_QUEUE_SIZE)
        ctx.packet_rx_low_pri_queue = None
        ret = ctx.add_rx_packet(packet_rvd)
        self.assertFalse(ret)

        # test add_rx_packet  low priority queue full case
        ctx.packet_rx_high_pri_queue = Queue.Queue(
            GCPSession.RX_HIGH_PRI_QUEUE_SIZE)

        ctx.packet_rx_low_pri_queue = Queue.Queue(
            GCPSession.RX_LOW_PRI_QUEUE_SIZE)

        self.assertTrue(ctx.is_rx_empty())
        for i in range(0, GCPSession.RX_LOW_PRI_QUEUE_SIZE):
            ctx.add_rx_packet(packet_rvd)

        self.assertTrue(ctx.packet_rx_low_pri_queue.full())
        try:
            ctx.add_rx_packet(packet_rvd)
        except Exception as e:
            self.assertIsInstance(e, GCPSessionFull)

        # test add_rx_packet  high priority queue full case
        for i in range(0, GCPSession.TX_HIGH_PRI_QUEUE_SIZE):
            ctx.add_rx_packet(gcp_packet=packet_rvd, high_priority=True)
        self.assertTrue(ctx.packet_rx_high_pri_queue.full())
        try:
            ctx.add_rx_packet(gcp_packet=packet_rvd, high_priority=True)
        except Exception as e:
            self.assertIsInstance(e, GCPSessionFull)

        ret = ctx.get_rx_high_pri_packet()
        self.assertEqual(ret, packet_rvd)

        ret = ctx.get_rx_low_pri_packet()
        self.assertEqual(ret, packet_rvd)

        for i in range(0, GCPSession.RX_HIGH_PRI_QUEUE_SIZE - 1):
            ret = ctx.get_rx_packet()
            self.assertEqual(ret, packet_rvd)
        self.assertTrue(ctx.packet_rx_high_pri_queue.empty())

        for i in range(0, GCPSession.RX_LOW_PRI_QUEUE_SIZE - 1):
            ret = ctx.get_rx_packet()
            self.assertEqual(ret, packet_rvd)
        self.assertTrue(ctx.packet_rx_low_pri_queue.empty())

        ret = ctx.get_rx_packet()
        self.assertIsNone(ret)

        ret = ctx.get_rx_high_pri_packet()
        self.assertIsNone(ret)

        ret = ctx.get_rx_low_pri_packet()
        self.assertIsNone(ret)

    def test_GCPSession_error(self):
        try:
            GCPSlaveDescriptor(addr_master='localhost', port_master=None,
                               interface_local="lo",
                               addr_family=socket.AF_INET6)
        except Exception as e:
            self.assertIsInstance(e, GCPSlaveSessionError)

        desc = GCPSlaveDescriptor(addr_master='localhost', port_master=60001,
                                  interface_local="lo",
                                  addr_family=socket.AF_INET)
        self.assertEqual(desc.get_uniq_id(), desc.uniq_id)
        self.assertEqual(desc.get_node_type(), GCPSessionDescriptor.NODE_TYPE_SLAVE)

        session = GCPSession(desc)
        self.assertEqual(-1, session.get_socket_fd())

        self.assertEqual(session.get_sock_string(None), "Socket_None")
        self.assertEqual(session.get_sock_string("test"), "{}:{} --> {}:{}".format(None, None,
                                                                                   None, None))

        session.session_state = GCPSession.SESSION_STATE_FAILED
        try:
            session.initiate()
        except Exception as e:
            self.assertIsInstance(e, GCPSessionError)

        session.reinit()
        self.assertEqual(session.session_state, GCPSession.SESSION_STATE_INIT)

        session.initiate()
        self.assertTrue(session.is_started())
        self.assertTrue(session.is_initiated())

        try:
            session.read_pkt(0)
        except Exception as e:
            self.assertEqual(1, session.stats.RxSessionErr)
            self.assertIsInstance(e, GCPSessionError)

        try:
            session.send_pkt(0)
        except Exception as e:
            self.assertEqual(1, session.stats.TxSessionErr)
            self.assertIsInstance(e, GCPSessionError)

        session.close()

    def test_GCPSlaveSession_error(self):
        desc = GCPSlaveDescriptor(addr_master='localhost', port_master=60001, interface_master='localhost',
                                  interface_local="localhost",
                                  addr_family=socket.AF_INET6)
        self.assertEqual(str(desc), "{}: {}:{} --> {}:{}".format(
            desc.get_node_type_str(),
            desc.addr_local,
            desc.port_local,
            desc.addr_remote,
            desc.port_remote))
        session = GCPSlaveSession(desc)
        session.session_state = GCPSession.SESSION_STATE_FAILED
        try:
            session.initiate()
        except Exception as e:
            self.assertIsInstance(e, GCPSessionError)
        session.reinit()
        session.initiate()
        self.assertFalse(session.is_initiated())

        desc = GCPSlaveDescriptor(addr_master='localhost', port_master=60001, port_local=60002,
                                  interface_local="localhost",
                                  addr_family=socket.AF_INET6)
        session = GCPSlaveSession(desc)
        session.initiate()
        self.assertFalse(session.is_initiated())

        desc = GCPSlaveDescriptor(addr_master='localhost', port_master=60001,
                                  addr_family=socket.AF_INET6)
        session = GCPSlaveSession(desc)
        session.initiate()
        self.assertNotEqual(session.session_state, GCPSession.SESSION_STATE_INIT)

        session.close()

    def test_GCPSessionOrchestrator(self):
        orch = GCPSessionOrchestrator()
        try:
            orch.add_sessions(None)
        except Exception as e:
            self.assertIsInstance(e, NotImplementedError)
        try:
            orch.remove_sessions(None)
        except Exception as e:
            self.assertIsInstance(e, NotImplementedError)
        try:
            orch.replace_session(None, None)
        except Exception as e:
            self.assertIsInstance(e, NotImplementedError)
        try:
            orch.orchestrate_cb(None)
        except Exception as e:
            self.assertIsInstance(e, NotImplementedError)

    def test_GCPMaster_error(self):
        desc = None
        try:
            master = GCPMaster(desc)
        except Exception as e:
            self.assertIsInstance(e, GCPMasterSessionError)

        desc = GCPMasterDescriptor(addr='dummy', interface_name='eth0',
                                   addr_family=socket.AF_INET6)
        master = GCPMaster(desc)
        self.assertIsInstance(master, GCPMaster)
        master.initiate()
        self.assertFalse(master.is_initiated())
        master.remove_connection(0)
        master.close()

        desc = GCPMasterDescriptor(addr='127.0.0.1', interface_name='eth0')
        master = GCPMaster(desc)
        self.assertIsInstance(master, GCPMaster)
        master.initiate()

        self.assertTrue(master.is_initiated())
        ret = master.get_fd_io_ctx(0)
        self.assertIsNone(ret)
        master.remove_connection(0)

        master.slave_cons[0] = GCPSession.GCP_IO_CTX(None)
        master.remove_connection(0)
        master.close()

    def test_GCPSession_send_pkt(self):
        desc = GCPMasterDescriptor(addr=None, port=60001)
        master = GCPMaster(session_descriptor=desc)
        # check if not initiated
        self.assertFalse(master.is_initiated())

        # initiate the session
        master.initiate()

        # check if initiated
        self.assertTrue(master.is_initiated())
        fd = master.io_ctx.socket.fileno()
        ret, pkt = master.send_pkt(fd)
        self.assertEqual(master.stats.TxQEmpty, 1)
        self.assertEqual(ret, GCPSession.PKT_SEND_DONE)
        self.assertIsNone(pkt)

        pkt_test = TestGCPPacket_encode_exception()
        master.io_ctx.add_tx_packet(pkt_test)
        self.assertFalse(master.io_ctx.is_tx_empty())
        ret, pkt = master.send_pkt(fd)
        self.assertEqual(master.stats.TxEncodeErr, 1)
        self.assertEqual(ret, GCPSession.PKT_SEND_FAILED)
        self.assertEqual(pkt, pkt_test)

        pkt_test = TestGCPPacket_encode_false()
        master.io_ctx.add_tx_packet(pkt_test)
        self.assertFalse(master.io_ctx.is_tx_empty())
        ret, pkt = master.send_pkt(fd)
        self.assertEqual(master.stats.TxEncodeFail, 1)
        self.assertEqual(ret, GCPSession.PKT_SEND_FAILED)
        self.assertEqual(pkt, pkt_test)

        pkt_test = TestGCPPacket_encode_get_sub_buffer()
        master.io_ctx.packet_tx_fragment = (pkt_test, 3)
        ret, pkt = master.send_pkt(fd)
        self.assertEqual(master.stats.TxSockErr, 1)
        self.assertEqual(ret, GCPSession.PKT_SEND_FAILED)
        self.assertIsNone(pkt)

        master.close()

    def test_GCPSession_read_pkt(self):

        desc = GCPMasterDescriptor(addr=None, port=60001)
        master = GCPMaster(session_descriptor=desc)
        # check if not initiated
        self.assertFalse(master.is_initiated())

        # initiate the session
        master.initiate()

        # check if initiated
        self.assertTrue(master.is_initiated())
        fd = master.io_ctx.socket.fileno()
        ret = master.read_pkt(fd)
        self.assertEqual(master.stats.RxSockErr, 1)
        self.assertIsNone(ret)
        master.close()


if __name__ == '__main__':
    unittest.main()
