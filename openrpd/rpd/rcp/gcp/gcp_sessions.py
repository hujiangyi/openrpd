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

import Queue
import binascii
import ctypes
import errno
import socket

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.rcp.gcp.gcp_lib.gcp_data_description import GCPException
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPEncodeError, GCPDecodeError
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.rcp.gcp.gcp_lib.gcp_packet import GCPPacket
from rpd.rcp.gcp.gcp_stats import GcpSessionStats


class GCPSessionError(GCPException):
    """GCP session general exception."""


class GCPSessionFull(GCPException):
    """GCP session queue full exception, stop rx/tx packet."""


class GCPSessionQHigh(GCPException):
    """GCP session queue at high watermark exception, stop rx/tx packet."""


class GCPSessionClosed(GCPSessionError):

    """GCP session unexpected close exception."""


class GCPMasterSessionError(GCPSessionError):

    """GCP session master error exception."""


class GCPSlaveSessionError(GCPSessionError):

    """GCP session slave error exception."""


class GCPSession(object):

    """Generic GCP session implementation.

    Class is not intended to be directly instantiated, should be used as
    an superclass.

    """

    # TODO REFACTOR: make a new class for session state and use its objects
    # TODO instead of type code values below
    # TODO 2: is the value assigning necessary?
    # The session states
    SESSION_STATE_INIT = 0
    SESSION_STATE_OPEN = 1
    SESSION_STATE_INPROCESS = 254
    SESSION_STATE_FAILED = 255

    # Class which describes received packet
    PacketClass = GCPPacket

    TCP_KEEPIDLE = 10
    TCP_KEEPINTVL = 5
    TCP_KEEPCNT = 3

    TCP_USER_TIMEOUT = 18
    TCP_USER_TIMEOUT_VALUE = 15000  # in millisecond

    # FIXME: there are rather high value, need tune based on future needs.
    # Mainly to avoid flood of packets.
    RX_HIGH_PRI_QUEUE_SIZE = 32
    RX_LOW_PRI_QUEUE_SIZE = 256
    TX_HIGH_PRI_QUEUE_SIZE = 32
    TX_LOW_PRI_QUEUE_SIZE = 64
    TX_LOW_PRI_QUEUE_HIGH_WATERMARK = 58

    __metaclass__ = AddLoggerToClass

    class GCP_IO_CTX(object):

        """Implements a I/O context for the GCP sessions. Just associates one
        socket with it's own RX and TX buffers."""

        __metaclass__ = AddLoggerToClass

        def __init__(self, socket):
            self.socket = socket
            # create buffers once to improve performance
            self.buffer_tx = ctypes.create_string_buffer(
                GCPPacket.MAX_PACKET_LEN)
            self.buffer_rx = ctypes.create_string_buffer(
                GCPPacket.MAX_PACKET_LEN)
            # stores fragmented GCP packet till outstanding data are received
            self.packet_fragment = None
            self.packet_rx_high_pri_queue = Queue.Queue(
                GCPSession.RX_HIGH_PRI_QUEUE_SIZE)
            self.packet_rx_low_pri_queue = Queue.Queue(
                GCPSession.RX_LOW_PRI_QUEUE_SIZE)
            self.packet_tx_high_pri_queue = Queue.Queue(
                GCPSession.TX_HIGH_PRI_QUEUE_SIZE)
            self.packet_tx_low_pri_queue = Queue.Queue(
                GCPSession.TX_LOW_PRI_QUEUE_SIZE)
            self.packet_tx_fragment = None  # (pkt, offset)

        def add_tx_packet(self, gcp_packet, high_priority=False):
            if None is self.packet_tx_high_pri_queue or None is self.packet_tx_low_pri_queue:
                self.logger.warning(
                    'Both high and low tx priority queue are not initiated.')
                return False
            if high_priority:
                if self.packet_tx_high_pri_queue.full():
                    raise GCPSessionFull(
                        "Packet TX high priority queue is full")
                self.packet_tx_high_pri_queue.put_nowait(gcp_packet)
                return True
            else:
                if self.packet_tx_low_pri_queue.full():
                    raise GCPSessionFull("Packet TX low priority queue is full")
                self.packet_tx_low_pri_queue.put_nowait(gcp_packet)
                return True

        def get_tx_packet(self):

            if not self.packet_tx_high_pri_queue.empty():
                return self.packet_tx_high_pri_queue.get_nowait()
            elif not self.packet_tx_low_pri_queue.empty():
                return self.packet_tx_low_pri_queue.get_nowait()
            else:
                return None

        def is_tx_low_pri_queue_at_high_watermark(self):
            return self.packet_tx_low_pri_queue.qsize() >= \
                   GCPSession.TX_LOW_PRI_QUEUE_HIGH_WATERMARK

        def is_tx_empty(self):
            return self.packet_tx_high_pri_queue.empty() and self.packet_tx_low_pri_queue.empty()

        def add_rx_packet(self, gcp_packet, high_priority=False):
            if None is self.packet_rx_high_pri_queue or None is self.packet_rx_low_pri_queue:
                self.logger.warning(
                    'Both high and low rx priority queue are not initiated.')
                return False
            if high_priority:
                if self.packet_rx_high_pri_queue.full():
                    raise GCPSessionFull(
                        "Packet RX high priority queue is full")
                self.packet_rx_high_pri_queue.put_nowait(gcp_packet)
                return True
            else:
                if self.packet_rx_low_pri_queue.full():
                    raise GCPSessionFull("Packet RX low priority queue is full")
                self.packet_rx_low_pri_queue.put_nowait(gcp_packet)
                return True

        def get_rx_packet(self):
            if not self.packet_rx_high_pri_queue.empty():
                return self.packet_rx_high_pri_queue.get_nowait()
            elif not self.packet_rx_low_pri_queue.empty():
                return self.packet_rx_low_pri_queue.get_nowait()
            else:
                return None

        def get_rx_high_pri_packet(self):
            if not self.packet_rx_high_pri_queue.empty():
                return self.packet_rx_high_pri_queue.get_nowait()
            else:
                return None

        def get_rx_low_pri_packet(self):
            if not self.packet_rx_low_pri_queue.empty():
                return self.packet_rx_low_pri_queue.get_nowait()
            else:
                return None

        def is_rx_empty(self):
            return self.packet_rx_high_pri_queue.empty() and self.packet_rx_low_pri_queue.empty()

        def close(self):
            if None is not self.socket:
                self.socket.close()
                self.socket = None
            self.buffer_rx = None
            self.buffer_tx = None
            self.packet_fragment = None
            self.packet_rx_low_pri_queue = None
            self.packet_rx_high_pri_queue = None
            self.packet_tx_low_pri_queue = None
            self.packet_tx_high_pri_queue = None
            self.packet_tx_fragment = None

    def __init__(self, session_descriptor):
        if not isinstance(session_descriptor, GCPSessionDescriptor):
            raise TypeError("Unexpected session descriptor type")
        self.descr = session_descriptor
        self.stats = GcpSessionStats()
        self.io_ctx = GCPSession.GCP_IO_CTX(None)
        self.session_state = GCPSession.SESSION_STATE_INIT

        # is used for IPv6 connection initiation
        self._ipv6_remote_addr_info = None

    def get_descriptor(self):
        """Returns the descriptor of this sessions."""
        return self.descr

    def get_socket(self):
        """Returns the socket of this sessions."""
        return self.io_ctx.socket

    def get_socket_fd(self):
        """Returns the file descriptor of the session's socket.

        The file descriptor should be considered as valid only if the
        session is initiated. Use the is_initiated() method to check
        session's state.

        """
        if not self.is_initiated():
            self.logger.warning(
                "Asking for the session's socket file descriptor of "
                "non initiated session %s.", self.get_descriptor())
            return -1
        return self._get_socket_fd()

    def _get_socket_fd(self):
        return self.io_ctx.socket.fileno()

    def get_fd_io_ctx(self, fd):
        """Returns IO context according to the FD passed as argument."""
        if self.io_ctx.socket.fileno() != fd:
            return None
        else:
            return self.io_ctx

    @staticmethod
    def get_sock_string(s):
        """Returns string describing the opened socket.

        :param s: Socket

        """
        if None is s:
            return "Socket_None"

        try:
            local = s.getsockname()
        except:
            local = (None, None)

        try:
            remote = s.getpeername()
        except:
            remote = (None, None)

        return "{}:{} --> {}:{}".format(local[0], local[1],
                                        remote[0], remote[1])

    def initiate(self):
        """Opens socket and binds it to the local address if specified.

        :raises GCPSessionError

        """
        # check the state of the session
        if self.session_state != GCPSession.SESSION_STATE_INIT:
            raise GCPSessionError("Trying to initiate session in wrong state")

        try:
            self.logger.info("Opening GCP session %s, AF: %s, Type: %s",
                             self.get_descriptor(), self.descr.get_addr_family(),
                             socket.SOCK_STREAM)

            # get addr info if this is IPv6
            if self.descr.get_addr_family() == socket.AF_INET6:
                rem_addr = self.descr.get_remote_addr()
                rem_addr = rem_addr if None is not rem_addr else "0::0"
                rem_port = self.descr.get_remote_port()
                rem_port = rem_port if None is not rem_port else 0

                self._ipv6_remote_addr_info = socket.getaddrinfo(
                    rem_addr,
                    rem_port,
                    socket.AF_INET6,
                    socket.SOCK_STREAM)
                self._ipv6_remote_addr_info = self._ipv6_remote_addr_info[0]
                (family, s_type, proto,
                 c_name, s_addr) = self._ipv6_remote_addr_info
                self.logger.debug("IPv6 remote addr info: %s",
                                  self._ipv6_remote_addr_info)
                gcp_sock = socket.socket(family, s_type, proto)
            else:
                gcp_sock = socket.socket(self.descr.get_addr_family(),
                                         socket.SOCK_STREAM)

            gcp_sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_REUSEADDR, 1)
            gcp_sock.setsockopt(socket.SOL_TCP,
                                socket.TCP_KEEPIDLE,
                                self.TCP_KEEPIDLE)
            gcp_sock.setsockopt(socket.SOL_TCP,
                                socket.TCP_KEEPINTVL,
                                self.TCP_KEEPINTVL)
            gcp_sock.setsockopt(socket.SOL_TCP,
                                socket.TCP_KEEPCNT,
                                self.TCP_KEEPCNT)
            gcp_sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_KEEPALIVE, 1)
            gcp_sock.setsockopt(socket.SOL_TCP,
                                self.TCP_USER_TIMEOUT,
                                self.TCP_USER_TIMEOUT_VALUE)
            all_interfaces = ("0.0.0.0" if
                              self.descr.get_addr_family() == socket.AF_INET
                              else "::")
            random_port = 0

            # bind the socket to the concrete address or port if specified
            if ((None is not self.descr.get_local_addr()) or
                    (None is not self.descr.get_local_port())):
                addr = (all_interfaces if None is self.descr.get_local_addr()
                        else self.descr.get_local_addr())
                port = (random_port if None is self.descr.get_local_port()
                        else self.descr.get_local_port())
                self.logger.debug("Binding socket to the address: %s:%s",
                                  addr, port)

                if self.descr.get_addr_family() == socket.AF_INET6:
                    ipv6_local_addr_info = socket.getaddrinfo(
                        addr,
                        port,
                        socket.AF_INET6,
                        socket.SOCK_STREAM)
                    self.logger.debug("IPv6 local addr info: %s",
                                      ipv6_local_addr_info)
                    (family, s_type, proto,
                     c_name, s_addr) = ipv6_local_addr_info[0]

                    gcp_sock.bind(s_addr)
                else:
                    gcp_sock.bind((addr, port))

            # set the state to OPEN
            self.logger.info("GCP session opened: %s %s",
                             self.descr.get_node_type_str(),
                             GCPSession.get_sock_string(gcp_sock))
            self.session_state = GCPSession.SESSION_STATE_OPEN
            self.io_ctx.socket = gcp_sock

        except socket.error as ex:
            self.logger.error("Failed to initiate the session (%s): %s",
                              self.descr, ex)
            self.session_state = GCPSession.SESSION_STATE_FAILED

    def is_started(self):
        """Returns False if the initiation has not been started yet,
        True otherwise."""
        return self.session_state != GCPSession.SESSION_STATE_INIT

    def is_initiated(self):
        """Returns True if this sessint has been initiated, False otherwise."""
        return self.session_state == GCPSession.SESSION_STATE_OPEN

    def is_session_failed(self):
        """Returns True if this sessin has failed, False otherwise."""
        return self.session_state == GCPSession.SESSION_STATE_FAILED

    def is_session_connecting(self):
        """Returns True if this sessin in connect process, False otherwise."""
        return self.session_state == GCPSession.SESSION_STATE_INPROCESS

    def close(self):
        """Closes the session."""
        soc_str = None
        if None is not self.io_ctx.socket:
            soc_str = GCPSession.get_sock_string(self.io_ctx.socket)
        self.io_ctx.close()
        self.session_state = GCPSession.SESSION_STATE_FAILED
        self.logger.info("Session closed: %s (%s)", self.descr, soc_str)

    def reinit(self):
        """Re-initialized failed session.

        The session may be initiated again after the re-initialization

        """
        self.io_ctx = self.GCP_IO_CTX(None)
        self.session_state = GCPSession.SESSION_STATE_INIT
        self.logger.info("Session re-initialized %s", self.descr)

    def read_pkt(self, fd):
        """Reads packet from the socket specified by file descriptor and stores
        the raw packet in the RX buffer. Decoded GCP packet is returned as a
        result. None is returned when receive failed or the packet is
        fragmented and needs to receive outstanding part.

        :raises GCPSessionError
        :raises GCPSessionClosed

        """
        ctx = self.get_fd_io_ctx(fd)
        if None is ctx:
            self.stats.RxSessionErr += 1
            raise GCPSessionError("Read packet called for non existing "
                                  "session")

        if None is ctx.packet_fragment:
            # receive the header first, so we will now how much data we
            # need to read in order to have complete packet
            try:
                received = ctx.socket.recv_into(ctx.buffer_rx,
                                                GCPPacket.MIN_PACKET_LEN)
            except socket.error as ex:
                if (ex.args[0] == errno.EAGAIN or
                            ex.args[0] == errno.EWOULDBLOCK):
                    self.stats.RxNoData += 1
                    # no any data to read
                    return None

                self.logger.error(
                    "Failed to read packet header from socket: %s", ex)
                self.stats.RxSockErr += 1
                return None

            if 0 == received:
                self.stats.RxSessionClose += 1
                self.logger.info("Session closed by opposite side: %s",
                                  self.get_descriptor())
                raise GCPSessionClosed("Session closed by opposite "
                                       "side: {}".format(
                    self.get_descriptor()))

            packet = self.PacketClass(ctx.buffer_rx, buf_data_len=received)

            # self.logger.debug("Received packet header (%uB): %s",
            #                  len(packet.get_data_sub_buffer()),
            #                  binascii.hexlify(packet.get_data_sub_buffer()))

            if received < GCPPacket.MIN_PACKET_LEN:
                # handle too short packet as fragmented immediatelly
                ctx.packet_fragment = packet
                self.stats.RxFrag += 1
                return None

            # Now decode the packet header, because it's only a header without
            # payload, the result must be DECODE_FRAGMENTED
            result = packet.decode()
            if result != GCPObject.DECODE_FRAGMENTED:
                if result == GCPObject.DECODE_DONE:
                    self.logger.debug("Empty packet received at %s",
                                      self.get_descriptor())
                    self.stats.Rx += 1
                    return packet

                self.logger.error(
                    "Unexpected result of packet header decoding: %u",
                    result)
                self.stats.RxDecodeFail += 1
                return None
        else:
            packet = ctx.packet_fragment

        # receive the rest of packet
        try:
            received = ctx.socket.recvfrom_into(packet.get_empty_sub_buffer(),
                                                packet.get_missing_len())
        except socket.error as ex:
            if ex.args[0] == errno.EAGAIN or ex.args[0] == errno.EWOULDBLOCK:
                self.stats.RxNoData += 1
                # no any data to read
                return None

            self.logger.error("Failed to read data from socket: %s", ex)
            self.stats.RxSockErr += 1
            return None

        # don't need to have the packet stored
        ctx.packet_fragment = None

        received = received[0]
        if 0 == received:
            self.logger.error("Failed to read outstanding data from socket")
            self.stats.RxSessionClose += 1
            return None

        packet.buf_data_len += received

        # self.logger.debug("Received data (%uB): %s",
        #                  len(packet.get_data_sub_buffer()),
        #                  binascii.hexlify(packet.get_data_sub_buffer()))

        if packet.get_missing_len() < 0:
            self.logger.error(
                "Invalid packet missing length, dropping all data")
            self.stats.RxInvalidLen += 1
            return None

        if packet.get_missing_len() > 0:
            # still no all data received
            ctx.packet_fragment = packet
            self.stats.RxFrag += 1
            return None

        # decoding is done, return the decoded packet
        self.logger.debug("Received GCP packet at %s", self.get_descriptor())
        self.stats.Rx += 1
        return packet

    # Return values of the send_pkt() method
    PKT_SEND_DONE = 0
    PKT_SEND_FRAGMENTED = 1
    PKT_SEND_FAILED = 255

    def send_pkt(self, fd):
        """Encodes and writes GCP packet from the TX buffer to the socket
        specified by file descriptor. Returns the tuple of this format::
        (PKT_SEND_*, GCP_packet)

        The GCP_packet value might be None, what means
        that the TX queue was empty.

        :raises GCPSessionError:

        """
        ctx = self.get_fd_io_ctx(fd)
        if None is ctx:
            self.stats.TxSessionErr += 1
            raise GCPSessionError(
                "Write packet called for non existing session")

        offset = 0
        if None is ctx.packet_tx_fragment:
            packet = ctx.get_tx_packet()
            if None is packet:
                self.stats.TxQEmpty += 1
                self.logger.error("Write packet called with empty TX queue")
                return self.PKT_SEND_DONE, None

            try:
                # buf_data_len = packet.compute_buffer_len()
                result = packet.encode(
                    ctx.buffer_tx, offset=0,
                    buf_data_len=GCPPacket.PACKET_LEN_UNLIMITED)
            except GCPEncodeError:
                self.logger.error("Failed to encode packet")
                self.stats.TxEncodeErr += 1
                return self.PKT_SEND_FAILED, packet

            if not result:
                self.logger.error("Encoding of the packet failed")
                self.stats.TxEncodeFail += 1
                return self.PKT_SEND_FAILED, packet
        else:
            packet = ctx.packet_tx_fragment[0]
            offset = ctx.packet_tx_fragment[1]
            ctx.packet_tx_fragment = None

        dbuf = packet.get_data_sub_buffer(offset)

        # self.logger.debug("Sending data (%uB): %s", len(dbuf), binascii.hexlify(dbuf))

        try:
            data_sent = ctx.socket.send(dbuf)
            if data_sent < len(dbuf):
                self.logger.debug(
                    "Sent packet fragment from %s, data_len: %u, bytes sent: %u",
                    self.get_descriptor(),
                    len(dbuf), data_sent)
                offset += data_sent
                self.stats.TxFrag += 1
                ctx.packet_tx_fragment = (packet, offset)
                return self.PKT_SEND_FRAGMENTED, packet
            else:
                self.stats.Tx += 1
                self.logger.debug("Sent packet from %s", self.get_descriptor())
                return self.PKT_SEND_DONE, packet
        except Exception as e:
            self.logger.info("catch socket send exception: %s", e)
            self.stats.TxSockErr += 1
            return self.PKT_SEND_FAILED, None


class GCPMaster(GCPSession):

    """Local host is a Master side of the session."""
    __metaclass__ = AddLoggerToClass
    SESSION_STATE_GCP_MASTER_INITIATED = 10

    def __init__(self, session_descriptor):
        """
        :raises GCPMasterSessionError
        """
        if not isinstance(session_descriptor, GCPMasterDescriptor):
            raise GCPMasterSessionError("Invalid GCP descriptor passed")

        super(GCPMaster, self).__init__(session_descriptor)

        # mapping of the slave FDs to it's IO contexts
        self.slave_cons = dict()

    def is_initiated(self):
        return self.session_state == self.SESSION_STATE_GCP_MASTER_INITIATED

    def initiate(self):
        super(GCPMaster, self).initiate()

        if not GCPSession.is_initiated(self):
            self.logger.error("Failed to initiate GCPSession")
            return

        try:
            self.logger.debug("Setting socket to listen")
            self.io_ctx.socket.setblocking(0)
            self.io_ctx.socket.listen(5)
        except RuntimeError as ex:
            self.logger.error("Failed to set socket to listen: %s", ex.__str__())
            return

        # initiated
        self.logger.info("GCP master is initiated: %s", self.get_descriptor())
        self.session_state = self.SESSION_STATE_GCP_MASTER_INITIATED

    def get_fd_io_ctx(self, fd):
        """Returns IO context according to the FD passed as argument.

        Extends the method from the GCPSession class and returns also
        master's slave connections' contexts.

        """
        ctx = GCPSession.get_fd_io_ctx(self, fd)
        if None is ctx:
            try:
                ctx = self.slave_cons[fd]
            except KeyError:
                return None

        return ctx

    def accept_connection(self):
        """Accepts new connection on the socket and returns file descriptor
        of the new connection."""
        connection, addr = self.io_ctx.socket.accept()
        connection.setblocking(0)
        self.slave_cons[connection.fileno()] = \
            GCPSession.GCP_IO_CTX(connection)

        self.logger.info("%s:: Accepted connection (%s)", self.descr,
                         GCPSession.get_sock_string(connection))
        return connection.fileno()

    def remove_connection(self, fd):
        """Closes and removes the connection specified by file descriptor."""
        try:
            ctx = self.slave_cons[fd]
        except KeyError:
            self.logger.debug(
                "Remove connection called for non existing connection")
            return

        self.logger.info("%s:: Closing connection (%s)", self.descr,
                         GCPSession.get_sock_string(ctx.socket))
        ctx.close()
        del self.slave_cons[fd]

    def close(self):
        for fd, ctx in self.slave_cons.items():
            ctx.close()
        self.slave_cons.clear()
        super(GCPMaster, self).close()


class GCPSlaveSession(GCPSession):

    """Local host is a Slave side of the session."""

    __metaclass__ = AddLoggerToClass
    SESSION_STATE_GCP_SLAVE_INITIATED = 10

    def __init__(self, session_descriptor):
        """
        :raises GCPSlaveSessionError
        """
        if not isinstance(session_descriptor, GCPSlaveDescriptor):
            raise GCPSlaveSessionError("Invalid GCP descriptor passed")

        super(GCPSlaveSession, self).__init__(session_descriptor)

    def start_and_check_connect(self):
        if self.descr.get_addr_family() == socket.AF_INET6:
            (family, s_type, proto,
             c_name, s_addr) = self._ipv6_remote_addr_info
            ret = self.io_ctx.socket.connect_ex(s_addr)
        else:
            ret = self.io_ctx.socket.connect_ex((self.descr.get_remote_addr(),
                                                 self.descr.get_remote_port()))
        return ret

    def initiate(self):
        super(GCPSlaveSession, self).initiate()

        # check if the GCP session initiation passed
        if not GCPSession.is_initiated(self):
            self.logger.error("GCP session initiation of the GCP slave failed")
            return

        try:
            # connect the socket to the master's address and port
            self.logger.info("Connecting to the GCP master: %s:%s",
                             self.descr.get_remote_addr(),
                             self.descr.get_remote_port())
            # set the socket to be non blocking
            self.io_ctx.socket.setblocking(0)
            ret = self.start_and_check_connect()
            if ret == errno.EINPROGRESS:
                self.session_state = \
                    GCPSlaveSession.SESSION_STATE_INPROCESS
            elif ret == errno.EISCONN:
                self.session_state = \
                    GCPSlaveSession.SESSION_STATE_GCP_SLAVE_INITIATED
            else:
                self.session_state = \
                    GCPSlaveSession.SESSION_STATE_FAILED
                self.logger.error("GCP slave session initiation failed: %d", ret)
            self.logger.info("Slave session initiate, start connect: %s, state: %d",
                             self.get_descriptor(), self.session_state)
        except socket.error as ex:
            self.logger.error("GCP slave session initiation failed: %s", ex)
            self.session_state = GCPSlaveSession.SESSION_STATE_FAILED

    def is_initiated(self):
        return (True if self.session_state ==
                        GCPSlaveSession.SESSION_STATE_GCP_SLAVE_INITIATED
                else False)


class GCPSessionDescriptor(object):
    """Generic descriptor of the GCP session.

    The descriptor consists of triplets: Node type, IP address, Port.

    """
    NODE_TYPE_MASTER = 1
    NODE_TYPE_SLAVE = 2

    DEFAULT_PORT_MASTER = 8190
    DEFAULT_PORT_SLAVE = 8191

    _node_type_map = {
        NODE_TYPE_MASTER: "MASTER",
        NODE_TYPE_SLAVE: "SLAVE"
    }

    __metaclass__ = AddLoggerToClass

    def __init__(self, node_type, addr_family,
                 addr_local, port_local, interface_local,
                 addr_remote, port_remote, interface_remote):
        """

        :param node_type: The type of node
         (NODE_TYPE_MASTER or NODE_TYPE_SLAVE)
        :param addr_family: AF_INET or AF_INET6
        :param addr_local: Local IP address
        :param port_local:  Local TCP port number
        :param interface_local: Interface name, is needed for IPv6 link local.
        :param addr_remote:  Remote IP address
        :param port_remote:  Remote TCP port number
        :param interface_remote: Interface name, is needed for IPv6 link local.
        :raises GCPSessionError

        """
        # Only IPv4 and IPv6 address families are supported
        if (addr_family != socket.AF_INET and
                    addr_family != socket.AF_INET6):
            raise GCPSessionError("Invalid address family passed")

        # It's not supported to specify only addr_remote or only port_remote
        if ((None is addr_remote) and (None is not port_remote) or
                ((None is not addr_remote) and (None is port_remote))):
            raise GCPSessionError("Invalid remote address ({}) or port ({}) "
                                  "passed".format(addr_remote, port_remote))

        self.node_type = node_type
        self.addr_local = addr_local
        self.port_local = port_local
        self.addr_remote = addr_remote
        self.port_remote = port_remote
        self.addr_family = addr_family
        self.interface_local = interface_local
        self.interface_remote = interface_remote
        # Set the uniq_id which should never be changed
        self.uniq_id = self._create_uniq_id()

    def _create_uniq_id(self):
        """Returns an ID of the descriptor which might be used for mapping or
        comparing.

        Might be overridden and should be called just once, in the
        constructor.

        """
        return ("{}:{}:{}:{}:{}".format(
            self.get_node_type_str(),
            self.addr_local,
            self.port_local,
            self.addr_remote,
            self.port_remote))

    def __str__(self):
        """Returns a string describing the session."""
        return ("{}: {}:{} --> {}:{}".format(self.get_node_type_str(),
                                             self.addr_local, self.port_local,
                                             self.addr_remote,
                                             self.port_remote))

    __repr__ = __str__

    def get_uniq_id(self):
        return self.uniq_id

    def get_local_addr(self):
        return self.addr_local

    def get_local_port(self):
        return self.port_local

    def get_remote_addr(self):
        return self.addr_remote

    def get_remote_port(self):
        return self.port_remote

    def get_node_type(self):
        return self.node_type

    def get_node_type_str(self):
        return GCPSessionDescriptor._node_type_map[self.node_type]

    def get_addr_family(self):
        return self.addr_family


class GCPMasterDescriptor(GCPSessionDescriptor):

    """Descriptor of the local GCP Master."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, addr=None,
                 port=GCPSessionDescriptor.DEFAULT_PORT_MASTER,
                 addr_family=socket.AF_INET,
                 interface_name=None):
        """If addr is set to None, then all interfaces are used.

        :raises GCPMasterSessionError

        """
        try:
            super(GCPMasterDescriptor, self).__init__(
                GCPSessionDescriptor.NODE_TYPE_MASTER,
                addr_family,
                addr, port, interface_local=interface_name,
                addr_remote=None, port_remote=None,
                interface_remote=None)
        except GCPSessionError as ex:
            raise GCPMasterSessionError(ex)

    def _create_uniq_id(self):
        """Local address and port are enough to differentiate one master from
        another."""
        return ("{}:{}:{}".format(self.get_node_type_str(),
                                  self.addr_local, self.port_local))


class GCPSlaveDescriptor(GCPSessionDescriptor):

    """Descriptor of the local GCP Slave."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, addr_master,
                 port_master=GCPSessionDescriptor.DEFAULT_PORT_MASTER,
                 interface_master=None,
                 addr_local=None, port_local=None,
                 interface_local=None,
                 addr_family=socket.AF_INET):
        """
        :raises GCPSlaveSessionError
        """
        try:
            super(GCPSlaveDescriptor, self).__init__(
                GCPSessionDescriptor.NODE_TYPE_SLAVE,
                addr_family=addr_family,
                addr_local=addr_local,
                port_local=port_local,
                interface_local=interface_local,
                addr_remote=addr_master,
                port_remote=port_master,
                interface_remote=interface_master)
        except GCPSessionError as ex:
            raise GCPSlaveSessionError(ex)


class GCPSessionOrchestrator(object):

    """Describes interface for the implementation of orchestrating class for
    GCP slave-to-master and master-to-slave sessions by the dispatcher object
    which serves timers events and events on sessions' sockets."""

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        """Creates one dictionary for active sessions and another dictionary
        for failed sessions.

        Unique ids of the session descriptors are used as keys in the
        dictionaries.

        """
        self.sessions_active = dict()
        self.sessions_failed = dict()

    def add_sessions(self, session_descriptors):
        """Creates sessions and orchestrates dispatching of events on the
        sessions.

        Sessions are defined by tuple of objects of the
        GCPSessionDescriptor type. When the new session is already
        stored as active, then an exception is raised. When the new
        session is already stored as failed, then the session is removed
        from the sessions_failed dictionary and added into the
        sessions_active dictionary.

        """
        raise NotImplementedError()

    def remove_sessions(self, session_descriptors):
        """Closes and removes sessions.

        Sessions are defined by tuple of objects of the
        GCPSessionDescriptor type.

        """
        raise NotImplementedError()

    def replace_session(self, session_to_remove, session_to_add):
        """Closes one session and opens another session in a make before break
        manner.

        Sessions are defined by objects of the GCPSessionDescriptor
        type. Sessions must be of the same type (two masters or two
        slaves).

        """
        # TODO maybe not needed
        raise NotImplementedError()

    def orchestrate_cb(self, arg):
        """Checks for the new sessions and starts their initiation.

        Looking for failed sessions and moves them from sessions_active
        to the sessions_failed. This callback is registered for a timer
        and is called periodically.

        """
        raise NotImplementedError()
