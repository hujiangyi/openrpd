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

import zmq

from google.protobuf.message import DecodeError

from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.dispatcher import dispatcher
from rpd.gpb.it_api_msgs_pb2 import t_ItApiRpdMessage,\
    t_ItApiServiceSuiteMessage
from rpd.common.utils import Convert


# Default TCP port where the testing manager will listen
DEFAULT_IT_API_PORT = 7777


class ItApiServer(object):
    """Implements server side of the IT (Integration Testing) API."""

    __metaclass__ = AddLoggerToClass

    def __init__(self, gpb_msg_class, rx_cb, disp=None):
        """Opens socket on the IT API port and listen for GPB messages.

        :param gpb_msg_class: A class of GPB messages which will be exchanged.
        :param rx_cb: User's RX callback which is called when some GPB message
         was received. The callback expects the GPB message as argument.
        :param disp: Dispatcher. New dispatcher is created if None is passed.

        """
        if None is gpb_msg_class:
            raise AttributeError("No GPB message class specified")

        if gpb_msg_class not in [t_ItApiRpdMessage, t_ItApiServiceSuiteMessage]:
            raise AttributeError("Unknown GPB message class passed")

        if None is rx_cb:
            raise AttributeError("No rx_cb specified")

        if None is disp:
            self.disp = dispatcher.Dispatcher()
        else:
            self.disp = disp

        self.rx_cb = rx_cb
        self.gpb_msg_class = gpb_msg_class
        setup_logging("ItManager", filename="IT.log")

        ctx = zmq.Context.instance()
        self.it_api_socket = ctx.socket(zmq.REP)
        self.it_api_socket.bind("tcp://*:{}".format(DEFAULT_IT_API_PORT))
        self.disp.fd_register(self.it_api_socket.getsockopt(zmq.FD),
                              self.disp.EV_FD_IN, self._it_api_socket_handler)

        self.logger.debug("Listening for testing requests")

    def _it_api_socket_handler(self, fd, event_mask):
        """This handler is registered in dispatcher to handle events on the IT
        API socket."""
        if not event_mask:
            self.logger.error(
                "Session event callback called without any event")
            return
        try:
            # receive message
            if event_mask & dispatcher.Dispatcher.EV_FD_IN:
                self.logger.debug("Handling receive event")
                self._it_api_rd_cb(fd)
        except KeyError:
            self.logger.error(
                "Session event callback called for unknown session")

    def _it_api_rd_cb(self, fd):
        """This callback is called to handle RD event on the IT API testing
        socket."""
        if self.it_api_socket is None:
            self.logger.warn("Message received on closed socket")
            return
        try:
            # socket can be closed in callback, must check if it is still valid
            while self.it_api_socket and not self.it_api_socket.closed and \
                    (self.it_api_socket.getsockopt(zmq.EVENTS) and zmq.POLLIN):
                msg = self.it_api_socket.recv(flags=zmq.NOBLOCK)
                self.logger.debug("IPC message from fd [%d] received, len[%d]",
                                  fd, len(msg))
                if len(msg) > 0:
                    try:
                        gpb_msg = self.gpb_msg_class()
                        gpb_msg.ParseFromString(msg)
                    except DecodeError as ex:
                        self.logger.error("Failed to decode IPC message: %s",
                                          ex.message)
                        return
                    try:
                        self.logger.debug("Calling user's RX CB")
                        self.rx_cb(gpb_msg)
                    except Exception as ex:
                        self.logger.error(
                            "User's rx_cb raise exception: %s", ex)
        except zmq.Again:
            # Ignore ... retry handled by dispatcher
            return

    def it_api_send_msg(self, gpb_msg):
        """Sends message back to connected client."""
        if not isinstance(gpb_msg, self.gpb_msg_class):
            raise TypeError("Invalid GPB message type passed")

        if None is self.it_api_socket or self.it_api_socket.closed:
            self.logger.error(
                "Write CB called when no any testing client connected")
            return

        if not gpb_msg.IsInitialized():
            self.logger.error("Non initialized GPB message passed")
            return

        msg_str = gpb_msg.SerializeToString()

        if 0 == len(msg_str):
            self.logger.warn('Empty IPC msg, dropping ...')
            return

        # TODO: noblock?
        self.it_api_socket.send(msg_str)

    def cleanup(self):
        """Cleanup of IT API socket."""
        if None is not self.it_api_socket:
            self.disp.fd_unregister(self.it_api_socket.getsockopt(zmq.FD))
            self.it_api_socket.close()
            self.it_api_socket = None


#
# Specialized ItApiServer classes
#
class ItApiServerOpenRpd(ItApiServer):

    """Specialized ItApiServer for OpenRPD side."""

    def __init__(self, rx_cb, disp=None):
        super(ItApiServerOpenRpd, self).__init__(
            gpb_msg_class=t_ItApiRpdMessage,
            rx_cb=rx_cb,
            disp=disp)


class ItApiServerServiceSuite(ItApiServer):
    """Specialized ItApiServer for Services Suite (OpenRPD counterparts)
    side."""

    def __init__(self, rx_cb, disp=None):
        super(ItApiServerServiceSuite, self).__init__(
            gpb_msg_class=t_ItApiServiceSuiteMessage,
            rx_cb=rx_cb,
            disp=disp)


class ItApiClient(object):
    """Implements client side of IT (Integration Testing) API."""

    __metaclass__ = AddLoggerToClass

    def __init__(self, gpb_msg_class):
        """Creates dispatcher if not passed and initializes instance.
        TODO params dont match

        :param gpb_msg_class: A class of GPB messages which will be exchanged.
        :param rx_cb: User's RX callback which is called when some GPB message
         was received. The callback expects the GPB message as argument.
        :param disp: Dispatcher. New dispatcher is created if None is passed.

        """
        if None is gpb_msg_class:
            raise AttributeError("No any GPB message class passed")

        if gpb_msg_class not in (t_ItApiRpdMessage,
                                 t_ItApiServiceSuiteMessage):
            raise AttributeError("Invalid GPB message class passed")

        self.gpb_msg_class = gpb_msg_class
        self.it_api_socket = None
        setup_logging("ItManager", filename="IT.log")

    def connect(self, ipv4_addr):
        """Creates socket and connects it to the IT API server identified by
        IPv4 address.

        :param ipv4_addr: IPv4 address of the IT API server's interface.
        :type ipv4_addr: String
        :returns: True if connected successfully, False otherwise.

        """
        if None is ipv4_addr:
            raise AttributeError("No IPv4 address of server passed")

        if not Convert.is_valid_ipv4_address(ipv4_addr):
            self.logger.error("Invalid IPv4 address passed: %s", ipv4_addr)
            return False

        port = DEFAULT_IT_API_PORT
        self.logger.debug("Openning socket and connecting to server: %s:%s",
                          ipv4_addr, port)

        ctx = zmq.Context.instance()
        self.it_api_socket = ctx.socket(zmq.REQ)
        self.it_api_socket.connect("tcp://{}:{}".format(ipv4_addr, port))

        self.logger.info("Connected to IT API server: %s:%s", ipv4_addr, port)

        return True

    def it_api_client_read_msg(self):
        """Reads GPB message from socket and returns it.

        None is returned if the read failed.

        """
        if self.it_api_socket is None or self.it_api_socket.closed:
            self.logger.warn("Message received on closed socket")
            return False
        # socket can be closed in callback, must check if it is still valid
        msg = self.it_api_socket.recv()
        self.logger.debug("IPC message received, len[%d]", len(msg))
        if len(msg) > 0:
            try:
                gpb_msg = self.gpb_msg_class()
                gpb_msg.ParseFromString(msg)
            except DecodeError as ex:
                self.logger.error(
                    "Failed to decode IPC message: %s", ex.message)
                return None
        else:
            return None
        return gpb_msg

    def it_api_send_msg(self, gpb_msg):
        """This method is used to send data to the IT API server. Method is
        blocking because it's waiting for reply GPB message from the server.

        :param gpb_msg: GPB message to be sent.
        :returns: GPB message received as reply.

        """
        if not isinstance(gpb_msg, self.gpb_msg_class):
            raise TypeError("Invalid GPB message type passed")

        if None is self.it_api_socket or self.it_api_socket.closed:
            self.logger.error(
                "Write CB called when no any testing client connected")
            return

        if not gpb_msg.IsInitialized():
            self.logger.error("Non initialized GPB message passed")
            return

        msg_str = gpb_msg.SerializeToString()

        if 0 == len(msg_str):
            self.logger.warn('Empty IPC msg, dropping ...')
            return

        self.it_api_socket.send(msg_str)
        self.logger.info("IT API message sent: length[%d]", len(msg_str))

        # Blocking - wait for response
        return self.it_api_client_read_msg()

    def cleanup(self):
        """Cleanup of IT API socket."""
        if None is not self.it_api_socket:
            self.it_api_socket.close()
            self.it_api_socket = None


#
# Specialized IT API client classes
#
class ItApiClientOpenRPD(ItApiClient):
    """IT API client for OpenRPD's IT API server."""

    def __init__(self):
        super(ItApiClientOpenRPD, self).__init__(
            gpb_msg_class=t_ItApiRpdMessage)


class ItApiClientServiceSuite(ItApiClient):
    """IT API client of Service Suite side IT API server."""

    def __init__(self):
        super(ItApiClientServiceSuite, self).__init__(
            gpb_msg_class=t_ItApiServiceSuiteMessage)
