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

import time
import socket
import zmq
import L2tpv3Connection
import L2tpv3ControlPacket
import L2tpv3Transport
import traceback
import L2tpv3Hal_pb2
from rpd.common.rpd_logging import AddLoggerToClass


class L2tpv3DispatcherError(Exception):
    ParameterTypeError = "Input parameter error"
    ParameterIsNone = "parameter is None"


class L2tpv3DispatcherStats(object):

    def __init__(self):
        self.exception = 0
        self.error = 0
        self.pkt_error = 0
        self.zmq_error = 0
        self.unexpected_else = 0

    def clear(self):
        self.exception = 0
        self.error = 0
        self.pkt_error = 0
        self.zmq_error = 0
        self.unexpected_else = 0


class L2tpv3Dispatcher(object):
    """This is the program entry point and the main loop.

    Currently, we use the pyzmq loop for this. The following features
    will be supported:
    1. Register/Unregister transport instance.
    2. Register/unregister zmq socket instance.
    3. Register/unregister the local address socket.
    3. Dispatch the event via callback.

    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, dispatcher, local_addr, create_global_listen=True, test_plan=None):
        self.dispatcher = dispatcher
        self.fdSockMapping = dict()
        self.time_tick = 1
        self.last_time_tick = time.time()
        self.socketMapping = dict()
        self.transportMapping = dict()
        self.zmqMapping = dict()
        self.unregisterRequest = list()
        self.stats = L2tpv3DispatcherStats()
        self.remoteAddrList = []

        # Create a global network here
        if create_global_listen:
            ret, reason = self.register_local_address(local_addr)
            if not ret:
                self.stats.error += 1
                raise L2tpv3DispatcherError(
                    "Cannot listen on local address, reason:" + reason)

        # test plane is used by the mater sim, it will inject a test plan in
        # planed time tick
        self.testPlan = test_plan
        self.dispatcherStartTime = time.time()

        self.dispatcher.timer_register(
            self.time_tick, self._l2tp_event_entry_point_timer_wrapper, None)

    def register_remote_address(self, remote_address="127.0.0.1"):
        if remote_address not in self.remoteAddrList:
            self.remoteAddrList.append(remote_address)

    def unregister_remote_address(self, remote_address="127.0.0.1"):
        if remote_address in self.remoteAddrList:
            self.remoteAddrList.remove(remote_address)

    def register_local_address(self, local_address="127.0.0.1"):
        """Set a new local address and let the L2TP bind to it.

        :param local_address: the local ip address which the l2tp daemon with try to bind.
        :return: True/False, and the reason

        """
        try:
            self.logger.info(
                "Create and register local address %s to l2tp daemon:" % local_address)

            # Find the address in self.socketMapping
            find_fd = -1
            for fd in self.socketMapping:
                if self.socketMapping[fd].addr == local_address and self.socketMapping[fd].connID == 0:
                    find_fd = fd

            if find_fd != -1:
                # pop un_register request from queue
                for req in self.unregisterRequest:
                    unreg_type = req['unregType']
                    value = req['value']
                    if unreg_type == "localaddress" and value == local_address:
                        self.unregisterRequest.remove(req)
                        self.dispatcher.fd_register(
                            find_fd, zmq.POLLIN | zmq.POLLERR, self._l2tp_event_entry_point)
                return True, "Addr:%s has been bind" % local_address

            local_network = L2tpv3Transport.L2tpv3Network(local_address, 0)
            if not local_network.socket:
                return False, "Socket has not been created"
            self.dispatcher.fd_register(
                local_network.fileno(), zmq.POLLIN | zmq.POLLERR, self._l2tp_event_entry_point)
            self.socketMapping[local_network.fileno()] = local_network
        except (socket.error, socket.herror, socket.gaierror) as e:
            reason = str(e)
            self.stats.exception += 1
            self.logger.error(
                "Cannot create a l2tp socket for IP:%s, reason:%s" % (local_address, reason))
            return False, reason
        return True, ""

    def _unregister_local_address(self, local_address):
        """Try to find the local address in dispatcher, and try to release
        the resource  and close the socket.

        TBD: This function will not close the connection which has been created.

        :param local_address: the local ip address which the l2tp daemon with
         try to bind.
        :return: True/False, and the reason

        """
        try:
            self.logger.info(
                "Release resource and close local address %s from l2tp daemon." % local_address)

            # Find the address in self.localAddress
            find_fd = -1
            for fd in self.socketMapping:
                if self.socketMapping[fd].addr == local_address and self.socketMapping[fd].connID == 0:
                    find_fd = fd
            if find_fd == -1:
                self.logger.warn(
                    "Cannot find the local address:%s in local address dict." % local_address)
                return False, "Cannot find the local address in l2tp interface bindings."

            # release the resources
            trans_network = self.socketMapping.pop(find_fd)

            # Close the socket
            trans_network.close()

        except (socket.error, socket.herror, socket.gaierror, KeyError) as e:
            reason = str(e)
            self.stats.exception += 1
            self.logger.warn(
                "Cannot delete IP:%s from a l2tp daemon, reason:%s" % (local_address, reason))
            return False, reason
        return True, ""

    def register_transport(self, transport):
        """Register the transport to dispatcher.

        :param transport: the connection transport layer.
        :return: None

        """
        net_socket = transport.network
        if not isinstance(net_socket, L2tpv3Transport.L2tpv3Network):
            self.logger.warn(L2tpv3DispatcherError.ParameterTypeError)
            self.stats.error += 1
            raise L2tpv3DispatcherError(
                L2tpv3DispatcherError.ParameterTypeError)

        self.logger.info("Add socket to L2tp dispatcher, addr(%s, %d)" %
                         (net_socket.addr, net_socket.connID))

        self.dispatcher.fd_register(
            net_socket.fileno(), zmq.POLLIN | zmq.POLLERR, self._l2tp_event_entry_point)

        self.socketMapping[net_socket.fileno()] = net_socket
        self.transportMapping[
            (transport.localAddr, transport.remoteAddr, transport.connection.localConnID)] = transport

    def _unregister_transport(self, transport):
        """Remove the transport from dispatcher, please note that, this
        function will not invoke the dispatcher unregister.

        :param transport: the connection transport layer.
        :return:

        """
        net_socket = transport.network
        if not isinstance(net_socket, L2tpv3Transport.L2tpv3Network):
            self.logger.warn(L2tpv3DispatcherError.ParameterTypeError)
            self.stats.error += 1
            raise L2tpv3DispatcherError(
                L2tpv3DispatcherError.ParameterTypeError)

        self.logger.info("Remove transport from L2tp dispatcher, addr(%s, %d)" %
                         (net_socket.addr, net_socket.connID))

        self.socketMapping.pop(net_socket.fileno())
        self.transportMapping.pop(
            (transport.localAddr, transport.remoteAddr, transport.connection.localConnID))

    def register_zmq(self, api_instance):
        """Register the zmq socket to dispatcher.

        :param api_instance: the zmq instance.
        :return: None

        """
        if api_instance is None:
            self.logger.error("Cannot register a none zmq socket")
            self.stats.error += 1
            raise L2tpv3DispatcherError(L2tpv3DispatcherError.ParameterIsNone)

        self.logger.debug("Register zmq socket to dispatcher:%s" %
                          api_instance.transport.path)
        self.dispatcher.fd_register(api_instance.transport.socket, zmq.POLLIN, self._l2tp_event_entry_point)
        self.zmqMapping[api_instance.transport.socket] = api_instance

    def unregister_zmq(self, api_instance):
        """Remove the zmq socket from dispatcher.

        :param api_instance: the connection transport layer.
        :return:

        """
        if api_instance is None:
            self.logger.warn("Cannot register a none zmq socket")
            self.stats.error += 1
            raise L2tpv3DispatcherError(L2tpv3DispatcherError.ParameterIsNone)

        self.logger.debug("Unregister zmq socket from dispatcher")
        self.dispatcher.fd_unregister(api_instance.transport.socket)
        self.zmqMapping.pop(api_instance.transport.socket)

    def request_unregister(self, req):
        """The reason we need a un-register request, since we don't want to
        change the whole structure in one cycle, In processing cycle, we just
        post a request and we will process it at the start of the every cycle.

        :param req:the connection transport layer.
        :return:

        """
        unreg_type = req['unregType']
        value = req['value']

        if unreg_type == 'transport':
            # Close and unregister it early, for avoiding receiving the packet
            # agent.
            self.dispatcher.fd_unregister(value.network.fileno())
        elif unreg_type == 'localaddress':
            # Find the address in self.localAddress
            find_fd = -1
            for fd in self.socketMapping:
                if self.socketMapping[fd].addr == value and self.socketMapping[fd].connID == 0:
                    find_fd = fd
            if find_fd == -1:
                reason = "Cannot find the local address:%s in local address dict." % value
                self.logger.warn(reason)
                self.stats.error += 1
                return False, reason
            self.dispatcher.fd_unregister(self.socketMapping[find_fd].fileno())
        else:
            reason = "unknown unregister type: %s" % unreg_type
            self.logger.warn(reason)
            self.stats.error += 1
            return False, reason

        self.unregisterRequest.append(req)

        return True, "Success"

    def _process_unregister_request(self):
        for req in self.unregisterRequest:
            self.logger.debug("Process the unregister request:%s" % str(req))

            unreg_type = req['unregType']
            value = req['value']

            if unreg_type == 'transport':
                self._unregister_transport(value)
                value.network.close()  # Close the socket
            elif unreg_type == 'localaddress':
                self._unregister_local_address(value)
            else:
                pass

        for i in xrange(len(self.unregisterRequest)):
            self.unregisterRequest.pop(0)

    def _l2tp_event_entry_point_timer_wrapper(self, arg):
        self._l2tp_event_entry_point(None, 0)

    def _l2tp_event_entry_point(self, sock, eventmask):
        """This is the entry point of L2TP module, the function will
        responsible for dispatch the event to correct routines.

        :param sock: this args may be fd or zmq socket.
        :param eventmask: POLLIN/POLLERR
        :return: None

        """
        # First we should process the unregister event.
        self._process_unregister_request()
        try:
            # For the transport sockets
            if sock is not None:
                if isinstance(sock, int) and eventmask == zmq.POLLIN:
                    if sock not in self.socketMapping:
                        self.logger.warn(
                            "Got a unexpected socket event, maybe the mgmt delete the mapping? ")
                        self.stats.error += 1
                        return
                    socket_recv = self.socketMapping[sock]
                    buf, addr = socket_recv.socket.recvfrom(2048)
                    if addr[0] not in self.remoteAddrList:
                        self.logger.debug(
                            "Got a l2tp invalid incoming control packet with addr=%s, remoteAddrList: %s"
                            % (addr[0], str(self.remoteAddrList)))
                        return
                    pkt = L2tpv3ControlPacket.L2tpv3ControlPacket.decode(buf)
                    connection_id = pkt.GetLocalConnectionID()
                    self.logger.debug(
                        "Got a l2tp control packet with addr=%s, localConnectionID = %d" % (addr[0], connection_id))
                    addr = (socket_recv.addr, addr[0], connection_id)
                    # We should check local Cache if we have this connection in cache, if yes, we should throw this
                    # packet to it's transport, it not, throw it into the
                    # global transport
                    if addr in self.transportMapping:
                        transport = self.transportMapping[addr]
                        transport.ReceivePacket(pkt, addr[1:])
                    elif connection_id != 0:
                        self.logger.warn(
                            "Cannot found the connection for packet, connectionId= %d" % connection_id)
                        self.stats.pkt_error += 1
                        return
                    else:
                        # For the connection ID = 0 case, we should create
                        # a connection
                        remote_connection_id, ok = pkt.GetRemoteConnectionID()
                        if not ok:
                            self.logger.warn(
                                "Cannot find the remote connection ID, skip this packet")
                            self.stats.pkt_error += 1
                            return
                        if pkt.ns != 0:
                            self.logger.warn(
                                "Got a control packet with wrong NS, will not create connection for it")
                            self.stats.pkt_error += 1
                            return

                        isRecoveryTunnelSCCRQ, recoverTunnelID, recoverRemoteTunnelID = pkt.isRecoveryTunnelSCCRQ()

                        if isRecoveryTunnelSCCRQ:
                            if not (addr[1], socket_recv.addr, recoverTunnelID) in L2tpv3Connection.L2tpConnection.ConnectionDb:
                                self.logger.warn(
                                    "Got a invalid recovery tunnel SCCRQ, will not create conection for it")
                                return
                            recoverConn = L2tpv3Connection.L2tpConnection.ConnectionDb[(addr[1], socket_recv.addr, recoverTunnelID)]
                            if recoverConn.remoteConnID != recoverRemoteTunnelID:
                                self.logger.warn(
                                    "Recover remote tunnel id mismatch in recovery tunnel SCCRQ, will not create conection for it")
                                return

                            if not recoverConn.failoverCapofCC:
                                self.logger.warn(
                                    "Recover connection doesn't have failover capability, will not create recovery tunnel"
                                )
                                return

                            if recoverConn.isInRecovery:
                                self.logger.warn(
                                    "Recover connection is already in recovery, will not create recovery tunnel")
                                return
                            recoverConn.isInRecovery = True
                        else:
                            # stop old connection if a new connection for the same remote address
                            for k in L2tpv3Connection.L2tpConnection.ConnectionDb:
                                connection = L2tpv3Connection.L2tpConnection.ConnectionDb[k]
                                """
                                we only get a single connection for the same remoteAddr,
                                Do not check the local ip address in case ip_addr is none for now
                                """
                                if connection.remoteAddr == addr[1]:
                                    if not connection.isInRecovery:
                                        connection.StopConnection()
                                        self.logger.info(
                                            "L2tp already got an connection for the remote address:%s, close the old connection"
                                            % connection.remoteAddr)
                                        break
                                    else:
                                        self.logger.info(
                                            "L2tp already got an connection in recovery for the remote address:%s, will not accpet new connection"
                                            % connection.remoteAddr
                                        )
                                        return
                        # Get current local address
                        conn = L2tpv3Connection.L2tpConnection(
                            connection_id, remote_connection_id, addr[1], localAddr=socket_recv.addr)
                        if isRecoveryTunnelSCCRQ:
                            conn.recoverConnection = recoverConn
                            conn.isRecoveryTunnel = True
                        conn.ReceiveControlPackets(pkt, addr[1:])
                # For the API instance ZMQ socket
                elif isinstance(sock, zmq.sugar.socket.Socket) and eventmask == zmq.POLLIN:
                    api_instance = self.zmqMapping[sock]
                    api_instance.recvAndProcess()
                elif eventmask == zmq.POLLERR:
                    self.logger.warn("Socket error event happens.")
                    self.stats.zmq_error += 1
                    # fixme we should handle the socket error.
                else:
                    self.logger.warn(
                        "Unexpected socket event happens, ignore it.")
                    self.stats.unexpected_else += 1
            else:
                self.dispatcher.timer_register(
                    self.time_tick, self._l2tp_event_entry_point_timer_wrapper, None)

            # Process the timeout event
            t = time.time()
            if t - self.last_time_tick < 0:
                self.logger.warn(
                    "The system time is changed, lower than previous, add some adjustment to it, system time:%s, "
                    "last time:%s", t, self.last_time_tick)
                self.last_time_tick = t
                return
            if t - self.last_time_tick >= self.time_tick:
                if t - self.last_time_tick > 60:
                    # if the the time escaped larger than 1 min, we assume
                    # that some one change the system time
                    self.logger.warn(
                        "The system time is changed, ahead too much, no need to change. current time:%s, last time:%s",
                        t, self.last_time_tick
                    )

                self.last_time_tick = t
                for k in self.transportMapping:
                    transport = self.transportMapping[k]
                    transport.TimetickCallback()

                # execute testPlan
                if self.testPlan:
                    time_elapse = time.time() - self.dispatcherStartTime
                    popup_list = list()
                    for t in self.testPlan:
                        # the format is {time: {handler: xxx, name:xxx,
                        # arg:xxx}}
                        if t < time_elapse:
                            plan = self.testPlan[t]
                            self.logger.debug(
                                "Start to execute test plan:" + plan["name"])
                            handler = plan['handler']
                            arg = plan['arg']
                            handler(arg)
                            popup_list.append(t)
                    for t in popup_list:
                        self.testPlan.pop(t)

        except Exception as e:
            self.stats.exception += 1
            self.logger.warn("Exception happens in l2tp module, error:" + str(e) + ", The Trace back is:\n" +
                             traceback.format_exc())

    def receive_hal_message(self, msg):
        if isinstance(msg, L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus) \
                or isinstance(msg, L2tpv3Hal_pb2.t_l2tpSessionRsp):
            local_ip = msg.session_selector.local_ip
            remote_ip = msg.session_selector.remote_ip
            local_session_id = msg.session_selector.local_session_id
            for addr in self.transportMapping:
                if (addr[0] == local_ip) and (addr[1] == remote_ip):
                    transport = self.transportMapping[addr]
                    try:
                        session = transport.connection.findSessionByLocalSessionID(
                            local_session_id)
                        if session:
                            session.ReceiveHalMsg(msg)
                        else:
                            self.logger.debug(
                                "Session has been removed: local ip %s, remote ip %s, session:%s",
                                local_ip, remote_ip, local_session_id)
                    except Exception as e:
                        self.stats.exception += 1
                        self.logger.warn(
                            "Exception happens when receive hal message, error:" +
                            str(e) + ", The Trace back is:\n" + traceback.format_exc())
        elif isinstance(msg, L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp):
            lcce_id = msg.lcce_id
            if lcce_id in self.transportMapping:
                transport = self.transportMapping[lcce_id]
            else:
                self.logger.info(
                    "Connection has been removed: lcce id %d",
                    lcce_id)
                return

            try:
                transport.connection.ReceiveHalMsg(msg)
            except Exception as e:
                self.stats.exception += 1
                self.logger.error("Error happens when receive hal message, error:" +
                                  str(e) + ", The Trace back is:\n" + traceback.format_exc())
