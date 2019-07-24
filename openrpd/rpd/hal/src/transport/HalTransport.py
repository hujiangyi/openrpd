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
import os
import logging
from time import time
from rpd.hal.src.HalStats import HalGlobalStats
from rpd.common.rpd_logging import AddLoggerToClass

# The following is the basic Hal transport requirement


class HalTransport(object):
    """HAL's abstraction of the transport.

    Its current implementation uses ZMQ as transport, but other types of
    transport, such as the UNIX socket or the raw socket, could be used
    as well.

    """
    __metaclass__ = AddLoggerToClass

    HalTransportClientMgr = 1
    HalTransportClientAgentPush = 2
    HalTransportClientAgentPull = 3
    HalTransportMapping = {
        HalTransportClientMgr: r"/tmp/Hal/HalClientMgr",
        HalTransportClientAgentPush: "/tmp/Hal/agent/client/%d/push",
        HalTransportClientAgentPull: "/tmp/Hal/agent/client/%d/pull",
    }

    HalServerMode = 1
    HalClientMode = 2

    HalSocketPushMode = zmq.PUSH
    HalSocketPullMode = zmq.PULL

    context = zmq.Context()

    def __init__(self, HalTransportType, mode, **para):
        self.monitor = None
        self.logger.debug(
            "Creating a transport with para: Type = %s, mode = %s, others = %s" % (str(HalTransportType),
                                                                                   str(mode), str(para)))
        if "disconnectHandlerCb" in para:
            self.disconnectHandlerCb = para["disconnectHandlerCb"]
        else:
            self.disconnectHandlerCb = None

        if HalTransportType in (HalTransport.HalTransportClientMgr,):
            self.transportType = HalTransportType
            self.path = HalTransport.HalTransportMapping[HalTransportType]

            # Check if the file exsits
            """
            if os.path.exists(HalTransport.HalTransportMapping[HalTransportType]):
                os.unlink(HalTransport.HalTransportMapping[HalTransportType])
            """
            # check if the directory exsits
            if os.path.exists(os.path.dirname(HalTransport.HalTransportMapping[HalTransportType])):
                pass
            else:
                os.makedirs(
                    os.path.dirname(HalTransport.HalTransportMapping[HalTransportType]))

            if mode == HalTransport.HalServerMode:
                self.socket = self.context.socket(
                    zmq.REP)  # do we need to set the HWM?
                self.binds()
            else:
                self.socket = self.context.socket(
                    zmq.REQ)  # do we need to set the HWM?
                self.connects()

            self.monitor = self.socket.get_monitor_socket()

        elif HalTransportType <= HalTransport.HalTransportClientAgentPull:
            index = para["index"]
            path = HalTransport.HalTransportMapping[HalTransportType] % index
            self.logger.info(
                "Start a agent transport interface, path = [%s]" % path)
            if os.path.exists(os.path.dirname(path)):
                pass
            else:
                os.makedirs(os.path.dirname(path))
            # get the transport type
            socketMode = para["socketMode"]
            self.socket = self.context.socket(socketMode)
            self.transportType = HalTransportType
            self.path = path
            if mode == HalTransport.HalServerMode:
                # create the socket
                self.binds()
            else:
                self.connects()
            self.monitor = self.socket.get_monitor_socket()
        else:
            self.logger.error(
                "Cannot create a transport since the Type[%s] is not supported.", HalTransportType)
            raise Exception("Unsupported HalTransportType")

        # logging rate limit
        self.lastSocketRetriedTime = time()
        self.lastSocketClosedTime = time()
        self.socketLogTimeout = 1

    def monitorHandler(self, msg):
        """ TODO parameter name doesnt match
        :param cb: The callback hander, currently ,we only support the disconnected callback
        :return: True for handled by handler, false for skip it
        1 EVENT_CONNECTED
        2 EVENT_CONNECT_DELAYED
        4 EVENT_CONNECT_RETRIED
        8 EVENT_LISTENING
        16 EVENT_BIND_FAILED
        32 EVENT_ACCEPTED
        64 EVENT_ACCEPT_FAILED
        128 EVENT_CLOSED
        256 EVENT_CLOSE_FAILED
        512 EVENT_DISCONNECTED
        1024 EVENT_MONITOR_STOPPED
        2047 EVENT_ALL

        """
        # self.logger.debug("Get a monitor event:%s" % msg)
        if msg["event"] == zmq.EVENT_DISCONNECTED:
            if self.disconnectHandlerCb is not None:
                self.disconnectHandlerCb(msg)
                return True
            return False
        elif msg["event"] == zmq.EVENT_CONNECT_RETRIED:
            if time() - self.lastSocketRetriedTime >= self.socketLogTimeout:
                self.logger.info("Retrying to connect the HAL...")
                self.lastSocketRetriedTime = time()
                return True
            return False
        elif msg["event"] == zmq.EVENT_CLOSED:
            if time() - self.lastSocketClosedTime >= self.socketLogTimeout:
                self.logger.info("Failed to connect the HAL...")
                self.lastSocketClosedTime = time()
                return True
            return False
        else:
            self.logger.debug("Skip handling msg event %d" % msg["event"])
            return False

    @staticmethod
    def getMonitorEndpoint(msg):
        return msg['endpoint']

    def send(self, msg):
        """Send a msg to a peer, BTW, this should be a nonblock send."""
        if msg is None or self.socket is None:
            msg = "Cannot send the msg since the msg is None, agent:%s" % self.path
            self.logger.error(msg)
            raise Exception(msg)

        self.logger.debug("agent[%s] sends a message to peer." % self.path)
        try:
            self.socket.send(msg, flags=zmq.NOBLOCK)
        except zmq.ZMQError as e:
            msg = "Got an error when trying with non-block send:" + str(e)
            self.logger.error(msg)
            import traceback
            self.logger.error(traceback.format_stack())
            HalGlobalStats.NrErrorMsgs += 1
            return False
        return True

    def recv(self):
        """Receive a msg from a peer, please note that this should be a
        nonblcok peer."""
        return self.socket.recv()

    def register(self, poller):
        """Register a sock to a poller, the transport will poll or select from
        the registered socks."""
        if poller is None:
            raise Exception("Cannot register to a None poller")

        poller.register(self.socket, zmq.POLLIN)

    def binds(self):
        """Bind to an address."""
        self.logger.debug("Binding to path:%s" % self.path)
        self.socket.bind("ipc://" + self.path)

    def connects(self):
        """Connect to an address."""
        self.logger.debug("Connecting to path:%s" % self.path)
        self.socket.connect("ipc://" + self.path)

    def close(self):
        self.logger.debug("Closing the socket:%s" % self.path)
        self.socket.close()

        # if self.monitor:
        #    self.socket.disable_monitor()
        #    self.monitor.close()


class HalPoller(object):
    """HAL poller."""
    POLLIN = zmq.POLLIN
    POLLOUT = zmq.POLLOUT

    def __init__(self):
        self.poller = zmq.Poller()

    def register(self, socket, flag=zmq.POLLIN):
        if socket is None:
            raise Exception("cannot register a None socket to poller")
        self.poller.register(socket, flag)

    def unregister(self, socket):
        if socket is None:
            raise Exception("cannot Unregister a None socket from poller")
        self.poller.unregister(socket)

    def poll(self, timeout=None):
        """Poll the registered socks, and return the ready sock list, similar
        to the linux epoll."""
        socks = self.poller.poll(timeout)
        return dict(socks) if socks else None

    def modify(self, socket, flags=POLLIN | POLLOUT):
        """Modify the flags for an already registered 0MQ socket or native
        fd."""
        self.register(socket, flags)
