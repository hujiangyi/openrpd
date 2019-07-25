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
from rpd.hal.src.transport.HalTransport import HalTransport, HalPoller
import os.path
import shutil
import zmq
import time


class TestHalTransport(unittest.TestCase):

    def setUp(self):
        # change the Haltransport lcoation
        # for path in HalTransport.HalTransportMapping:
        # HalTransport.HalTransportMapping[path] = "/tmp/HalUnitTest" +
        # HalTransport.HalTransportMapping[path]
        pass

    def tearDown(self):
        pass

    @unittest.skip("Skipping rapid create & distroy due to zmq issue")
    def test_createTransport(self):

        transportMgr = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalServerMode,
            disconnectHandlerCb=None)
        transportMgr.socket.disable_monitor()
        transportMgr.monitor.close()
        transportMgr.close()
        self.assertIsNotNone(transportMgr)
        try:
            shutil.rmtree(os.path.dirname("/tmp/HalUnitTest/"))
        except Exception as e:
            pass
        transportClient = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalClientMode)
        transportClient.socket.disable_monitor()
        transportClient.monitor.close()
        transportClient.close()
        self.assertIsNotNone(transportClient)

        transportAgentPush = HalTransport(
            HalTransport.HalTransportClientAgentPush, HalTransport.HalServerMode,
            index=0, socketMode=HalTransport.HalSocketPushMode,
            disconnectHandlerCb=None)
        transportAgentPush.socket.disable_monitor()
        transportAgentPush.monitor.close()
        transportAgentPush.close()
        self.assertIsNotNone(transportAgentPush)

        transportAgentPull = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalServerMode,
            index=0, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=None)
        transportAgentPull.socket.disable_monitor()
        transportAgentPull.monitor.close()
        transportAgentPull.close()
        self.assertIsNotNone(transportAgentPull)

        transportAgentPull = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalClientMode,
            index=0, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=None)
        transportAgentPull.socket.disable_monitor()
        transportAgentPull.monitor.close()
        transportAgentPull.close()
        self.assertIsNotNone(transportAgentPull)

        # error case
        try:
            transport = HalTransport(1000, HalTransport.HalClientMode,
                                     index=0, socketMode=HalTransport.HalSocketPullMode,
                                     disconnectHandlerCb=None)
        except Exception as e:
            self.assertEqual(str(e), "Unsupported HalTransportType")

    def _disconnectCb(self, msg):
        """The disconenct CB.

        :return:

        """
        return

    def test_getMonitorEndpoint(self):

        msg = {
            "endpoint": 0x12345,
        }

        self.assertEqual(HalTransport.getMonitorEndpoint(msg), 0x12345)

    def test_eventHandlerMonitor(self):
        """test HalTransport#monitorHandler,

        check whether the
        EVENT_DISCONNECTED can be handle, if status is false case fail

        check
        whether the EVENT_CONNECT_RETRIED can be handle, if status before the
        timeout/after timeout was wrong, case fail

        check whether the
        EVENT_CLOSED can be handle, if status before the timeout/after timeout
        was wrong, case fail

        check whether the unnormal event can be handle, if
        status was wrong case fail.

        :keyword:HalTransport#monitorHandler
        :exception:assertFalse(transport.monitorHandler(msg)),
                   assertFalse(transport.monitorHandler(msg)),
                   assertFalse(transport.monitorHandler(msg)),
                   assertFalse(transport.monitorHandler(msg))
        :parameter:
        :return:

        """
        transport = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalServerMode,
            disconnectHandlerCb=None)

        msg = {
            "event": zmq.EVENT_DISCONNECTED,
        }
        self.assertFalse(transport.monitorHandler(msg))
        transport.socket.disable_monitor()
        transport.monitor.close()
        transport.close()

        transport = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalServerMode,
            disconnectHandlerCb=self._disconnectCb)
        self.assertTrue(transport.monitorHandler(msg))

        msg = {
            "event": zmq.EVENT_CONNECT_RETRIED,
        }
        self.assertFalse(transport.monitorHandler(msg))
        time.sleep(transport.socketLogTimeout)
        self.assertTrue(transport.monitorHandler(msg))

        transport.socket.disable_monitor()
        transport.monitor.close()
        transport.close()

        transport = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalServerMode,
            disconnectHandlerCb=self._disconnectCb)
        msg = {
            "event": zmq.EVENT_CLOSED,
        }
        self.assertFalse(transport.monitorHandler(msg))
        time.sleep(transport.socketLogTimeout)
        self.assertTrue(transport.monitorHandler(msg))

        msg = {
            "event": 10001,
        }
        self.assertFalse(transport.monitorHandler(msg))

        transport.socket.disable_monitor()
        transport.monitor.close()
        transport.close()

    def test_send(self):
        """test HalTransport#send.

        check whether none message can be send, if
        can't catch the specific exception case fail

        check whether hello
        message can be send, if the returned value is false case fail.

        :keyword:HalTransport#send
        :exception:assertRegexpMatches(str(e), "Cannot send the msg since the msg is None, agent.*"),
                   assertEqual(pushSock.send("hello"), True)
        :parameter:
        :return:

        """
        transport = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalServerMode,
            disconnectHandlerCb=self._disconnectCb)

        try:
            transport.send(None)
        except Exception as e:
            self.assertRegexpMatches(
                str(e), "Cannot send the msg since the msg is None, agent.*")
        transport.socket.disable_monitor()
        transport.monitor.close()
        transport.close()

        pushSock = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalClientMode,
            index=19, socketMode=HalTransport.HalSocketPushMode, disconnectHandlerCb=None)
        self.assertEqual(pushSock.send("hello"), True)

        pushSock.socket.disable_monitor()
        pushSock.monitor.close()
        pushSock.close()

    @unittest.skip("Skipping rapid create & distroy due to zmq issue")
    def test_recv(self):
        """test HalTransport#recv.

        check if it can handle the method event, with
        the exception/logicality's correct

        check whether hello message can be
        receive after send out, if the returned value match case fail.

        :keyword:HalTransport#recv
        :exception:assertEqual(pullSock.recv(), "hello")
        :parameter:
        :return:

        """
        pullSock = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalServerMode,
            index=20, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=None)
        pullSock.socket.disable_monitor()
        pullSock.monitor.close()
        pullSock.close()

        pullSock = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalServerMode,
            index=20, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=None)
        pushSock = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalClientMode,
            index=20, socketMode=HalTransport.HalSocketPushMode, disconnectHandlerCb=None)

        pushSock.send("hello")
        print("Try to receive the message")
        self.assertEqual("hello", pullSock.recv())

        pullSock.socket.disable_monitor()
        pullSock.monitor.close()
        pullSock.close()

        pushSock.socket.disable_monitor()
        pushSock.monitor.close()
        pushSock.close()

    def test_register(self):
        """test HalTransport#register.

        check whether none socket can be
        register, if the specific exception can't be catch case fail

        check
        whether the socket can be register, if the socket can't find in poller
        map case fail.

        :keyword:HalTransport#register
        :exception:assertEqual(str(e), "Cannot register to a None poller"),
                   assertIn(pullSock.socket, poller.poller._map)
        :parameter:
        :return:

        """
        pullSock = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalServerMode,
            index=20, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=None)

        poller = HalPoller()
        try:
            pullSock.register(None)
        except Exception as e:
            self.assertEqual(str(e), "Cannot register to a None poller")

        pullSock.register(poller)

        self.assertIn(pullSock.socket, poller.poller._map)

        pullSock.socket.disable_monitor()
        pullSock.monitor.close()
        pullSock.close()

    def test_poller(self):
        """test create HalPoller.

        check whether the socket can be register, if
        the socket can't find in poller map case fail

        check whether the socket
        can be unregister, if the socket can find in poller map case fail.

        :keyword:HalPoller
        :exception:assertIn(pullSock.socket, poller.poller._map),
                   assertNotIn(pullSock.socket, poller.poller._map)
        :parameter:
        :return:

        """
        pullSock = HalTransport(
            HalTransport.HalTransportClientAgentPull, HalTransport.HalServerMode,
            index=20, socketMode=HalTransport.HalSocketPullMode,
            disconnectHandlerCb=None)

        poller = HalPoller()

        poller.register(pullSock.socket)
        self.assertIn(pullSock.socket, poller.poller._map)
        poller.unregister(pullSock.socket)
        self.assertNotIn(pullSock.socket, poller.poller._map)
        poller.register(pullSock.socket)

        socks = poller.poll(500)

        pullSock.socket.disable_monitor()
        pullSock.monitor.close()
        pullSock.close()


class TestHalPoller(unittest.TestCase):

    def test_poller(self):
        poller = HalPoller()
        try:
            poller.modify(None)
        except Exception:
            pass
        try:
            poller.unregister(None)
        except Exception:
            pass


class TestNegative(unittest.TestCase):

    def test_creative(self):
        try:
            transport = HalTransport(1000, HalTransport.HalClientMode,
                                     index=0, socketMode=HalTransport.HalSocketPullMode,
                                     disconnectHandlerCb=None)
        except Exception as e:
            self.assertEqual(str(e), "Unsupported HalTransportType")


if __name__ == '__main__':
    unittest.main()
