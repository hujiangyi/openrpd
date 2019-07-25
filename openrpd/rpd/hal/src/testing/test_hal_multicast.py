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
import os
import time
import zmq
import unittest
import subprocess
from zmq.utils.monitor import recv_monitor_message
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalPoller
from rpd.hal.lib.drivers.HalDriver0 import HalDriver0
from rpd.hal.simulator.start_hal import start_hal
from rpd.common.rpd_logging import setup_logging


redis_sock_file = "/tmp/testHalAgentDRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"

hal_conf_content = """
{
    "db":{
        "address":"%s",
        "timeout":30,
        "msgDB":12,
        "indexDB":11
    }
}
""" % redis_sock_file

hal_conf_file_name = "/tmp/test_hal_multicast.conf"
hal_process = None


def setup_db():
    global hal_process
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
                           redis_sock_file + " \nunixsocketperm 700\n"
    filename = "/tmp/test_halagentd.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    # generate the hal_conf_file
    with open(hal_conf_file_name, "w") as f:
        f.write(hal_conf_content)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(redis_sock_file):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")

    hal_process = start_hal(hal_cfg_file=hal_conf_file_name)


class HalClientTest(HalDriver0):

    def connect_to_hal(self):
        self.connectionSetup()
        self.register(self.drvID)
        i = 0
        max_times = 10
        expected_msgs = ["HalClientInterestNotificationCfgRsp",
                         "HalClientHelloRsp"]
        while expected_msgs != []:
            socks = self.poller.poll(1000)
            print socks
            i += 1
            if i > max_times:
                self.logger.error("break while due to reach %d times" % max_times)
                break

            if not socks:
                continue
            for sock in socks:
                if self.pushSock is not None and sock == self.pushSock.monitor:
                    self.pushSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if self.pullSock is not None and sock == self.pullSock.monitor:
                    self.pullSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if self.mgrConnection is not None and sock == self.mgrConnection.monitor:
                    self.mgrConnection.monitorHandler(
                        recv_monitor_message(sock))
                    continue
                if socks[sock] == HalPoller.POLLIN:
                    try:
                        bin = sock.recv(flags=zmq.NOBLOCK)
                        msg = HalMessage.DeSerialize(bin)
                        print msg.msg
                        self.logger.debug("Got a zmq msg:%s" % msg.msg)
                        if msg.msg.MsgType in expected_msgs:
                            expected_msgs.remove(msg.msg.MsgType)
                        if msg.type in self.HalMsgsHandler:
                            handler = self.HalMsgsHandler[msg.type]
                            handler(msg)
                        else:
                            self.logger.error(
                                "Unsupported msg type:%s" % msg.type)
                    except zmq.ZMQError as e:
                        self.logger.debug(
                            "Got an error when trying with non-block read:" + str(e))
                    except Exception as e:
                        self.logger.error(
                            "Error happens, reason:%s" % str(e))
                continue

    def close_connection(self):
        self.poller.unregister(self.pullSock.socket)
        self.poller.unregister(self.pullSock.monitor)
        self.poller.unregister(self.pushSock.monitor)
        self.poller.unregister(self.mgrConnection.socket)
        self.poller.unregister(self.mgrConnection.monitor)
        self.pullSock.close()
        self.pushSock.close()
        self.mgrConnection.socket.disable_monitor()
        self.mgrConnection.monitor.close()
        self.mgrConnection.close()

    def sendCfgRspMsg(self, cfg):
        """The configuration response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :return:

        """
        cfgMsg = cfg.msg
        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=cfgMsg.SeqNum,
            Rsp={
                "Status": HalCommon_pb2.SUCCESS,
                "ErrorDescription": ""
            },
            CfgMsgType=cfgMsg.CfgMsgType,
            CfgMsgPayload=cfgMsg.CfgMsgPayload)
        self.pushSock.send(msg.Serialize())


class HalClientTestErrorRsp(HalClientTest):

    def sendCfgRspMsg(self, cfg):
        """The configuration response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :return:

        """
        cfgMsg = cfg.msg
        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=cfgMsg.SeqNum,
            Rsp={
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": ""
            },
            CfgMsgType=cfgMsg.CfgMsgType,
            CfgMsgPayload=cfgMsg.CfgMsgPayload)
        self.pushSock.send(msg.Serialize())


class TestHalAgentDriver(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_db()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        subprocess.call(["killall", "redis-server"])
        if hal_process is not None:
            hal_process.terminate()

    @unittest.skip('skip test_two_client_send_and_recv')
    def test_two_client_send_and_recv(self):
        sender_client = HalClientTest(
            "sender client", "sender client, used to send a hello msg to recv client",
            "1.0.0",
            (1, 2, 100, 102), (1, ), (1, ))

        sender_client.connect_to_hal()
        recv_client = HalClientTest("receiver client",
                                    "receiver client, used to receive a hello msg from sender client",
                                    "1.0.0",
                                    (1024, ), (1, ), (1, ))

        recv_client.connect_to_hal()

        sender_client.sendCfgMsg(1024, "hello, I am a sender~")

        content = recv_client.pullSock.recv()
        msg = HalMessage.DeSerialize(content)

        self.assertEqual(msg.msg.CfgMsgType, 1024)
        recv_client.close_connection()
        sender_client.close_connection()

    @unittest.skip('skip test_three_client_send_and_recv')
    def test_three_clients_send_and_recv(self):
        sender_client = HalClientTest(
            "sender client", "sender client, used to send a hello msg to recv client",
            "1.0.0",
            (1, 2, 100, 102), (1, ), (1, ))

        sender_client.connect_to_hal()
        recv_client1 = HalClientTest("receiver client",
                                     "receiver client, used to receive a hello msg from sender client",
                                     "1.0.0",
                                     (1024, ), (1, ), (1, ))
        recv_client1.connect_to_hal()

        recv_client2 = HalClientTest("receiver client",
                                     "receiver client, used to receive a hello msg from sender client",
                                     "1.0.0",
                                     (1024, ), (1, ), (1, ))

        recv_client2.connect_to_hal()

        sender_client.sendCfgMsg(1024, "hello, I am a sender~")

        content = recv_client1.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)
        recv_client1.recvCfgMsgCb(msg)

        content = recv_client2.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)
        recv_client2.recvCfgMsgCb(msg)

        # try to receive the msg from sender
        content = sender_client.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)

        recv_client1.close_connection()
        recv_client2.close_connection()
        sender_client.close_connection()

    def _test_three_clients_send_and_recv_timeout(self):
        sender_client = HalClientTest(
            "sender client", "sender client, used to send a hello msg to recv client",
            "1.0.0",
            (1, 2, 100, 102), (1, ), (1, ))

        sender_client.connect_to_hal()
        recv_client1 = HalClientTest("receiver client",
                                     "receiver client, used to receive a hello msg from sender client",
                                     "1.0.0",
                                     (1024, ), (1, ), (1, ))
        recv_client1.connect_to_hal()

        recv_client2 = HalClientTest("receiver client",
                                     "receiver client, used to receive a hello msg from sender client",
                                     "1.0.0",
                                     (1024, ), (1, ), (1, ))

        recv_client2.connect_to_hal()

        sender_client.sendCfgMsg(1024, "hello, I am a sender~")

        content = recv_client1.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)
        recv_client1.recvCfgMsgCb(msg)

        content = recv_client2.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)

        # try to receive the msg from sender
        content = sender_client.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)

        recv_client1.close_connection()
        recv_client2.close_connection()
        sender_client.close_connection()

    @unittest.skip('skip test_three_client_send_and_recv_failed')
    def test_three_clients_send_and_recv_failed(self):
        sender_client = HalClientTest(
            "sender client", "sender client, used to send a hello msg to recv client",
            "1.0.0",
            (1, 2, 100, 102), (1, ), (1, ))

        sender_client.connect_to_hal()
        recv_client1 = HalClientTest("receiver client",
                                     "receiver client, used to receive a hello msg from sender client",
                                     "1.0.0",
                                     (1024, ), (1, ), (1, ))
        recv_client1.connect_to_hal()

        recv_client2 = HalClientTestErrorRsp("receiver client",
                                             "receiver client, used to receive a hello msg from sender client",
                                             "1.0.0",
                                             (1024, ), (1, ), (1, ))

        recv_client2.connect_to_hal()

        sender_client.sendCfgMsg(1024, "hello, I am a sender~")

        content = recv_client1.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)
        recv_client1.recvCfgMsgCb(msg)

        content = recv_client2.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)
        recv_client2.recvCfgMsgCb(msg)

        # try to receive the msg from sender
        content = sender_client.pullSock.recv()
        msg = HalMessage.DeSerialize(content)
        self.assertEqual(msg.msg.CfgMsgType, 1024)
        self.assertEqual(msg.msg.Rsp.Status, HalCommon_pb2.FAILED)

        recv_client1.close_connection()
        recv_client2.close_connection()
        sender_client.close_connection()


if __name__ == '__main__':
    setup_logging('HAL', filename="hal_client.log")
    unittest.main()
