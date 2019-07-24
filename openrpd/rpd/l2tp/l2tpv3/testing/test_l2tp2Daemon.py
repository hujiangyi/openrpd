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
"""This is the simulate peer file, Ut will not cover this packet."""
from random import randint
import pdb
import unittest
import traceback
import time
import zmq

import l2tpv3.src.L2tpv3Connection as L2tpv3Connection
import l2tpv3.src.L2tpv3Dispatcher as L2tpv3Dispatcher
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
import l2tpv3.src.L2tpv3Session as L2tpv3Session
import l2tpv3.src.L2tpv3ControlPacket as L2tpv3ControlPacket
import l2tpv3.src.L2tpv3Fsm as L2tpFsm
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass


def createSessionAndFire(connection):
    session = L2tpv3Session.L2tpv3Session(
        randint(1, 0xFFFFFFFF), 0, "sender", connection)
    connection.addSession(session)
    # session.LocalRequest()


def processStep(dispatcher):
    dispatcher._processUnregisterRequest()
    socks = dict(dispatcher.poller.poll(1000 * dispatcher.timetick))
    try:
        for sock in socks:
            # For the transport sockets
            print "zmq.POLLIN is:", zmq.POLLIN
            if isinstance(sock, int) and socks[sock] == zmq.POLLIN:
                socketRecv = dispatcher.socketMapping[sock]
                print "socketRecv is:", socketRecv
                buf, addr = socketRecv.socket.recvfrom(2048)
                print "buf is:", buf
                print "addr is:", addr
                pkt = L2tpv3ControlPacket.L2tpv3ControlPacket.decode(buf)
                print "after decode,pkt is:", pkt
                connId = pkt.GetLocalConnectionID()
                dispatcher.logger.debug(
                    "Got a l2tp control packet with addr=%s, localConnectionID = %d" % (addr[0], connId))
                dispatcher.logger.debug(pkt)
                addr = (addr[0], connId)
                # We should check local Cache if we have this connection in cache, if yes, we should throw this
                # packet to it's transport, it not, throw it into the global
                # transport
                if addr in dispatcher.transportMapping:
                    transport = dispatcher.transportMapping[addr]
                    transport.ReceivePacket(pkt, addr)
                elif connId != 0:
                    dispatcher.logger.warn(
                        "Cannot found the connection for packet, connectionId= %d" % connId)
                    return
                else:
                    remoteId, ok = pkt.GetRemoteConnectionID()
                    if not ok:
                        dispatcher.logger.warn(
                            "Cannot find the remote connection ID, skip this packet")
                        return

                    if pkt.ns != 0:
                        dispatcher.logger.warn(
                            "Got a control packet with wrong NS, will not create connection for it")
                        return
                    conn = L2tpv3Connection.L2tpConnection(
                        connId, remoteId, addr[0])
                    conn.ReceiveControlPackets(pkt, addr)
            # For the API instance ZMQ socket
            elif isinstance(sock, zmq.sugar.socket.Socket) and socks[sock] == zmq.POLLIN:
                apiInstance = dispatcher.zmqMapping[sock]
                apiInstance.recvAndProcess()
            else:
                dispatcher.logger.error(
                    "Unexpected socket event happens, ignore it.")

        # Proccess the timeout event
        t = time.time()
        if t - dispatcher.lastTimetick < 0:
            dispatcher.logger.error(
                "The system time is changed, lower than previous, add some adjustment to it.")
            dispatcher.lastTimetick = t
            return

        if t - dispatcher.lastTimetick >= dispatcher.timetick:
            if t - dispatcher.lastTimetick > 60:
                # if the the time escaped larger than 1 min, we assume that
                # some one change the system time
                dispatcher.logger.error(
                    "The system time is changed, ahead too much, no need to change. ")

            dispatcher.lastTimetick = t
            for k in dispatcher.transportMapping:
                transport = dispatcher.transportMapping[k]
                transport.TimetickCallback()

            # execute testPlan
            if dispatcher.testPlan:
                timeElapse = time.time() - dispatcher.dispatcherStartTime
                popupList = list()
                for t in dispatcher.testPlan:
                    # the format is {time: {handler: xxx, name:xxx, arg:xxx}}
                    if t < timeElapse:
                        plan = dispatcher.testPlan[t]
                        dispatcher.logger.debug(
                            "Start to execute test plan:" + plan["name"])
                        handler = plan['handler']
                        arg = plan['arg']
                        handler(arg)
                        popupList.append(t)
                for t in popupList:
                    dispatcher.testPlan.pop(t)

    except Exception as e:
        dispatcher.logger.error(traceback.format_exc())


class test2DaemonSingleNode(unittest.TestCase):

    __metaclass__ = AddLoggerToClass

    def setUp(self):
        self.connection = ""
        self.dispatcher = ""
        self.LocalAddr = "127.0.0.1"
        # self.LocalAddrList = {"127.0.0.2"}
        # self.remoteAddrList = {"127.0.0.1","127.0.0.2"}
        self.remoteAddrList = {"127.0.0.2"}
        setup_logging('L2TP')

    def CreateConnection(self, RemoteAddr):
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(self.LocalAddr,
                                                       createGlobalListen=False)
        dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        self.dispatcher = dispatcher

        # we need to create connection
        connection = L2tpv3Connection.L2tpConnection(0, 0, RemoteAddr)
        self.connection = connection

        # Initiate SCCRQ connection request message
        connection.localRequest(RemoteAddr)

        processStep(dispatcher)

        # Validate if FSM current state is established

        if L2tpFsm.L2tpv3ConnectionFsm.StateEstablished != connection.fsm.current:
            self.logger.info(
                "FSM current state is not established,current state is:%s" % (connection.fsm.current))
            # self.fail("Connection is not establshed!!!")

        else:
            self.logger.info("Connection is established successfully")

    def ConnectionTearDown(self, connection):
        connection.CloseConnection()

    def CreateSession(self, connection):
        session = L2tpv3Session.L2tpv3Session(
            randint(1, 0xFFFFFFFF), 0, "sender", connection)
        self.session = session
        connection.addSession(session)
        session.LocalRequest()
        processStep(self.dispatcher)

    @unittest.skip("Skipping the first testcase")
    def testCreate2DaemonOnSingleNode(self):
        for remoteAddr in self.remoteAddrList:
            self.CreateConnection(remoteAddr)

        print "ConnectionDb is:", self.connection.ConnectionDb

        self.assertEqual(
            len(self.connection.ConnectionDb.keys()), len(self.remoteAddrList))

        for key in self.connection.ConnectionDb.keys():
            print "ConnectionDb of key %s is %s" % (key, self.connection.ConnectionDb[key].__dict__)
        pdb.set_trace()

        # TearDown all connections
        for conn_key in self.connection.ConnectionDb.keys():
            self.ConnectionTearDown(self.connection.ConnectionDb[conn_key])

        self.assertEqual(len(self.connection.ConnectionDb.keys()), 0)


if __name__ == "__main__":
    unittest.main()
