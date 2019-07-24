#!/usr/bin/python
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
from __future__ import print_function

import argparse

import zmq

import l2tpv3.src.L2tpv3GlobalSettings as globalSettings
import l2tpv3.src.L2tpv3_pb2 as l2tpMsg


def _generateParser():
    parser = argparse.ArgumentParser(
        prog="L2tpClient",
        description="L2tp client to monitor the Daemon")

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Query all l2TP Daemon information"
    )

    parser.add_argument(
        "-c", "--connection",
        nargs="+",
        action="store",
        help='Query Connection information, args " -c 127.0.0.1 12345678[local connection ID]"'
    )

    parser.add_argument(
        "-s", "--session",
        nargs=1,
        help='Query session information, args "-s 12345678[local sessionID]", also, you must specify the '
             '-c for connection info'
    )

    parser.add_argument(
        "-d", "--debug",
        nargs="+",
        action="store",
        help='Set the module debug level, usage:--debug modulename level'
    )

    parser.add_argument(
        "-b", "--bind",
        nargs=1,
        action="store",
        help="Send command to l2tp daemon to let the l2tp to *bind* to another ip address.",
    )

    parser.add_argument(
        "-u", "--unbind",
        nargs=1,
        action="store",
        help="Send command to l2tp daemon to let the l2tp to *unbind* to an ip address.",
    )

    parser.add_argument(
        "-x", "--clearstats",
        action="store_true",
        help="Send command to l2tp daemon to clear the stats."
    )

    parser.add_argument(
        "-m", "--mcast",
        action="store_true",
        help="Send command to l2tp daemon to query mcast info."
    )
    return parser


def _main():
    parser = _generateParser()
    args = parser.parse_args()

    # Check the flags
    if args.all and (args.connection is not None or args.session is not None):
        print("you cannot set the 'all' and other options simultaneously.")
        return

    if args.session is not None and args.connection is None:
        print("You have to specify the connection information.")
        return
    socket = _createZmqInstance()
    if args.all:
        _processSysinfoQuery(socket)
    elif args.session is not None:
        _processSessionQuery(socket, args.session, args.connection)
    elif args.connection is not None:
        _processConnectionQuery(socket, args.connection)
    elif args.debug is not None:
        _processDebug(socket, args.debug)
    elif args.bind is not None:
        _processBind(socket, args.bind)
    elif args.unbind is not None:
        _processUnbind(socket, args.unbind)
    elif args.clearstats:
        _processClearStats(socket)
    elif args.mcast:
        _processMcastinfo(socket)

    else:
        print("Unexpected command received, please check your parameter.")
        parser.print_help()

    socket.close()
    return


def _processBind(socket, bindPara):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.BIND_LOCAL_ADDRESS
    cmd.bindIP.localIP = bindPara[0]
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)


def _processUnbind(socket, unbindPara):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.UNBIND_LOCAL_ADDRESS
    cmd.bindIP.localIP = unbindPara[0]
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)


def _createZmqInstance():
    # Create a zmq
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(globalSettings.L2tpv3GlobalSettings.APITransportPath)
    return socket


def _processDebug(socket, debugPara):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.DEBUG

    debug = cmd.debug
    debug.module = debugPara[0]
    debug.level = debugPara[1]
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)


def _processSysinfoQuery(socket):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.SYSTEM_INFO
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.STATS_INFO
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)


def _processSessionQuery(socket, session, connection):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.SESSION_INFO

    sess = cmd.sess
    conn = sess.conn
    conn.remoteAddr = connection[0]
    conn.connectionID = int(connection[1])
    sess.localSessionID = int(session[0])

    data = cmd.SerializeToString()
    socket.send(data)

    data = socket.recv()

    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)

    print(msg)


def _processConnectionQuery(socket, connection):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.CONNECTION_INFO
    para = l2tpMsg.ConnectionPara()
    para.remoteAddr = connection[0]
    para.connectionID = int(connection[1])
    cmd.conn.MergeFrom(para)
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)

def _processClearStats(socket):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.CLEAR_STATS_INFO
    data = cmd.SerializeToString()
    socket.send(data)
    print("Clear l2tp stats successfully")

def _processMcastinfo(socket):
    cmd = l2tpMsg.L2tpCommandReq()
    cmd.cmd = l2tpMsg.MCAST_INFO
    data = cmd.SerializeToString()
    socket.send(data)
    data = socket.recv()
    msg = l2tpMsg.L2tpCommandRsp()
    msg.ParseFromString(data)
    print(msg)

if __name__ == "__main__":
    _main()
