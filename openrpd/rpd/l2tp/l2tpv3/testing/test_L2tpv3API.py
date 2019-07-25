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
import zmq
import time
import threading
import l2tpv3.src.L2tpv3_pb2 as l2tpMsg
from l2tpv3.src.L2tpv3API import L2tpv3API, L2tpv3APIClient
import l2tpv3.src.L2tpv3Connection as L2tpv3Connection
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
import l2tpv3.src.L2tpv3Session as L2tpv3Session
import l2tpv3.src.L2tpv3Dispatcher as L2tpv3Dispatcher
from l2tpv3.src.L2tpv3Hal import L2tpHalClient
from random import randint
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.mcast.src.mcast import Mcast
from rpd.confdb.testing.test_rpd_redis_db import setup_test_redis, stop_test_redis


class L2tpMcastList(object):
    HEADER = ["Interface", "LocalIp", "Grp", "Src", "Status", "Refcnt", "Last Chg"]
    HEADER_SESSION = ["Interface", "LocalIp", "Grp", "Src", "Status", "SESSIONS"]

    def __init__(self):
        self.interface = "N/A"
        self.LocalIp = "N/A"
        self.Grp = "N/A"
        self.Src = "N/A"
        self.Session = []
        self.last_change_time = time.time()


class testL2tpv3API(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("L2TP")
        setup_test_redis()

        # Construct the API transport path
        ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        print ApiPath
        cls.api = L2tpv3API(ApiPath)
        for key in Mcast.McastDb.keys():
            Mcast.McastDb[key].close()

    @classmethod
    def tearDownClass(cls):
        stop_test_redis()
        cls.api.transport.socket.unbind(cls.api.transport.path)
        for key in Mcast.McastDb.keys():
            if isinstance(Mcast.McastDb[key], Mcast):
                Mcast.McastDb[key].close()

    def test_A0__handleConnectionQuery_isNot_conn_msg(self):
        """
        msg.HasField("conn") = False

        Check: Cannot find the connection parameter in connection query msg

        Result: FAILURE

        """
        # Create a msg
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CONNECTION_INFO
        msg = self.api._handleMsg(cmd)

        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the connection parameter in connection query msg")

    def test_A1__handleConnectionQuery_connIDisNotin_connDB(self):
        """(remoteAddr, connID) is not in connectionDb Not create a connection.

        Check: Cannot find the connection in local connection DB

        Result:
        FAILURE.

        """
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CONNECTION_INFO

        para = l2tpMsg.ConnectionPara()

        # Create invalid addr and connID
        para.remoteAddr = "127.0.0.1"
        para.connectionID = 0xA90A0853
        para.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress

        cmd.conn.MergeFrom(para)
        msg = self.api._handleMsg(cmd)

        # FAILURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the connection in local connection DB")

    def test_A2__handleConnectionQuery_connID_isin_connDB(self):
        """(remoteAddr, connID) is in connectionDb Create a connection.

        Result: success.

        """
        # Create a connection
        global_dispatcher = Dispatcher()
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress = '127.0.0.1'
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(
            global_dispatcher,
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress,
            create_global_listen=False)

        self.dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        self.connection = L2tpv3Connection.L2tpConnection(
            9527, 21203, "127.0.0.1")

        # Create a msg
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CONNECTION_INFO

        # connection is in local connection DB
        para = l2tpMsg.ConnectionPara()

        # Get addr and connID invoke connection
        para.remoteAddr = self.connection.remoteAddr
        para.connectionID = self.connection.localConnID
        para.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress

        cmd.conn.MergeFrom(para)
        msg = self.api._handleMsg(cmd)
        # SUCCESS = 1
        self.assertEqual(msg.rsp, 1)

    def test_Z__handleSystemInfo(self):
        """
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SYSTEM_INFO
        Get system info

        """
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SYSTEM_INFO
        msg = self.api._handleMsg(cmd)

        print "\n------------handleSystemInfo--START------------\n", str(msg)
        print "\n------------handleSystemInfo--END------------\n"

        # SUCCESS = 1
        self.assertEqual(msg.rsp, 1)

    def test_B0__handleSessionQuery_isNot_sess_msg(self):
        """
        msg.HasField("sess") = False
        No any para

        Check: Cannot find the debug parameter in debug msg

        result: FAILURE

        """
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO
        msg = self.api._handleMsg(cmd)

        # FAILURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the session parameter in session query msg")

    def test_B1__handleSessionQuery_connID_AND_sessID_isNotin_DB(self):
        """No connection and no session.

        Check: Cannot find the connection in
        local connection DB

        Result: FAILURE.

        """
        # Create a msg
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO

        sess = cmd.sess
        conn = sess.conn
        conn.remoteAddr = '127.0.0.1'
        conn.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress
        # Connection is not in connection DB
        conn.connectionID = 1652974642

        # Local session is not in connection session
        # connection ------> session
        sess.localSessionID = 2406980214

        msg = self.api._handleMsg(cmd)

        # FAILIURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the connection in local connection DB")

    def test_B2__handleSessionQuery_sessID_isNotin_AND_connID_isin_DB(self):
        """Create connection and no session.

        Check: Cannot find the session in
        local connection DB

        Result: FAILURE.

        """
        # Create a connection for connection ID
        global_dispatcher = Dispatcher()
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress = '127.0.0.1'
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(
            global_dispatcher,
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress,
            create_global_listen=False)

        self.dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        self.connection = L2tpv3Connection.L2tpConnection(
            7097, 8208, "127.0.0.1")

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO

        sess = cmd.sess
        conn = sess.conn

        # connection is in local connection DB
        conn.remoteAddr = self.connection.remoteAddr
        conn.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress
        conn.connectionID = self.connection.localConnID

        # Local session is not in connection session
        sess.localSessionID = 2406980214

        msg = self.api._handleMsg(cmd)

        # FAILIURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the session in local connection DB")

    def test_B3__handleSessionQuery_localsessionID_isin_AND_connID_isNotin_DB(self):
        """No connection and create session.

        Check: Cannot find the connection
        in local connection DB

        Result: Failure.

        """
        # Create a connection for connection ID
        global_dispatcher = Dispatcher()
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress = '127.0.0.1'
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(
            global_dispatcher,
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress,
            create_global_listen=False)

        self.dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        self.connection = L2tpv3Connection.L2tpConnection(
            10202, 1719, "127.0.0.1")

        # Create a session for sessionID
        session = L2tpv3Session.L2tpv3Session(
            randint(1, 0xFFFFFFFF), 0, "sender", self.connection)
        self.connection.addSession(session)
        session.LocalRequest()

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO

        sess = cmd.sess
        conn = sess.conn

        # connectionID is not in local connection DB
        conn.remoteAddr = '127.0.0.1'
        # Connection is not in connection DB && return
        conn.connectionID = 1652974642

        # Local session is in connection session
        sess.localSessionID = session.localSessionId

        msg = self.api._handleMsg(cmd)

        # FAILIURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the connection in local connection DB")

    def test_B4__handleSessionQuery_localsessionID_AND_connID_isin_DB(self):
        """Create connection and session.

        Result: success.

        """
        # Create a connection for connectionID
        global_dispatcher = Dispatcher()
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress = '127.0.0.1'
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(
            global_dispatcher,
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress,
            create_global_listen=False)

        self.dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        self.connection = L2tpv3Connection.L2tpConnection(
            3110, 7222, "127.0.0.1")

        # Create a session for sessionID
        session = L2tpv3Session.L2tpv3Session(
            randint(1, 0xFFFFFFFF), 0, "sender", self.connection)
        self.connection.addSession(session)
        session.LocalRequest()

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_INFO

        sess = cmd.sess
        conn = sess.conn

        # connection is in local connection DB
        conn.remoteAddr = self.connection.remoteAddr
        conn.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress
        conn.connectionID = self.connection.localConnID

        # Local session is in connection session
        sess.localSessionID = session.localSessionId

        msg = self.api._handleMsg(cmd)
        print msg

        # Success = 1
        self.assertEqual(msg.rsp, 1)

    def test_C0__handleDebug_isNot_debugmsg(self):
        """
        Check: Cannot find the debug parameter in debug msg
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.DEBUG
        No any para
        msg.HasField("debug") = False

        Result: FAILURE

        """
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.DEBUG

        msg = self.api._handleMsg(cmd)

        # FAILIURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(
            msg.retMsg, "Cannot find the debug parameter in debug msg")

    def test_C1__handleDebug_is_debugmsg_AND_isNotin_system(self):
        """Para is invalid(debug.module and debug.level)

        Check: Cannot find the
        debug module in system

        result: FAILURE.

        """
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.DEBUG

        # Create invalid para
        debug = cmd.debug

        debug.module = 'RemoteSessionID is Invalid'
        debug.level = 'debug is invalid'

        msg = self.api._handleMsg(cmd)

        # FAILIURE = 2
        self.assertEqual(msg.rsp, 2)
        self.assertEqual(msg.retMsg, "Cannot find the debug module in system")

    def test_C2__handleDebug_is_debugmsg_AND_isin_system_and_isnotin_map(self):
        """Para: debug.module is valid and debug.level is invalid.

        Check: Cannot
        map the level name to logging level

        Result: FAILURE.

        """

        # allClasses== ['RemoteSessionID', 'L2tpv3Session', 'CallSerialNumber',
        # 'Hostname', 'L2tpv3Dispatcher', 'L2tpv3StopCCN', 'PseudowireCapList',
        # 'L2tpv3Hello', 'l2tpV3TerminatePkt', 'TieBreaker', 'L2tpv3CDN', 'RemoteEndID',
        # 'GeneralL2tpv3AVP', 'l2tpv3AVP', 'CircuitStatus', 'L2SpecificSublayer',
        # 'L2tpv3Network', 'PseudowireType', 'ProtocolVersion', 'ResultCode',
        # 'FrameCapabilities', 'L2tpv3SessionSenderFsm', 'LocalSessionID', 'L2tpv3ZLB',
        # 'SequencingRequired', 'L2tpv3API', 'ControlMessageAVP', 'L2tpV3Fsm',
        # 'L2tpv3ConnectionFsm', 'FirmwareRevision', 'L2tpv3Transport', 'VendorName',
        # 'ReceiveWinSize', 'L2tpv3SessionRecipientFsm', 'RouterID',
        # 'AssignedControlConnectionID', 'L2tpConnection', 'DataSequencing',
        # 'L2tpv3APITransport', 'L2tpv3ControlPacket']

        # len(allClasses_keys) = 40

        allClasses = AddLoggerToClass.moduleMapping
        allClasses_keys = allClasses.keys()

        for module_value in allClasses_keys:

            cmd = l2tpMsg.L2tpCommandReq()
            cmd.cmd = l2tpMsg.DEBUG

            debug = cmd.debug

            # debug.module is valid
            debug.module = module_value
            # debug.level is invalid
            debug.level = "Not is in levelMapping"

            msg = self.api._handleMsg(cmd)

            # FAILIURE = 2
            self.assertEqual(msg.rsp, 2)
            self.assertEqual(
                msg.retMsg, "Cannot map the level name to logging level")

    def test_C2__handleDebug_is_debugmsg_AND_isin_system_and_isin_map(self):
        """Para: OK Can map the level name to logging level.

        Result: Success.

        """
        debugPara = ['debug', 'info', 'warn', 'error']
        allClasses = AddLoggerToClass.moduleMapping
        allClasses_keys = allClasses.keys()

        for level_value in debugPara:

            for module_value in allClasses_keys:

                cmd = l2tpMsg.L2tpCommandReq()
                cmd.cmd = l2tpMsg.DEBUG

                debug = cmd.debug
                # Valid Para
                debug.module = module_value
                debug.level = level_value

                msg = self.api._handleMsg(cmd)

                # Success = 1
                self.assertEqual(msg.rsp, 1)

    # Invalid API: test it for coverage and No change the sourcecode
    # D0 --- D6
    def test_D0__handleTest(self):

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.TEST
        cmd.test.para1 = "this is test para1"
        cmd.test.para2 = "this is test para2"
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.SUCCESS)

        # add a fail case

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.TEST
        msg = self.api._handleTest(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    def test_D1__handleConnectionSetup(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CONNECTION_SETUP
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    def test_D2__handleConnectionTeardown(self):
        socket = self._createZmqInstance()
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CONNECTION_TEARDOWN

        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    def test_D3__handleConnectionStats(self):
        socket = self._createZmqInstance()
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CONNECTION_STATS
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    def test_D4__handleSessionStats(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_STATS
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    def test_D5__handleSessionSetup(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_SETUP
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    def test_D6__handleSessionTeardown(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.SESSION_TEARDOWN

        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

    @staticmethod
    def _createZmqInstance():
        # Create a zmq
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.connect(L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath)
        return socket

    def test_bind_local_ip(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.BIND_LOCAL_ADDRESS
        cmd.bindIP.localIP = "127.0.0.3"
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.SUCCESS)

        # not msg.HasField("bindIP")
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.BIND_LOCAL_ADDRESS
        # cmd.bindIP.localIP = "127.0.0.3"
        msg = self.api._handleMsg(cmd)
        self.assertEqual(
            msg.retMsg, "Cannot find the bindIP parameter in bindIP msg")
        self.assertEqual(msg.rsp, 2)

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.BIND_LOCAL_ADDRESS
        cmd.bindIP.localIP = "192.168.0.1"
        msg = self.api._handleMsg(cmd)
        # self.assertEqual(msg.retMsg, "Cannot find the bindIP parameter in
        # bindIP msg")
        self.assertEqual(msg.rsp, 2)

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.UNBIND_LOCAL_ADDRESS
        cmd.bindIP.localIP = "127.0.0.3"
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.SUCCESS)

        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.UNBIND_LOCAL_ADDRESS
        cmd.bindIP.localIP = "127.0.0.1"
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.FAILURE)

        # not msg.HasField("bindIP")
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.UNBIND_LOCAL_ADDRESS
        # cmd.bindIP.localIP = "127.0.0.3"
        msg = self.api._handleMsg(cmd)
        self.assertEqual(
            msg.retMsg, "Cannot find the bindIP parameter in bindIP msg")
        self.assertEqual(msg.rsp, 2)

    def test_handleStatsQuery(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.STATS_INFO
        msg = self.api._handleMsg(cmd)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = None
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client = None
        print msg

        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(global_dispatcher, "127.0.0.1", False, None)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        dispatcher.stats.exception = 1
        dispatcher.stats.zmq_error = 1
        dispatcher.stats.error = 1
        # setup the halclient
        hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                   "the HAL client of L2TP feature",
                                   "1.0", (3078,), global_dispatcher)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client = hal_client
        hal_client.stats.exception = 10
        msg = self.api._handleMsg(cmd)
        print msg
        hal_client.stats = None

    def test_handleClearStatsQuery(self):
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = None
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client = None
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.CLEAR_STATS_INFO
        msg = self.api._handleMsg(cmd)
        print msg
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(global_dispatcher, "127.0.0.1", False, None)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = dispatcher
        dispatcher.stats.exception = 1
        dispatcher.stats.zmq_error = 1
        dispatcher.stats.error = 1
        # setup the halclient
        hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                   "the HAL client of L2TP feature",
                                   "1.0", (3078,), global_dispatcher)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client = hal_client
        hal_client.stats.exception = 10
        msg = self.api._handleMsg(cmd)
        self.assertEqual(dispatcher.stats.error, 0)

    @classmethod
    def format_print(self, value):
        """convert the dict content to a string."""

        output = ""
        header = list(value["header"])
        data = value["data"]

        max_len = [len(str(a)) for a in header]
        for para_tuple in data:
            max_len = [max_len[i] if max_len[i] > len(str(para_tuple[i])) else len(str(para_tuple[i]))
                       for i in range(len(max_len))]
        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"
        generate_format += "\n"

        output += generate_format % tuple(header)
        for para_tuple in data:
            output += generate_format % para_tuple
        return output

    def test__handleMcastInfo(self):
        cmd = l2tpMsg.L2tpCommandReq()
        cmd.cmd = l2tpMsg.MCAST_INFO
        msg = self.api._handleMsg(cmd)
        self.assertEqual(msg.rsp, l2tpMsg.SUCCESS)

        session_1 = ("127.0.0.1", "127.0.0.1", 1, 1)
        session_2 = ("127.0.0.1", "127.0.0.1", 2, 2)
        session_3 = ("127.0.0.1", "127.0.0.1", 3, 3)
        address = ("127.0.0.1", "5.5.5.1", "229.1.1.255", 0)
        mcast = Mcast(address=address)
        mcast.join(session_1)
        time.sleep(0.1)
        mcast.join(session_2)
        msg = self.api._handleMsg(cmd)
        print msg
        self.assertEqual(msg.rsp, l2tpMsg.SUCCESS)

        Mcast.McastDb[("127.0.0.1", "5.5.5.1", "225.1.1.255", 0)] = "test"
        msg = self.api._handleMsg(cmd)
        print msg
        data = []
        print "********"
        for mcastInfo in msg.mcast_info.mcastInfoList:
            mcast_line = L2tpMcastList()
            mcast_line.Grp = mcastInfo.grp
            mcast_line.Src = mcastInfo.src
            mcast_line.LocalIp = mcastInfo.local_ip
            mcast_line.interface = mcastInfo.interface
            mcast_line.status = mcastInfo.status
            mcast_line.last_change_time = mcastInfo.lastchange
            for session in mcastInfo.session:
                mcast_line.Session.append(session)
            print mcast_line.Grp, mcast_line.Src, mcast_line.LocalIp, mcast_line.LocalIp, mcast_line.interface,\
                mcast_line.status, mcast_line.last_change_time, len(mcast_line.Session)
            item = (mcast_line.interface, mcast_line.LocalIp, mcast_line.Grp, mcast_line.Src,
                    mcast_line.status, str(len(mcast_line.Session)), mcast_line.last_change_time)
            data.append(item)
            del mcast_line
            printval = {
                "header": L2tpMcastList.HEADER, "data": data}
            output = testL2tpv3API.format_print(printval)
            print output
            del data[:]
        self.assertEqual(msg.rsp, l2tpMsg.SUCCESS)
        Mcast.McastDb.pop(("127.0.0.1", "5.5.5.1", "225.1.1.255", 0))

        for key in Mcast.McastDb.keys():
            Mcast.McastDb[key].close()


class fake_conn(object):

    def __init__(self):
        self.remoteAddr = "1.1.1.1"
        self.localAddr = "1.1.1.1"
        self.connectionID = 1234


class ThreadingAPI(object):
    """ Threading example class
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, interval=1):
        """ Constructor
        :type interval: int
        :param interval: Check interval, in seconds
        """
        self.interval = interval
        self.ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        self.api = L2tpv3API(self.ApiPath)
        self.run_flag = True

        self.thread = threading.Thread(target=self.run, args=())
        self.thread.daemon = True                            # Daemonize thread
        self.thread.start()                                  # Start the execution

    def run(self):
        """ Method that runs forever """
        while self.run_flag:
            # Do something
            self.api.recvAndProcess()
            time.sleep(self.interval)


class testL2tpv3APIClient(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("L2TP")
        # Construct the API transport path
        cls.ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath

    @classmethod
    def tearDownClass(cls):
        pass

    def test_L2tpv3APIClient(self):
        con = fake_conn()
        client_error = L2tpv3APIClient()
        self.assertIsInstance(client_error, L2tpv3APIClient)

        ret = client_error.requestSessInfo(conn=con, sess=3, timeout=1)
        self.assertIsNone(ret)
        del(client_error)

        api = ThreadingAPI(0.1)
        self.assertIsInstance(api, ThreadingAPI)
        client = L2tpv3APIClient()
        self.assertIsInstance(client, L2tpv3APIClient)

        ret = client.requestSessInfo(conn=con, sess=3)
        self.assertIsNotNone(ret)
        api.run_flag = False
        api.thread.join()

    def test_requestSystemInfo(self):
        con = fake_conn()
        client_error = L2tpv3APIClient()
        self.assertIsInstance(client_error, L2tpv3APIClient)

        ret = client_error.requestSystemInfo(timeout=1)
        self.assertIsNone(ret)
        del(client_error)

        api = ThreadingAPI(0.1)
        self.assertIsInstance(api, ThreadingAPI)
        client = L2tpv3APIClient()
        self.assertIsInstance(client, L2tpv3APIClient)

        ret = client.requestSystemInfo()
        self.assertIsNotNone(ret)
        api.run_flag = False
        api.thread.join()


if __name__ == "__main__":
    unittest.main()
