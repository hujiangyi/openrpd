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

"""This file defines the simple interface to control the L2TP connection and
session."""
import zmq
import logging
import rpd.python_path_resolver
import L2tpv3Connection
import L2tpv3Session
import L2tpv3GlobalSettings
import L2tpv3GcppConnection
import L2tpv3ControlPacket
import re
import datetime
import L2tpv3_pb2 as l2tpMsg
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.utils import IPCClient
from L2tpv3Hal import  L2tpHalClient
from rpd.mcast.src.mcast import Mcast
import L2tpv3Fsm

class L2tpv3APIClient(IPCClient):

    def __init__(self):
        super(L2tpv3APIClient, self).__init__(L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath)


    def requestSystemInfo(self, timeout=2500):
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SYSTEM_INFO
        bin = self.sendReq(msg, timeout)
        if not bin:
            return None
        rsp = l2tpMsg.L2tpCommandRsp()
        rsp.ParseFromString(bin)
        return rsp


    def requestSessInfo(self, conn,sess, timeout = 2500):
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SESSION_INFO
        msg.sess.conn.remoteAddr = conn.remoteAddr
        msg.sess.conn.localAddr = conn.localAddr
        msg.sess.conn.connectionID = conn.connectionID
        msg.sess.localSessionID = sess
        bin = self.sendReq(msg, timeout)
        if not bin:
            return None
        rsp = l2tpMsg.L2tpCommandRsp()
        rsp.ParseFromString(bin)
        return rsp

class L2tpv3APITransport(object):
    __metaclass__ = AddLoggerToClass
    context = zmq.Context()

    def __init__(self, path):
        self.logger.debug("Create a API transport, path=" + path)
        self.path = path

        self.socket = self.context.socket(zmq.REP)
        # self.socket.setsockopt()
        self.socket.bind(self.path)


class L2tpv3API(object):
    __metaclass__ = AddLoggerToClass

    def __init__(self, path):
        self.logger.debug("Create a l2TP API instance")
        self.transport = L2tpv3APITransport(path)
        self._handlers = {
            l2tpMsg.CONNECTION_SETUP: self._handleConnectionSetup,
            l2tpMsg.CONNECTION_TEARDOWN: self._handleConnectionTeardown,
            l2tpMsg.CONNECTION_INFO: self._handleConnectionQuery,
            l2tpMsg.CONNECTION_STATS: self._handleConnectionStats,
            l2tpMsg.SESSION_INFO: self._handleSessionQuery,
            l2tpMsg.SESSION_STATS: self._handleSessionStats,
            l2tpMsg.SESSION_SETUP: self._handleSessionSetup,
            l2tpMsg.SESSION_TEARDOWN: self._handleSessionTeardown,
            l2tpMsg.DEBUG: self._handleDebug,
            l2tpMsg.TEST: self._handleTest,
            l2tpMsg.SYSTEM_INFO: self._handleSystemInfo,
            l2tpMsg.BIND_LOCAL_ADDRESS: self._handleBindIP,
            l2tpMsg.UNBIND_LOCAL_ADDRESS: self._handleUnBindIP,
            l2tpMsg.STATS_INFO: self._handleStatsQuery,
            l2tpMsg.CLEAR_STATS_INFO: self._handleClearStats,
            l2tpMsg.MCAST_INFO: self._handleMcastInfo,
            l2tpMsg.STATIC_SESSION_INFO: self._handleStaticSessionQuery,
            l2tpMsg.STATIC_SYSTEM_INFO: self._handleStaticSystemInfo,

        }

    def recvAndProcess(self):
        try:
            data = self.transport.socket.recv(flags=zmq.NOBLOCK)
            msg = l2tpMsg.L2tpCommandReq()
            msg.ParseFromString(data)
            self.logger.debug("Got a request from the user:%s" % (msg))

            retMsg = self._handleMsg(msg)
            self.logger.debug("Send the return message to remote")
            self.transport.socket.send(
                retMsg.SerializeToString(), flags=zmq.NOBLOCK)
        except zmq.ZMQError as e:
            self.logger.warn(
                "Cannot read the zmq contents from zmq, reason:%s" % str(e))

    def _handleMsg(self, msg):
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE

        if msg.cmd in self._handlers:
            handler = self._handlers[msg.cmd]
            retMsg = handler(msg)
        return retMsg

    def _handleConnectionSetup(self, msg):
        self.logger.debug(
            "Handling the Connection Setup message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE
        retMsg.retMsg = "This command is not supported now."
        return retMsg

    def _handleConnectionTeardown(self, msg):
        self.logger.debug(
            "Handling the Connection teardown message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE
        retMsg.retMsg = "This command is not supported now."
        return retMsg

    def _handleSessionSetup(self, msg):
        self.logger.debug("Handling the session setup message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE
        retMsg.retMsg = "This command is not supported now."
        return retMsg

    def _handleSessionTeardown(self, msg):
        self.logger.debug(
            "Handling the session teardown message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE
        retMsg.retMsg = "This command is not supported now."
        return retMsg

    def _handleConnectionQuery(self, msg):
        self.logger.debug(
            "Handling the Connection query message, msg = %s" % msg)

        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        if not msg.HasField("conn"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the connection parameter in connection query msg"
            return retMsg

        conn = msg.conn
        remoteAddr = conn.remoteAddr
        localAddr = conn.localAddr
        connID = conn.connectionID

        # Try to find the session
        connectionDb = L2tpv3Connection.L2tpConnection.ConnectionDb
        if not (remoteAddr, localAddr, connID) in connectionDb:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the connection in local connection DB"
            return retMsg
        connection = connectionDb[(remoteAddr, localAddr, connID)]
        retMsg.connInfo.connectionID = connection.localConnID
        retMsg.connInfo.remoteConnectionID = connection.remoteConnID
        retMsg.connInfo.remoteAddr = connection.remoteAddr
        retMsg.connInfo.localAddr = L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress
        if "hostname" in connection.info:
            retMsg.connInfo.hostname = connection.info["hostname"]
        else:
            retMsg.connInfo.hostname = "N/A"

        retMsg.connInfo.currentState = connection.fsm.current
        retMsg.connInfo.localSessionID.extend(connection.sessions.keys())

        retMsg.retMsg = "Success"
        return retMsg

    def _handleStaticSessionQuery(self, msg):
        self.logger.debug("Handling the session query message, msg = %s", msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        if not msg.HasField("sess"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the session parameter in session query msg"
            return retMsg

        sess = msg.sess
        conn = sess.conn
        remoteAddr = conn.remoteAddr
        localAddr = conn.localAddr
        connID = conn.connectionID
        localSessionId = sess.localSessionID
        if connID == 0:
            staticPseudowireDb = L2tpv3GcppConnection.L2tpv3GcppProvider.staticPseudowireDB
            if staticPseudowireDb is None:
                self.logger.debug("Gcpp session table staticPseudowireDb is empty ")
                retMsg.rsp = l2tpMsg.FAILURE
                retMsg.retMsg = "Cannot find the connection in local Gcpp DB"
                return retMsg
            for key, staticL2tpSession in staticPseudowireDb.items():
                if staticL2tpSession.direction == L2tpv3GcppConnection.StaticL2tpSession.DIRECTION_RETURN:
                    if localSessionId == staticL2tpSession.sessionId \
                            and staticL2tpSession.localAddress == localAddr \
                            and staticL2tpSession.destAddress == remoteAddr:
                        retMsg.sessInfo.connectionID = 0
                        retMsg.sessInfo.currentState = L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished
                        retMsg.sessInfo.remoteSessionID = staticL2tpSession.sessionId
                        retMsg.sessInfo.localSessionID = 0
                        retMsg.sessInfo.sessionType =\
                            L2tpHalClient.sessionSubTypeStr[staticL2tpSession.l2SublayerType]
                        retMsg.sessInfo.lastchangetime =\
                            datetime.datetime.fromtimestamp(staticL2tpSession.lastchangetime).\
                            strftime("%H:%M:%S %Y-%m-%d")
                        retMsg.sessInfo.status = staticL2tpSession.status
                elif localSessionId == staticL2tpSession.sessionId and staticL2tpSession.localAddress == localAddr\
                        and staticL2tpSession.sourceAddress == remoteAddr:
                    retMsg.sessInfo.connectionID = 0
                    retMsg.sessInfo.currentState = L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished
                    retMsg.sessInfo.remoteSessionID = 0
                    retMsg.sessInfo.localSessionID = staticL2tpSession.sessionId
                    retMsg.sessInfo.sessionType =\
                        L2tpHalClient.sessionSubTypeStr[staticL2tpSession.l2SublayerType]
                    retMsg.sessInfo.lastchangetime =\
                        datetime.datetime.fromtimestamp(staticL2tpSession.lastchangetime).\
                        strftime("%H:%M:%S %Y-%m-%d")
                    retMsg.sessInfo.status = staticL2tpSession.status
                else:
                    continue
            return retMsg
        return retMsg

    def _handleSessionQuery(self, msg):
        self.logger.debug("Handling the session query message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        if not msg.HasField("sess"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the session parameter in session query msg"
            return retMsg

        sess = msg.sess
        conn = sess.conn
        remoteAddr = conn.remoteAddr
        localAddr = conn.localAddr
        connID = conn.connectionID
        localSessionId = sess.localSessionID

        connectionDb = L2tpv3Connection.L2tpConnection.ConnectionDb
        if not (remoteAddr, localAddr, connID) in connectionDb:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the connection in local connection DB"
            return retMsg
        connection = connectionDb[(remoteAddr, localAddr, connID)]

        if localSessionId not in connection.sessions:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the session in local connection DB"
            return retMsg

        session = connection.sessions[localSessionId]

        retMsg.sessInfo.connectionID = connID
        retMsg.sessInfo.currentState = session.fsm.current
        retMsg.sessInfo.localSessionID = session.localSessionId
        retMsg.sessInfo.remoteSessionID = session.remoteSessionId
        retMsg.sessInfo.sessionType = L2tpHalClient.sessionSubTypeStr[session.session_l2Sublayer]
        retMsg.sessInfo.lastchangetime = datetime.datetime.fromtimestamp(session.lastchangetime).\
            strftime("%H:%M:%S %Y-%m-%d")
        retMsg.sessInfo.status = session.local_circuit_status
        if hasattr(sess, "icrqReq") and sess.icrqReq:
            icrq = L2tpv3ControlPacket.L2tpv3ControlPacket(
                remoteConnID=connection.remoteConnID,
                avps=session.avps_icrq)
            retMsg.sessInfo.icrqPktAvps = icrq.encode(
                reGenerateAvpStr=True)[12:]
        return retMsg

    def _handleConnectionStats(self, msg):
        self.logger.debug(
            "Handling the Connection stats message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE
        retMsg.retMsg = "This command is not supported now."
        return retMsg

    def _handleSessionStats(self, msg):
        self.logger.debug("Handling the session stats message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.FAILURE
        retMsg.retMsg = "This command is not supported now."
        return retMsg

    def _handleDebug(self, msg):
        self.logger.debug("Handling the debug message, msg = %s" % msg)

        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        if not msg.HasField("debug"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the debug parameter in debug msg"
            return retMsg

        lvl = msg.debug.level
        module = msg.debug.module

        allClasses = AddLoggerToClass.moduleMapping

        p = re.compile(module)
        retList = list()
        for name in allClasses:
            if p.match(name) is not None:
                retList.append(name)

        if len(retList) == 0:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the debug module in system"
            return retMsg

        levelMapping = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warn': logging.WARN,
            'error': logging.ERROR,
        }
        if lvl not in levelMapping:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot map the level name to logging level"
            return retMsg

        for name in retList:
            logger = allClasses[name]
            logger.setLevel(levelMapping[lvl])

        return retMsg

    def _handleStaticSystemInfo(self, msg):
        self.logger.debug("Handling the system info message, msg = %s", msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        # Try to find the session
        systemResult = l2tpMsg.SystemQueryResult()
        staticPseudowireDb = L2tpv3GcppConnection.L2tpv3GcppProvider.staticPseudowireDB
        num = 0
        staticSessionDic = {}
        dstAddr = ""
        for key, staticL2tpSession in staticPseudowireDb.items():
            if staticL2tpSession.direction == L2tpv3GcppConnection.StaticL2tpSession.DIRECTION_FORWARD:
                dstAddr = staticL2tpSession.sourceAddress
            else:
                dstAddr = staticL2tpSession.destAddress
            srcAddr = staticL2tpSession.localAddress
            if (srcAddr, dstAddr) not in staticSessionDic.keys():
                staticSessionDic[(srcAddr, dstAddr)] = []
            staticSessionDic[(srcAddr, dstAddr)].append(staticL2tpSession.sessionId)
        for key, value in staticSessionDic.items():
            num += 1
            (srcAddr, dstAddr) = key
            connInfo = systemResult.conns.add()
            connInfo.connectionID = 0
            connInfo.remoteConnectionID = 0
            connInfo.remoteAddr = dstAddr
            connInfo.localAddr = srcAddr
            connInfo.hostname = "N/A"
            connInfo.currentState = L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished
            connInfo.localSessionID.extend(value)

        self.logger.debug("CLI: Handling staticPseudowireDB message num=%d", num)
        retMsg.sysInfo.MergeFrom(systemResult)

        return retMsg

    def _handleSystemInfo(self, msg):
        self.logger.debug("Handling the system info message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        # Try to find the session
        connectionDb = L2tpv3Connection.L2tpConnection.ConnectionDb

        systemResult = l2tpMsg.SystemQueryResult()
        for connectionKey in connectionDb:
            connection = connectionDb[connectionKey]
            connInfo = systemResult.conns.add()
            connInfo.connectionID = connection.localConnID
            connInfo.remoteConnectionID = connection.remoteConnID
            connInfo.remoteAddr = connection.remoteAddr
            connInfo.localAddr = connection.localAddr
            if "hostname" in connection.info:
                connInfo.hostname = connection.info["hostname"]
            else:
                connInfo.hostname = "N/A"

            connInfo.currentState = connection.fsm.current
            connInfo.localSessionID.extend(connection.sessions.keys())

        retMsg.sysInfo.MergeFrom(systemResult)

        return retMsg

    def _handleTest(self, msg):
        self.logger.debug("Handling the test message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        if not msg.HasField("test"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the test parameter in test msg"
            return retMsg

        test = msg.test

        for des, val in test.ListFields():
            self.logger.info(
                "test msg: para = %s, value = %s" % (des.name, val))

        return retMsg

    def _handleBindIP(self, msg):
        """Handle the command "bind an IP address to l2tp".

        :param msg: command message, which has to include BindPara
        :return: rsp message.

        """
        self.logger.debug(
            "Handling the bind IP command message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        if not msg.HasField("bindIP"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the bindIP parameter in bindIP msg"
            return retMsg

        ipMsg = msg.bindIP
        ip = ipMsg.localIP

        dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher
        ret, reason = dispatcher.register_local_address(ip)
        if ret:
            retMsg.rsp = l2tpMsg.SUCCESS
        else:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = reason

        return retMsg

    def _handleUnBindIP(self, msg):
        """Handle the command "unbind an IP address to l2tp".

        :param msg: command message, which has to include BindPara
        :return: rsp message.

        """
        self.logger.debug(
            "Handling the unbind IP command message, msg = %s" % msg)
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"

        if not msg.HasField("bindIP"):
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = "Cannot find the bindIP parameter in bindIP msg"
            return retMsg

        ipMsg = msg.bindIP
        ip = ipMsg.localIP

        dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher
        ret, reason = dispatcher.request_unregister({
            "unregType": "localaddress",
            "value": ip
        })
        if ret:
            retMsg.rsp = l2tpMsg.SUCCESS
        else:
            retMsg.rsp = l2tpMsg.FAILURE
            retMsg.retMsg = reason

        return retMsg

    def _handleStatsQuery(self, msg):
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"
        try:
            dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher
            l2tphal = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client

            if dispatcher:
                retMsg.stats_info.dispacher_stats.exception = dispatcher.stats.exception
                retMsg.stats_info.dispacher_stats.error = dispatcher.stats.error
                retMsg.stats_info.dispacher_stats.pkt_error = dispatcher.stats.pkt_error
                retMsg.stats_info.dispacher_stats.zmq_error = dispatcher.stats.zmq_error
                retMsg.stats_info.dispacher_stats.unexpected_else = dispatcher.stats.unexpected_else

            if l2tphal:
                retMsg.stats_info.halclient_stats.exception = l2tphal.stats.exception
                retMsg.stats_info.halclient_stats.error = l2tphal.stats.error
                retMsg.stats_info.halclient_stats.zmq_error = l2tphal.stats.zmq_error
        except Exception as e:
            self.logger.warn("Failed when query l2tp Stats exception: %s", str(e))
        return retMsg

    def _handleClearStats(self, msg):
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"
        try:
            dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher
            l2tphal = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client

            if dispatcher:
                dispatcher.stats.clear()
            if l2tphal:
                l2tphal.stats.clear()
        except Exception as e:
            self.logger.warn("Failed when clear l2tp Stats exception: %s", str(e))
        return retMsg

    def _handleMcastInfo(self, msg):
        retMsg = l2tpMsg.L2tpCommandRsp()
        retMsg.rsp = l2tpMsg.SUCCESS
        retMsg.retMsg = "Success"
        mcastResult = l2tpMsg.McastQueryResult()
        for mcast in Mcast.McastDb.values():
            if isinstance(mcast, Mcast):
                mcastInfo = mcastResult.mcastInfoList.add()
                mcastInfo.grp = mcast.grp_ip
                mcastInfo.src = mcast.src_ip
                mcastInfo.local_ip = mcast.local_ip
                mcastInfo.status = "JOINED" if mcast.status==Mcast.JOINED else "LEAVED"
                mcastInfo.interface = mcast.interface
                mcastInfo.lastchange = datetime.datetime.fromtimestamp(mcast.lastchange).strftime("%H:%M:%S %Y-%m-%d")
                for session in mcast.sessionList:
                    mcastInfo.session.append(str(session))

        retMsg.mcast_info.MergeFrom(mcastResult)
        return retMsg
