#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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

from cli import cli_framework_def as cli_def
import l2tpv3.src.L2tpv3_pb2 as l2tpMsg
import time
import socket
import l2tpv3.src.L2tpv3Fsm as L2tpv3Fsm
import l2tpv3.src.L2tpv3ControlPacket as L2tpv3ControlPacket


class L2tpSessionLine(object):
    """
    line information for l2tp session
    """
    HEADER = "LocSessID RemSessID LocTunID  RemTunID  State Type       Last Chg"
    HEADER_LINK = "LocSessID RemSessID LocTunID  RemTunID  State Type       Link Last Chg"
    state_str = {
        L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateIdle: 'idle',
        L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateWaitConn: 'wiccn',
        L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished: 'est',
    }

    def __init__(self):
        self.local_session_id = 0
        self.remote_session_id = 0
        self.local_connection_id = 0
        self.remote_connection_id = 0
        self.last_change_time = time.time()
        self.local_addr = "0.0.0.0"
        self.remote_addr = "0.0.0.0"
        self.host_name = "N/A"
        self.state = "idle"
        self.type = "N/A"
        self.icrq_avps = None
        self.link_status = "DOWN"


class L2tpConnectionLine(object):
    """
    line information for l2tp connection
    """
    HEADER = ("LocTunID", "RemTunID", "Remote Name", "State",
              "Remote Address", "Local Address", "Sessn Count")
    state_str = {
        L2tpv3Fsm.L2tpv3ConnectionFsm.StateIdle: 'idle',
        L2tpv3Fsm.L2tpv3ConnectionFsm.StateWaitCtlReply: 'wcrp',
        L2tpv3Fsm.L2tpv3ConnectionFsm.StateWaitCtlConn: 'wsccn',
        L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished: 'est',
    }

    def __init__(self):
        self.local_connection_id = 0
        self.remote_connection_id = 0
        self.local_addr = "0.0.0.0"
        self.remote_addr = "0.0.0.0"
        self.host_name = "N/A"
        self.state = "idle"
        self.session_count = 0


class L2tpMcastList(object):
    HEADER = ["Interface", "LocalIp", "Grp", "Src", "Status", "Refcnt", "Last Chg"]
    HEADER_SESSION = ["Interface", "LocalIp", "Grp", "Src", "Status", "SESSIONS"]

    def __init__(self):
        self.interface = "N/A"
        self.LocalIp = "N/A"
        self.Grp = "N/A"
        self.Src = "N/A"
        self.Session = []
        self.last_change_time = "N/A"


class L2tpCli(object):
    """L2tp cli class."""

    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli

        self.cli_table = (
            ('l2tp', 'layer 2 vpn', self.show_l2tp, ["show"], cli_def.ADMIN_MODE),
            ('tunnel', 'layer 2 vpn tunnels', self.show_l2tp_tunnel, ["show", "l2tp"], cli_def.ADMIN_MODE),
            ('session', 'layer 2 vpn sessions', self.show_l2tp_session, ["show", "l2tp"], cli_def.ADMIN_MODE),
            ('link', 'layer 2 vpn sessions link status', self.show_l2tp_session_link, ["show", "l2tp", "session"],
             cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_NUMBER, "local tunnel id ", None, ["show", "l2tp", "session"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_NUMBER, "local session id ",
             self.show_l2tp_session_detail, ["show", "l2tp", "session", cli_def.FUNC_ARG_TYPE_NUMBER],
             cli_def.ADMIN_MODE),
            ('multicast', 'multicast joined sessions', self.show_l2tp_mcast, ["show", "l2tp"], cli_def.ADMIN_MODE),
            ('statistics', 'Error statistics', self.show_l2tp_stats, ["show", "l2tp"], cli_def.ADMIN_MODE)
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

    @classmethod
    def format_ipv6(self, str):
        grp_addrinfo = socket.getaddrinfo(str, None)[0]
        return grp_addrinfo[4][0]

    def format_print(self, val):
        """convert the dict content to a string."""

        output = ""
        header = list(val["header"])
        data = val["data"]

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
            output += generate_format % tuple(para_tuple)
        return output

    def sendMsg(self, module, msg):
        """
        send ipc to other module
        """
        if module not in self.cli.ipc or not self.cli.ipc[module]:
            self.cli.log.error("The client is on disconencted state, "
                               "skip to send the message.")
            return False

        if msg.IsInitialized():
            self.cli.ipc[module].send(msg.SerializeToString())
            return True
        return False

    def recvMsg(self, module, timeout=None):
        """
        recv ipc from other module
        """
        if module in self.cli.ipc and self.cli.ipc[module]:
            try:
                bin = self.cli.ipc[module].recv()
            except KeyboardInterrupt:
                self.cli.log.error("receive KeyboardInterrupt")
                return None
            msg = l2tpMsg.L2tpCommandRsp()
            msg.ParseFromString(bin)
            return msg
        else:
            self.cli.log.error("Cannot receive msg since module %d socket is NULL"
                               % module)
            return None

    def send(self, msg):
        """
        send ipc msg
        """
        return self.sendMsg(cli_def.L2TP_IPC, msg)

    def recv(self):
        """
        recv ipc msg
        """
        return self.recvMsg(cli_def.L2TP_IPC)

    def show_l2tp(self):
        """'show l2tp' cabllback."""
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SYSTEM_INFO
        ret = self.send(msg)
        print msg
        if ret:
            rsp = self.recv()
            print rsp
        else:
            self.cli.log.error("send msg to module %d fail" % cli_def.L2TP_IPC)

    def show_l2tp_tunnel(self):
        """'show l2tp tunnel' cabllback."""
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SYSTEM_INFO
        ret = self.send(msg)
        total_channel = 0
        total_session = 0
        if not ret:
            print "Send message to L2tp API failed"
            return
        else:
            connectionInfo = list()
            systemResult = self.recv()
            for connInfo in systemResult.sysInfo.conns:
                connection_line = L2tpConnectionLine()
                connection_line.remoteAddr = connInfo.remoteAddr
                connection_line.localAddr = connInfo.localAddr
                connection_line.connectionID = connInfo.connectionID
                connection_line.remote_connection_id = connInfo.remoteConnectionID
                connection_line.state = connInfo.currentState
                connection_line.host_name = connInfo.hostname
                connection_line.session_count = len(connInfo.localSessionID)
                connectionInfo.append(connection_line)
                total_channel += 1
                total_session += connection_line.session_count
            print "L2TP Tunnel Information Total tunnels %d" % total_channel + " sessions %d" % total_session
            # "LocTunID   RemTunID   Remote Name   State  Remote Address  SessCount"
            print_list = list()
            print_list.append(L2tpConnectionLine.HEADER)
            max_len = [len(a) for a in L2tpConnectionLine.HEADER]
            for connection_line in connectionInfo:
                dic = {}
                dic["LocTunID"] = str(hex(connection_line.connectionID))[2:]
                dic["RemTunID"] = str(hex(connection_line.remote_connection_id))[2:]
                dic["Remote Name"] = connection_line.host_name
                dic["State"] = L2tpConnectionLine.state_str[connection_line.state]
                dic["Remote Address"] = connection_line.remoteAddr
                dic["Local"] = connection_line.localAddr
                dic["Sessn Count"] = str(connection_line.session_count)

                para_tuple = (dic["LocTunID"],
                              dic["RemTunID"],
                              dic["Remote Name"],
                              dic["State"],
                              self.format_ipv6(dic["Remote Address"]),
                              self.format_ipv6(dic["Local"]),
                              dic["Sessn Count"])
                print_list.append(para_tuple)
                max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                           for i in range(len(max_len))]

        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"

        for field in print_list:
            print generate_format % field
        del connectionInfo[:]

    def show_l2tp_session(self):
        """'show l2tp session' cabllback."""

        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SYSTEM_INFO
        total_channel = 0
        total_session = 0
        ret = self.send(msg)
        if not ret:
            print "Send message to L2tp API failed"
            return
        else:
            systemResult = self.recv()

        sessionInfo = list()
        for connInfo in systemResult.sysInfo.conns:
            session_info_req = l2tpMsg.L2tpCommandReq()
            query_sess_msg = session_info_req.sess
            query_conn = query_sess_msg.conn
            query_conn.remoteAddr = connInfo.remoteAddr
            query_conn.localAddr = connInfo.localAddr
            query_conn.connectionID = connInfo.connectionID
            total_channel += 1
            total_session += len(connInfo.localSessionID)
            for localSessionId in connInfo.localSessionID:
                query_sess_msg.localSessionID = localSessionId
                session_info_req.cmd = l2tpMsg.SESSION_INFO
                ret = self.send(session_info_req)
                if not ret:
                    print "Send session query message to L2tp API failed"
                    return
                session_info_rsp = self.recv()
                # get the correct result
                session_line = L2tpSessionLine()
                session_line.state = session_info_rsp.sessInfo.currentState
                session_line.local_session_id = session_info_rsp.sessInfo.localSessionID
                session_line.remote_session_id = session_info_rsp.sessInfo.remoteSessionID
                session_line.last_change_time = session_info_rsp.sessInfo.lastchangetime
                session_line.local_connection_id = session_info_rsp.sessInfo.connectionID
                session_line.type = session_info_rsp.sessInfo.sessionType
                session_line.remote_connection_id = connInfo.remoteConnectionID
                session_line.remote_addr = connInfo.remoteAddr
                session_line.local_addr = connInfo.localAddr
                session_line.host_name = connInfo.hostname
                sessionInfo.append(session_line)
        print "L2TP Tunnel Information Total tunnels %d" % total_channel + " sessions %d" % total_session
        print L2tpSessionLine.HEADER
        # "LocID      RemID      LocTunID   RemTunID   State       Type   Last Chg"
        for session_line in sessionInfo:
            print "%08x " % session_line.local_session_id, \
                  "%08x " % session_line.remote_session_id, \
                  "%08x " % session_line.local_connection_id, \
                  "%08x " % session_line.remote_connection_id, \
                  "%-5s" % L2tpSessionLine.state_str[session_line.state], \
                  "%-10s" % session_line.type,\
                  "%-s" % session_line.last_change_time
        del sessionInfo[:]

    def show_l2tp_session_detail(self, parameters):
        """'show l2tp session <local tunnel> <local session>' cabllback."""

        # get all connections
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SYSTEM_INFO

        ret = self.send(msg)
        if not ret:
            print "Send message to L2tp API failed"
            return
        else:
            systemResult = self.recv()

        sessionInfo = list()
        print parameters
        for connInfo in systemResult.sysInfo.conns:
            if connInfo.connectionID == int(parameters[0]):
                session_info_req = l2tpMsg.L2tpCommandReq()
                query_sess_msg = session_info_req.sess
                query_conn = query_sess_msg.conn
                query_conn.remoteAddr = connInfo.remoteAddr
                query_conn.localAddr = connInfo.localAddr
                query_conn.connectionID = connInfo.connectionID

                for localSessionId in connInfo.localSessionID:
                    if localSessionId == int(parameters[1]):
                        query_sess_msg.localSessionID = localSessionId
                        session_info_req.cmd = l2tpMsg.SESSION_INFO
                        query_sess_msg.icrqReq = True
                        ret = self.send(session_info_req)
                        if not ret:
                            print "Send session query message to L2tp API failed"
                            return
                        session_info_rsp = self.recv()
                        # get the correct result
                        session_line = L2tpSessionLine()
                        session_line.state = session_info_rsp.sessInfo.currentState
                        session_line.local_session_id = session_info_rsp.sessInfo.localSessionID
                        session_line.remote_session_id = session_info_rsp.sessInfo.remoteSessionID
                        session_line.last_change_time = session_info_rsp.sessInfo.lastchangetime
                        session_line.local_connection_id = session_info_rsp.sessInfo.connectionID
                        session_line.type = session_info_rsp.sessInfo.sessionType
                        if hasattr(session_info_rsp.sessInfo, "icrqPktAvps"):
                            session_line.icrq_avps = \
                                L2tpv3ControlPacket.l2tpv3AVP.decodeAll(session_info_rsp.sessInfo.icrqPktAvps)
                        session_line.remote_connection_id = connInfo.remoteConnectionID
                        session_line.remote_addr = connInfo.remoteAddr
                        session_line.local_addr = connInfo.localAddr
                        session_line.host_name = connInfo.hostname
                        sessionInfo.append(session_line)
                        break
                break
        print L2tpSessionLine.HEADER
        # "LocID      RemID      LocTunID   RemTunID   State       Type   Last Chg"
        for session_line in sessionInfo:
            print "%08x " % session_line.local_session_id, \
                  "%08x " % session_line.remote_session_id, \
                  "%08x " % session_line.local_connection_id, \
                  "%08x " % session_line.remote_connection_id, \
                  "%-5s" % L2tpSessionLine.state_str[session_line.state], \
                  "%-10s" % session_line.type,\
                  "%-s\n" % session_line.last_change_time
            for avp in session_line.icrq_avps:
                print avp.__class__, ":"
                print str(avp)
        del sessionInfo[:]
        pass

    def show_l2tp_session_link(self):
        """'show l2tp session' cabllback."""

        # get all connections
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.SYSTEM_INFO
        total_channel = 0
        total_session = 0
        ret = self.send(msg)
        if not ret:
            print "Send message to L2tp API failed"
            return
        else:
            systemResult = self.recv()

        sessionInfo = list()
        for connInfo in systemResult.sysInfo.conns:
            session_info_req = l2tpMsg.L2tpCommandReq()
            query_sess_msg = session_info_req.sess
            query_conn = query_sess_msg.conn
            query_conn.remoteAddr = connInfo.remoteAddr
            query_conn.localAddr = connInfo.localAddr
            query_conn.connectionID = connInfo.connectionID
            total_channel += 1
            total_session += len(connInfo.localSessionID)
            for localSessionId in connInfo.localSessionID:
                query_sess_msg.localSessionID = localSessionId
                session_info_req.cmd = l2tpMsg.SESSION_INFO
                ret = self.send(session_info_req)
                if not ret:
                    print "Send session query message to L2tp API failed"
                    return
                session_info_rsp = self.recv()
                # get the correct result
                session_line = L2tpSessionLine()
                session_line.state = session_info_rsp.sessInfo.currentState
                session_line.local_session_id = session_info_rsp.sessInfo.localSessionID
                session_line.remote_session_id = session_info_rsp.sessInfo.remoteSessionID
                session_line.last_change_time = session_info_rsp.sessInfo.lastchangetime
                session_line.local_connection_id = session_info_rsp.sessInfo.connectionID
                session_line.type = session_info_rsp.sessInfo.sessionType
                session_line.link_status = "UP" if session_info_rsp.sessInfo.status else "DOWN"
                session_line.remote_connection_id = connInfo.remoteConnectionID
                session_line.remote_addr = connInfo.remoteAddr
                session_line.local_addr = connInfo.localAddr
                session_line.host_name = connInfo.hostname
                sessionInfo.append(session_line)
        print "L2TP Tunnel Information Total tunnels %d" % total_channel + " sessions %d" % total_session
        print L2tpSessionLine.HEADER_LINK
        # "LocID      RemID      LocTunID   RemTunID   State       Type   Last Chg"
        for session_line in sessionInfo:
            print "%08x " % session_line.local_session_id, \
                  "%08x " % session_line.remote_session_id, \
                  "%08x " % session_line.local_connection_id, \
                  "%08x " % session_line.remote_connection_id, \
                  "%-5s" % L2tpSessionLine.state_str[session_line.state], \
                  "%-10s" % session_line.type,\
                  "%-4s" % session_line.link_status,\
                  "%-s" % session_line.last_change_time
        del sessionInfo[:]

    def show_l2tp_mcast(self):
        """'show l2tp multicast' cabllback."""
        # msg = t_CliMessage()
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.MCAST_INFO
        ret = self.send(msg)
        data = []
        if ret:
            rsp = self.recv()
            for mcastInfo in rsp.mcast_info.mcastInfoList:
                mcast_line = L2tpMcastList()
                mcast_line.Grp = mcastInfo.grp
                mcast_line.Src = mcastInfo.src
                mcast_line.LocalIp = mcastInfo.local_ip
                mcast_line.interface = mcastInfo.interface
                mcast_line.status = mcastInfo.status
                mcast_line.last_change_time = mcastInfo.lastchange
                for session in mcastInfo.session:
                    mcast_line.Session.append(session)
                item = (mcast_line.interface, mcast_line.LocalIp, mcast_line.Grp, mcast_line.Src,
                        mcast_line.status, str(len(mcast_line.Session)), mcast_line.last_change_time)
                data.append(item)
                del mcast_line
            printval = {
                "header": L2tpMcastList.HEADER, "data": data}
            output = self.format_print(printval)
            print output
            del data[:]

        else:
            self.cli.log.error("send msg to module %d fail" % cli_def.L2TP_IPC)

    def show_l2tp_stats(self):
        msg = l2tpMsg.L2tpCommandReq()
        msg.cmd = l2tpMsg.STATS_INFO
        ret = self.send(msg)
        if ret:
            rsp = self.recv()
            print rsp
        else:
            self.cli.log.error("send msg to module %d fail" % cli_def.L2TP_IPC)
