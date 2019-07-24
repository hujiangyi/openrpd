#
# Copyright (c) 2016 Cisco and/or its affiliates,
# MaxLinear, Inc. ("MaxLinear"), and
# Cable Television Laboratories, Inc. ("CableLabs")
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

import re
import zmq
import struct
import socket
import binascii
import psutil
import traceback
import commands
import rpd.python_path_resolver
from zmq.utils.monitor import recv_monitor_message
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg.HalMessage import HalMessage
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.lib.clients.HalClient0 import HalClient, HalClientError
import L2tpv3Hal_pb2
import L2tpv3Connection
import L2tpv3Session
import L2tpv3GcppConnection
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import l2tpv3.src.L2tpv3CiscoAVPs as L2tpv3CiscoAVPs
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
from vendorAVPs.src.L2tpv3VspAvps import l2tpv3VspAvps
import L2tpv3VspAvp_pb2 as L2tpv3VspAvp_pb2
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common import rpd_event_def
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
from rpd.common.utils import Convert
from rpd.gpb.StaticPwStatus_pb2 import t_StaticPwStatus
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.mcast.src.mcast import Mcast
from rpd.rcp.rcp_lib import rcp_tlv_def
from zmq.utils.monitor import recv_monitor_message
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass

class L2tpHalClientError(HalClientError):

    def __init__(self, msg, expr=None):
        super(L2tpHalClientError, self).__init__(msg)
        self.msg = "L2tpHalClientError: " + msg
        self.expr = expr

class L2tpv3HalStats(object):
    def __init__(self):
        self.exception = 0
        self.error = 0
        self.zmq_error = 0

    def clear(self):
        self.exception = 0
        self.error = 0
        self.zmq_error = 0

class L2tpHalClient(HalClient):
    """The Client for Hal."""
    __metaclass__ = AddLoggerToClass
    # channel type definition according to the spec
    NONE_TYPE = 0
    DS_OFDM = 1
    DS_OFDM_PLC = 2
    DS_SCQAM = 3
    US_ATDMA = 4
    US_OFDMA = 5
    SCTE_55_1_FWD = 6
    SCTE_55_1_RET = 7
    SCTE_55_2_FWD = 8
    SCTE_55_2_RET = 9
    NDF = 10
    NDR = 11
    channel_type_to_message_id = {
        NONE_TYPE: HalConfigMsg.MsgTypeL2tpv3SessionReqNone,
        DS_OFDM: HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdm,
        DS_OFDM_PLC: HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdmPlc,
        DS_SCQAM: HalConfigMsg.MsgTypeL2tpv3SessionReqDsScqam,
        US_ATDMA: HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma,
        US_OFDMA: HalConfigMsg.MsgTypeL2tpv3SessionReqUsOfdma,
        SCTE_55_1_FWD: HalConfigMsg.MsgTypeL2tpv3SessionReqScte551Fwd,
        SCTE_55_1_RET: HalConfigMsg.MsgTypeL2tpv3SessionReqScte551Ret,
        SCTE_55_2_FWD: HalConfigMsg.MsgTypeL2tpv3SessionReqScte552Fwd,
        SCTE_55_2_RET: HalConfigMsg.MsgTypeL2tpv3SessionReqScte552Ret,
        NDF: HalConfigMsg.MsgTypeL2tpv3SessionReqNdf,
        NDR: HalConfigMsg.MsgTypeL2tpv3SessionReqNdr,
    }

    notification_list = {
        HalConfigMsg.MsgTypeL2tpv3SessionStatusNotification: "STATUS_NOTIFY",
        HalConfigMsg.MsgTypeRpdCapabilities: "RPD_CAPABILITY_NOTIFY"
    }
    supportmsg_list = [
        HalConfigMsg.MsgTypeVspAvpExchange,
        HalConfigMsg.MsgTypeGcppToL2tp,
    ]
    # depi pw subtype definition according to the spec(4491,15)(4491,17)
    NONE_SESSION_TYPE = 0
    MPT_LEGACY = 1
    PSP_LEGACY = 2
    MCM = 3
    PSP_DEPI = 4
    reserved = 5
    PSP_UEPI_SCQAM = 6
    PSP_UEPI_OFDMA = 7
    PSP_BW_REQ_SCQ = 8
    PSP_BW_REQ_OFDMA = 9
    PSP_PROBE = 10
    PSP_RNG_REQ_SCQ = 11
    PSP_RNG_REQ_OFDMA = 12
    PSP_MAP_SCQ = 13
    PSP_MAP_OFDMA = 14
    PSP_SPECMAN = 15
    PSP_PNM = 16
    PSP_55_1_FWD = 17
    PSP_55_1_RET = 18
    PSP_55_2_FWD = 19
    PSP_55_2_RET = 20
    PSP_NDF = 21
    PSP_NDR = 22
    sessionSubTypeStr = {
        NONE_SESSION_TYPE: "NONE",
        MPT_LEGACY: "MPT_LEGACY",
        PSP_LEGACY: "PSP_LEGACY",
        MCM: "MCM",
        PSP_DEPI: "PSP_DEPI",
        reserved: "reserved",
        PSP_UEPI_SCQAM: "UEPI_SCQAM",
        PSP_UEPI_OFDMA: "UEPI_OFDMA",
        PSP_BW_REQ_SCQ: "BW_SCQAM",
        PSP_BW_REQ_OFDMA: "BW_OFDMA",
        PSP_PROBE: "PSP_PROBE",
        PSP_RNG_REQ_SCQ: "RNG_SCQ",
        PSP_RNG_REQ_OFDMA: "RNG_OFDMA",
        PSP_MAP_SCQ: "MAP_SCQ",
        PSP_MAP_OFDMA: "MAP_OFDMA",
        PSP_SPECMAN: "SPECMAN",
        PSP_PNM: "PSP_PNM",
        PSP_55_1_FWD: "55_1_FWD",
        PSP_55_1_RET: "55_1_RET",
        PSP_55_2_FWD: "55_2_FWD",
        PSP_55_2_RET: "55_2_RET",
        PSP_NDF: "PSP_NDF",
        PSP_NDR: "PSP_NDR",
    }
    # pw cap for avp (0,62)
    MPTPW = 12
    PSPPW = 13
    pwTypeStr = {
        MPTPW: "MPTPW",
        PSPPW: "PSPPW",
    }
    DEFAULT_MTU_PAYLOAD = 9216
    DEFAULT_MCAST_CAP = True

    def __init__(self, appName, appDesc, appVer, interestedNotification,
                 dispatcher,supportedMsgType=[],logConfigurePath=None):
        """
        :param appName: The application name, such as RPD CLI
        :param appDesc: A brief description about this application, such as
                        the functionality description
        :param appVer: Driver specific version, such as 1.0.1
        :param interestedNotification: a tuple or list for the application
                        interested msg types, the form will be (1, 2, 456, 10)
        :return: HalClient object

        """
        # sanity check the input args
        super(L2tpHalClient, self).__init__(appName, appDesc,
                                            appVer, interestedNotification,logConfigurePath,supportedMsgType)
        self.dispatcher = dispatcher
        self.handler = None
        self.stats = L2tpv3HalStats()
        self.l2tpv3StaticSession = L2tpv3GcppConnection.L2tpv3GcppProvider()

        # default the capability of system
        self.pw_cap_list = L2tpHalClient.pwTypeStr.keys()
        self.sublayer_pw_cap_list = L2tpHalClient.sessionSubTypeStr.keys()
        self.mtu_payload = L2tpHalClient.DEFAULT_MTU_PAYLOAD
        self.mcast_cap = L2tpHalClient.DEFAULT_MCAST_CAP


        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalSetLoggingLevelRsp": self.recvHalSetLoggingLevelRspCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfig": self.recvCfgMsgCb,
            "HalConfigRsp": self.recvCfgMsgRspCb,
            "HalClientInterestNotificationCfgRsp":
                self.sendInterestedNotificationsRspCb,
            "HalNotification": self.recvHalNotification
        }

    def start(self, cfg_cb=None):
        """start poll the transport socket.

        :return:

        """
        self.logger.debug("Start the client poll...")
        try:
            self.connectionSetup(self.dispatcher)
            self.handler = cfg_cb
            self.register(self.clientID)
        except Exception as e:
            self.logger.warn("L2tp hal client start fail exception %s", str(e))
            self.stats.exception += 1


    @staticmethod
    def get_mac_of_ip(ipaddr):
        mac = "00:00:00:00:00:00"
        # find the ip from local interface first
        local_mac = L2tpHalClient.get_local_mac(ipaddr)
        if local_mac:
            return local_mac

        # get remote mac address from route and arp table
        if Convert.is_valid_ipv4_address(ipaddr):
            with open("/proc/net/arp") as f:
                arp_table = f.read()
            table = map(lambda x: x.split(), arp_table.split("\n"))
            item = filter(lambda x: len(x) > 3 and x[0] == ipaddr, table)
            if item:
                mac = item[0][3]
            else:
                gw_ip = L2tpHalClient.get_gateway(ipaddr)
                item = filter(lambda x: len(x) > 0 and x[0] == gw_ip, table)
                if item:
                    mac = item[0][3]
            return mac
        if Convert.is_valid_ipv6_address(ipaddr):
            ret, arp_table = commands.getstatusoutput("ip -6 neigh")
            table = map(lambda x: x.split(), arp_table.split("\n"))
            item = filter(lambda x: len(x) > 4 and x[0] == ipaddr, table)
            if item:
                mac = item[0][4]
            else:
                gw_ip = L2tpHalClient.get_gateway(ipaddr)
                item = filter(lambda x: len(x) > 0 and x[0] == gw_ip, table)
                if item:
                    mac = item[0][4]
            return mac


    @staticmethod
    def get_mac_bytes_from_ip(ipaddr):
        mac = L2tpHalClient.get_mac_of_ip(ipaddr)
        ret = binascii.unhexlify(mac.replace(":", ""))
        return ret

    @staticmethod
    def get_gateway(ipaddr):
        if ipaddr == "127.0.0.1" or ipaddr == "::1":
            return ipaddr
        if Convert.is_valid_ipv4_address(ipaddr):
            data = socket.inet_aton(ipaddr)
            int_ip, = struct.unpack("I", data)

            route_table = L2tpHalClient.get_route_table()
            default_gw = None
            for entry in route_table:
                tip = int_ip & int(entry[2], 16)
                if int(entry[2], 16) == 0:
                    default_gw_int = int(entry[1], 16)
                    default_gw = socket.inet_ntoa(struct.pack("I", default_gw_int))
                    continue
                if tip == int(entry[0], 16):
                    gw_int = int(entry[1], 16)
                    gw_s = socket.inet_ntoa(struct.pack("I", gw_int))
                    if gw_s == "0.0.0.0":
                        return ipaddr
                    else:
                        return gw_s
        if Convert.is_valid_ipv6_address(ipaddr):
            data = socket.inet_pton(socket.AF_INET6, ipaddr)
            int_ip = int(binascii.hexlify(data), 16)
            default_gw = None
            routes = open("/proc/net/ipv6_route").readlines()
            for route in routes:
                route = [s for s in route.strip().split(" ") if s]
                if (route[0] == "00000000000000000000000000000000" and route[1] == "00"
                    and route[9] != "lo" and not route[9].startswith("nettest")):
                    default_gw = Convert.format_proc_address(route[4])
                    continue
                if int_ip == int(route[0], 16):
                    gw_s = Convert.format_proc_address(route[4])
                    if gw_s == "::":
                        continue
                    else:
                        return gw_s
        if default_gw:
            return default_gw
        else:
            return ipaddr

    @staticmethod
    def get_route_table():
        _rt = []
        rt_m = re.compile(
            '^[a-z0-9]*\W([0-9A-F]{8})\W([0-9A-F]{8})[\W0-9]*([0-9A-F]{8})')
        rt = open('/proc/net/route', 'r')
        for line in rt.read().split('\n'):
            if rt_m.match(line):
                _rt.append(rt_m.findall(line)[0])
        rt.close()
        return _rt

    @staticmethod
    def get_local_mac(ipaddr):
        if_addrs = psutil.net_if_addrs()
        for interface in if_addrs:
            find = False
            for snic in if_addrs[interface]:
                if snic.family == socket.AF_INET or \
                                snic.family == socket.AF_INET6:
                    if snic.address == ipaddr:
                        find = True
                        break
            if find:
                for snic in if_addrs[interface]:
                    if snic.family == socket.AF_PACKET:
                        return snic.address
        return None

    def recvHalNotification(self, notify):
        self.logger.info(
            "receive a hal notification type %d ", notify.msg.HalNotificationType)
        if notify.msg.HalNotificationType == HalConfigMsg.MsgTypeL2tpv3SessionStatusNotification:
            circuit_status = L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus()
            circuit_status.ParseFromString(notify.msg.HalNotificationPayLoad)
            if self.handler:
                try:
                    self.handler(circuit_status)
                except Exception as e:
                    self.logger.warn("L2TP hal client handle recvHalNotification exception %s", str(e))
                    self.stats.exception += 1

        if notify.msg.HalNotificationType == HalConfigMsg.MsgTypeRpdCapabilities:
            capability_rsp = t_RpdCapabilities()
            capability_rsp.ParseFromString(notify.msg.HalNotificationPayLoad)
            #self.handleCapRsp(capability_rsp)

        return True

    def get_message_type_from_remote_end_id(self, remote_end_id):
        try:
            channel_type_ret_list = []
            for item in remote_end_id:
                channel_type = item.RfChannelType

                if channel_type != L2tpHalClient.NONE_TYPE and channel_type not in channel_type_ret_list:
                    channel_type_ret_list.append(channel_type)
            return channel_type_ret_list
        except Exception as e:
            self.logger.warn("Exception happens, when get remote end id, reason:%s" % str(e))
            self.stats.exception += 1
            return None

    def send_l2tp_lcce_assignment_msg(self, lcce, msg_type):
        """
        :param lcce: lcce tunnel
        :param operation: ADD or DEL
        :return:
        """

        if not isinstance(lcce, L2tpv3Connection.L2tpConnection):
            self.stats.error += 1
            raise L2tpHalClientError(
                "lcce parameter should be a connection type")
        try:
            req_msg = L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq()
            # fill operation message type
            req_msg.msg_type = L2tpv3Connection.L2tpConnection.HalReqOperationMapping[
                msg_type]
            # fill lcce assignment
            req_msg.lcce_id = lcce.localConnID
            req_msg.lcce_info.remote_ip = lcce.remoteAddr
            req_msg.lcce_info.remote_mac = self.get_mac_bytes_from_ip(lcce.remoteAddr)
            req_msg.lcce_info.local_ip = lcce.localAddr
            req_msg.lcce_info.local_mac = self.get_mac_bytes_from_ip(lcce.localAddr)
            req_msg.lcce_info.mtu = lcce.pathMTU
            payload = req_msg.SerializeToString()
            self.sendCfgMsg(
                HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment, payload)
            self.logger.info(
                "send lcce assignment message to hal type:%d, length:%d",
                HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment, len(payload))
            return True
        except Exception as e:
            self.logger.error("Error happens, reason:%s" % str(e))
            self.stats.exception += 1
            raise L2tpHalClientError("cfg message send error")

    def fill_static_session_req_data(self, msg_type, req_data, staticL2tpMsg):
        local_ip = staticL2tpMsg.localAddress
        src_ip = staticL2tpMsg.sourceAddress
        self.logger.debug("Fill static session msg_type:%d, source_ip:%s remote_ip=%s",
                         msg_type, local_ip, src_ip)
        try:
            if msg_type == L2tpv3Session.L2tpv3Session.ADD_SESSION \
                    or msg_type == L2tpv3Session.L2tpv3Session.DEL_SESSION \
                    or msg_type == L2tpv3Session.L2tpv3Session.UPDATE_SESSION:
                for index, pseudoChannel in staticL2tpMsg.pwAssociation.items():
                    req_data.remote_end_id.add(RfPortIndex=pseudoChannel.rfPortIndex,
                                               RfChannelType=pseudoChannel.channelType,
                                               RfChannelIndex=pseudoChannel.channelIndex,
                                               mpts_tag=pseudoChannel.channelIndex)
                req_data.sublayer_type = staticL2tpMsg.depiL2SublayerSubtype
                req_data.pw_type = staticL2tpMsg.l2SublayerType
                req_data.remote_mtu = staticL2tpMsg.mtuSize
                # if a multi-cast

                if L2tpv3GcppConnection.L2tpv3GcppProvider.isMultiCast(
                        staticL2tpMsg.groupAddress):
                    self.logger.debug("Gcpp info: handler a multi-cast message")
                    req_data.mcast_info.add(
                        src_ip=local_ip, grp_ip=staticL2tpMsg.groupAddress)
                    address = (local_ip, src_ip, staticL2tpMsg.groupAddress, 0)
                    try:
                        mcast = Mcast.findMcastInstance(address=address)
                        if msg_type == L2tpv3Session.L2tpv3Session.ADD_SESSION \
                                or msg_type == L2tpv3Session.L2tpv3Session.UPDATE_SESSION:
                            if mcast is None:
                                mcast = Mcast(address=address)
                            mcast.join(session=(local_ip, staticL2tpMsg.sourceAddress,
                                                staticL2tpMsg.sessionId, staticL2tpMsg.sessionId))
                            if mcast.status != Mcast.JOINED:
                                self.logger.warn("Static Gcpp Session [%d, %d] mcast join failed %s:",
                                                 staticL2tpMsg.sessionId, staticL2tpMsg.sessionId, address)
                        else:
                            if mcast is not None:
                                mcast.leave(session=(local_ip, staticL2tpMsg.sourceAddress,
                                                     staticL2tpMsg.sessionId, staticL2tpMsg.sessionId))
                    except Exception as e:
                        self.logger.warn("Static Gcpp Session [%d, %d] mcast join failed %s: %s",
                                         staticL2tpMsg.sessionId, staticL2tpMsg.sessionId, address, str(e))
                req_data.lcce_id = 0
                req_data.local_mac = L2tpHalClient.get_mac_bytes_from_ip(local_ip)
                if staticL2tpMsg.direction == \
                        L2tpv3GcppConnection.StaticL2tpSession.DIRECTION_RETURN:
                    req_data.phb_info.add(phb_id=staticL2tpMsg.usPhbId, flow_id=0)
                    req_data.remote_mac = L2tpHalClient.get_mac_bytes_from_ip(
                                          staticL2tpMsg.destAddress)
                else:
                    req_data.remote_mac = binascii.unhexlify("000000000000")
                return True
        except Exception as e:
            raise L2tpHalClientError("error:" + str(e))

    def send_static_l2tp_session_req_msg(self, msg_type, staticL2tpMsg):
        """
        :param session: session
        :param operation: ADD or DEL
        :return:

        """
        try:
            req_msg = L2tpv3Hal_pb2.t_l2tpSessionReq()
            # fill operation message type
            req_msg.msg_type = L2tpv3Session.L2tpv3Session.HalReqOperationMapping[
                msg_type]
            req_msg.session_selector.local_session_id = staticL2tpMsg.sessionId
            req_msg.session_selector.remote_session_id = staticL2tpMsg.sessionId
            if staticL2tpMsg.direction == L2tpv3GcppConnection.StaticL2tpSession.DIRECTION_FORWARD:
                req_msg.session_selector.remote_ip = \
                    ["0.0.0.0", "::0"][Convert.is_valid_ipv6_address(staticL2tpMsg.groupAddress)]
            elif staticL2tpMsg.direction == L2tpv3GcppConnection.StaticL2tpSession.DIRECTION_RETURN:
                req_msg.session_selector.remote_ip = staticL2tpMsg.destAddress
            else:
                self.logger.debug(
                    "Gcpp session direction not match the fwd flag index:%d ", staticL2tpMsg.index)
                return
            # fill request data
            req_msg.session_selector.local_ip = staticL2tpMsg.localAddress
            req_data = req_msg.req_data
            self.fill_static_session_req_data(msg_type, req_data, staticL2tpMsg)
            for index, pseudoChannel in staticL2tpMsg.pwAssociation.items():
                channel_type = pseudoChannel.channelType
                if channel_type != L2tpHalClient.NONE_TYPE:
                    payload = req_msg.SerializeToString()
                    self.sendCfgMsg(
                        L2tpHalClient.channel_type_to_message_id[channel_type], payload)
                    self.logger.info(
                        "Send static session cfg message to hal type:%d, length:%d local_sesId=%d "
                        " remote_sesId=%d localAddress=%s remote_ip =%s",
                        L2tpHalClient.channel_type_to_message_id[channel_type], len(payload),
                        req_msg.session_selector.local_session_id,
                        req_msg.session_selector.remote_session_id,
                        staticL2tpMsg.localAddress,
                        req_msg.session_selector.remote_ip)
                    break
            return True
        except Exception as e:
            self.logger.error("Error happens static Gcpp, reason:%s" % str(e))
            self.stats.exception += 1
            raise L2tpHalClientError("cfg message static Gcpp send error")

    @staticmethod
    def fill_session_req_req_data(session, msg_type, req_data):
        try:
            if msg_type == L2tpv3Session.L2tpv3Session.ADD_SESSION \
                    or msg_type == L2tpv3Session.L2tpv3Session.UPDATE_SESSION \
                    or msg_type == L2tpv3Session.L2tpv3Session.DEL_SESSION:
                # set the target circuit_status in req message
                if msg_type == L2tpv3Session.L2tpv3Session.DEL_SESSION:
                    req_data.circuit_status = False
                else:
                    req_data.circuit_status = True
                for avp in session.avps_icrq:
                    if isinstance(avp, L2tpv3RFC3931AVPs.RemoteEndID):
                        for rf_selector, value, in avp.rpd_mapping:
                            RfPortIndex, RfChannelType, RfChannelIndex, = rf_selector
                            mpts_tag = value
                            req_data.remote_end_id.add(RfPortIndex=RfPortIndex,
                                                       RfChannelType=RfChannelType,
                                                       RfChannelIndex=RfChannelIndex,
                                                       mpts_tag=mpts_tag)
                    if isinstance(avp, L2tpv3CableLabsAvps.DepiL2SpecificSublayerSubtype):
                        req_data.sublayer_type = avp.pw_type
                    if isinstance(avp, L2tpv3RFC3931AVPs.L2SpecificSublayer):
                        req_data.pw_type = avp.l2Sublayer
                    if isinstance(avp, L2tpv3CableLabsAvps.LocalMTUCableLabs):
                        req_data.remote_mtu = avp.localMTU
                    if isinstance(avp, L2tpv3CableLabsAvps.DepiRemoteMulticastJoin):
                        req_data.mcast_info.add(
                            src_ip=avp.src_ip, grp_ip=avp.group_ip)
                    if isinstance(avp, L2tpv3CableLabsAvps.DepiResourceAllocReq):
                        for phb, flowid, in avp.allocas:
                            req_data.phb_info.add(phb_id=phb,
                                                  flow_id=flowid)
                    if isinstance(avp, L2tpv3CableLabsAvps.UpstreamFlow):
                        for phb, flowid, in avp.allocas:
                            req_data.phb_info.add(phb_id=phb,
                                                  flow_id=flowid)

                #import pdb; pdb.set_trace()
                req_data.lcce_id = session.connection.localConnID
                req_data.local_mac = L2tpHalClient.get_mac_bytes_from_ip(
                    session.connection.localAddr)
                req_data.remote_mac = L2tpHalClient.get_mac_bytes_from_ip(
                    session.connection.remoteAddr)
                l2tpv3VspAvps().sendnotify_VspAvps(session.avps_icrq)
                # TBD vlan information
                return True

        except Exception as e:
            raise L2tpHalClientError("error" + str(e))

    def send_l2tp_session_req_msg(self, session, msg_type):
        """
        :param session: session
        :param operation: ADD or DEL
        :return:

        """

        if not isinstance(session, L2tpv3Session.L2tpv3Session):
            self.stats.error += 1
            raise L2tpHalClientError(
                "session parameter should be a session type")
        try:
            req_msg = L2tpv3Hal_pb2.t_l2tpSessionReq()
            # fill operation message type
            req_msg.msg_type = L2tpv3Session.L2tpv3Session.HalReqOperationMapping[
                msg_type]
            # fill session_selector
            req_msg.session_selector.local_session_id = session.localSessionId
            req_msg.session_selector.remote_session_id = session.remoteSessionId
            req_msg.session_selector.lcce_id = session.connection.localConnID
            req_msg.session_selector.local_ip = session.connection.localAddr
            req_msg.session_selector.remote_ip = session.connection.remoteAddr
            # fill request data
            req_data = req_msg.req_data

            self.fill_session_req_req_data(session, msg_type, req_data)
            channel_type_list = self.get_message_type_from_remote_end_id(
                req_data.remote_end_id)
            if channel_type_list and len(channel_type_list):
                for channel_type in channel_type_list:
                    payload = req_msg.SerializeToString()
                    self.sendCfgMsg(
                        L2tpHalClient.channel_type_to_message_id[channel_type], payload)
                    self.logger.info(
                        "send session cfg message to hal type:%d, length:%d",
                        L2tpHalClient.channel_type_to_message_id[channel_type], len(payload))
                return True
        except Exception as e:
            self.logger.error("Error happens, reason:%s" % str(e))
            self.stats.exception += 1
            raise L2tpHalClientError("cfg message send error")

    def connectionSetup(self, disp=None):
        """Create the connection to the mgr and setup the poller.

        :return:

        """
        self.logger.debug("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr,
                                          HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)

        # create the poller
        if self.poller is None:
            self.poller = disp.get_poll()

        # register the mgr socket
        disp.fd_register(self.mgrConnection.socket,
                         zmq.POLLIN, self.l2tp_hal_cb)
        disp.fd_register(self.mgrConnection.monitor,
                         zmq.POLLIN, self.l2tp_hal_cb)

    def connectionDisconnectCb(self, msg):
        """The connection has been detected disconnected , register it again We
        have reconenct, we have to assure the regiter message is received by
        the HAL.

        :param msg:
        :return:

        """

        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return
        self.logger.debug("Detected disconnected, register again")
        # clean up the push and pull socket
        # self.poller.unregister(self.pullSock.socket)
        try:
            self.poller.unregister(self.mgrConnection.socket)
            self.poller.unregister(self.mgrConnection.monitor)
            self.mgrConnection.socket.disable_monitor()
            self.mgrConnection.monitor.close()
            self.mgrConnection.close()

            # re-register the message
            self.connectionSetup(disp=self.dispatcher)
            self.register(self.clientID)
        except Exception as e:
            self.logger.warn("Detected disconnected, exception happened, %s", str(e))
        # The zmq lower part will handle the reconnect

        self.disconnected = True

    def l2tp_hal_cb(self, sock, mask):
        if self.pushSock is not None and sock == self.pushSock.monitor:
            self.pushSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.pullSock is not None and sock == self.pullSock.monitor:
            self.pullSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.mgrConnection is not None and sock == self.mgrConnection.monitor:
            self.mgrConnection.monitorHandler(recv_monitor_message(sock))
            return

        while sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
            try:
                bin = sock.recv(flags=zmq.NOBLOCK)
                msg = HalMessage.DeSerialize(bin)
                # self.logger.debug("Got a zmq msg:%s" % msg.msg)
                if msg.type in self.HalMsgsHandler:
                    handler = self.HalMsgsHandler[msg.type]
                    handler(msg)
            except zmq.ZMQError as e:
                self.stats.zmq_error += 1
                self.logger.debug(
                    "Got an error when trying with non-block read:" + str(e))
                break
            except Exception as e:
                self.stats.exception += 1
                self.logger.warn("Exception happens when l2tp hal recv socket, reason:%s" % str(e))
                break

    def recvRegisterMsgCb(self, cfg):
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
        :return:

        """
        # self.logger.debug("Recv a Message from the Hal:" % str(cfg.msg))

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.error(
                "Cannot register to Hal, reason[%s]" % cfg.msg.Rsp.ErrorDescription)
            self.stats.error += 1
            return

        self.clientID = cfg.msg.ClientID

        # Setup the push and pull connection
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

        # get the index of the path
        index = self._getIndexFromPath()
        if index == -1:
            self.logger.error(
                "Cannot get index from the path [%s]" % self.pushPath)
            self.stats.error += 1
            return
        if self.index == -1:
            self.index = index
            self.pushSock = HalTransport(
                HalTransport.HalTransportClientAgentPull,
                HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPushMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            self.pullSock = HalTransport(
                HalTransport.HalTransportClientAgentPush,
                HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPullMode,
                disconnectHandlerCb=self.connectionDisconnectCb)
            # register to the poller
            self.dispatcher.fd_register(self.pullSock.socket,
                                        zmq.POLLIN, self.l2tp_hal_cb)
            self.dispatcher.fd_register(self.pushSock.monitor,
                                        zmq.POLLIN, self.l2tp_hal_cb)
            self.dispatcher.fd_register(self.pullSock.monitor,
                                        zmq.POLLIN, self.l2tp_hal_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        if self.interestedNotification is not None:
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def recvCfgMsgCb(self, cfg):
        """Receive a configuration message from the Hal, processing it.

        :param cfg:
        :return:

        """
        if cfg.msg.CfgMsgType == HalConfigMsg.MsgTypeVspAvpExchange:
            self.logger.info(
                "CfgMsgType: %d", HalConfigMsg.MsgTypeVspAvpExchange)
            cfgRsp = l2tpv3VspAvps().update_VspAvp(cfg)
            if None is not cfgRsp:
                cfgRspStatus = HalCommon_pb2.SUCCESS
                if (cfgRsp.rspCode != L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_SUCCESS):
                    cfgRspStatus = HalCommon_pb2.FAILED

                msg = HalMessage(
                    "HalConfigRsp", SrcClientID=cfg.msg.SrcClientID, SeqNum=cfg.msg.SeqNum,
                    Rsp={
                        "Status": cfgRspStatus,
                        "ErrorDescription": ""
                    },
                    CfgMsgType=cfg.msg.CfgMsgType,
                    CfgMsgPayload=cfgRsp.SerializeToString())

                self.pushSock.send(msg.Serialize())

        elif cfg.msg.CfgMsgType == HalConfigMsg.MsgTypeGcppToL2tp:
            flag = True
            config_data = cfg.msg.CfgMsgPayload
            config_data = t_RcpMessage()
            config_data.ParseFromString(cfg.msg.CfgMsgPayload)
            config = config_data.RpdDataMessage.RpdData
            self.logger.info("Recv configure request message, %s" % config)
            if not config.HasField("StaticPwConfig"):
                return
            op = config_data.RpdDataMessage.RpdDataOperation
            if op == t_RpdDataMessage.RPD_CFG_READ:
                self.logger.info("Read the configure message")
            else:
                staticPwCfg = config.StaticPwConfig
                flag, staticL2tpMsg = self.l2tpv3StaticSession.saveGcppSessionData(staticPwCfg)
                if flag:
                    if staticL2tpMsg.ccapCoreOwner is None:
                        msgType = L2tpv3Session.L2tpv3Session.DEL_SESSION
                        self.send_static_l2tp_session_req_msg(msgType, staticL2tpMsg)
                        self.l2tpv3StaticSession.removeStaticSession(staticL2tpMsg.sessionId,
                                                                     staticL2tpMsg.direction)
                    elif staticL2tpMsg.circuitStatus >> 15 & 0x1:
                        msgType = L2tpv3Session.L2tpv3Session.ADD_SESSION
                        self.send_static_l2tp_session_req_msg(msgType, staticL2tpMsg)
                    else:
                        msgType = L2tpv3Session.L2tpv3Session.DEL_SESSION
                        self.send_static_l2tp_session_req_msg(msgType, staticL2tpMsg)
            rsp = t_RcpMessage()
            rsp.ParseFromString(cfg.msg.CfgMsgPayload)
            rsp.RpdDataMessage.RpdData.CopyFrom(config)
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            payload = rsp.SerializeToString()
            if flag:
                status = HalCommon_pb2.SUCCESS
            else:
                status = HalCommon_pb2.FAILED
            msg = HalMessage(
                "HalConfigRsp", SrcClientID=cfg.msg.SrcClientID, SeqNum=cfg.msg.SeqNum,
                Rsp={
                    "Status": status,
                    "ErrorDescription": "GCPP to static L2tp"
                },
                CfgMsgType=cfg.msg.CfgMsgType,
                CfgMsgPayload=payload)
            self.pushSock.send(msg.Serialize())
        return True


    def recvCfgMsgRspCb(self, cfg):
        """Receive a configuration response message from the Hal, processing
        it.

        :param cfg:
        :return:

        """
        cfgMsg = cfg.msg
        self.logger.debug(
            "Recv a configuration response message:" + str(cfgMsg))

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            try:
                if cfgMsg.CfgMsgType == HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment:
                    lcceReq = L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq()
                    lcceReq.ParseFromString(cfg.msg.CfgMsgPayload)

                    self.notify.warn(rpd_event_def.RPD_EVENT_L2TP_WARN[0],
                                     "LCCE configured failed: "
                                     + L2tpv3Connection.L2tpConnection.HalReqOperationSet[lcceReq.msg_type] + " "
                                     + lcceReq.lcce_info.local_ip,
                                     rpd_event_def.RpdEventTag.ccap_ip(lcceReq.lcce_info.remote_ip))
                    self.stats.error += 1

                else:
                    sessionReq = L2tpv3Hal_pb2.t_l2tpSessionReq()
                    sessionReq.ParseFromString(cfg.msg.CfgMsgPayload)

                    self.notify.warn(rpd_event_def.RPD_EVENT_L2TP_WARN[0],
                                     "Session configured failed: "
                                     + L2tpv3Session.L2tpv3Session.HalReqOperationSet[sessionReq.msg_type] + " "
                                     + str(sessionReq.session_selector.local_session_id),
                                     rpd_event_def.RpdEventTag.ccap_ip(sessionReq.session_selector.remote_ip))
                    self.stats.error += 1
            except Exception as e:
                self.stats.exception += 1
                self.logger.warn("Error happens when handle session cfg rsp failed msg")
                self.logger.warn(traceback.format_exc())
            return False

        if cfgMsg.CfgMsgType == HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment:
            try:
                lcceRsp = L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp()
                lcceRsp.ParseFromString(cfgMsg.CfgMsgPayload)
                self.handler(lcceRsp)
                return True
            except Exception as e:
                self.logger.warn("Error happens when handle lcce cfg rsp")
                self.logger.warn(traceback.format_exc())
                self.stats.exception += 1
                raise L2tpHalClientError("cfg message lcce rsp send error")
        else:
            try:
                sessionRsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
                sessionRsp.ParseFromString(cfgMsg.CfgMsgPayload)
                local_ip = sessionRsp.session_selector.local_ip
                remote_ip = sessionRsp.session_selector.remote_ip
                local_session_id = sessionRsp.session_selector.local_session_id
                flag, staticL2tpMsg = self.l2tpv3StaticSession.getStaticSessionBySesId(
                    local_session_id, local_ip, remote_ip)
                if flag:
                    self.handlerStaticL2tpRspMsg(sessionRsp, staticL2tpMsg)
                    self.logger.debug("Handler the static L2tp message")
                else:
                    self.handler(sessionRsp)
                    self.logger.debug("Handler the L2tp message")
                return True
            except Exception as e:
                self.logger.warn("Error happens when handle session cfg rsp")
                self.logger.warn(traceback.format_exc())
                self.stats.exception += 1
                raise L2tpHalClientError("cfg message session rsp send error")

    def handlerStaticL2tpRspMsg(self, msg, staticL2tpMsg):
        if isinstance(msg, L2tpv3Hal_pb2.t_l2tpSessionRsp):
            staticL2tpMsg.status = \
                (staticL2tpMsg.circuitStatus >> 15 & 0x1) & msg.result
        if staticL2tpMsg.enableNotifications:
            staticPwStatus = t_StaticPwStatus()
            comStaticPwStatus = staticPwStatus.CommonStaticPwStatus
            comStaticPwStatus.Direction = staticL2tpMsg.direction
            comStaticPwStatus.Index = staticL2tpMsg.index
            comStaticPwStatus.RpdCircuitStatus = staticL2tpMsg.circuitStatus
            self.sendNotificationMsg(HalConfigMsg.MsgTypeStaticPwStatus,
                                     staticPwStatus.SerializeToString())
            self.logger.debug("Send staitc l2tp status notification")

if __name__ == "__main__":
    setup_logging('L2TP', filename="l2tp_hal.log")
    dispatcher = Dispatcher()
    hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                               "the HAL client of L2TP feature",
                               "1.0", tuple(L2tpHalClient.notification_list.keys()), dispatcher,
                               L2tpHalClient.supportmsg_list)
    hal_client.start()
    dispatcher.loop()
