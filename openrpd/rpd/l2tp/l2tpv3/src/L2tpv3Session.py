#
# Copyright (c) 2016 Cisco and/or its affiliates,
#                    MaxLinear, Inc. ("MaxLinear"), and
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
import L2tpv3ControlPacket
import L2tpv3Fsm
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import l2tpv3.src.L2tpv3CiscoAVPs as L2tpv3CiscoAVPs
import L2tpv3GlobalSettings
import L2tpv3Hal_pb2
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
from vendorAVPs.src.L2tpv3VspAvps import l2tpv3VspAvps
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.mcast.src.mcast import Mcast
from rpd.common.utils import SysTools
from rpd.common.utils import Convert
from rpd.common import rpd_event_def
from .L2tpv3SessionDb import L2tpSessionRecord
from rpd.common import utils
from rpd.common.rpdinfo_utils import RpdInfoUtils
import L2tpv3Hal
from rpd.rcp.rcp_lib.rcp_tlv_def import OP_STATUS_UP, OP_STATUS_DOWN


class L2tpv3Session(object):
    """This is the main session processing code.

    The class will recv the event from the connection and feed the event
    to FSM. Also this class is responsible for processing the state
    change.

    """
    __metaclass__ = AddLoggerToClass
    CIRCUIT_STATUS_UP = True
    CIRCUIT_STATUS_DOWN = False
    ADD_SESSION = 1
    DEL_SESSION = 2
    UPDATE_SESSION = 3
    READ_SESSION = 4
    HalReqOperationSet = {
        ADD_SESSION: "ADD_SESSION",
        DEL_SESSION: "DEL_SESSION",
        UPDATE_SESSION: "UPDATE_SESSION",
        READ_SESSION: "READ_SESSION",
    }
    HalReqOperationMapping = {
        ADD_SESSION: L2tpv3Hal_pb2.t_l2tpSessionReq.ADD_L2TPv3_SESSION,
        DEL_SESSION: L2tpv3Hal_pb2.t_l2tpSessionReq.DEL_L2TPv3_SESSION,
        UPDATE_SESSION: L2tpv3Hal_pb2.t_l2tpSessionReq.UPDATE_L2TPv3_SESSION,
        READ_SESSION: L2tpv3Hal_pb2.t_l2tpSessionReq.READ_L2TPv3_SESSION,
    }

    def __init__(self, localSession, remoteSession, fsmType, connection=None):
        """
        :param localSession: The local session ID.
        :param remoteSession: The remote session ID.
        :param fsmType: This is the a flag to indicate if the fsm type is a sender or recipient
        :param connection: This is the connection that the session belongs to.

        """
        self.logger.info(
            "Create a session with local session ID:%d, remote session ID:%d", localSession, remoteSession)
        self.localSessionId = localSession
        self.remoteSessionId = remoteSession
        self.connection = connection
        self.avps_icrq = list()
        self.avps_cdn = list()
        self.mcast = list()
        self.local_circuit_status = L2tpv3Session.CIRCUIT_STATUS_DOWN
        self.lastchangetime = time.time()
        self.session_l2Sublayer = 0

        # For RFC 4951 to silently close a session without sending an CDN
        self.silentlyCleared = False
        self.stale = False

        if fsmType == 'sender':
            callbacks = [
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventLocalRequest,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderLocalRequest,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventCloseRequest,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderCloseRequest,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventRecvBadICRP,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderRecvBadICRP,
                },

                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventRecvGoodICRP,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderRecvGoodICRP,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventRecvCDN,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderRecvCDN,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventRecvICCN,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderRecvICCN,
                },

                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventRecvICRQLoseTie,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderRecvICRQLoseTie,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionSenderFsm.EventRecvICRQWinTie,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventSenderRecvICRQWinTie,
                }
            ]
            # We only have one fsm, ether sender, ether recipient
            self.fsm = L2tpv3Fsm.L2tpv3SessionSenderFsm(callbacks)
        else:
            callbacks = [
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventCloseRequest,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientCloseRequest,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvBadICCN,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientRecvBadICCN,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvBadICRQ,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientRecvBadICRQ,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvCDN,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientRecvCDN,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvGoodICCN,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientRecvGoodICCN,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvGoodICRQ,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientRecvGoodICRQ,
                },
                {
                    "Type": "event",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvICRP,
                    "TrackPoint": "on",
                    "Handler": self.fsmEventRecipientRecvICRP,
                },
                {
                    "Type": "state",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateIdle,
                    "TrackPoint": "enter",
                    "Handler": self.fsmStateRecipientIdle,
                },
                {
                    "Type": "state",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateWaitConn,
                    "TrackPoint": "enter",
                    "Handler": self.fsmStateRecipientEnterWaitConn,
                },
                {
                    "Type": "state",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateEstablished,
                    "TrackPoint": "enter",
                    "Handler": self.fsmStateRecipientEnterStateEstablished,
                },
                {
                    "Type": "state",
                    "Name": L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateEstablished,
                    "TrackPoint": "leave",
                    "Handler": self.fsmStateRecipientLeaveStateEstablished,
                },

            ]
            # We only have one fsm, ether sender, ether recipient
            self.fsm = L2tpv3Fsm.L2tpv3SessionRecipientFsm(callbacks)

            # the place to save the session info
            self.info = dict()

    def CloseSession(self):
        """This function just trigger a fsm state change, when entering the
        state, the state callback code will handle the processing job.

        :return:

        """
        self.fsm.closeRequest()

    def ReceiveICCN(self, pkt):
        """Receive a ICCN packet from the connection. Will process the AVPs.

        :param pkt: THe decoded l2tp control packet.
        :return: a ICCN response packet or None

        """
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.connection.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.ICCNMandatoryAVPs, pkt.avps)
            if ret is not True:
                self.fsm.recvBadICCN()
                return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Avp cannot be handled correctly")

        self.logger.debug(
            "L2Tp session[%d, %d] receive a ICCN message", self.localSessionId, self.remoteSessionId)

        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                # We got a bad ICCN, we should send a CDN
                if not avp.handleAvp(pkt, None):
                    self.fsm.recvBadICCN()
                    return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Avp cannot be handled correctly")
        self.logger.debug(
            "Session[%d, %d] got a good ICCN, send it to fsm.", self.localSessionId, self.remoteSessionId)
        self.fsm.recvGoodICCN()
        # We need to send the ZLB.
        ackpkt = L2tpv3ControlPacket.L2tpv3ACK(connID=self.connection.remoteConnID)
        return ackpkt

    def LocalRequest(self):
        """Local request will trigger the session to send a ICRQ to remote,
        currently, this function is just for simulator usage.

        :return: None

        """
        self.logger.debug(
            "Got a local request to setup the session, will send a ICRQ to remote")

        if isinstance(self.fsm, L2tpv3Fsm.L2tpv3SessionRecipientFsm):
            self.logger.warn(
                "Recipient does not support the local request, do nothing.")
            return

        if self.fsm.current == L2tpv3Fsm.L2tpv3SessionSenderFsm.StateIdle:
            msgAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
                L2tpv3RFC3931AVPs.ControlMessageAVP.ICRQ)
            localSessionId = L2tpv3RFC3931AVPs.LocalSessionID(
                self.localSessionId)
            remoteSessionId = L2tpv3RFC3931AVPs.RemoteSessionID(
                self.remoteSessionId)
            remote_end_id = L2tpv3RFC3931AVPs.RemoteEndID(
                (((0, 3, 0), 0), ((0, 3, 1), 1)))
            DepiL2SpecificSublayerSubtype = L2tpv3CableLabsAvps.DepiL2SpecificSublayerSubtype(3)

            icrq = L2tpv3ControlPacket.L2tpv3ControlPacket(
                self.connection.remoteConnID,
                avps=(msgAvp, localSessionId, remoteSessionId, remote_end_id, DepiL2SpecificSublayerSubtype))
            self.connection.transport.SendPacket(icrq)

        self.fsm.localRequest()

    def ReceiveICRP(self, pkt):
        """Receive a ICRP from remote, if it is a good ICRP, will send a ICCN.
        this function will be used for simulator purpose.

        :param pkt: The ICRP control packet, has been decoded.
        :return:

        """
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.connection.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.ICRPMandatoryAVPs, pkt.avps)
            if ret is not True:
                if isinstance(self.fsm, L2tpv3Fsm.L2tpv3SessionSenderFsm):
                    self.fsm.recvBadICRP()
                return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Avp cannot be handled correctly")

        self.logger.debug(
            "Session [%d, %d] gets a l2tp ICRP message.", self.localSessionId, self.remoteSessionId)

        if isinstance(self.fsm, L2tpv3Fsm.L2tpv3SessionRecipientFsm):
            self.logger.debug(
                "Recipient session [%d, %d] gets a l2tp ICRP message.", self.localSessionId,
                self.remoteSessionId)
            self.fsm.recvICRP()
            # this event will trigger the recipient state
            # machine transferring to idle state.
            return

        # Find the local session ID
        for avp in pkt.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.LocalSessionID):
                self.remoteSessionId = avp.sessionID
                self.connection.addSession(self)

        # If the incoming l2TP ICRP does not contain a local session ID
        if not self.remoteSessionId:
            self.logger.warn(
                "Session[%d, %d] is terminated due to not find the local session ID in ICRP message.",
                self.localSessionId, self.remoteSessionId)
            self.fsm.recvBadICRP()
            return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 5, "")

        # send a ICCN
        msgAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICCN)
        iccn = L2tpv3ControlPacket.L2tpv3ControlPacket(
            self.connection.remoteConnID, avps=(msgAvp,))
        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                # We got a bad ICRP, we should send a CDN
                if not avp.handleAvp(pkt, iccn):
                    self.fsm.recvBadICRP()
                    return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Avp cannot be handled correctly")

        self.logger.debug(
            "Sender session [%d, %d] gets a good l2tp ICRP message.", self.localSessionId,
            self.remoteSessionId)
        self.fsm.recvGoodICRP()
        return iccn

    def ReceiveICRQ(self, pkt):
        """Receive a ICRQ from remote, if it is a good ICRQ, will send a ICRP.

        :param pkt: The ICRQ control packet, has been decoded.
        :return: ICRP packet or None

        """

        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.connection.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.ICRQMandatoryAVPs, pkt.avps)
            if ret is not True:
                self.fsm.recvBadICRQ()
                return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Avp cannot be handled correctly")

        self.logger.debug(
            "L2tp session[%d, %d] receives a ICRQ message.", self.localSessionId, self.remoteSessionId)

        avps = list()
        avps.append(L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP))
        avps.append(L2tpv3RFC3931AVPs.DataSequencing(
            L2tpv3RFC3931AVPs.DataSequencing.AllSeq))
        # TODO  add sbfd support for ipv6
        if Convert.is_valid_ipv4_address(self.connection.localAddr):
            avps.append(L2tpv3RFC3931AVPs.SbfdDiscriminator(
                int(socket.inet_aton(self.connection.localAddr).encode('hex'), 16)))
            avps.append(L2tpv3RFC3931AVPs.SbfdVccv(
                L2tpv3RFC3931AVPs.SbfdVccv.VccvValue))

        # Need add some Cable labs avp
        self.logger.debug(
            "Session [%d, %d]sends a ICRP packet to remote, connection:%d",
            self.localSessionId, self.remoteSessionId,
            pkt.Connection.remoteConnID)

        icrp = L2tpv3ControlPacket.L2tpv3ControlPacket(
            pkt.Connection.remoteConnID, 0, 0, avps)
        del self.avps_icrq[:]
        del self.mcast[:]
        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                if isinstance(avp, L2tpv3CableLabsAvps.DepiL2SpecificSublayerSubtype):
                    self.session_l2Sublayer = avp.pw_type
                self.avps_icrq.append(avp)
                # We got a bad ICRQ, we should send a CDN
                if not avp.handleAvp(pkt, icrp):
                    self.fsm.recvBadICRQ()
                    return L2tpv3ControlPacket.L2tpv3CDN(
                        self, 2, 4, "Avp cannot be handled correctly")
        self.logger.debug("We got a good ICRQ, send to fsm")
        self.fsm.recvGoodICRQ()
        return icrp

    def ReceiveCDN(self, pkt):
        """Receive a CDN packet, not check the AVP.

        :param pkt: The CDN control packet, has been decoded.
        :return: None

        """
        self.logger.debug(
            "L2Tp session[%d, %d] receive a CDN message", self.localSessionId, self.remoteSessionId)
        del self.avps_cdn[:]
        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                self.avps_cdn.append(avp)
        self.fsm.recvCDN()
        ackpkt = L2tpv3ControlPacket.L2tpv3ACK(connID=self.connection.remoteConnID)
        return ackpkt

    def ReceiveSLI(self, pkt):
        """Receive a SLI packet, handle the AVP.

        :param pkt:
        :return:

        """
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.connection.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.SLIMandatoryAVPs, pkt.avps)
            if ret is not True:
                return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Cannot handle AVP in SLI message")

        self.logger.debug(
            "L2Tp Session[%d, %d] receive a SLI message", self.localSessionId, self.remoteSessionId)
        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                if not avp.handleAvp(pkt, None):
                    return L2tpv3ControlPacket.L2tpv3CDN(self, 2, 4, "Cannot handle AVP in SLI message")

        return None

    def sendSLI(self):
        if self.fsm.current == L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateEstablished and\
                self.connection and self.connection.transport:
            msgAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
                L2tpv3RFC3931AVPs.ControlMessageAVP.SLI)
            localSessionId = L2tpv3RFC3931AVPs.LocalSessionID(
                self.localSessionId)
            remoteSessionId = L2tpv3RFC3931AVPs.RemoteSessionID(
                self.remoteSessionId)
            circuitstatus = L2tpv3RFC3931AVPs.CircuitStatus(
                active=self.local_circuit_status, new=False)
            sli = L2tpv3ControlPacket.L2tpv3ControlPacket(
                self.connection.remoteConnID,
                avps=(msgAvp, localSessionId, remoteSessionId, circuitstatus))
            self.connection.transport.SendPacket(sli)
            self.logger.info(
                "send SLI status change to remote: " + "local:" +
                str(self.localSessionId) + " remote:" +
                str(self.remoteSessionId) + " status:" + str(self.local_circuit_status))

    def ReceiveHalMsg(self, msg):
        status_change = False
        if isinstance(msg, L2tpv3Hal_pb2.t_l2tpSessionCircuitStatus):
            if msg.status != self.local_circuit_status:
                self.local_circuit_status = msg.status
                status_change = True
        if isinstance(msg, L2tpv3Hal_pb2.t_l2tpSessionRsp):
            if msg.result:
                if msg.req_data.circuit_status != self.local_circuit_status:
                    self.local_circuit_status = msg.req_data.circuit_status
                    status_change = True
        # notify an event
        if status_change:
            if self.local_circuit_status == L2tpv3Session.CIRCUIT_STATUS_UP:
                opStatus = OP_STATUS_UP
                self.notify.info(rpd_event_def.RPD_EVENT_L2TP_SESSION_UP[0],
                                 str(hex(self.localSessionId)), str(hex(self.connection.localConnID)),
                                 rpd_event_def.RpdEventTag.ccap_ip(self.connection.remoteAddr))
            else:
                opStatus = OP_STATUS_DOWN
                self.notify.error(rpd_event_def.RPD_EVENT_L2TP_SESSION_DOWN[0],
                                  str(hex(self.localSessionId)), str(hex(self.connection.localConnID)),
                                  rpd_event_def.RpdEventTag.ccap_ip(self.connection.remoteAddr))
            # nodify core
            self.sendSLI()
            self.updateSessionRecord_dpconfig(opStatus)

    def SendHalMsg(self, msg_type):
        hal_client = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client
        if hal_client:
            self.logger.info(
                "L2tp Session[%d, %d] send [%s] Hal message",
                self.localSessionId, self.remoteSessionId, self.HalReqOperationSet[msg_type])
            hal_client.send_l2tp_session_req_msg(session=self,
                                                 msg_type=msg_type)
        pass

    def fsmEventRecipientCloseRequest(self, event):
        pass

    def fsmEventRecipientRecvICRP(self, event):
        pass

    def fsmEventRecipientRecvBadICRQ(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmEventRecipientRecvCDN(self, event):
        pass

    def fsmEventRecipientRecvGoodICRQ(self, event):
        self.logger.info(
            "Session [%d, %d] received event:" + event.src + " " + event.dst + "  " + event.event,
            self.localSessionId, self.remoteSessionId)
        self.notify.info(rpd_event_def.RPD_EVENT_L2TP_INFO[0],
                         "Good ICRQ received, " + str(hex(self.localSessionId)) + " "
                         + str(hex(self.connection.localConnID)),
                         rpd_event_def.RpdEventTag.ccap_ip(self.connection.remoteAddr))

    def fsmEventRecipientRecvGoodICCN(self, event):
        self.logger.info(
            "Session [%d, %d] received event:" + event.src + " " + event.dst + "  " + event.event,
            self.localSessionId, self.remoteSessionId)
        self.notify.info(rpd_event_def.RPD_EVENT_L2TP_INFO[0],
                         "Good ICCN received, " + str(hex(self.localSessionId))
                         + " " + str(hex(self.connection.localConnID)),
                         rpd_event_def.RpdEventTag.ccap_ip(self.connection.remoteAddr))

    def fsmEventRecipientRecvBadICCN(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmEventSenderLocalRequest(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmEventSenderCloseRequest(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmEventSenderRecvGoodICRP(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmEventSenderRecvBadICRP(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmEventSenderRecvICRQLoseTie(self, event):
        pass

    def fsmEventSenderRecvICRQWinTie(self, event):
        pass

    def fsmEventSenderRecvICCN(self, event):
        pass

    def fsmEventSenderRecvCDN(self, event):
        pass

    def fsmStateRecipientEnterStateEstablished(self, event):
        self.lastchangetime = time.time()
        self.SendHalMsg(L2tpv3Session.ADD_SESSION)
        self.updateSessionRecord()
        # if multicast session ,send mcast join
        for avp in self.avps_icrq:
            if isinstance(avp, L2tpv3CableLabsAvps.DepiRemoteMulticastJoin):
                address = (self.connection.localAddr, avp.src_ip, avp.group_ip, 0)
                try:
                    mcast = Mcast.findMcastInstance(address=address)
                    if mcast is None:
                        mcast = Mcast(address=address)
                    mcast.join(session=(self.connection.localAddr, self.connection.remoteAddr,
                                        self.localSessionId, self.remoteSessionId))
                    self.mcast.append(address)
                    if mcast.status != Mcast.JOINED:
                        self.logger.warn("Session [%d, %d] mcast join failed %s:",
                                         self.localSessionId,
                                         self.remoteSessionId, address)
                except Exception as e:
                    self.logger.warn("Session [%d, %d] mcast join failed %s: %s",
                                     self.localSessionId, self.remoteSessionId, address, str(e))

    def fsmStateRecipientLeaveStateEstablished(self, event):
        self.SendHalMsg(L2tpv3Session.DEL_SESSION)
        # if multicast session ,send mcast leave

        for avp in self.avps_cdn:
            if isinstance(avp, L2tpv3CableLabsAvps.DepiRemoteMulticastLeave):
                address = (self.connection.localAddr, avp.src_ip, avp.group_ip, 0)
                if address in self.mcast:
                    self.mcast.remove(address)
                    try:
                        mcast = Mcast.findMcastInstance(address=address)
                        if mcast is not None:
                            mcast.leave(session=(self.connection.localAddr, self.connection.remoteAddr,
                                                 self.localSessionId, self.remoteSessionId))
                    except Exception as e:
                        self.logger.warn(
                            "Session [%d, %d] mcast join failed %s: %s",
                            self.localSessionId, self.remoteSessionId, address, str(e))
                else:
                    self.logger.warn("mcast address[%s] is not joined in session[0x%x]",
                                     address, self.localSessionId)

        while len(self.mcast):
            address = self.mcast.pop(0)
            self.logger.warn("mcast address[%s] is not in session[0x%x] cdn avps",
                             str(address), self.localSessionId)
            try:
                mcast = Mcast.findMcastInstance(address=address)
                if mcast is not None:
                    mcast.leave(session=(self.connection.localAddr, self.connection.remoteAddr,
                                         self.localSessionId, self.remoteSessionId))
            except Exception as e:
                self.logger.warn(
                    "Session [%d, %d] mcast join failed %s: %s",
                    self.localSessionId, self.remoteSessionId, address, str(e))

    def fsmStateRecipientEnterWaitConn(self, event):
        self.lastchangetime = time.time()
        pass

    def fsmStateRecipientIdle(self, event):
        """Callback function will called when fsm changed to this state.
        CDN is to be sent to remote and remove the session.

        :param event: The event that triggers the fsm to idle state.
        :return:

        """
        self.logger.debug("Session [%d, %d] state is transferred to idle, event:" + event.src + " " + event.dst +
                          "  " + event.event, self.localSessionId, self.remoteSessionId)
        self.lastchangetime = time.time()
        if event.event == "startup":
            # for startup, ignore it.
            return

        if event.event == L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventRecvCDN and self.connection is not None:
            self.logger.debug(
                "We reach to this state since we receive a CDN, don't need to send the CDN again")
            self.connection.transport.needSendZlb = True
            self.connection.removeSession(self)
            return

        # we should send the CDN to remote
        if event.event == L2tpv3Fsm.L2tpv3SessionRecipientFsm.EventCloseRequest:
            retcode = 3
            errorcode = 0
            msg = "Admin closes the session"

        else:  # fixme we should figure that
            retcode = 3
            errorcode = 0
            msg = "Admin closes the session"

        if self.connection is not None:
            self.logger.debug(
                "Send a CDN to remote since the session is terminated")
            if not self.silentlyCleared:
                transport = self.connection.transport
                cdn = L2tpv3ControlPacket.L2tpv3CDN(self, retcode, errorcode, msg)
                transport.SendPacket(cdn, None)
            # Clean up the session
            self.connection.removeSession(self)

    def updateSessionRecord(self):
        sessionRecord = L2tpSessionRecord()
        rfchanList = self.getRfchanInfo(self.avps_icrq)
        direction = sessionRecord.parseDirection(rfchanList)
        sessionRecord.updateL2tpSessionKey(self.connection.remoteAddr,
                                           self.connection.localAddr,
                                           direction,
                                           self.localSessionId)

        thecoreId = sessionRecord.getCoreId(self.connection.remoteAddr)
        description = sessionRecord.getDescription(rfchanList)
        pwtype = self.getPwType(self.avps_icrq)
        sessType = sessionRecord.parseSessionType(pwtype)
        sessSubType = sessionRecord.parseSessionSubType(
            self.session_l2Sublayer)
        coreMTU = self.getCoreIfMTU(self.avps_icrq)
        rpdMTU = L2tpv3Hal.L2tpHalClient.getRpdIfMTU()
        maxPayload = coreMTU
        if (rpdMTU < coreMTU):
            maxPayload = rpdMTU
        opStatus = OP_STATUS_UP
        lastchangetime = RpdInfoUtils.getSysUpTime()
        creationtime = lastchangetime
        counterDiscTime = utils.Convert.pack_timestamp_to_string(time.time())

        sessionRecord.updateL2tpSessionRecordData(
            coreId=thecoreId,
            connCtrlId=self.connection.localConnID,
            udpPort=0,
            descr=description,
            sessionType=sessType,
            sessionSubType=sessSubType,
            maxPayload=maxPayload,
            pathPayload=0,
            rpdIfMtu=rpdMTU,
            coreIfMtu=coreMTU,
            errorCode=1,
            creationTime=creationtime,
            operStatus=opStatus,
            localStatus=0,
            lastChange=lastchangetime,
            counterDiscontinuityTime=counterDiscTime)
        sessionRecord.write()

    def updateSessionRecord_dpconfig(self, op_status):
        sessionRecord = L2tpSessionRecord()
        rfchanList = self.getRfchanInfo(self.avps_icrq)
        direction = sessionRecord.parseDirection(rfchanList)
        sessionRecord.updateL2tpSessionKey(self.connection.remoteAddr,
                                           self.connection.localAddr,
                                           direction,
                                           self.localSessionId)
        sessionRecord.read()
        opStatus = op_status
        sessionRecord.updateL2tpSessionRecordData_dpconfig(operStatus=opStatus)
        sessionRecord.write()

    def deleteSessionRecord(self):
        sessionRecord = L2tpSessionRecord()
        rfchanList = self.getRfchanInfo(self.avps_icrq)
        direction = sessionRecord.parseDirection(rfchanList)
        sessionRecord.updateL2tpSessionKey(self.connection.remoteAddr,
                                           self.connection.localAddr,
                                           direction,
                                           self.localSessionId)
        sessionRecord.delete()

    def getRfchanInfo(self, avps):
        rfChanList = set()
        for avp in avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.RemoteEndID):
                for rf_selector, value, in avp.rpd_mapping:
                    RfPortIndex, RfChanType, RfChanIndex = rf_selector
                    rfChanList.add((RfPortIndex, RfChanType, RfChanIndex))
        return rfChanList

    def getPwType(self, avps):
        pwtype = 0
        for avp in avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.PseudowireType):
                pwtype = avp.pwType
                break
        return pwtype

    def getCoreIfMTU(self, avps):
        coreMTU = 0
        for avp in avps:
            if isinstance(avp, L2tpv3CableLabsAvps.LocalMTUCableLabs):
                coreMTU = avp.localMTU
                break
        return coreMTU
