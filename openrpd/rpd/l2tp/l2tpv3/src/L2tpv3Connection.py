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
from random import randint
import time
import L2tpv3ControlPacket
import L2tpv3Fsm
import L2tpv3GlobalSettings
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import L2tpv3Session
import L2tpv3Transport
import L2tpv3Hal_pb2
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common import rpd_event_def
from l2tpv3.src.L2tpv3RFC3931AVPs import ReceiveWinSize


class L2tpConnection(object):
    CREATED = 1
    CLOSED = 2
    ADD_LCCE = 1
    DEL_LCCE = 2
    UPDATE_LCCE = 3
    READ_LCCE = 4
    HalReqOperationSet = {
        ADD_LCCE: "ADD_LCCE",
        DEL_LCCE: "DEL_LCCE",
        UPDATE_LCCE: "UPDATE_LCCE",
        READ_LCCE: "READ_LCCE",
    }
    HalReqOperationMapping = {
        ADD_LCCE: L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq.ADD_L2TPv3_LCCE,
        DEL_LCCE: L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq.DEL_L2TPv3_LCCE,
        UPDATE_LCCE: L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq.UPDATE_L2TPv3_LCCE,
        READ_LCCE: L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq.READ_L2TPv3_LCCE,
    }
    CHANNEL_INDEX_BIT = 0
    PORT_INDEX_BIT = 8
    CHANNEL_TYPE_BIT = 16
    SUBLAYER_BIT = 20
    MULTIPLE_CHANNEL_BIT = 28
    CHANNEL_INDEX_MASK = 0x000000FF
    PORT_INDEX_MASK = 0x0000FF00
    CHANNEL_TYPE_MASK = 0x000F0000
    SUBLAYER_MASK = 0x01F00000
    MULTIPLE_CHANNEL_MASK = 0x10000000

    """
    L2TP Tunnel handling class. This class will receive the packet, create the session,  dispatch the packet to current
    connection or some sessions.
    """
    ConnectionDb = dict()
    __metaclass__ = AddLoggerToClass
    SCCRQMandatoryAVPs = (
        L2tpv3RFC3931AVPs.ControlMessageAVP,
        L2tpv3RFC3931AVPs.Hostname,
        L2tpv3RFC3931AVPs.RouterID,
        L2tpv3RFC3931AVPs.AssignedControlConnectionID,
        L2tpv3RFC3931AVPs.PseudowireCapList,
    )

    def __init__(self, localConnectionID, remoteConnectionID, remoteAddr,
                 localAddr=L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress):
        if localConnectionID != 0:
            self.logger.info(
                "Create a connection with ID:%d", localConnectionID)
        else:
            self.logger.info('Got a connection setup with None local connection ID, we will find it in the remote '
                             'connection ID, or generate random one.')
            while True:
                localConnectionId = randint(1, 0xFFFFFFFF)
                localConnectionID = localConnectionId

                # Check if the connection ID is used?
                if (remoteAddr, localAddr, localConnectionID) not in self.ConnectionDb.keys():
                    self.logger.debug(
                        "Found a unique connection ID.")
                    break

        # RFC4951
        self.failoverCapofCC = False
        self.failoverCapofDC = False
        self.recoveryTime = 0
        self.isRecoveryTunnel = False
        self.isInRecovery = False
        self.recoverConnection = None
        self.silentlyCleared = False

        self.remoteAddr = remoteAddr
        self.localAddr = localAddr
        self.localConnID = localConnectionID    # This is also being used as the lcce_id
        self.remoteConnID = remoteConnectionID
        # TODO - fill in pathMTU based on path discovery
        # RPHY spec section 10.3.4 says 2000, setting above
        # that to allow for various headers.  Section A.2
        # mentions 2362
        self.pathMTU = 2500

        # Save this connection into global connection DB
        self.ConnectionDb[(remoteAddr, localAddr, localConnectionID)] = self

        # Create the transport
        dispatcher = L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher
        self.transport = L2tpv3Transport.L2tpv3Transport(
            self, localAddr=localAddr, remoteAddr=remoteAddr)
        self.transport.SetDispatcher(dispatcher)
        self.transport.RegisterTransport()

        # session related info
        self.sessions = dict()
        self.sessionsByRemoteSessionId = dict()
        # it is the identification to check the connection is closed or not
        self.connection_status = L2tpConnection.CREATED

        # FSM callbacks
        callbacks = [
            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventLocalRequest,
                "TrackPoint": "on",
                "Handler": self.fsmEventLocalRequest,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvGoodSCCRQ,
                "TrackPoint": "on",
                "Handler": self.fsmEventRecvGoodSCCRQ,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvBadSCCRQ,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvBadSCCRQ,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvGoodSCCRP,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvGoodSCCRP,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvSCCRQLoseTieGood,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvSCCRQLoseTieGood,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvSCCRQLoseTieBad,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvSCCRQLoseTieBad,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvSCCRQWinSCCRQ,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvSCCRQWinSCCRQ,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvStopCCN,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvStopCCN,
            },

            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvGoodSCCCN,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvGoodSCCCN,
            },
            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvBadSCCCN,
                "TrackPoint": "on",
                "Handler": self.fsmEventrecvBadSCCCN,
            },
            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventCloseRequest,
                "TrackPoint": "on",
                "Handler": self.fsmEventcloseRequest,
            },
            {
                "Type": "event",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.EventRecvHALError,
                "TrackPoint": "on",
                "Handler": self.fsmEventHalError,
            },
            {
                "Type": "state",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.StateWaitCtlConn,
                "TrackPoint": "enter",
                "Handler": self.fsmStateWaitCtlConn,
            },
            {
                "Type": "state",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.StateIdle,
                "TrackPoint": "enter",
                "Handler": self.fsmStateIdle,
            },
            {
                "Type": "state",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished,
                "TrackPoint": "enter",
                "Handler": self.fsmStateEnterStateEstablished,
            },
            {
                "Type": "state",
                "Name": L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished,
                "TrackPoint": "leave",
                "Handler": self.fsmStateLeaveStateEstablished,
            },
        ]

        # the handlers for control message.
        self.ctlMsgHandler = {
            L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRQ: self.recvSCCRQ,
            L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRP: self.recvSCCRP,
            L2tpv3RFC3931AVPs.ControlMessageAVP.SCCCN: self.recvSCCCN,
            L2tpv3RFC3931AVPs.ControlMessageAVP.StopCCN: self.recvStopCCN,
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICRQ: self.recvICRQ,
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP: self.recvICRP,
            L2tpv3RFC3931AVPs.ControlMessageAVP.ICCN: self.recvICCN,
            L2tpv3RFC3931AVPs.ControlMessageAVP.CDN: self.recvCDN,
            L2tpv3RFC3931AVPs.ControlMessageAVP.HELLO: self.recvHELLO,
            L2tpv3RFC3931AVPs.ControlMessageAVP.SLI: self.recvSLI,
            L2tpv3RFC3931AVPs.ControlMessageAVP.FSQ: self.recvFSQ,
            L2tpv3RFC3931AVPs.ControlMessageAVP.FSR: self.recvFSR,

        }

        self.fsm = L2tpv3Fsm.L2tpv3ConnectionFsm(callbacks)

        # The region to same the connection information
        self.info = dict()

    def CloseConnection(self):
        """Clean up the resource, including the following parts:

        * sessions
        * transport
        * fsm

        :return: none

        """
        if self.connection_status == L2tpConnection.CREATED:
            keys = self.sessions.keys()
            for sessionId in keys:
                session = self.sessions[sessionId]
                if hasattr(session.fsm.fsm, 'transition'):
                    delattr(session.fsm.fsm, 'transition')
                    self.logger.debug("The session %d fsm is undergoing!!", sessionId)
                session.CloseSession()
                self.removeSession(session)
            # Send a StopCCN
            self.transport.SendPacket(
                L2tpv3ControlPacket.L2tpv3StopCCN(self, 1, 0, "Close the connection"), None)

            # process the transport
            self.transport.CloseTransport()

            # remove it from the global connection DB
            self.ConnectionDb.pop((self.remoteAddr, self.localAddr, self.localConnID))
            self.connection_status = L2tpConnection.CLOSED

    def StopConnection(self):
        """Clean up the resource, including the following parts without
        notify driver:

        * sessions
        * transport
        * fsm

        :return: none

        """
        if self.connection_status == L2tpConnection.CREATED:
            if hasattr(self.fsm.fsm, 'transition'):
                delattr(self.fsm.fsm, 'transition')
                self.logger.debug("The connection %d fsm is undergoing!!", self.localConnID)
            self.fsm.closeRequest()
            keys = self.sessions.keys()
            for sessionId in keys:
                session = self.sessions[sessionId]
                self.removeSession(session)

            if not self.silentlyCleared:
                # Send a StopCCN
                self.transport.SendPacket(
                    L2tpv3ControlPacket.L2tpv3StopCCN(self, 1, 0, "Close the connection"), None)

            # process the transport
            self.transport.CloseTransport()

            # remove it from the global connection DB
            self.ConnectionDb.pop(
                (self.remoteAddr, self.localAddr, self.localConnID))
            self.connection_status = L2tpConnection.CLOSED

    def checkMustAvps(self, mandatoryavpsset, avps):
        s1 = set(mandatoryavpsset)
        s2 = set([avp.__class__ for avp in avps])
        ret = s1.issubset(s2)
        return ret

    def ReceiveControlPackets(self, pkt, addr):
        """The function is called by the dispatcher re-inject.

        :param pkt: decoded l2tp control pkt.
        :param addr: remote addr.
        :return: None

        """
        self.logger.debug(
            "Connection:[%d., %d] receive a packet for dispatcher." % (self.localConnID, self.remoteConnID))
        self.transport.ReceivePacket(pkt, addr)

    def HandlePkt(self, pkt):
        """Handle the incoming control packet.

        :param pkt: decoded l2tp control pkt.
        :return: None or control packet.

        """
        self.logger.debug("Connection[%d,%d] is handling the packet" %
                          (self.localConnID, self.remoteConnID))
        pkt.SetPktConnection(self)
        if len(pkt.avps) >= 1:
            if not isinstance(pkt.avps[0], L2tpv3RFC3931AVPs.ControlMessageAVP):
                self.logger.warn(
                    "Cannot handle the msg without ControlMsg AVP.")
                # self.fsm.closeRequest()
                return None

            controlAvp = pkt.avps[0]
            if controlAvp.messageType in self.ctlMsgHandler:
                handler = self.ctlMsgHandler[controlAvp.messageType]
                pkt = handler(pkt)
            else:
                # TBD: for the message that the system can not handle,
                # currently we will ignore it.
                self.logger.warn(
                    "Cannot handle packet, msg type:%d, pkt:%s", controlAvp.messageType, str(pkt))
                return None
            return pkt
        else:
            return None

    def allocate_local_session_id(self, pkt):
        for avp in pkt.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.RemoteSessionID):
                if avp.sessionID:
                    self.logger.debug("remotesessionID is assigned:%x", avp.sessionID)
                    return avp.sessionID
                else:
                    break

        flag = found = sublayer_type = 0
        RfPortIndex = RfChannelType = RfChannelIndex = 0
        for avp in pkt.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.RemoteEndID):
                if len(avp.rpd_mapping) > 1:
                    flag = 1     # multi-channel mode
                for rf_selector, value, in avp.rpd_mapping:
                    RfPortIndex, RfChannelType, RfChannelIndex, = rf_selector
                    found = 1
                    break        # Use the first channel info
                if sublayer_type:
                    break
            if isinstance(avp, L2tpv3CableLabsAvps.DepiL2SpecificSublayerSubtype):
                sublayer_type = avp.pw_type
                if found:
                    break
        """
            Flag means there are multiple channels in configuration.
            RFChannelType range in (0, 11) defined in r-depi table 9.
            sublayer_type range in (1, 22) defined in r-depi table 24.
        """
        sessionid = ((flag << L2tpConnection.MULTIPLE_CHANNEL_BIT) & L2tpConnection.MULTIPLE_CHANNEL_MASK) \
            + ((sublayer_type << L2tpConnection.SUBLAYER_BIT) & L2tpConnection.SUBLAYER_MASK) \
            + ((RfChannelType << L2tpConnection.CHANNEL_TYPE_BIT) & L2tpConnection.CHANNEL_TYPE_MASK) \
            + ((RfPortIndex << L2tpConnection.PORT_INDEX_BIT) & L2tpConnection.PORT_INDEX_MASK) \
            + ((RfChannelIndex << L2tpConnection.CHANNEL_INDEX_BIT) & L2tpConnection.CHANNEL_INDEX_MASK)

        self.logger.debug("Allocate sessionid:%x for RemoteEndID(%x,%x,%x)",
                          sessionid, RfPortIndex, sublayer_type, RfChannelIndex)

        return sessionid

    def recvICRQ(self, pkt):
        """Receve a ICRQ packet.

        :param pkt:
        :return:

        """
        self.logger.debug(
            "Receive a ICRQ packet, we need to find it's session and send the packet to the session.")

        # Find the remote Session
        remoteSessid = None
        for avp in pkt.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.LocalSessionID):
                remoteSessid = avp.sessionID

        if remoteSessid is None:
            self.logger.warn("Got a ICRQ packet but no local session ID is set, we cannot send "
                             "ICCN since we don't know the session ID")
            return None

        # Try to find the session, this is the case sender or some error packet
        # happens
        session = self.findSessionByRemoteSessionID(remoteSessid)

        if session is not None:
            pkt.SetPktSession(session)
            return session.ReceiveICRQ(pkt)

        localSessionId = self.allocate_local_session_id(pkt)
        if (localSessionId is None):
            self.logger.warn("Got a ICRQ packet but no correct RemoteEndID is set")
            return None

        session = L2tpv3Session.L2tpv3Session(
            localSessionId, remoteSessid, 'receive', self)
        self.addSession(session)
        pkt.SetPktSession(session)
        return session.ReceiveICRQ(pkt)

    def _findSession(self, pkt):
        # Find the remote Session
        remoteSessid = 0
        localSessId = 0
        for avp in pkt.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.LocalSessionID):
                remoteSessid = avp.sessionID
            elif isinstance(avp, L2tpv3RFC3931AVPs.RemoteSessionID):
                localSessId = avp.sessionID

        if not remoteSessid and not localSessId:
            self.logger.warn("Got a packet but no local/remote session ID is set, we cannot send "
                             "rsp since we don't know the session ID")
            return None

        # Try to find the session, this is the case sender or some error packet
        # happens
        session1 = self.findSessionByRemoteSessionID(remoteSessid)
        session2 = self.findSessionByLocalSessionID(localSessId)
        if session1 is None and session2 is None:
            # generate a fake session for it, for send the CDN
            session = L2tpv3Session.L2tpv3Session(
                randint(1, 0xFFFFFFFF), remoteSessid, 'receive', self)
            cdn = L2tpv3ControlPacket.L2tpv3CDN(
                session, 2, 5, "Cannot find the session in local runtime DB")
            self.transport.SendPacket(cdn)
            return None

        return session1 if session1 else session2

    def recvICCN(self, pkt):
        """Receive a ICCN packet.

        :param pkt: Decoded control packet.
        :return: None.

        """
        self.logger.debug("Receive a ICCN message")
        session = self._findSession(pkt)
        if session is not None:
            pkt.SetPktSession(session)
            return session.ReceiveICCN(pkt)

    def recvCDN(self, pkt):
        """Receive a CDN packet.

        :param pkt: Decoded control packet.
        :return: None.

        """
        self.logger.debug("Receive a CDN message")
        session = self._findSession(pkt)
        if session is not None:
            pkt.SetPktSession(session)
            return session.ReceiveCDN(pkt)

    def recvICRP(self, pkt):
        """Receive a ICRP packet.

        :param pkt: Decoded control packet.
        :return: None.

        """
        self.logger.debug("Receive a ICRP message")
        session = self._findSession(pkt)
        if session is not None:
            pkt.SetPktSession(session)
            return session.ReceiveICRP(pkt)

    def recvHELLO(self, pkt):
        """Receive a HELLO packet.

        :param pkt: Decoded control packet.
        :return: None.

        """
        self.logger.debug(
            "Receive a Hello message from remote, send a ZLB to it")
        return L2tpv3ControlPacket.L2tpv3ZLB(self.remoteConnID)

    def recvSLI(self, pkt):
        """Receive a SLI packet.

        :param pkt: Decoded control packet.
        :return: None.

        """
        self.logger.debug("Receive a SLI message from remote")
        session = self._findSession(pkt)
        if session is not None:
            pkt.SetPktSession(session)
            return session.ReceiveSLI(pkt)

    def addSession(self, session):
        if not isinstance(session, L2tpv3Session.L2tpv3Session):
            self.logger.warn("session is not l2tpv3session instance, session:%s", str(session))
            return

        self.logger.debug(
            "Add a session[%d, %d] to connection dict." % (session.localSessionId, session.remoteSessionId))

        self.sessions[session.localSessionId] = session
        self.sessionsByRemoteSessionId[session.remoteSessionId] = session

    def removeSession(self, session):
        session.deleteSessionRecord()   # remove l2tpsessinfo db record
        if session.localSessionId in self.sessions:
            self.sessions.pop(session.localSessionId)

        if session.remoteSessionId in self.sessionsByRemoteSessionId:
            self.sessionsByRemoteSessionId.pop(session.remoteSessionId)

    def closeUnEstSessions(self):
        keys = self.sessions.keys()
        for sessionId in keys:
            session = self.sessions[sessionId]
            if session.fsm.current != L2tpv3Fsm.L2tpv3SessionRecipientFsm.StateEstablished:
                session.silentlyCleared = True
                session.CloseSession()

    def findSessionByRemoteSessionID(self, remoteSession):
        if remoteSession in self.sessionsByRemoteSessionId:
            return self.sessionsByRemoteSessionId[remoteSession]
        return None

    def findSessionByLocalSessionID(self, sessionID):
        if sessionID in self.sessions:
            return self.sessions[sessionID]
        return None

    def localRequest(self, addr):
        # send a SCCRQ to remote

        msgAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRQ)
        assignedAvp = L2tpv3RFC3931AVPs.AssignedControlConnectionID(
            self.localConnID)
        sccrq = L2tpv3ControlPacket.L2tpv3ControlPacket(
            0, avps=(msgAvp, assignedAvp))
        self.transport.SendPacket(sccrq, (addr, 0))

        self.fsm.localRequest()

    def recvSCCRQ(self, pkt):
        """Receive SCCRQ."""
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.SCCRQMandatoryAVPs, pkt.avps)
            if ret is not True:
                self.fsm.recvBadSCCRQ()
                return L2tpv3ControlPacket.L2tpv3StopCCN(self, 2, 4, "Avp cannot handled correctly")
        sccrpAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRP)
        recvWinSize = ReceiveWinSize(L2tpv3GlobalSettings.L2tpv3GlobalSettings.ReceiveWindowSize)

        sccrp = L2tpv3ControlPacket.L2tpv3ControlPacket(
            self.remoteConnID, 0, 0, (sccrpAvp, recvWinSize))

        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                # We got a bad SCCRQ, we should send a CDN
                if not avp.handleAvp(pkt, sccrp):
                    self.fsm.recvBadSCCRQ()
                    return L2tpv3ControlPacket.L2tpv3StopCCN(self, 2, 4, "Avp cannot handled correctly")
        self.fsm.recvGoodSCCRQ()
        return sccrp

    def recvSCCRP(self, pkt):
        """On openRPD, we will behave as an recipient, so we will not receive
        SCCRP in normal case.

        :param pkt:
        :return:

        """
        self.logger.debug("Receive a SCCRP packet")

        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.SCCRPMandatoryAVPs, pkt.avps)
            if ret is not True:
                self.fsm.recvBadSCCRP()
                return L2tpv3ControlPacket.L2tpv3StopCCN(self, 2, 4, "Avp cannot handled correctly")
        # Get the localAssignedID from the SCCRP
        remoteConnID = 0
        for avp in pkt.avps:
            if isinstance(avp, L2tpv3RFC3931AVPs.AssignedControlConnectionID):
                remoteConnID = avp.connectionID

        self.remoteConnID = remoteConnID
        scccnAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.SCCCN)
        scccn = L2tpv3ControlPacket.L2tpv3ControlPacket(
            self.remoteConnID, 0, 0, (scccnAvp,))

        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                # We got a bad ICRQ, we should send a CDN
                if not avp.handleAvp(pkt, scccn):
                    self.fsm.recvBadSCCRP()
                    return L2tpv3ControlPacket.L2tpv3StopCCN(self, 2, 4, "Avp cannot handled correctly")

        self.fsm.recvGoodSCCRP()
        return scccn

    def recvSCCCN(self, pkt):
        """Receive a SCCCN pkt, we should process the avp and check the result.

        :param pkt:
        :return:

        """
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.SCCCNMandatoryAVPs, pkt.avps)
            if ret is not True:
                self.fsm.recvBadSCCCN()
                return
        self.transport.needSendZlb = True
        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                self.logger.debug(avp)
                # We got a bad SCCCN, we should send a CDN
                if not avp.handleAvp(pkt, None):
                    self.fsm.recvBadSCCCN()
                    return
        self.fsm.recvGoodSCCCN()

        if pkt.Connection.isRecoveryTunnel:
            recoverConn = pkt.Connection.recoverConnection

            if recoverConn is not None:
                recoverConn.resetTransport()
                recoverConn.isInRecovery = False
            # tear down the recovery tunnel
            pkt.Connection.StopConnection()

            if recoverConn is not None:
                # silently clear sessions not in an established state
                recoverConn.closeUnEstSessions()
                # Query the sessions that might have been in inconsistent states
                # based on data channel inactivity
                recoverConn.queryInactSessions()
        ackpkt = L2tpv3ControlPacket.L2tpv3ACK(connID=self.remoteConnID)
        return ackpkt

    def resetTransport(self):
        if self.transport is not None:
            # flush the transmit/receive windows
            self.transport.sendList = list()
            self.transport.receiveWindow.clear()
            # reset control channel sequence numbers
            self.transport.ackNr = 0
            self.transport.ns = 0

    def recvStopCCN(self, pkt):
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.StopCCNMandatoryAVPs, pkt.avps)
            if ret is not True:
                return

        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                avp.handleAvp(pkt, None)
        self.fsm.recvStopCCN()
        ackpkt = L2tpv3ControlPacket.L2tpv3ACK(connID=self.remoteConnID)
        return ackpkt

    def recvFSQ(self, pkt):
        """Receive a FSQ packet.

        :param pkt: Decoded control packet.
        :return: FSR.

        """
        self.logger.debug("Receive a FSQ message from remote")
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.MustAvpsCheck is True:
            ret = self.checkMustAvps(
                L2tpv3ControlPacket.L2tpv3ControlPacket.FSQMandatoryAVPs, pkt.avps)
            if ret is not True:
                return

        fsrAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
            L2tpv3RFC3931AVPs.ControlMessageAVP.FSR)
        fsr = L2tpv3ControlPacket.L2tpv3ControlPacket(
            self.remoteConnID, 0, 0, (fsrAvp,))

        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                avp.handleAvp(pkt, fsr)

        return fsr

    def recvFSR(self, pkt):
        """Receive a FSP packet.

        :param pkt: Decoded control packet.
        :return: None.

        """
        self.logger.debug("Receive a FSR message from remote")
        self.transport.needSendZlb = True
        if len(pkt.avps) > 1:
            for i in xrange(1, len(pkt.avps)):
                avp = pkt.avps[i]
                avp.handleAvp(pkt, None)
        return

    def ReceiveHalMsg(self, msg):
        if isinstance(msg, L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp):
            if msg.result is False:
                self.fsm.recvHalError()

    def SendHalMsg(self, msg_type):
        hal_client = L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client
        if hal_client:
            self.logger.info(
                "L2Tp LCCE[%d, %d] send [%s] Hal message",
                self.localConnID, self.remoteConnID, self.HalReqOperationSet[msg_type])
            if(msg_type in (L2tpConnection.ADD_LCCE, L2tpConnection.DEL_LCCE,
                            L2tpConnection.UPDATE_LCCE, L2tpConnection.READ_LCCE)):
                hal_client.send_l2tp_lcce_assignment_msg(lcce=self,
                                                         msg_type=msg_type)

    def fsmEventLocalRequest(self, event):
        # "onlocalRequest: receive the event:" + e.src + " " + e.dst + "  " + e.event
        pass

    def fsmEventRecvGoodSCCRQ(self, event):
        # We have two case here and will take two different actions
        self.logger.info(
            "Connection[%d, %d] received event:" + event.src + " " + event.dst + "  " + event.event,
            self.localConnID, self.remoteConnID)
        self.notify.info(rpd_event_def.RPD_EVENT_L2TP_INFO[0], "Good SCCRQ received " + str(hex(self.localConnID)),
                         rpd_event_def.RpdEventTag.ccap_ip(self.remoteAddr))
        if event.dst == L2tpv3Fsm.L2tpv3ConnectionFsm.StateWaitCtlConn:
            pass  # we should send a SCCRP here
        else:  # for the dst state is Idle
            pass  # send stop CCN and clean up this connection

    def fsmEventrecvBadSCCRQ(self, event):
        pass

    def fsmEventrecvGoodSCCRP(self, event):
        pass

    def fsmEventrecvBadSCCRP(self, event):
        pass

    def fsmEventrecvSCCRQLoseTieGood(self, event):
        pass

    def fsmEventrecvSCCRQLoseTieBad(self, event):
        pass

    def fsmEventrecvSCCRQWinSCCRQ(self, event):
        pass

    def fsmEventrecvGoodSCCCN(self, event):
        self.logger.info(
            "Connection[%d, %d] received event:" + event.src + " " + event.dst + "  " + event.event,
            self.localConnID, self.remoteConnID)
        self.notify.info(rpd_event_def.RPD_EVENT_L2TP_INFO[0], "Good SCCCN received" + str(hex(self.localConnID)),
                         rpd_event_def.RpdEventTag.ccap_ip(self.remoteAddr))
        if event.dst == L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished:
            pass  # we should send a zlb
        else:  # for other states
            pass  # we should send the stop CCN, clean up

    def fsmEventrecvStopCCN(self, event):
        pass  # clean up the connection

    def fsmEventcloseRequest(self, event):
        pass

    def fsmEventrecvBadSCCCN(self, event):
        pass

    def fsmEventHalError(self, event):
        """State transition to idle for this event will send a StopCCN
        and close the connection"""
        pass

    def fsmStateIdle(self, event):
        """Callback function will called when fsm changed to this state.
        CDN will be sent to remote and remove the session.

        :param event: The event that triggers the fsm to idle state.
        :return:

        """
        self.logger.info("Connection[%d, %d] state is transferred to idle, event:" + event.src + " " + event.dst +
                         "  " + event.event, self.localConnID, self.remoteConnID)
        if event.event == "startup":
            # for startup, ignore it.
            return

        if self.isRecoveryTunnel and event.src != L2tpv3Fsm.L2tpv3ConnectionFsm.StateEstablished:
            recoverConn = self.recoverConnection
            if recoverConn is not None:
                self.logger.info(
                    "Connection[%d, %d] tranfers to idle from non est state, stop the recover connection[%d, %d] silently",
                    self.localConnID, self.remoteConnID, recoverConn.localConnID, recoverConn.remoteConnID)

                keys = self.sessions.keys()
                for sessionId in keys:
                    session = self.sessions[sessionId]
                    session.silentlyCleared = True
                recoverConn.silentlyCleared = True

                recoverConn.StopConnection()

        if event.event == "closeRequest":
            return

        # since the connection, we have know the [lcoal, remote] connection ID pair, so we should send the StopCCN when
        # got this state
        self.logger.info(
            "The Connection has been changed to idle, send stopCCN and cleanup the resource")
        self.CloseConnection()

    def fsmStateWaitCtlConn(self, event):
        self.logger.debug(
            "received event:" + event.src + " " + event.dst + "  " + event.event)

    def fsmStateEnterStateEstablished(self, event):
        self.lastchangetime = time.time()
        self.SendHalMsg(self.ADD_LCCE)

    def fsmStateLeaveStateEstablished(self, event):
        # TBD - Should DEL_LCCE message be sent unconditionally?
        #       If it is, concern would be getting in a Send/Receive msg loop
        if event.event is not "recvHalError":
            # Should SendHalMsg return a status and the status tracked
            # to detect OpenRPD / CCAP / Driver / FW being out of sync
            # in regards to the number of used connection resources?
            # Example is if because of a timeout or other error a device
            # doesn't end up properly deleting a connection, the resource
            # in the Phy is not available.
            self.SendHalMsg(self.DEL_LCCE)

    def queryInactSessions(self):
        inActiveSessions = list()
        keys = self.sessions.keys()
        for sessionId in keys:
            session = self.sessions[sessionId]
            if session.local_circuit_status != L2tpv3Session.L2tpv3Session.CIRCUIT_STATUS_UP:
                self.logger.debug("query for inactive session [%d, %d]" % (session.localSessionId, session.remoteSessionId))
                inActiveSessions.append(session)

        if inActiveSessions:
            fsqAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
                L2tpv3RFC3931AVPs.ControlMessageAVP.FSQ)
            fssAvps = tuple()
            for ses in inActiveSessions:
                fss = L2tpv3RFC3931AVPs.FailoverSessionState(ses.localSessionId, ses.remoteSessionId)
                fssAvps = fssAvps + (fss,)
            fsq = L2tpv3ControlPacket.L2tpv3ControlPacket(
                self.remoteConnID, 0, 0, (fsqAvp,) + fssAvps)
            self.transport.SendPacket(fsq)

    def queryStaleSessions(self):
        staleSessions = list()
        keys = self.sessions.keys()
        for sessionId in keys:
            session = self.sessions[sessionId]
            if session.stale:
                self.logger.debug("query for stale session [%d, %d]" % (session.localSessionId, session.remoteSessionId))
                staleSessions.append(session)

        if staleSessions:
            fsqAvp = L2tpv3RFC3931AVPs.ControlMessageAVP(
                L2tpv3RFC3931AVPs.ControlMessageAVP.FSQ)
            fssAvps = tuple()
            for ses in staleSessions:
                fss = L2tpv3RFC3931AVPs.FailoverSessionState(ses.localSessionId, ses.remoteSessionId)
                fssAvps = fssAvps + (fss,)
            fsq = L2tpv3ControlPacket.L2tpv3ControlPacket(
                self.remoteConnID, 0, 0, (fsqAvp,) + fssAvps)
            self.transport.SendPacket(fsq)
