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

import copy
import socket
import time
from json import JSONEncoder

from sortedcontainers import SortedListWithKey

import L2tpv3ControlPacket
import L2tpv3GlobalSettings
from L2tpv3Dispatcher import L2tpv3Dispatcher
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common import rpd_event_def
from rpd.common.utils import Convert
import L2tpv3RFC3931AVPs


class L2tpv3TransportError(Exception):
    """The L2TPV3 Transport Error Class, this class defines the class type used
    in l2tpv3 transport layer."""
    ParameterTypeError = "Input Parameter Error"
    ParameterIsNone = "Parameter is None"


class TransportEncoder(JSONEncoder):
    """This class is for internal usage, it is used to stringify the transport
    class to string using the json.

    For the fields in ExcludedFields, will not appear the final output.

    """
    ExcludedFields = ("logger", "socket", "sendList",
                      "receiveWindow", "dispatcher", "connection")

    def __init__(self):
        """should configure the indent to 4, pretty useful for the pretty
        print."""
        super(TransportEncoder, self).__init__(indent=4)

    def default(self, o):
        """The default function will return the instance dict.

        minus the ExcludedFields keys.

        """
        retDict = copy.copy(o.__dict__)

        for field in self.ExcludedFields:
            if field in retDict:
                retDict.pop(field)

        return retDict


class L2tpv3Network(object):
    """Create the low level socket, means, wrap the socket class."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, localAddr, connID):
        """Init the L2TP socket and bind to it.

        :param localAddr: The local IP address that we want to bind L2TP socket to it.
        :param connID: The connection ID, in L2tpv3 domain, it means the lcoal connection ID.

        """
        self.socket = None
        self.addr = localAddr
        self.connID = connID
        if Convert.is_valid_ipv4_address(localAddr):
            self.socket = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_L2TP)
            self.socket.setblocking(False)  # Set the socket to non-block mode
            self.socket.bind((localAddr, connID))
            self.logger.info(
                "Create L2TP socket and bind to it, local IP address:%s, local Connection ID:%d, socket: %d" %
                (localAddr, connID, self.socket.fileno()))
        elif Convert.is_valid_ipv6_address(localAddr):
            self.socket = socket.socket(
                socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_L2TP)
            self.socket.setblocking(False)  # Set the socket to non-block mode
            self.socket.bind(('', connID))
            self.logger.info(
                "Create L2TP socket and bind to any adress, local Connection ID:%d, socket: %d" %
                (connID, self.socket.fileno()))
        else:
            self.logger.info(
                "Create L2TP socket failed, invalid local IP address:%s, local Connection ID:%d" %
                (localAddr, connID))
            self.socket = None

    def close(self):
        if self.socket:
            self.logger.info(
                "Close the socket[%s, %d]." % (self.addr, self.connID))
            self.socket.close()

    def fileno(self):
        """Return the fd of the socket. It is used by the dispatcher to
        register.

        :return: The socket corresponding fd

        """
        if self.socket:
            return self.socket.fileno()


class L2tpv3Transport(object):

    """L2tpv3Transport will handle all connection transport related features.

    1.  Handle the Nr and Ns in l2TP packet.
    2.  Maintain a receive window and seq the control message packet.
    3.  Maintain a resend list and resend the packet it is timeout.
    4.  Process the ZLB message send.
    5.  Process the hello message send.
    6.  Process the connection keep alive and terminate the connection when there is no packet received.

    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, connection, localAddr="", remoteAddr=""):
        """
        :param connection: The connection instance of the L2TP connection, which holds all the connection information:
        :param localAddr: The local IP address.
        :param remoteAddr: Remote IP address.

        """
        self.ackNr = 0  # This variable will be used to record the which packet we want to received.
        self.ns = 0  # This variable is used for next send packet ns value, will increase 1 when sending a packet

        self.receiveWindow = SortedListWithKey(key=self._recvWinKey)
        self.receiveWindowSize = L2tpv3GlobalSettings.L2tpv3GlobalSettings.ReceiveWindowSize
        self.remoteWindowSize = 1024
        self.wrapCount = 0

        self.sendList = list()
        # Will only use the Push/Pop, will not use the
        # insert
        self.timeTickValue = 1  # Default is 1s

        self.localAddr = localAddr
        self.network = L2tpv3Network(
            localAddr, connection.localConnID)  # For receie the SCCRQ

        self.lastSendTime = time.time()  # for the Hello and ZLB
        self.lastRecvTime = time.time()  # for process the connection timeout
        self.helloMsgTimeout = L2tpv3GlobalSettings.L2tpv3GlobalSettings.HelloMsgTimeout
        self.connectionTimeout = L2tpv3GlobalSettings.L2tpv3GlobalSettings.ConnectionTimeout
        self.sendZlbTimeout = L2tpv3GlobalSettings.L2tpv3GlobalSettings.SendZlbTimeout
        self.sendTimeout = L2tpv3GlobalSettings.L2tpv3GlobalSettings.SendTimeout

        self.resendTimes = 10

        self.lastTimetick = time.time()

        self.remoteAddr = remoteAddr
        self.connection = connection

        # If we need to send a ZLB to remote
        self.needSendZlb = False

        self.logger.info(
            "Create a transport for addr:[%s, %s], connection:%d" % (localAddr, remoteAddr,
                                                                     connection.localConnID))

    def __str__(self):
        return TransportEncoder().encode(self)

    def CloseTransport(self):
        """Close the transport, mainly unregister from the dispatcher.

        :return: None

        """
        self.logger.info(
            "Close transport for localAddr:%s, remoteAddr:%s, localConnectionID:%d, remoteConnection:%d" % (
                self.localAddr, self.remoteAddr, self.connection.localConnID, self.connection.remoteConnID
            ))
        self.dispatcher.request_unregister({
            "unregType": "transport",
            "value": self
        })

    def _recvWinKey(self, pkt):
        """This is the key function for the our receive window, the function
        will return a value which is used to sort the receive window ns value.

        :param pkt: The pakcet which will be added into the window
        :return: A value, which is used by the sorted list to save the packet into the list.

        """
        if pkt.ns >= self.ackNr:
            ret = self.wrapCount * 65536 + pkt.ns
        else:
            ret = (self.wrapCount + 1) * 65536 + pkt.ns

        return ret

    def SetDispatcher(self, dispatcher):
        """Set dispatcher will assign the global dispatcher to internal
        variable, and using by the class.

        :param dispatcher: the global dispatcher.
        :return: None

        """
        if not isinstance(dispatcher, L2tpv3Dispatcher):
            self.logger.warn(L2tpv3TransportError.ParameterTypeError + ", the dispatcher is not instance of "
                             "L2tpv3Dispatcher.")
            raise L2tpv3TransportError(L2tpv3TransportError.ParameterTypeError)

        self.dispatcher = dispatcher

    def RegisterTransport(self):
        """register the transport to dispatcher.

        :return: None

        """
        self.logger.info("Register the transport to dispatcher, addr = %s, connection ID = %d" %
                         (self.localAddr, self.connection.localConnID))
        self.dispatcher.register_transport(self)

    def ReceivePacket(self, pkt, addr):
        """The pkt is a control packet, with a connection ID Based on the
        RFc3931, we will use the ns value as the key, however, ns value only
        has 16bit, say, it will wrap when we reach 65535, so we have to
        consider this situation. A windowsize is considered to start from the
        self.ackNr, for wrap reason, we will add an wrap count variable, so the
        window start from:

            wrapCount * 65536 + self.ackNr
        AckNr|-------windowsize--------|

        a packet is considered to in the window:
            (pkt.ns >= ackNr) and (pkt.ns < ackNr + windowSize)
            (pkt.ns < ackNr) and (pkt.ns + 65536 > ackNr + windowSize)

        we also need to identify if the packet is early, or late.
        early, means the pkt is beyond the window, we will do nothing for the packet.
        late, we will consider we have processed this message, will send ack to it.

        """
        # The pkt should be decoded
        if not isinstance(pkt, L2tpv3ControlPacket.L2tpv3ControlPacket):
            self.logger.warn(L2tpv3TransportError.ParameterTypeError + ", the dispatcher is not instance of "
                             "L2tpv3ControlPacket.")
            raise L2tpv3TransportError(L2tpv3TransportError.ParameterTypeError)

        if self.connection.isInRecovery:
            self.logger.info(
                "Drop the control message since connection is in recovery")
            return

        if self.connection.isRecoveryTunnel:
            if not pkt.isZlb and pkt.avps[0].messageType not in L2tpv3RFC3931AVPs.ControlMessageAVP.RecoveryTunnelMesagedSet:
                self.logger.warn(
                    "Receive an invalid control message in recovery tunnel")
                return

        self.lastRecvTime = time.time()  # for process the connection timeout

        ns = pkt.ns
        nr = pkt.nr
        self.logger.debug("Receive a packet in transport layer:ns = %d, Nr = %d, "
                          "Current ns= %d and ackNr = %d " % (ns, nr, self.ns, self.ackNr))

        pkt.SetPacketTransport(self)
        pkt.SetPktConnection(self.connection)

        # remove the ack send
        while len(self.sendList) > 0 and self.sendList[0]["pkt"].ns < nr:
            self.sendList.pop(0)
        if pkt.isZlb:
            # For ZLB message, will not in the receive window
            return

        # insert the packet into the window, process the duplicate one and the
        # skip one
        tmpNs = ns
        if ns < self.ackNr:
            tmpNs += 65536

        # Check if the packet is a early packet, maybe we can use the 16bit
        # signed number for this:)
        tmpNr = self.ackNr
        if tmpNr < ns:
            tmpNr += 65536
        if (tmpNr - ns < 32768) and (tmpNr - ns > 0):  # late ones
            # will send the ZLB to remote
            self.logger.debug(
                "This packet is considered a duplicated one, send ack to it")
            self.SendPacket(L2tpv3ControlPacket.L2tpv3ZLB(
                self.connection.remoteConnID), addr)
            return

        if (tmpNs >= self.ackNr) and (tmpNs < self.ackNr + self.receiveWindowSize):
            if len(self.receiveWindow) >= self.receiveWindowSize:
                self.logger.warn(
                    "Receive window size reaches the max : %d", self.receiveWindowSize)
                pass  # Do we need send a ack?
            for item in self.receiveWindow.irange(pkt, pkt):
                self.logger.debug(
                    "pkt ns[%d] is already in receiveWindow", pkt.ns)
                break
            else:
                self.receiveWindow.add(pkt)
        else:
            self.logger.warn(
                "Receive a packet with wrong Nr/Ns, Nr:%d, Ns:%d, ackNr:%d, wrap_count:%d",
                nr, ns, self.ackNr, self.wrapCount)
            return

        # Give a chance to process the receive window
        # If we did not receive the window for a long time,
        self.logger.debug(
            "Receive a packet with windowsize:%d,firstNs=%d, ackNr=%d",
            len(self.receiveWindow), self.receiveWindow[0].ns, self.ackNr)
        while len(self.receiveWindow) > 0 and self.receiveWindow[0].ns == self.ackNr:
            self.ackNr += 1

            if self.ackNr >= 65536:
                self.wrapCount += 1
                self.ackNr = 0
            pktProcessing = self.receiveWindow.pop(0)
            retPkt = self.connection.HandlePkt(pktProcessing)
            if retPkt is not None:
                self.SendPacket(retPkt, addr=addr)

    def SendPacket(self, pkt, addr=None):
        """Will send the packet with this transport domain."""
        if not isinstance(pkt, L2tpv3ControlPacket.L2tpv3ControlPacket):
            self.logger.warn(
                L2tpv3TransportError.ParameterTypeError + ", the pkt is not a instance of L2tpv3ControlPacket.")
            raise L2tpv3TransportError(L2tpv3TransportError.ParameterTypeError)

        # Put the packet into the sendlist for funture ack
        pkt.ns = self.ns
        if not pkt.isZlb:
            self.ns += 1
            if self.ns >= 65536:
                self.ns = 0
            self.sendList.append({
                "time": time.time(),
                "pkt": pkt,
                "sendTimes": 0,
            })

        pkt.nr = self.ackNr

        if addr is None:
            addr = (self.remoteAddr, self.connection.remoteConnID)

        if self.network is not None:
            try:
                self.network.socket.sendto(pkt.encode(True), addr)
            except Exception as e:
                self.logger.warn(
                    "Send a packet for connection[%d] fail, exception %s"
                    % (self.connection.remoteConnID, e))
            self.lastSendTime = time.time()
            self.needSendZlb = False

        # when sending out a FSR for an incoming FSQ some sessions may be stale
        if pkt.isFSR():
            self.connection.queryStaleSessions()

    def _reSendPacket(self, pkt):
        """Will re-send the packet, the ns will not change and the nr will be
        changed."""
        pkt.nr = self.ackNr
        self.logger.debug(
            "Re-send the packet to remote:%s for connection[%d]" % (pkt, pkt.connectionID))

        addr = (self.remoteAddr, self.connection.remoteConnID)
        if self.network is not None:
            try:
                self.network.socket.sendto(pkt.encode(True), addr)
            except Exception as e:
                self.logger.warn(
                    "Re-send the packet to remote for connection[%d] sendto fail, exception %r"
                    % (pkt.connectionID, e))
            self.lastSendTime = time.time()
            self.needSendZlb = False

    def TimetickCallback(self):
        """Check the timers, we should process the lastSendtime and
        lastRecvTime."""
        currtime = time.time()

        # if some one changed the system time
        time_offset = 0
        if currtime - self.lastTimetick >= 5:
            self.logger.warn(
                "Transport[localAddr:%s, remoteAddr:%s, localConnectionID:%d, remoteConnection:%d] "
                "detected time change, current time is %f, lasttime tick time is %f" % (
                    self.localAddr, self.remoteAddr, self.connection.localConnID,
                    self.connection.remoteConnID, currtime,
                    self.lastTimetick
                ))
            # Try to update the resend list packet timeout
            if len(self.sendList) > 0:
                tLast = self.sendList[len(self.sendList) - 1]["time"]
                for resendStructure in self.sendList:
                    resendStructure["time"] = currtime + (
                        resendStructure["time"] - tLast)

            # Try to update the last recv time and last send time
            time_offset = currtime - self.lastTimetick

        elif currtime - self.lastTimetick < 0:
            self.logger.warn(
                "Transport[localAddr:%s, remoteAddr:%s, localConnectionID:%d, remoteConnection:%d] "
                "detected time change, current time is %f, lasttime tick time is %f" % (
                    self.localAddr, self.remoteAddr, self.connection.localConnID,
                    self.connection.remoteConnID, currtime, self.lastTimetick
                ))
            # Update sth, and trigger an event
            self.lastSendTime = self.lastTimetick - currtime - 1000
            if self.helloMsgTimeout > self.connectionTimeout:
                self.lastRecvTime = currtime - self.helloMsgTimeout - 1
            else:
                self.lastRecvTime = currtime - self.connectionTimeout - 1

            # Update the sendlist
            if len(self.sendList) > 0:
                tLast = self.sendList[len(self.sendList) - 1]["time"]
                for resendStructure in self.sendList:
                    resendStructure["time"] = currtime + (
                        resendStructure["time"] - tLast)

            # Try to update the last recv time and last send time
            time_offset = currtime - self.lastTimetick

        self.lastRecvTime += time_offset
        self.lastSendTime += time_offset
        self.lastTimetick = currtime
        if self.needSendZlb and self.lastSendTime + self.sendZlbTimeout < currtime:
            self.logger.debug("Send a ZLB message remote")
            self.SendPacket(
                L2tpv3ControlPacket.L2tpv3ZLB(self.connection.remoteConnID))
            self.needSendZlb = False

        # Process the lastSend
        if self.lastSendTime + self.helloMsgTimeout < currtime and self.lastRecvTime + self.helloMsgTimeout < currtime:
            self.logger.debug(
                "We don't receive any packet for long time, send a hello to remote.")
            if self.connection.fsm.current == self.connection.fsm.StateEstablished:
                self.SendPacket(
                    L2tpv3ControlPacket.L2tpv3Hello(self.connection.remoteConnID))

        if self.lastRecvTime + self.connectionTimeout < currtime:
            self.logger.debug(
                "The connection[%d] seems dead, close it!" % self.connection.localConnID, )
            self.notify.error(rpd_event_def.RPD_EVENT_L2TP_CONN_ERR[0],
                              rpd_event_def.RpdEventTag.ccap_ip(self.connection.remoteAddr))
            self.connection.CloseConnection()

        # Process the send list
        for resendStructure in self.sendList:
            if currtime > resendStructure["time"] + self.sendTimeout:
                self.logger.warn(
                    "Resend the packet %s to remote." % resendStructure)
                pkt = resendStructure["pkt"]
                self._reSendPacket(pkt)
                resendStructure["time"] = time.time()
                resendStructure["sendTimes"] += 1

                # if we resend the packets for a long time and not get the
                # response
                if resendStructure["sendTimes"] > self.resendTimes:
                    self.logger.warn("Connection[%d] has tried to send packet %d time(s), no response from remote, "
                                     "close the connection.", self.connection.localConnID,
                                     resendStructure["sendTimes"])
                    self.connection.CloseConnection()
