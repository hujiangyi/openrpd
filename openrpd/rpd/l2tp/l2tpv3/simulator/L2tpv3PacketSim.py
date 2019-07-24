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

import socket

import dpkt

import l2tpv3.src.L2tpv3ControlPacket as L2tpv3ControlPacket
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_L2TP)

# s.bind(("0.0.0.0", 0))
f = open("./L2TPV3ControlMinimum.pcap")

pcap = dpkt.pcap.Reader(f)

sccrq = None
sccrp = None
scccn = None
stopccn = None

icrq = None
icrp = None
iccn = None

for ts, buf in pcap:

    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    data = ip.data
    pkt = L2tpv3ControlPacket.L2tpv3ControlPacket.decode(data[4:])
    # print pkt
    if len(pkt.avps) >= 1:
        avp = pkt.avps[0]
        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and sccrq is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRQ:
            print "Found accrq"
            sccrq = pkt
        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and sccrp is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.SCCRP:
            print "Found sccrp"
            sccrp = pkt
        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and scccn is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.SCCCN:
            print "Found scccn"
            scccn = pkt

        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and stopccn is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.StopCCN:
            print "found stopCCN"
            stopccn = pkt

        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and icrq is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.ICRQ:
            print "Found icrq"
            icrq = pkt
        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and icrp is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.ICRP:
            print "Found sccrp"
            icrp = pkt
        if isinstance(avp, L2tpv3RFC3931AVPs.ControlMessageAVP) and iccn is None and \
                avp.messageType == L2tpv3RFC3931AVPs.ControlMessageAVP.ICCN:
            print "Found scccn"
            iccn = pkt

            # s.sendto(data[4:], ('127.0.0.1', 1))
            # break


# Fisrt Send a SCCRQ with connection ID = 1

sccrq.ns = 0
sccrq.nr = 0
sccrq.connectionID = 0
sccrqSock = socket.socket(
    socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_L2TP)

for avp in sccrq.avps:
    if isinstance(avp, L2tpv3RFC3931AVPs.AssignedControlConnectionID):
        conntionID1 = avp.connectionID

print "Bind to connection:%d" % conntionID1
sccrqSock.bind(("127.0.0.1", conntionID1))

s.sendto(sccrq.encode(), ("127.0.0.1", 0))

buf, addr = sccrqSock.recvfrom(2048)
sccrpRecv = L2tpv3ControlPacket.L2tpv3ControlPacket.decode(buf)
recvNs = sccrpRecv.ns
recvNr = sccrpRecv.nr

# finc the connection ID in  sccrp:

for avp in sccrpRecv.avps:
    if isinstance(avp, L2tpv3RFC3931AVPs.AssignedControlConnectionID):
        conntionID = avp.connectionID
"""
conntionID = 3430682202

"""
# print "Get remote Connection ID:%d" % conntionID
scccn.ns = 1
scccn.nr = 1
scccn.connectionID = conntionID

buf = scccn.encode()
s.sendto(buf, ('127.0.0.1', 1))

# Send ICRQ
icrq.ns = 2
icrq.nr = 1
icrq.connectionID = conntionID
buf = icrq.encode()
icrq.avps = icrq.avps
print icrq
s.sendto(buf, ('127.0.0.1', 1))

"""
#Recevie the icrp
"""
buf, addr = sccrqSock.recvfrom(2048)
icrpRecv = L2tpv3ControlPacket.L2tpv3ControlPacket.decode(buf)

for avp in icrpRecv.avps:
    if isinstance(avp, L2tpv3RFC3931AVPs.LocalSessionID):
        print "The remote session ID is %d" % avp.sessionID
        sessionID = avp.sessionID
        break

iccn.ns = 3
iccn.nr = 2
iccn.connectionID = conntionID

for avp in iccn.avps:
    if isinstance(avp, L2tpv3RFC3931AVPs.RemoteSessionID):
        avp.sessionID = sessionID
# Change the AVPs
print iccn
buf = iccn.encode(True)
s.sendto(buf, ('127.0.0.1', 1))

cdnMsg = L2tpv3RFC3931AVPs.ControlMessageAVP(
    L2tpv3RFC3931AVPs.ControlMessageAVP.CDN)
retcode = L2tpv3RFC3931AVPs.ResultCode(
    L2tpv3RFC3931AVPs.ControlMessageAVP.StopCCN, 0, 0, "test")
# Get the lcoal session ID
localAvp = None
for avp in iccn.avps:
    if isinstance(avp, L2tpv3RFC3931AVPs.LocalSessionID):
        lcoalSessionID = avp.sessionID
        localAvp = L2tpv3RFC3931AVPs.LocalSessionID(lcoalSessionID)
remoteAvp = L2tpv3RFC3931AVPs.RemoteSessionID(sessionID)
cdn = L2tpv3ControlPacket.L2tpv3ControlPacket(
    conntionID, avps=(cdnMsg, retcode, localAvp, remoteAvp))

cdn.ns = 4
cdn.nr = 2
cdn.connectionID = conntionID
print cdn
buf = cdn.encode(True)
s.sendto(buf, ('127.0.0.1', 1))

stopccn.ns = 5
stopccn.nr = 2
stopccn.connectionID = conntionID
for avp in stopccn.avps:
    if isinstance(avp, L2tpv3RFC3931AVPs.AssignedControlConnectionID):
        avp.value = conntionID1

print stopccn
buf = stopccn.encode(True)
s.sendto(buf, ('127.0.0.1', 1))
