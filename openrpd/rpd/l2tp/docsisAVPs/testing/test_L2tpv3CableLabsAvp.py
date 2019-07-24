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
import struct
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror
from docsisAVPs.src.L2tpv3CableLabsAvps import LocalMTUCableLabs, DepiResourceAllocReplyCableLabs, \
    RemoteMTUCableLabs, DepiPseudowireSubtypeCapList, DepiPseudowireSubtype, \
    DepiL2SpecificSublayerSubtype, DepiMulticastCapability, DepiRemoteMulticastJoin,\
    DepiRemoteMulticastLeave, DepiResourceAllocReq, UpstreamFlow

from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
import l2tpv3.src.L2tpv3ControlPacket as L2tpv3ControlPacket
from rpd.dispatcher.dispatcher import Dispatcher
from l2tpv3.src.L2tpv3Hal import L2tpHalClient
from l2tpv3.src.L2tpv3Hal import L2tpHalClientError
import rpd.hal.src.HalConfigMsg as HalConfigMsg
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
import rpd.hal.src.HalConfigMsg as HalConfiMsg
from rpd.hal.src.msg import HalCommon_pb2
from l2tpv3.src.L2tpv3Session import L2tpv3Session
from l2tpv3.src.L2tpv3Connection import L2tpConnection
import l2tpv3.src.L2tpv3RFC3931AVPs as L2tpv3RFC3931AVPs
import docsisAVPs.src.L2tpv3CableLabsAvps as L2tpv3CableLabsAvps
from l2tpv3.src.L2tpv3Dispatcher import L2tpv3Dispatcher
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from rpd.common.rpd_logging import AddLoggerToClass


class testL2tpv3CableLabsAVP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn_address = '127.0.0.1'
        global_dispatcher = Dispatcher()
        dispatcher = L2tpv3Dispatcher(global_dispatcher, cls.conn_address, False, None)
        L2tpv3GlobalSettings.Dispatcher = dispatcher
        # setup the halclient
        cls.hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                       "the HAL client of L2TP feature",
                                       "1.0", tuple(L2tpHalClient.notification_list.keys()), global_dispatcher)
        cls.hal_client.handler = dispatcher.receive_hal_message
        L2tpv3GlobalSettings.l2tp_hal_client = cls.hal_client
        pass

    @classmethod
    def tearDownClass(cls):
        L2tpv3GlobalSettings.Dispatcher.request_unregister(
            {"unregType": "localaddress", "value": cls.conn_address})
        pass

    def test_LocalMTU(self):
        avp1 = LocalMTUCableLabs(1234)
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        self.assertEqual(avp2[0].localMTU, 1234)
        self.assertEqual(avp1.localMTU, 1234)
        # test handleAvp
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = L2tpv3ControlPacket.L2tpv3ControlPacket()
        ret = avp1.handleAvp(pkt=None, retPak=pkt)
        mtu_payload = self.hal_client.mtu_payload
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], RemoteMTUCableLabs)
        self.assertEqual(pkt.avps[0].localMTU, mtu_payload)

    def test_RemoteMTU(self):
        avp1 = RemoteMTUCableLabs(1234)

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)

    def test_Upstreamflow(self):
        avp1 = UpstreamFlow(((1, 2), (4, 5)))
        print avp1
        buf = avp1.encode()
        print len(buf)
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1

    def test_ResourceAlloc(self):
        avp1 = DepiResourceAllocReplyCableLabs(((1, 2), (4, 5)))
        print avp1
        buf = avp1.encode()
        print len(buf)
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1

    def test_ResourceAllocReq(self):
        avp1 = DepiResourceAllocReq(value=((0, 1),(2, 3)))
        print avp1
        buf = avp1.encode()
        print len(buf)
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        # test handleAvp
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = L2tpv3ControlPacket.L2tpv3ControlPacket()
        ret = avp1.handleAvp(pkt=None, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], DepiResourceAllocReplyCableLabs)
        self.assertEqual(pkt.avps[0].allocas, ((0, 1),(2, 3)))

    def test_DepiPseudowireSubtypeCapList(self):
        avp1 = DepiPseudowireSubtypeCapList(value=(1, 2, 3, 4))
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2
        print avp1
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = L2tpv3ControlPacket.L2tpv3ControlPacket()
        ret = avp1.handleAvp(pkt=None, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], DepiPseudowireSubtypeCapList)
        self.assertEqual(pkt.avps[0].pw_list, (1, 2, 3, 4))

    def test_DepiPseudowireSubtype(self):
        avp1 = DepiPseudowireSubtype(value=3)
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2
        print avp1

    def test_DepiL2SpecificSublayerSubtype(self):
        avp1 = DepiL2SpecificSublayerSubtype(value=3)
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2
        print avp1
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = L2tpv3ControlPacket.L2tpv3ControlPacket()
        ret = avp1.handleAvp(pkt=None, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], DepiL2SpecificSublayerSubtype)
        self.assertEqual(pkt.avps[0].pw_type, avp1.pw_type)

    def test_DepiMulticastCapability(self):
        avp1 = DepiMulticastCapability(value=True)
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2
        print avp1
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = L2tpv3ControlPacket.L2tpv3ControlPacket()
        ret = avp1.handleAvp(pkt=None, retPak=pkt)
        self.assertTrue(ret)
        mcast_cap = self.hal_client.mcast_cap
        self.assertIsInstance(pkt.avps[0], DepiMulticastCapability)
        self.assertEqual(pkt.avps[0].mcast_capable, mcast_cap)

    def test_DepiRemoteMulticastJoin(self):
        data = DepiRemoteMulticastJoin.decode(struct.pack("!34B",0x00,0x00,
                                                   0x1, 0x1, 0x2, 0x1,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x1, 0x1, 0x1, 0x1,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00
                                                   ))
        self.assertIsInstance(data, DepiRemoteMulticastJoin)
        self.assertEqual(data.src_ip, "1.1.2.1")
        self.assertEqual(data.group_ip, "1.1.1.1")

        data = DepiRemoteMulticastJoin.decode(struct.pack("!34B", 0x00, 0x00,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x12,
                                                          0x11, 0x11, 0x11, 0x11
                                                          ))

        self.assertIsInstance(data, DepiRemoteMulticastJoin)
        self.assertEqual("1111:1111:1111:1111:1111:1111:1111:1111", data.src_ip)
        self.assertEqual("1111:1111:1111:1111:1111:1112:1111:1111", data.group_ip)

        avp1 = DepiRemoteMulticastJoin(value=("5.5.5.1", "223.222.222.255"))
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        self.assertEqual(avp1.src_ip, avp2[0].src_ip)
        self.assertEqual(avp1.group_ip, avp2[0].group_ip)
        avp1 = DepiRemoteMulticastJoin(value=("2001:5:5:3::0:1", "2001:5:5::0:1"))
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        self.assertEqual(avp1.src_ip, avp2[0].src_ip)
        self.assertEqual(avp1.group_ip, avp2[0].group_ip)

    def test_DepiRemoteMulticastLeave(self):

        data = DepiRemoteMulticastLeave.decode(struct.pack("!34B",0x00,0x00,
                                                   0x1, 0x1, 0x2, 0x1,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x1, 0x1, 0x1, 0x1,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00
                                                   ))
        self.assertIsInstance(data, DepiRemoteMulticastLeave)
        self.assertEqual(data.src_ip, "1.1.2.1")
        self.assertEqual(data.group_ip, "1.1.1.1")

        data = DepiRemoteMulticastLeave.decode(struct.pack("!34B", 0x00, 0x00,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x11,
                                                          0x11, 0x11, 0x11, 0x12,
                                                          0x11, 0x11, 0x11, 0x11
                                                          ))

        self.assertIsInstance(data, DepiRemoteMulticastLeave)
        avp1 = DepiRemoteMulticastLeave(value=("5.5.5.1", "223.222.222.255"))
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2
        print avp1
        self.assertEqual(avp1.src_ip, avp2[0].src_ip)
        self.assertEqual(avp1.group_ip, avp2[0].group_ip)
        self.assertIsInstance(avp2[0], DepiRemoteMulticastLeave)
        avp1 = DepiRemoteMulticastLeave(value=("2001:5:5:3::0:1", "2001:5:5::0:1"))
        buf = avp1.encode()
        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        self.assertEqual(avp1.src_ip, avp2[0].src_ip)
        self.assertEqual(avp1.group_ip, avp2[0].group_ip)

    def test_init_para_error(self):
        try:
            LocalMTUCableLabs("1234")
        except l2tpv3AVPerror as e:
            self.assertEqual(str(e), "parameter type error")
        try:
            RemoteMTUCableLabs("1234")
        except l2tpv3AVPerror as e:
            self.assertEqual(str(e), "parameter type error")
        try:
            DepiResourceAllocReplyCableLabs(value=1)
        except l2tpv3AVPerror as e:
            self.assertEqual(str(e), "parameter type error")
        try:
            DepiResourceAllocReq(value=1)
        except l2tpv3AVPerror as e:
            self.assertEqual(str(e), "parameter type error")
        try:
            UpstreamFlow(value=1)
        except l2tpv3AVPerror as e:
            self.assertEqual(str(e), "parameter type error")
        try:
            DepiPseudowireSubtypeCapList("1234")
        except l2tpv3AVPerror as e:
                self.assertEqual(str(e), "parameter type error")
        try:
            DepiPseudowireSubtype(value=23)
        except l2tpv3AVPerror as e:
                self.assertEqual(str(e), "parameter type error")
        try:
            DepiL2SpecificSublayerSubtype(value=23)
        except l2tpv3AVPerror as e:
                self.assertEqual(str(e), "parameter type error")
        try:
            DepiMulticastCapability(value=5)
        except l2tpv3AVPerror as e:
                self.assertEqual(str(e), "parameter type error")
        try:
            DepiRemoteMulticastJoin(value=5)
        except l2tpv3AVPerror as e:
                self.assertEqual(str(e), "parameter type error")
        try:
            DepiRemoteMulticastLeave(value=5)
        except l2tpv3AVPerror as e:
                self.assertEqual(str(e), "parameter type error")

if __name__ == "__main__":
    unittest.main()
