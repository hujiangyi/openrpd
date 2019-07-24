
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
from l2tpv3.src.L2tpv3CiscoAVPs import SessionTieBreakerCisco, AssignedConnectionIDCisco, PseudowireCapListCisco,\
    LocalSessionIDCisco, RemoteSessionIDCisco, PseudowireTypeCisco, DraftAVPVersionCisco, DepiMcmtsSimplificationCisco
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror

from l2tpv3.src import L2tpv3RFC3931AVPs
from l2tpv3.src import L2tpv3ControlPacket
from l2tpv3.src import L2tpv3GlobalSettings
from l2tpv3.src import L2tpv3Connection

import unittest

class fake_con():
    def __init__(self):
        self.localConnID = 123

class fake_pkt():
    def __init__(self):
        self.Connection = fake_con()
        self.avps = []
        self.Session = None
class fake_sess():
    def __init__(self):
        self.localSessionId = 12


class TestL2tpv3CiscoAVPs(unittest.TestCase):

    def setUp(self):
        pass
        # self.localConnID = 0x1234567

    def tearDown(self):
        pass

    def test_SessionTieBreakerCisco(self):
        avp1 = SessionTieBreakerCisco("abcdesgh")

        buf = avp1.encode()

        avp2 = SessionTieBreakerCisco.decodeAll(buf)
        print avp2[0]
        print avp1

        # Add: Start
        # not isinstance(value, str)
        try:
            avp3 = SessionTieBreakerCisco(value=121)
        except Exception as e:
            pass

        # if len(value) != 8
        try:
            avp4 = SessionTieBreakerCisco(value="1234567")
        except Exception as e:
            pass

        # test handleAvp
        # return True
        self.assertEqual(
            avp1.handleAvp(pkt="0x1234567", retPak="0xqwert"), True)
        # Add: End

    def test_AssignedConnectionIDCisco(self):
        avp1 = AssignedConnectionIDCisco(0x12345678)

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = fake_pkt()
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], AssignedConnectionIDCisco)

        # Add: Start
        # (not isinstance(value, int) and not isinstance(value, long))\
        # or not isinstance(mustAvp, bool) or not isinstance(hiddenAvp, bool)
        try:
            avp3 = AssignedConnectionIDCisco(
                value="1011", mustAvp=12, hiddenAvp=21, attrValue=None)
        except Exception as e:
            pass

        # test handleAvp
        # retPak is None and return True
        self.assertEqual(avp1.handleAvp(pkt="0x1234567", retPak=None), True)
        # retPak is Not None

        try:
            avp1.handleAvp(pkt="0x1234567", retPak="0x232332ss")
        except Exception as e:
            pass

        # Add: End

    def test_PseudowireCapListCisco(self):
        avp1 = PseudowireCapListCisco((1, 2, 3, 4, 5, 6))

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1

        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = fake_pkt()
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], PseudowireCapListCisco)

        # Add: Start
        # not isinstance(value, tuple) or not isinstance(mustAvp, bool)
        # or not isinstance(hiddenAvp, bool)
        try:
            avp3 = PseudowireCapListCisco(
                value=2, mustAvp=2, hiddenAvp=2, attrValue=None)
        except Exception as e:
            pass

        # retPak is None
        self.assertEqual(avp1.handleAvp(pkt="0x1234567", retPak=None), True)
        # retPak is Not None
        try:
            avp1.handleAvp(pkt="0x1234567", retPak="NotNone")
        except Exception as e:
            pass

        # Add: End

    def test_LocalSessionIDCisco(self):
        avp1 = LocalSessionIDCisco(0x12345678)

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1


        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = fake_pkt()
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertFalse(ret)
        pkt.Session = fake_sess()
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], LocalSessionIDCisco)

        # Add: Start
        # (not isinstance(value, int) and not isinstance(value, long)) \
        # or not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool)
        try:
            avp3 = LocalSessionIDCisco(
                value="null", mustAvp=0, hiddenAvp=0, attrValue=None)
        except Exception as e:
            pass

        # Test handleAvp
        # retPak is None
        self.assertEqual(avp1.handleAvp(pkt="0x", retPak=None), True)
        # retPak is Not None
        try:
            avp1.handleAvp(pkt="0xcvb", retPak="0x12345")
        except Exception as e:
            pass
        # Add: End

    def test_RemoteSessionIDCisco(self):
        avp1 = RemoteSessionIDCisco(0x12345678)

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1
        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = fake_pkt()
        pkt_avp = LocalSessionIDCisco(0x112)
        pkt.avps.append(pkt_avp)
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertTrue(ret)

        # Add: Start
        # (not isinstance(value, int) and not isinstance(value, long))
        # or not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool)
        try:
            avp3 = RemoteSessionIDCisco(
                value="", mustAvp=3, hiddenAvp=1, attrValue=None)
        except Exception as e:
            pass

        # Test handleAvp
        # retPak is None
        self.assertEqual(avp1.handleAvp(pkt="0x", retPak=None), True)
        # retPak is Not None
        try:
            avp1.handleAvp(pkt="0xcvb", retPak="0x12345")
        except Exception as e:
            pass
        # Add: End

    def test_PseudowireTypeCisco(self):
        avp1 = PseudowireTypeCisco(12)

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1

        # Add: Start
        # (not isinstance(value, int) and not isinstance(value, long))
        # or not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool)
        try:
            avp3 = PseudowireTypeCisco(
                value="", mustAvp=3, hiddenAvp=1, attrValue=None)
        except Exception as e:
            pass

        # Test handleAvp
        # retPak is None
        self.assertEqual(avp1.handleAvp(pkt="0x", retPak=None), True)
        # retPak is Not None
        try:
            avp1.handleAvp(pkt="0xcvb", retPak="0x12345")
        except Exception as e:
            pass
        # Add: End

    def test_DraftAVPVersionCisco(self):
        avp1 = DraftAVPVersionCisco(12)

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1


        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = fake_pkt()
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], DraftAVPVersionCisco)

        # Add: Start
        # (not isinstance(value, int) and not isinstance(value, long))
        # or not isinstance(hiddenAvp, bool) or not isinstance(mustAvp, bool)
        try:
            avp3 = DraftAVPVersionCisco(value="", attrValue=None)
        except Exception as e:
            self.assertIsInstance(e, l2tpv3AVPerror)

        # attrValue is NOT None
        avp4 = DraftAVPVersionCisco(12, "zyj")

        # Test handleAvp
        # retPak is None
        self.assertEqual(avp1.handleAvp(pkt="0x", retPak=None), True)
        # retPak is Not None
        try:
            avp1.handleAvp(pkt="0xcvb", retPak="0x12345")
        except Exception as e:
            pass
        # Add: End

    def test_DepiMcmtsSimplificationCisco(self):
        avp1 = DepiMcmtsSimplificationCisco(1, 2, "hello")

        buf = avp1.encode()

        avp2 = l2tpv3AVP.decodeAll(buf)
        print avp2[0]
        print avp1

        ret = avp1.handleAvp(pkt=None, retPak=None)
        self.assertTrue(ret)
        pkt = fake_pkt()
        ret = avp1.handleAvp(pkt=pkt, retPak=pkt)
        self.assertTrue(ret)
        self.assertIsInstance(pkt.avps[0], DepiMcmtsSimplificationCisco)
        # Add: Start
        # isinstance(value, str) or (not isinstance(typeDef, int) and not isinstance(typeDef, long))
        # or (not isinstance(version, int) and not isinstance(version, long))
        try:
            avp3 = DepiMcmtsSimplificationCisco(
                typeDef="234", version="wwq", value=0, attrValue=None)
        except Exception as e:
            self.assertEqual(str(e), "parameter type error")

        # attrValue is NOT None
        avp4 = DepiMcmtsSimplificationCisco(12, 11, "zyj")

        # Test handleAvp
        # retPak is None
        self.assertEqual(avp1.handleAvp(pkt="0x", retPak=None), True)
        # retPak is Not None
        try:
            avp1.handleAvp(pkt="0xcvb", retPak="0x12345")
        except Exception as e:
            pass
        # Add: End


if __name__ == "__main__":
    unittest.main()
