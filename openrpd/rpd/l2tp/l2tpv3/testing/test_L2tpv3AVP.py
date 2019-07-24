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
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, GeneralL2tpv3AVP
import l2tpv3.src.L2tpv3RFC3931AVPs
import l2tpv3.src.L2tpv3CiscoAVPs
import docsisAVPs.src.L2tpv3CableLabsAvps
import unittest
import struct
from rpd.common.rpd_logging import AddLoggerToClass


class TestL2tpv3AVP(unittest.TestCase):
    # open the logger
    __metaclass__ = AddLoggerToClass

    def setUp(self):
        self.avp = l2tpv3AVP()

    def tearDown(self):
        pass

    def test_l2tpv3AVP(self):
        """Valid instance and invalid instance."""
        # Not isinstance
        try:
            avp000 = l2tpv3AVP(
                AttrType=6, AttrValue="t", VendorID=6, MustAvp="l", HidenAVP="h")
        except Exception as e:
            self.assertEqual(str(e), 'Args type error')

        # Instance
        avp = l2tpv3AVP()
        print "------>>>", str(avp)

    def test_l2tpv3AVP_encode(self):
        self.avp.encode()

    def test_l2tpv3AVP_decode(self):
        """len(buf) < 6.

        len(buf) < length

        len(buf) >= length.

        """
        # len(buf) < 6
        try:
            self.avp.decode(buf="12345")
        except Exception as e:
            self.assertRegexpMatches(str(e),
                                     "Cannot decode the buffer since the buf is too low")

        # len(buf) < length
        try:
            self.avp.decode(buf="1234567")
        except Exception as e:
            self.assertRegexpMatches(str(e),
                                     "Cannot decode the buffer since the buf is too low")

        # len(buf) >= length
        # flags=12594
        # length = flags & 0x03ff ---> 12594&0x03ff=306
        # 51*6=306
        buff0 = "12345678901234567890123456789012345678901234567890H" * 6
        self.avp.decode(buf=buff0)

    def test_l2tpv3AVP_handleAvp(self):
        self.avp.handleAvp(pkt="ads123", retPak="nofalse")

    def test_l2tpv3AVP_SetFlags(self):
        # raise NotImplementedError
        try:
            self.avp.SetFlags(mustAvp="101", hiddenAvp="202")
        except Exception as e:
            pass

    def test_l2tpv3AVP_decodeAll(self):
        """offset < len(buf)

        len(buf) < length

        len(buf) >= length: ???

        """
        # offset < len(buf)
        try:
            self.avp.decodeAll(buf="12345")
        except Exception as e:
            self.assertRegexpMatches(str(e),
                                     "Cannot decode the buffer since the buf is too low")

        # len(buf) < length
        try:
            self.avp.decodeAll(buf="1234567")
        except Exception as e:
            self.assertRegexpMatches(str(e),
                                     "Cannot decode the buffer since the buf is too low")

        buff0 = "12345678901234567890123456789012345678901234567890H" * 6
        self.avp.decodeAll(buf=buff0)

        # len(buf) >= length and (vendorID, attrType) is in
        # l2tpv3AVP.SubclassMapping
        buff00 = "00000078901234567890123456789012345678901234567890M" * 6
        self.avp.decodeAll(buf=buff00)

        """
        ICRQ request:

        """
        buf = struct.pack('!176B',
                          0xc, 8, 0x0, 0x0,
                          0x0, 0x0, 0x0, 10,
                          0xc, 10, 0x0, 0x0,
                          0, 15, 0, 0,
                          0, 0,
                          0xc, 10, 0x0, 0x0,
                          0, 63, 0x40, 0x00,
                          0x00, 0x01,
                          0xc, 10, 0x0, 0x0,
                          0, 64, 0x0, 0x0,
                          0x0, 0x0,
                          0xc, 40, 0x0, 0x0,
                          0x0, 66, 0x0, 0x0,
                          0x00, 0x03, 0x00, 0x00,
                          0x00, 0x03, 0x01, 0x01,
                          0x00, 0x03, 0x02, 0x02,
                          0x00, 0x03, 0x03, 0x03,
                          0x00, 0x03, 0x04, 0x04,
                          0x00, 0x03, 0x05, 0x05,
                          0x00, 0x03, 0x06, 0x06,
                          0x00, 0x03, 0x07, 0x07,
                          0xc, 8, 0, 0,
                          0, 68, 0, 12,
                          0xc, 8, 0, 0,
                          0, 69, 0, 3,
                          0xc, 8, 0, 0,
                          0, 71, 0, 2,
                          0xc, 8, 0x11, 0x8b,
                          0x0, 0x2, 0x1, 0x0,
                          0xc, 8, 0x11, 0x8b,
                          0x0, 0x4, 0x7, 0xD0,
                          0xc, 10, 0, 0x9,
                          0x0, 0x3, 0x00, 0x00,
                          0x00, 0x01,
                          0xc, 40, 0x11, 0x8b,
                          0x0, 11, 0, 0,
                          0x5, 0x6, 0x7, 0x8,
                          0, 0, 0, 0,
                          0, 0, 0, 0,
                          0, 0, 0, 0,
                          0x22, 0x23, 0x24, 0x25,
                          0, 0, 0, 0,
                          0, 0, 0, 0,
                          0, 0, 0, 0,
                          0xc, 8, 0x11, 0x8b,
                          0x0, 13, 0x80, 0,
                          )
        retavp = self.avp.decodeAll(buf=buf)
        print retavp
        for avp in retavp:
            if isinstance(avp, GeneralL2tpv3AVP):
                self.fail("can not decode avp %s" % avp)

    def test_l2tpv3AVP_validateAvps(self):
        self.avp.validateAvps(avps="list")
        self.assertEqual(self.avp.validateAvps(avps="list"), False)


if __name__ == "__main__":
    unittest.main()
