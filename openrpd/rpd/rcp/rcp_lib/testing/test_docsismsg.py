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
import binascii

from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.rcp_lib import docsis_message
from rpd.gpb.RfChannel_pb2 import t_RfChannel
from rpd.common.rpd_logging import setup_logging


class TestOCD(unittest.TestCase):

    def test_OCDTLV(self):
        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c2000087c60e01e02f00000100cae53ca4ea00750000030531009f08000100010104020102030422212ec0040110054181048a04d2051a056205aa05f2063a068206ca0719072507300739075e07670772077e078a07d2081a086208aa08f2093a098209ca0a120a5a0aa20aea0b320b7a050510000004650505100b9a0fff0505140748074f060100"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        ocd_msg.decode(ocd_buf, 0, len(ocd_buf))
        ocd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200008ec60e01e02f00000100cae53ca4ea007c0000030531009f08000103010105020105030422212ec0040110054181048a04d2051a056205aa05f2063a068206ca0719072507300739075e07670772077e078a07d2081a086208aa08f2093a098209ca0a120a5a0aa20aea0b320b7a050510000004650505100b9a0fff0505140748074f0505500748074f060100"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        ocd_msg.decode(ocd_buf, 0, len(ocd_buf))
        ocd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c2000053c60e01e02f00000100cae53ca4ea00410000030531009f08000100010104020102030422212ec0040110050502000004650505900000000105069000000001010505100b9a0fff0505140748074f060100"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        ocd_msg.decode(ocd_buf, 0, len(ocd_buf))
        ocd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        # Include CRC
        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c2000053c60e01e02f00000100cae53ca4ea00410000030531009f08000100010104020102030422212ec0040110050502000004650505900000000105069000000001010505100b9a0fff0505140748074f06010000000000"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        ocd_msg.decode(ocd_buf, 0, len(ocd_buf))
        ocd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

    def test_Negative(self):
        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c2000087"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        try:
            ocd_msg.decode(ocd_buf, 0, len(ocd_buf))
            decodedone = True
        except docsis_message.DocsisMsgDecodeError:
            decodedone = False
        self.assertFalse(decodedone)

        # unsupported type
        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200008ec60e01e02f00000100cae53ca4ea007c00000305ff009f08000103010105020105030422212ec0040110054181048a04d2051a056205aa05f2063a068206ca0719072507300739075e07670772077e078a07d2081a086208aa08f2093a098209ca0a120a5a0aa20aea0b320b7a050510000004650505100b9a0fff0505140748074f0601000505540748074f"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        self.assertEqual(ocd_msg.decode(ocd_buf, 0, len(ocd_buf)), ocd_msg.DECODE_FAILED)

        # decode fail
        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200008ec60e01e02f00000100cae53ca4ea00790000030531009f08000103010105020105030422212ec0040110054181048a04d2051a056205aa05f2063a068206ca0719072507300739075e07670772077e078a07d2081a086208aa08f2093a098209ca0a120a5a0aa20aea0b320b7a050510000004650505100b9a0fff0505140748074f06010005055407"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        self.assertEqual(ocd_msg.decode(ocd_buf, 0, len(ocd_buf)), ocd_msg.DECODE_FAILED)
        ocd_msg.skip_convert(gcp_msg_def.NotifyREQ,
                             rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                             rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)

        try:
            ocd_msg._update_tlv_dict()
        except AttributeError:
            pass

        # Invalid MMM length field
        ocd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c2000053c60e01e02f00000100cae53ca4ea00400000030531009f08000100010104020102030422212ec0040110050502000004650505900000000105069000000001010505100b9a0fff0505140748074f060100"

        ocd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(ocd_buf)
        print "buf is"
        print repr(ocd_buf)
        try:
            ocd_msg.decode(ocd_buf, 0, len(ocd_buf))
            decodedone = True
        except docsis_message.DocsisMsgDecodeError:
            decodedone = False
        self.assertFalse(decodedone)


class TestDPD(unittest.TestCase):

    def test_DPDTLV(self):
        dpd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200002261fc01e02f00000100cae53ca4e900100000030532009fff0205052400000fff"
        dpd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(dpd_buf)
        print "buf is"
        print repr(dpd_buf)
        dpd_msg.decode(dpd_buf, 0, len(dpd_buf))
        dpd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        dpd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "C200002261FC01E02F00000100CAE53CA4E900100000030532009F010205052A00000FFF"
        dpd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(dpd_buf)
        print "buf is"
        print repr(dpd_buf)
        dpd_msg.decode(dpd_buf, 0, len(dpd_buf))
        dpd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        dpd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "C200002261FC01E02F00000100CAE53CA4E900100000030532009F000205052800000FFF"
        dpd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(dpd_buf)
        print "buf is"
        print repr(dpd_buf)
        dpd_msg.decode(dpd_buf, 0, len(dpd_buf))
        dpd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        dpd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "C200003161FC01E02F00000100CAE53CA4E9001F0000030532009F00020505a800000FFF05056800000FFF0506a800000FFFFF"
        dpd_buf = binascii.a2b_hex(pkt)
        print "buf len:", len(dpd_buf)
        print "buf is"
        print repr(dpd_buf)
        dpd_msg.decode(dpd_buf, 0, len(dpd_buf))
        dpd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh


class TestUCD(unittest.TestCase):

    def test_UCDTLV(self):
        ucd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200016af52b01e02f00000100219f7b6638020e000003010200010d0401010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000042501010101020102030200260402018c050100060110070201520801000901160a01010b01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101"

        buf = binascii.a2b_hex(pkt)
        print "buf len:", len(buf)
        print "buf is"
        print repr(buf)
        self.assertEqual(ucd_msg.decode(buf, 0, len(buf)), ucd_msg.DECODE_DONE)
        ucd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        # decode fail
        ucd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        # next data appears has not enough data to read TL, so there is exception in _fast_decode
        pkt = "c200016b052b01e02f00000100219f7b66380218000003010200010d0401010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000043501010107020101030200260402018c050100060110070201520801000901160a01010b01010c01010d0200020e01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101"

        buf = binascii.a2b_hex(pkt)
        print "buf len:", len(buf)
        print "buf is"
        print repr(buf)
        self.assertEqual(ucd_msg.decode(buf, 0, len(buf)), ucd_msg.DECODE_FAILED)
        ucd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        ucd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c2000169f52b01e02f00000100219f7b6638020e000003010200010d0401010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000042501550101020102030200260402018c050100060110070201520801000901160a01010b01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101"

        buf = binascii.a2b_hex(pkt)
        print "buf len:", len(buf)
        print "buf is"
        print repr(buf)
        self.assertEqual(ucd_msg.decode(buf, 0, len(buf)), ucd_msg.DECODE_DONE)
        ucd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

    def test_UCDTLV_New_Fields_Added(self):
        UCID = 3
        ConfChangeCount = 10
        MiniSlotSize = 20
        DCID = 5
        ucd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        # Insert the fields' values into the DOCSIS packet (version 3, type 29)
        pkt = "c200016af52b01e02f00000100219f7b6638020E000003031D00" + "%02x" % UCID + "%02x" % ConfChangeCount + "%02x" % MiniSlotSize + "%02x" % DCID + \
            "010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000042501010101020102030200260402018c050100060110070201520801000901160a01010b01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101"

        buf = binascii.a2b_hex(pkt)
        print "buf len:", len(buf)
        print "buf is"
        print repr(buf)
        ucd_msg.decode(buf, 0, len(buf))
        ucd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

        # Make sure the values are parsed and used to set the appropriate TLVs.
        UsScQamChannelConfig = rfCh.UsScQamChannelConfig
        self.assertEqual(UsScQamChannelConfig.UpStreamChanId, UCID)
        self.assertEqual(UsScQamChannelConfig.ConfigChangeCount, ConfChangeCount)
        self.assertEqual(UsScQamChannelConfig.DownStreamChanId, DCID)

    def test_OFDMUCDTLV(self):
        ucd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200016af52b01e02f00000100219f7b6638020e000003010200010d0401010108020401312d00038003f02833ebf02833ebf02833ebf02833ebf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0df3dec0edf3dec0edf3dec0edf3dec0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b000000000000000000000000000000000000000000000000000000000000042501010101020102030200260402018c050100060110070201520801000901160a01010b01010425030101010201020302018004020006050105060122070201520801000901300a01010b01010425040101010201020302018004020006050105060122070201520801000901300a01010b0101042505010101020102030200400402018c05010306014c0702015208010c0901160a01020b0101042506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b0101052506010101020102030200400402018c0501090601e8070201520801fe0901160a01020b01010640c0edf1642892a9974767da0417bbc2758f36ff5739350dc1871988d3d22b603f296b0000000000000000000000000000000000000000000000000000000000000701010801010901010a01010b0201010c0201010d0201010e090102030405060708090f0101100101110101120401020304130101140101151001020304050607080910111213141516160101"

        buf = binascii.a2b_hex(pkt)
        print "buf len:", len(buf)
        print "buf is"
        print repr(buf)
        ucd_msg.decode(buf, 0, len(buf))
        ucd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh

    def test_OFDMUCDTLV_Type51(self):
        ucd_msg = docsis_message.DocsisMsgMacMessage()
        rfCh = t_RfChannel()
        pkt = "c200002261fc01e02f00000100cae53ca4e90158000003053300000100000380c3f033fc3303c0300ed11ee52525ee2e2ee22eeeee222ee2eee2e2e2222e22e22a666eee2e2e2e6a2eea6e626eae2a622e6e2aa62e66e2262e2a2e622a262a2a2e6e66e26a62eea2ee2eee2ee2e22e22eee222e2eeee22e2e222ee2222e2222e30fc0cff0cc0f00c00fff333c3cfcf30c3f033fc3303c0300ed11ee52525ee2e100101120400000005130400000a05180207ff19090000000000000000001A01061B01051C01011D04042c1d801E080000098f0d500fff200106210300014d170903130200801602004017090414020060160200401709051502593b16020040170b061504593b593b16020040170d091506593b593b593b16020040170f0a1508593b593b593b593b1602004017110b150a593b593b593b593b593b1602004017130c150c593b593b593b593b593b593b1602004017150d150e593b593b593b593b593b593b593b16020040"

        buf = binascii.a2b_hex(pkt)
        print "buf len:", len(buf)
        print "buf is"
        print repr(buf)
        ucd_msg.decode(buf, 0, len(buf))
        ucd_msg.convert_to_RCPSequence(gcp_msg_def.NotifyREQ,
                                       rcp_tlv_def.RCP_MSG_TYPE_IRA, rfCh,
                                       rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)
        print rfCh


if __name__ == '__main__':
    setup_logging("GCP", filename="test_ocd.log")
    unittest.main()
