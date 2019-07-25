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
import itertools

# REQUIRED; DO NOT REMOVE
from rpd.rcp.gcp.gcp_lib.testing import test_gcp_tlv_def

from rpd.rcp.gcp.gcp_lib.gcp_msg_def import *
from rpd.rcp.gcp.gcp_lib.gcp_packet import GCPPacket, Message, MessageFields,\
    TLVData, GCPMSGFieldsEncodeError


_msg_tlvs = {}


def _setUpClass():
    """Method saves current tlvs allowd in the GCP messages used in this TC and
    associates testing TLVs with the GCP messages."""

    # TODO we need this method, because if the RCP package is imported
    # TODO before the GCP and then tests from GCP are executed,
    # TODO there are defined TLVs also from the RCP package, but these
    # TODO tests are for GCP only
    # TODO Try to solve this problem without these methods

    # save current TLVs associated with the GCP messages
    for msg_id, msg_descr in GCP_MSG_SET.child_dict_by_id.items():
        _msg_tlvs[msg_id] = msg_descr.tlvs
        msg_descr.tlvs = DescriptionSet("TestingTLVs_" + msg_descr.name)

    # Association of test TLVs with GCP messages
    M_NotifyError.add_tlv_set(
        test_gcp_tlv_def.Testing_GCP_TLV_SET_NTF_Error)
    M_NotifyREQ.add_tlv_set(test_gcp_tlv_def.Testing_GCP_TLV_SET_NTF_REQ)


def _tearDownClass():
    """Method sets saved TLVs to be associated with GCP messages."""
    for msg_id, msg_descr in GCP_MSG_SET.child_dict_by_id.items():
        msg_descr.tlvs = _msg_tlvs[msg_id]

    _msg_tlvs.clear()


class TestGCPPacket(unittest.TestCase):
    """Implements unittest for th GCPPacket class."""
    @classmethod
    def setUpClass(cls):
        _setUpClass()

    @classmethod
    def tearDownClass(cls):
        _tearDownClass()

    def test_encap_decap(self):
        packet_enc = GCPPacket()
        packet_dec = GCPPacket()

        packet_enc.transaction_identifier = 11
        packet_enc.protocol_identifier = 22
        packet_enc.unit_id = 33
        packet_enc.length = 1  # just unit ID

        buf = packet_enc.encode()
        self.assertIsNotNone(buf, "Failed to encode packet")

        self.assertTrue(packet_dec.decode(buf, offset=0,
                                          buf_data_len=len(buf)))

        # self.assertTrue(packet_enc._ut_compare(packet_dec))

    def test_packet_notify(self):
        """Packet + Notify(Fields)"""
        packet_enc = GCPPacket()

        packet_enc.transaction_identifier = 11
        packet_enc.protocol_identifier = 22
        packet_enc.unit_id = 33

        # Create message with all fields, without any TLV
        msg = Message(NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)
        packet_enc.msgs.append(msg)
        buf = packet_enc.encode()
        self.assertIsNotNone(buf)

        packet_dec = GCPPacket()
        self.assertEqual(
            packet_dec.decode(buf, offset=0, buf_data_len=len(buf)),
            packet_dec.DECODE_DONE)

        # self.assertTrue(packet_enc._ut_compare(packet_dec))

    def test_packet_two_notifies(self):
        """Packet + Notify(Fields + TLV) + Notify (Fields)"""
        packet_enc = GCPPacket()

        packet_enc.transaction_identifier = 11
        packet_enc.protocol_identifier = 22
        packet_enc.unit_id = 33

        # Create message with all fields and with TLV
        msg = Message(NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)
        packet_enc.msgs.append(msg)
        # Create message with all fields, without any TLV
        msg = Message(NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)
        packet_enc.msgs.append(msg)
        # Encode Packet with both messages
        buf = packet_enc.encode()
        self.assertIsNotNone(buf)

        packet_dec = GCPPacket()
        self.assertEqual(
            packet_dec.decode(buf, offset=0, buf_data_len=len(buf)),
            packet_dec.DECODE_DONE)

        # self.assertTrue(packet_enc._ut_compare(packet_dec))

    def test_packet_all_msg_fields(self):
        """Packet + all messages with all message fields statically."""
        packet_enc = GCPPacket()

        packet_enc.transaction_identifier = 5
        packet_enc.protocol_identifier = 5
        packet_enc.unit_id = 5

        # Notify Request
        msg = Message(NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)
        packet_enc.msgs.append(msg)
        # Notify Response
        msg = Message(NotifyRSP)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0)
        packet_enc.msgs.append(msg)
        # Notify Error
        msg = Message(NotifyError)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.ReturnCode.set_val(GCP_RC_MESSAGE_FAILURE.rc)
        packet_enc.msgs.append(msg)
        # Management Request
        msg = Message(ManagementREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Port.set_val(3)
        msg.msg_fields.Channel.set_val(1)
        msg.msg_fields.Command.set_val(4)
        packet_enc.msgs.append(msg)
        # Management Response
        msg = Message(ManagementRSP)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.Mode.set_val(0)
        msg.msg_fields.ReturnCode.set_val(GCP_RC_SUCCESS.rc)
        packet_enc.msgs.append(msg)
        # Management Error
        msg = Message(NotifyError)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.ReturnCode.set_val(GCP_RC_INV_MODE.rc)
        packet_enc.msgs.append(msg)
        # Data Structures Request
        msg = Message(DataStructREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.Mode.set_val(0)
        msg.msg_fields.Port.set_val(3)
        msg.msg_fields.Channel.set_val(1)
        msg.msg_fields.VendorID.set_val(4)
        msg.msg_fields.VendorIndex.set_val(15)
        packet_enc.msgs.append(msg)
        # Data Structures Response
        msg = Message(DataStructRSP)
        msg.msg_fields.TransactionID.set_val(4)
        msg.msg_fields.Mode.set_val(0)
        msg.msg_fields.Port.set_val(1)
        msg.msg_fields.Channel.set_val(2)
        msg.msg_fields.VendorID.set_val(4)
        msg.msg_fields.VendorIndex.set_val(15)
        packet_enc.msgs.append(msg)
        # Data Structures Error
        msg = Message(DataStructError)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.ExceptionCode.set_val(GCP_RC_INV_MODE.rc)
        packet_enc.msgs.append(msg)

        # Check if all messages were filled
        self.assertEqual(len(packet_enc.msgs),
                         len(GCP_MSG_SET.child_dict_by_id))

        # Encode Packet with both messages
        buf = packet_enc.encode()
        self.assertIsNotNone(buf)

        packet_dec = GCPPacket()
        self.assertEqual(
            packet_dec.decode(buf, offset=0, buf_data_len=len(buf)),
            packet_dec.DECODE_DONE)

        # self.assertTrue(packet_enc._ut_compare(packet_dec))

    def test_packet_notify_scale(self):
        """Packet + 10x Notify(Fields + TLV)"""
        packet_enc = GCPPacket()

        packet_enc.transaction_identifier = 11
        packet_enc.protocol_identifier = 22
        packet_enc.unit_id = 33

        # Create messages and fill them
        for _ in itertools.repeat(None, 10):
            msg = Message(NotifyREQ)
            msg.msg_fields.TransactionID.set_val(5)
            msg.msg_fields.EventCode.set_val(1)
            msg.msg_fields.Mode.set_val(0b10000000)
            msg.msg_fields.Status.set_val(2)
            packet_enc.msgs.append(msg)

        buf = packet_enc.encode()
        self.assertNotEqual(buf, None)

        packet_dec = GCPPacket()
        self.assertEqual(
            packet_dec.decode(buf, offset=0, buf_data_len=len(buf)),
            packet_dec.DECODE_DONE)
        # self.assertTrue(packet_enc._ut_compare(packet_dec))


class TestGCPMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _setUpClass()

    @classmethod
    def tearDownClass(cls):
        _tearDownClass()

    def test_msg_fields_instantiate(self):
        """Tests instantiation of MSG fields for all message IDs."""
        for msg_id, data in GCP_MSG_SET.child_dict_by_id.items():
            MessageFields(msg_id)

    def test_msg_tlv_data_instantiate(self):
        for msg_id, data in GCP_MSG_SET.child_dict_by_id.items():
            TLVData(msg_id)

    def test_tlv_data(self):
        tlv_enc = TLVData(NotifyREQ, unittest=True)
        tlv_enc.TestCapabilities.NumBdirPorts.set_val(4)
        alloc_ds = \
            tlv_enc.TestCapabilities.AllocDsChanResources.add_new_repeated()
        alloc_ds.DsPortIndex.set_val(1)
        alloc_ds.AllocatedDsOfdmChannels.set_val(11)
        alloc_ds.AllocatedDsScQamChannels.set_val(111)

        alloc_ds = \
            tlv_enc.TestCapabilities.AllocDsChanResources.add_new_repeated()
        alloc_ds.DsPortIndex.set_val(2)
        alloc_ds.AllocatedDsOfdmChannels.set_val(22)
        alloc_ds.AllocatedDsScQamChannels.set_val(222)

        alloc_ds = \
            tlv_enc.TestCapabilities.AllocDsChanResources.add_new_repeated()
        alloc_ds.DsPortIndex.set_val(3)
        alloc_ds.AllocatedDsOfdmChannels.set_val(33)
        alloc_ds.AllocatedDsScQamChannels.set_val(333)

        buf = tlv_enc.encode()
        self.assertIsNotNone(buf)

        tlv_dec = TLVData(NotifyREQ, unittest=True)
        self.assertEqual(tlv_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         tlv_dec.DECODE_DONE)
        self.assertTrue(tlv_enc._ut_compare(tlv_dec))

    def test_tlv_data_repeated_negative(self):
        tlv_enc = TLVData(NotifyREQ, unittest=True)
        tlv_enc.TestCapabilities.NumBdirPorts.set_val(4)
        tlv_enc.TestCapabilities.LcceChannelReachability.add_new_repeated()
        buf = tlv_enc.encode()
        self.assertIsNotNone(buf)

        tlv_dec = TLVData(NotifyREQ)
        self.assertEqual(tlv_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         tlv_dec.DECODE_DONE)
        self.assertFalse(tlv_enc._ut_compare(tlv_dec))

    def test_value_constraint(self):
        # Same like previous test, but we set TLV with limited range of values
        tlv_enc = TLVData(NotifyREQ, unittest=True)
        # Bool constraint
        with self.assertRaises(ValueError):
            tlv_enc.TestCapabilities.SupportsUdpEncap.set_val(2)
        sub_tlv = \
            tlv_enc.TestCapabilities.LcceChannelReachability.add_new_repeated()

        # TODO test range constraint
        # with self.assertRaises(ValueError):
        #    sub_tlv.ChannelType.set_val(0)

        # test range constraint <1,10>
        # with self.assertRaises(ValueError):
        #    sub_tlv.ChannelType.set_val(15)

        buf = tlv_enc.encode()
        self.assertIsNone(buf)

        # Range constraint <1,10> - valid value
        sub_tlv.ChannelType.set_val(10)
        buf = tlv_enc.encode()
        self.assertIsNotNone(buf)

    def test_msg_fields(self):
        # set all fields in each message and do encode<=>decode test
        for msg_id in GCP_MSG_SET.child_dict_by_id.keys():
            msg_enc = MessageFields(msg_id)

            # Set all msg fields values to 5
            for idx, field in enumerate(msg_enc._ext_dict.keys()):
                val = idx + 5
                # Valid value for bitfield and enums
                if field in ['Mode', 'ReturnCode']:
                    val = 0
                getattr(msg_enc, field).set_val(val)

            buf = msg_enc.encode()
            self.assertIsNotNone(buf)

            msg_dec = MessageFields(msg_id)
            self.assertEqual(msg_dec.decode(buf, offset=0,
                                            buf_data_len=len(buf)),
                             msg_dec.DECODE_DONE)

            self.assertTrue(msg_enc._ut_compare(msg_dec))

    def test_msg_field_exc(self):
        msg_enc = MessageFields(NotifyREQ)
        # Set all msg fields values to 5
        for field in msg_enc._ext_dict.keys():
            val = 5
            # Valid value for bitfield - MSB is always valid
            if field == 'Mode':
                val = 0b10000000
            getattr(msg_enc, field).set_val(val)
        # Unset first field
        getattr(msg_enc, msg_enc._ext_dict.keys()[0]).unset_val()
        with self.assertRaises(GCPMSGFieldsEncodeError):
            msg_enc.encode()

    def test_msg_fields_static(self):
        msg_enc = MessageFields(NotifyRSP)
        msg_enc.TransactionID.set_val(5)
        msg_enc.EventCode.set_val(1)
        msg_enc.Mode.set_val(0)
        buf = msg_enc.encode()
        self.assertIsNotNone(buf)

        msg_dec = MessageFields(NotifyRSP)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)
        self.assertTrue(msg_enc._ut_compare(msg_dec))

    def test_msg_static(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(NotifyRSP)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0)
        buf = msg.encode()
        self.assertIsNotNone(buf)

        msg_dec = Message(NotifyRSP)
        ret = msg_dec.decode(buf, offset=0, buf_data_len=len(buf))
        self.assertEqual(ret, msg_dec.DECODE_DONE)
        self.assertTrue(msg._ut_compare(msg_dec))

    def test_msg_with_tlv(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(NotifyREQ)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.EventCode.set_val(1)
        msg.msg_fields.Mode.set_val(0b10000000)
        msg.msg_fields.Status.set_val(2)
        msg.tlv_data.TestCapabilities.NumBdirPorts.set_val(1)

        buf = msg.encode()
        self.assertIsNotNone(buf)

        msg_dec = Message(NotifyREQ)
        self.assertEqual(msg_dec.decode(buf, offset=0, buf_data_len=len(buf)),
                         msg_dec.DECODE_DONE)
        self.assertTrue(msg._ut_compare(msg_dec))

    def test_msg_with_unexpected_tlvs(self):
        # Encode message with mandatory fields, decode buffer and compare objs
        msg = Message(NotifyREQ)

        # Try to fill TLV, which is not expected
        with self.assertRaises(AttributeError):
            msg.tlv_data.TestCcapCoreId.Index.set_val(6)

    def test_msg_instantiate(self):
        for msg_id, data in GCP_MSG_SET.child_dict_by_id.items():
            Message(msg_id)

    def TUCtest_msg_instantiation_negative(self):
        """Tests instantiation of Message class for undefined message ID.

        This case should be handled without application crash.

        """
        with self.assertRaises(AttributeError):
            MessageFields(0)
        with self.assertRaises(AttributeError):
            TLVData(0)

        msg = Message(0)
        # TODO following might change
        self.assertIsNotNone(msg,
                             "Message without fields and TLVs should be "
                             "created for undefined message ID")
        self.assertIsNotNone(msg.msg_fields, "Message fields should be None "
                                             "for undefined MSG ID")
        self.assertIsNotNone(msg.tlv_data, "Message's tlv data should be None "
                                           "for undefined MSG ID")
        with self.assertRaises(KeyError):
            Message(255)

    def test_msg_with_tlvs_of_all_classes_negative(self):
        msg = Message(NotifyError)
        msg.msg_fields.TransactionID.set_val(5)
        msg.msg_fields.ReturnCode.set_val(GCP_RC_MESSAGE_FAILURE.rc)

        with self.assertRaises(ValueError):
            # tuple length == 5  expected == 6
            msg.tlv_data.TestCapabilities.TestRpdIdentification. \
                DeviceMacAddress. \
                set_val("01:02:03:04:05")

        with self.assertRaises(ValueError):
            # tuple item 0 <= item <= 255
            msg.tlv_data.TestCapabilities.TestRpdIdentification. \
                DeviceMacAddress.set_val((0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x563))

        with self.assertRaises(ValueError):
            # not tuple
            msg.tlv_data.TestCapabilities.TestRpdIdentification. \
                DeviceMacAddress.set_val("not a MAC address")

        with self.assertRaises(ValueError):
            # not tuple
            msg.tlv_data.TestCapabilities.TestRpdIdentification. \
                DeviceMacAddress.set_val()

        with self.assertRaises(AttributeError):
            msg.tlv_data.TestUsOfdmaSubcarrierCfgState. \
                TestNotDefined.set_val("not defined")


if __name__ == '__main__':
    unittest.main()
