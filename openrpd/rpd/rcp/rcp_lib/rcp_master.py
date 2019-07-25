#!/usr/bin/python
#
# Copyright (c) 2016 Cisco and/or its affiliates, and
#                    Teleste Corporation, and
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

import struct
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.rcp.rcp_lib import rcp
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_object


class RCPMasterSequence(rcp.RCPSequence):

    """Implements RCP sequences and their encoding and decoding methods."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, gcp_message_id, rcp_message_id):
        super(RCPMasterSequence, self).__init__(gcp_message_id, rcp_message_id)

    def _decode_process(self):
        """Implements decoding of RCP sequences.

    :raises RCPSequenceDecodeError:

        """
        if self.get_max_len() < rcp.RCP_SEQUENCE_MIN_LEN:
            raise rcp.RCPSequenceDecodeError(
                "RCP sequence length ({}) is too low, min length "
                "is {} bytes".format(self.get_max_len(), rcp.RCP_SEQUENCE_MIN_LEN))

        # decode sequence and operation
        bulk = [
            ("rcp_seq_type", self.TLV_type_fmt, self.TLV_type_len),
            ("rcp_seq_len", self.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
            ("rcp_seq_num_type", self.TLV_type_fmt, self.TLV_type_len),
            ("rcp_seq_num_len",
             self.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
            ("rcp_seq_num", rcp_tlv_def.C_SequenceNumber_10.format_str,
             rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val()),
            ("rcp_oper_type", self.TLV_type_fmt, self.TLV_type_len),
            ("rcp_oper_len", self.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
            ("rcp_oper", rcp_tlv_def.C_Operation_11.format_str,
             rcp_tlv_def.C_Operation_11.get_tlv_length_val())
        ]

        try:
            ret_bulk = self.unpack_bulk(bulk)
            if not ret_bulk:
                raise rcp.RCPSequenceDecodeError(
                    "Failed to decode sequence header and operation in one bulk")
        except gcp_object.GCPDecodeError:
            self.logger.error("Failed to decode RCP sequence header")
            raise rcp.RCPSequenceDecodeError(
                "Failed to decode RCP sequence header")

        # Check the sequence TLV
        rcp_sequence_tlv_type = ret_bulk["rcp_seq_type"]
        if rcp_sequence_tlv_type != rcp_tlv_def.C_RCPSequence_09.id:
            raise rcp.RCPSequenceDecodeError(
                "Unexpected sequence TLV type: {}".format(
                    rcp_sequence_tlv_type))

        sequence_length = ret_bulk["rcp_seq_len"]
        self.logger.debug(
            "Decoding RCPSequence with length: %u", sequence_length)
        # The sequence number and operation is already unpacked
        sequence_length -= rcp.RCP_SEQUENCE_NUMBER_LEN
        sequence_length -= rcp.RCP_OPERATION_LEN

        if sequence_length > self.get_max_len():
            raise rcp.RCPSequenceDecodeError(
                "RCP sequence length ({}) exceeds over RCP message remaining "
                "length ({})".format(sequence_length, self.get_max_len()))

        # check if this sequence is last sequence of the RCP message
        is_last_sequence = False
        if sequence_length >= self.get_max_len():
            is_last_sequence = True

        # Check and set the sequence number
        tlv_type = ret_bulk["rcp_seq_num_type"]
        if tlv_type != rcp_tlv_def.C_SequenceNumber_10.id:
            raise rcp.RCPSequenceDecodeError(
                "Unexpected Sequence Number TLV type: {}, expected: {}".format(
                    tlv_type, rcp_tlv_def.C_SequenceNumber_10.id))

        tlv_len = ret_bulk["rcp_seq_num_len"]
        if tlv_len != rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val():
            raise rcp.RCPSequenceDecodeError(
                "Unexpected Sequence Number TLV length: {}, "
                "expected: {}".format(
                    tlv_len,
                    rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val()))

        self.seq_number = ret_bulk["rcp_seq_num"]
        self.logger.debug(
            "Decoding RCPSequence with number: %u", self.seq_number)

        # Check and set the operation
        tlv_type = ret_bulk["rcp_oper_type"]
        if tlv_type != rcp_tlv_def.C_Operation_11.id:
            raise rcp.RCPSequenceDecodeError(
                "Unexpected operation TLV type: {}, expected: {}".format(
                    tlv_type, rcp_tlv_def.C_Operation_11.id))

        tlv_len = ret_bulk["rcp_oper_len"]
        if tlv_len != rcp_tlv_def.C_Operation_11.get_tlv_length_val():
            raise rcp.RCPSequenceDecodeError(
                "Unexpected operation TLV length: {}, expected: {}".format(
                    tlv_len, rcp_tlv_def.C_Operation_11.get_tlv_length_val()))

        self.operation = ret_bulk["rcp_oper"]
        if self.operation in rcp_tlv_def.RCP_OPERATION_TYPES:
            self.logger.debug(
                "Decoding RCPSequence with operation type: %s(%u)",
                rcp_tlv_def.RCP_OPERATION_DICT[self.operation],
                self.operation)
        else:
            raise rcp.RCPSequenceDecodeError("Unknown RCP operation: {}".format(
                self.operation))

        # check ResponseCode
        val = struct.unpack_from("!B", self.buffer, self.offset)
        if val[0] == 19:
            self.offset += 4
            sequence_length -= 4

        # decode TLVs inside the sequence
        parent_fmt = rcp_tlv_def.RCP_SEQ_RCP_MSG_TLV_SET_MAPPING[self.rcp_message_id]
        ret = self._fast_decode(parent_fmt, self.parent_gpb, self.offset, sequence_length, 0)

        self.offset += sequence_length  # update the offset

        if ret != gcp_object.GCPObject.DECODE_DONE:
            self.logger.error("RCP message: %s, (%u), Failed to decode TLVs of "
                              "sequence, unexpected result: %u",
                              self.rcp_message_name, self.rcp_message_id, ret)
            return gcp_object.GCPObject.DECODE_FAILED

        if not is_last_sequence:
            return gcp_object.GCPObject.DECODE_NEXT

        return gcp_object.GCPObject.DECODE_DONE


class RCPMasterMessage(rcp.RCPMessage):

    __metaclass__ = AddLoggerToClass

    RCPSequenceClass = RCPMasterSequence

    def __init__(self, gcp_message_id,
                 rcp_message_id=rcp_tlv_def.RCP_MSG_TYPE_NONE):
        super(RCPMasterMessage, self).__init__(gcp_message_id, rcp_message_id)


class RCP_MasterTLVData(rcp.RCP_TLVData):

    """Implements TLVData for RCP protocol.

    Stores RCP messages and implements encoding and decoding methods.

    """

    __metaclass__ = AddLoggerToClass

    RCPMessageClass = RCPMasterMessage

    def __init__(self, gcp_message_id):

        super(RCP_MasterTLVData, self).__init__(gcp_message_id)


class MasterMessage(rcp.Message):

    """Overrides GCP message's behavior of instantiating TLVData.

    RCP_TLVData class is used here.

    """
    __metaclass__ = AddLoggerToClass
    TLVDataClass = RCP_MasterTLVData

    def __init__(self, message_id=0):
        super(MasterMessage, self).__init__(message_id)


class RCPMasterPacket(rcp.RCPPacket):

    """Overrides GCP packet's behavior of instantiating GCP messages.

    The overridden Message class is used here, because it uses RCP
    messages.

    """
    __metaclass__ = AddLoggerToClass
    # Use local Message class implementation
    MessageClass = MasterMessage

    def __init__(self, buffer=None, buf_data_len=None):
        super(RCPMasterPacket, self).__init__(buffer, buf_data_len)
