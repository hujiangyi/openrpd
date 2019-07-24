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


import binascii
import struct

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.utils import Convert
from rpd.gpb import rcp_pb2
from rpd.rcp.gcp.gcp_lib import gcp_object, gcp_packet, gcp_msg_def
from rpd.rcp.gcp.gcp_lib.gcp_tlv_def import DataDescription, EnumConstraint
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject


RCP_MSG_HDR_LEN = gcp_packet.TLVData.TLV_type_len + \
                  rcp_tlv_def.RCP_TLV_LENGTH_LEN
RCP_SEQUENCE_HDR_LEN = gcp_packet.TLVData.TLV_type_len + \
                       rcp_tlv_def.RCP_TLV_LENGTH_LEN
RCP_SEQUENCE_NUMBER_LEN = gcp_packet.TLVData.TLV_type_len + \
                          rcp_tlv_def.RCP_TLV_LENGTH_LEN + \
                          rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val()
RCP_OPERATION_LEN = gcp_packet.TLVData.TLV_type_len + \
                    rcp_tlv_def.RCP_TLV_LENGTH_LEN + \
                    rcp_tlv_def.C_Operation_11.get_tlv_length_val()

RCP_SEQUENCE_MIN_LEN = RCP_SEQUENCE_HDR_LEN + \
                       RCP_SEQUENCE_NUMBER_LEN + \
                       RCP_OPERATION_LEN

# The first TLV has to be RCP message with sequence and operation
RCP_MSG_MIN_LEN = RCP_MSG_HDR_LEN + RCP_SEQUENCE_MIN_LEN


#
# RCP exceptions
#
class RCPException(gcp_object.GCPException):
    pass


class RCPEncodeDecodeError(gcp_object.GCPEncodeDecodeError, RCPException):
    pass


class RCPDecodeError(RCPEncodeDecodeError):
    pass


class RCPEncodeError(RCPEncodeDecodeError):
    pass


class RCPMessageEncodeError(RCPEncodeError):
    pass


class RCPMessageDecodeError(RCPDecodeError):
    pass


class RCPSequenceEncodeError(RCPEncodeError):
    pass


class RCPSequenceDecodeError(RCPDecodeError):
    pass


class RCPSequence(gcp_packet.TLVData):
    """Implements RCP sequences and their encoding and decoding methods."""
    __metaclass__ = AddLoggerToClass

    def _get_tlv_fmts(self):
        """Returns dict of allowed TLVs' formats for RCP message specified by
        ID.
        """
        return rcp_tlv_def. \
            RCP_SEQ_RCP_MSG_TLV_SET_MAPPING[self.rcp_message_id]. \
            child_dict_by_id

    def __init__(self, gcp_message_id, rcp_message_id,
                 seq_number=0,
                 operation=rcp_tlv_def.RCP_OPERATION_TYPE_NONE,
                 parent_gpb=None,
                 skip_create_tlv_data=False,
                 unittest=False):

        self.rcp_message_id = rcp_message_id
        self.gcp_message_id = gcp_message_id
        self.seq_number = seq_number
        self.operation = operation
        self._rcp_ext_dict = None
        self.ipc_msg = None
        self.parent_gpb = parent_gpb
        # hold the rsp code, the encode process will use it
        self.rcp_seq_ret_code = None

        try:
            self.gcp_message_name = \
                gcp_msg_def.GCP_MSG_SET.child_dict_by_id[gcp_message_id].name
        except KeyError:
            raise RCPException(
                "Invalid GCP message id: {}".format(gcp_message_id))

        if None is parent_gpb:
            self.ipc_msg = rcp_pb2.t_RcpMessage()
            parent_gpb = self.ipc_msg.RpdDataMessage.RpdData
            self.parent_gpb = parent_gpb
            if (rcp_message_id == 3 or rcp_message_id == 1 or unittest) and not skip_create_tlv_data:
                try:
                    super(RCPSequence, self).__init__(gcp_message_id, parent_gpb=parent_gpb)
                except gcp_object.GCPException as ex:
                    self.logger.exception("Failed to initiate RCP Sequence")
                    raise RCPException(
                        "Failed to instantiate RCPSequence for "
                        "RCP message ({}): {}".format(self.rcp_message_id, ex))
        elif not skip_create_tlv_data:
            try:
                super(RCPSequence, self).__init__(
                    gcp_message_id, parent_gpb=parent_gpb)
            except gcp_object.GCPException as ex:
                self.logger.exception("Failed to initiate RCP Sequence")
                raise RCPException(
                    "Failed to instantiate RCPSequence for "
                    "RCP message ({}): {}".format(self.rcp_message_id, ex))

        if rcp_message_id not in rcp_tlv_def.RCP_MSG_DICT:
            raise AttributeError("Invalid RCP message id passed")

        self.rcp_message_name = rcp_tlv_def.RCP_MSG_DICT[rcp_message_id]

        # check the operation
        if ((operation != rcp_tlv_def.RCP_OPERATION_TYPE_NONE) and
                (operation not in rcp_tlv_def.RCP_OPERATION_TYPES)):
            raise RCPException("Unknown RCP operation: {}".format(operation))

    def _decode_process(self):
        """Implements decoding of RCP sequences.

	:raises RCPSequenceDecodeError:

        """
        if self.get_max_len() < RCP_SEQUENCE_MIN_LEN:
            raise RCPSequenceDecodeError(
                "RCP sequence length ({}) is too low, min length "
                "is {} bytes".format(self.get_max_len(), RCP_SEQUENCE_MIN_LEN))

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
                raise RCPSequenceDecodeError(
                    "Failed to decode sequence header and operation in one bulk")
        except gcp_object.GCPDecodeError:
            self.logger.error("Failed to decode RCP sequence header")
            raise RCPSequenceDecodeError(
                "Failed to decode RCP sequence header")

        # Check the sequence TLV
        rcp_sequence_tlv_type = ret_bulk["rcp_seq_type"]
        if rcp_sequence_tlv_type != rcp_tlv_def.C_RCPSequence_09.id:
            raise RCPSequenceDecodeError(
                "Unexpected sequence TLV type: {}".format(
                    rcp_sequence_tlv_type))

        sequence_length = ret_bulk["rcp_seq_len"]
        self.logger.debug(
            "Decoding RCPSequence with length: %u", sequence_length)
        # The sequence number and operation is already unpacked
        sequence_length -= RCP_SEQUENCE_NUMBER_LEN
        sequence_length -= RCP_OPERATION_LEN

        if sequence_length > self.get_max_len():
            raise RCPSequenceDecodeError(
                "RCP sequence length ({}) exceeds over RCP message remaining "
                "length ({})".format(sequence_length, self.get_max_len()))

        # check if this sequence is last sequence of the RCP message
        is_last_sequence = False
        if sequence_length >= self.get_max_len():
            is_last_sequence = True

        # Check and set the sequence number
        tlv_type = ret_bulk["rcp_seq_num_type"]
        if tlv_type != rcp_tlv_def.C_SequenceNumber_10.id:
            raise RCPSequenceDecodeError(
                "Unexpected Sequence Number TLV type: {}, expected: {}".format(
                    tlv_type, rcp_tlv_def.C_SequenceNumber_10.id))

        tlv_len = ret_bulk["rcp_seq_num_len"]
        if tlv_len != rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val():
            raise RCPSequenceDecodeError(
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
            raise RCPSequenceDecodeError(
                "Unexpected operation TLV type: {}, expected: {}".format(
                    tlv_type, rcp_tlv_def.C_Operation_11.id))

        tlv_len = ret_bulk["rcp_oper_len"]
        if tlv_len != rcp_tlv_def.C_Operation_11.get_tlv_length_val():
            raise RCPSequenceDecodeError(
                "Unexpected operation TLV length: {}, expected: {}".format(
                    tlv_len, rcp_tlv_def.C_Operation_11.get_tlv_length_val()))

        self.operation = ret_bulk["rcp_oper"]
        if self.operation in rcp_tlv_def.RCP_OPERATION_TYPES:
            self.logger.debug(
                "Decoding RCPSequence with operation type: %s(%u)",
                rcp_tlv_def.RCP_OPERATION_DICT[self.operation],
                self.operation)
        else:
            raise RCPSequenceDecodeError("Unknown RCP operation: {}".format(
                self.operation))

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

    def _fast_decode(self, parent_fmt, parent_gpb, offset, length, intent, tl_format="!BH", tl_offset=3):
        """Decode function designed for performance.

        A simple and quick method is used to decode the msg. The decode time
        using the previous regular method takes about 30ms per TLV, which is
        not acceptable. Our target is less than 10ms decode time per TLV.

        :param parent_fmt: This is the TLV define DB, which is TLvDesc, we
         will use the child_dict_by_id top find the TLV definition
        :param parent_gpb: This the process result, we will set the
         corresponding value in gpb.
        :param offset: the buffer offset, relative to beginning of the buffer.
        :param length: the TLV set length.
        :return: True for no any errors, False for Errors

        """
        intent_str = "-" * intent
        # self.logger.debug(intent_str + "fast decode: buffer:%s", binascii.hexlify(self.buffer[offset:offset + length]))
        while length > 0:
            # Unpack the type and length
            (tlv_type, tlv_len) = struct.unpack_from(tl_format, self.buffer, offset=offset)

            # self.logger.debug(intent_str + "fast decode: type:%d, len:%d, val:%s.", tlv_type, tlv_len,
            #                  binascii.hexlify(self.buffer[offset + tl_offset: offset + tl_offset + tlv_len]))

            if tlv_type in parent_fmt.child_dict_by_id:
                fmt = parent_fmt.child_dict_by_id[tlv_type]

                #self.logger.debug(intent_str + "fast decode: get the format from the DB, name: %s, format str:%s, desc:%d",
                #                  fmt.name, fmt.format_str, fmt.desc_type)
                # Also forward a step for the gpb
                if fmt.desc_type == DataDescription.TYPE_REPEATED:
                    #self.logger.debug(intent_str + "fast decode: decode a repeated fields, will enter the recursive loop.")
                    gpb = getattr(parent_gpb, fmt.name).add()
                    if self._fast_decode(fmt, gpb, offset + tl_offset, tlv_len, intent + 4,
                                         tl_format=tl_format, tl_offset=tl_offset) == gcp_object.GCPObject.DECODE_FAILED:

                        self.logger.error(
                            "Cannot decode the TLV %s, len:%d, offset:%d.",
                            fmt.name, tlv_len, offset + tl_offset)
                        return gcp_object.GCPObject.DECODE_FAILED

                elif fmt.desc_type == DataDescription.TYPE_REPEATED_FIELDS:
                    #self.logger.debug(intent_str + "fast decode: decode a repeated leaf.")
                    # For the repeated fields, it's the leaf, we should decode it asap
                    if fmt.format_str not in DataDescription.WELL_KNOWN_LEN:
                        self.logger.error(
                            "Repeated Leaf fields length is not correct: %s, %s",
                            fmt.name, fmt.format_str)
                        return gcp_object.GCPObject.DECODE_FAILED

                    # For the variable len
                    if fmt.value_is_mac():
                        fmt_str = "!%uB" % DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                        val = struct.unpack_from(fmt_str, self.buffer, offset + tl_offset)
                        val = Convert.bytes_to_mac_str(val)
                    elif fmt.value_is_ip_addr():
                        fmt_str = "!%uB" % tlv_len
                        val = struct.unpack_from(fmt_str, self.buffer, offset + tl_offset)
                        val = Convert.bytes_to_ip_addr(val)
                    elif DataDescription.WELL_KNOWN_LEN[fmt.format_str] == DataDescription.VARIABLE_LEN:
                        fmt_str = "!%us" % tlv_len
                        val = struct.unpack_from(fmt_str, self.buffer, offset + tl_offset)
                        val = val[0]
                    else:
                        fmt_str = fmt.format_str
                        val = struct.unpack_from(fmt_str, self.buffer, offset + tl_offset)
                        val = val[0]

                    #self.logger.debug(intent_str + "fast decode: get the value {} for repeated leaf.".format(val))
                    # append the values
                    getattr(parent_gpb, fmt.name).append(val)

                elif fmt.desc_type == DataDescription.TYPE_PARENT:
                    #self.logger.debug(intent_str + "fast decode: decode a parent.")
                    gpb = getattr(parent_gpb, fmt.name)
                    if tlv_len != 0:
                        if self._fast_decode(fmt, gpb, offset + tl_offset, tlv_len, intent + 4,
                                             tl_format=tl_format, tl_offset=tl_offset) == gcp_object.GCPObject.DECODE_FAILED:
                            self.logger.error(
                                "Cannot decode the TLV %s, len:%d, offset:%d.",
                                fmt.name, tlv_len, offset + tl_offset)
                            return gcp_object.GCPObject.DECODE_FAILED
                    else:
                        GCPObject.default_gpb(gpb)

                else:  # For leaf case
                    if tlv_len == 0:
                        if fmt.format_str in DataDescription.DEFAULT_READ_VALUE:
                            if None is not fmt.constraint and isinstance(fmt.constraint, EnumConstraint):
                                val = fmt.constraint.allowed_values.keys()[0]
                            else:
                                val = DataDescription.DEFAULT_READ_VALUE[fmt.format_str]
                            if fmt.value_is_mac():
                                val = Convert.bytes_to_mac_str(val)
                            if fmt.value_is_ip_addr():
                                val = Convert.bytes_to_ip_addr(val)
                            setattr(parent_gpb, fmt.name, val)
                        else:
                            self.logger.error(
                                "Cannot decode the Read TLV %s, len:%d, offset:%d.",
                                fmt.name, tlv_len, offset + tl_offset)
                            return gcp_object.GCPObject.DECODE_FAILED
                    else:
                        # For the variable len
                        if fmt.value_is_mac():
                            fmt_str = "!%uB" % DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                            val = struct.unpack_from(
                                fmt_str, self.buffer, offset + tl_offset)
                            val = Convert.bytes_to_mac_str(val)
                        elif fmt.value_is_ip_addr():
                            fmt_str = "!%uB" % tlv_len
                            val = struct.unpack_from(
                                fmt_str, self.buffer, offset + tl_offset)
                            val = Convert.bytes_to_ip_addr(val)
                        elif DataDescription.WELL_KNOWN_LEN[fmt.format_str] == DataDescription.VARIABLE_LEN:
                            fmt_str = "!%us" % tlv_len
                            val = struct.unpack_from(
                                fmt_str, self.buffer, offset + tl_offset)
                            val = val[0]
                        else:
                            fmt_str = fmt.format_str
                            val = struct.unpack_from(
                                fmt_str, self.buffer, offset + tl_offset)
                            val = val[0]

                        setattr(parent_gpb, fmt.name, val)
            else:
                self.logger.error(
                    "Cannot find the tlv type %d in tlv format %s",
                    tlv_type, parent_fmt.name)

            offset += tl_offset
            offset += tlv_len
            length -= tl_offset
            length -= tlv_len

            # self.logger.debug(intent_str + "fast decode: the length %d, offset;%d", length, offset)

        return gcp_object.GCPObject.DECODE_DONE

    def _fast_encode(self, parent_fmt, parent_gpb, offset, intent):
        """Encode function designed for performance.

        This is to replace ValueFromGPB, which is a clean design but with
        insufficient performance.

        This function will try to encode the TLV first and then return the
        len value, then fill back the length value. Computing the length
        first would be a waste of time. TODO two return values

        :param parent_fmt: This is the TLV define DB, which is TLvDesc,
         we will use the child_dict_by_id top find the TLV definition
        :param parent_gpb: This the process result, we will set the
         corresponding value in gpb.
        :param offset: the buffer offset, relative to beginning of the buffer.
        :return: True for no any errors, False for Errors
        :return: it return a tuple, (error code, length)

        """
        intent_str = "-" * intent
        # self.logger.debug(intent_str + "fast encode: encode the gpb:%s, at offset:%d", parent_gpb, offset)

        gpb_fields = parent_gpb.ListFields()
        encode_len = 0

        for field in gpb_fields:
            field_desc = field[0]
            field_val = field[1]
            ret_encode_len = 0
            #self.logger.debug(intent_str + "fast encode: encode the field %s", field_desc.name)
            if field_desc.name not in parent_fmt.child_dict_by_name:
                #self.logger.error("Cannot find the gpb %s in tlv format %s", field_desc.name, parent_fmt.name)
                return gcp_object.GCPObject.DECODE_FAILED, encode_len

            fmt = parent_fmt.child_dict_by_name[field_desc.name]
            #self.logger.debug(intent_str + "fast encode: get the format from the DB, name: %s, format str:%s, desc:%d",
            #                  fmt.name, fmt.format_str, fmt.desc_type)

            if fmt.desc_type == DataDescription.TYPE_REPEATED: # Repeated parents
                ret_encode_len = 0
                # For every repeated parent
                for repeated_parent_val in field_val:
                    ret_code, repeated_encode_len = self._fast_encode(
                        fmt, repeated_parent_val,
                        offset + 3 + ret_encode_len, intent + 4)
                    if ret_code != gcp_object.GCPObject.DECODE_DONE:
                        self.logger.error(
                            "Cannot encode the gpb %s in tlv format %s",
                            field_val, fmt.name)
                        return gcp_object.GCPObject.DECODE_FAILED, encode_len

                    # Encode the type and the type and length
                    struct.pack_into(
                        "!BH", self.buffer, offset + ret_encode_len,
                        fmt.id, repeated_encode_len)

                    ret_encode_len += 3 + repeated_encode_len

            elif fmt.desc_type == DataDescription.TYPE_REPEATED_FIELDS:
                if not isinstance(field_val, list):
                    self.logger.error(
                        "Cannot encode the gpb %s in tlv format %s, it's type is not expected.",
                        field_val, fmt.name)
                    return gcp_object.GCPObject.DECODE_FAILED, encode_len
                ret_encode_len = 0
                for repeated_leaf_val in field_val: # For every repeated leaf
                    if isinstance(repeated_leaf_val, unicode):
                        repeated_leaf_val = repeated_leaf_val.encode("ascii")
                    if fmt.value_is_mac():
                        fmt_str = "!%uB" % DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                        val = Convert.mac_to_tuple_of_bytes(repeated_leaf_val)
                        val_len = DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                    elif fmt.value_is_ip_addr():
                        val = Convert.ipaddr_to_tuple_of_bytes(
                            repeated_leaf_val)
                        fmt_str = "!%uB" % len(val)
                        val_len = len(val)
                    elif DataDescription.WELL_KNOWN_LEN[fmt.format_str] == DataDescription.VARIABLE_LEN:
                        fmt_str = "!%us" % len(repeated_leaf_val)
                        val = [repeated_leaf_val]
                        val_len = len(repeated_leaf_val)
                    else:
                        fmt_str = fmt.format_str
                        val = [repeated_leaf_val]
                        val_len = DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                    fmt_str = "!BH" + fmt_str
                    ret_val = [fmt.id, val_len]
                    ret_val.extend(val)
                    #self.logger.debug(intent_str + "fast encode: set the value %s for repeated leaf.", str(val))
                    struct.pack_into(fmt_str, self.buffer, offset + ret_encode_len, *ret_val)
                    ret_encode_len += 3 + val_len

            elif fmt.desc_type == DataDescription.TYPE_PARENT:
                # The field val is an gpb object
                next_offset = offset + 3
                ret_code, ret_encode_len = self._fast_encode(
                    fmt, field_val, next_offset, intent + 4)
                if ret_code != gcp_object.GCPObject.DECODE_DONE:
                    self.logger.error(
                        "Cannot encode the gpb %s in tlv format %s",
                        field_val, fmt.name)
                    return gcp_object.GCPObject.DECODE_FAILED, encode_len
                struct.pack_into(
                    "!BH", self.buffer, offset, fmt.id, ret_encode_len)
                ret_encode_len += 3
            else:  # For leaf case
                #self.logger.debug(intent_str + "fast encode: encode a leaf: field name:%s.", fmt.name)
                if isinstance(field_val, unicode):
                    field_val = field_val.encode("ascii")
                if fmt.value_is_mac():
                    fmt_str = "!%uB" % DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                    val = Convert.mac_to_tuple_of_bytes(field_val)
                    ret_encode_len = DataDescription.WELL_KNOWN_LEN[fmt.format_str]
                elif fmt.value_is_ip_addr():
                    val = Convert.ipaddr_to_tuple_of_bytes(field_val)
                    fmt_str = "!%uB" % len(val)
                    ret_encode_len = len(val)
                elif DataDescription.WELL_KNOWN_LEN[fmt.format_str] == DataDescription.VARIABLE_LEN:
                    fmt_str = "!%us" % len(field_val)
                    val = [field_val]
                    ret_encode_len = len(field_val)
                else:
                    fmt_str = fmt.format_str
                    val = [field_val]
                    ret_encode_len = DataDescription.WELL_KNOWN_LEN[fmt.format_str]

                fmt_str = "!BH" + fmt_str[1:]
                ret_val = [fmt.id, ret_encode_len]
                ret_val.extend(val)
                #self.logger.debug(intent_str + "fast encode: set the value %s for leaf, format str:%s",
                #                  str(ret_val), fmt_str)
                struct.pack_into(fmt_str, self.buffer, offset, *ret_val)
                ret_encode_len += 3

            offset += ret_encode_len
            encode_len += ret_encode_len

        return gcp_object.GCPObject.DECODE_DONE, encode_len

    def _encode_process(self):
        """Implements encoding of RCP sequence.

        :raises RCPSequenceEncodeError:

        """
        # encode all TLV data
        ret_code_len = 0
        original_offset = self.offset
        if self.rcp_seq_ret_code is not None:
            struct.pack_into(
                "!BHB", self.buffer, self.offset + RCP_SEQUENCE_MIN_LEN,
                19, 1, self.rcp_seq_ret_code)
            ret_code_len = 4

        tlv_offset = self.offset + RCP_SEQUENCE_MIN_LEN + ret_code_len
        # self.logger.debug("Rcp Sequence-------- encode start:%d", self.offset)

        try:
            parent_fmt = rcp_tlv_def.RCP_SEQ_RCP_MSG_TLV_SET_MAPPING[self.rcp_message_id]
            ret, encode_length = self._fast_encode(parent_fmt, self.parent_gpb, tlv_offset, 0)
            if ret != gcp_object.GCPObject.DECODE_DONE:
                raise gcp_object.GCPEncodeError(
                    "RCP message: %s, (%u), Failed to encode TLVs of sequence, unexpected "
                    "result: %u", self.rcp_message_name,
                    self.rcp_message_id, ret)
        except gcp_object.GCPEncodeError as ex:
            self.logger.error(
                "Failed to encode TLV data of the RCP sequence: %s", ex)
            return False
        # self.logger.debug("Rcp Sequence------Encode Done, self.offset = %d, encoded len:%d", self.offset, encode_length)
        # encode the rcp message header

        length = ret_code_len + encode_length + RCP_SEQUENCE_MIN_LEN - RCP_SEQUENCE_HDR_LEN
        if (length + RCP_SEQUENCE_HDR_LEN) > self.get_max_len():
            raise RCPSequenceEncodeError(
                "There's no enough space to encode RCP seq, required: {} bytes, available: {} "
                "bytes".format((length + RCP_SEQUENCE_HDR_LEN),
                               self.get_max_len()))

        bulk = [
            (rcp_tlv_def.C_RCPSequence_09.id,
             gcp_packet.TLVData.TLV_type_fmt,
             gcp_packet.TLVData.TLV_type_len),
            (length,
             gcp_packet.TLVData.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
            (rcp_tlv_def.C_SequenceNumber_10.id,
             gcp_packet.TLVData.TLV_type_fmt,
             gcp_packet.TLVData.TLV_type_len),
            (rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val(),
             gcp_packet.TLVData.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
            (self.seq_number,
             rcp_tlv_def.C_SequenceNumber_10.format_str,
             rcp_tlv_def.C_SequenceNumber_10.get_tlv_length_val()),
            (rcp_tlv_def.C_Operation_11.id,
             gcp_packet.TLVData.TLV_type_fmt,
             gcp_packet.TLVData.TLV_type_len),
            (rcp_tlv_def.C_Operation_11.get_tlv_length_val(),
             gcp_packet.TLVData.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
            (self.operation, rcp_tlv_def.C_Operation_11.format_str,
             rcp_tlv_def.C_Operation_11.get_tlv_length_val())
        ]

        try:
            ret = self.pack_bulk(bulk)
        except gcp_object.GCPEncodeError:
            self.logger.error("Failed to encode RCP sequence header")
            raise RCPSequenceEncodeError("Failed to encode RCP sequence header")
        if not ret:
            self.logger.error(
                "Failed to encode RCP sequence header and operation TLV")
            return False

        # Update the offset
        self.offset = original_offset + encode_length + RCP_SEQUENCE_MIN_LEN + ret_code_len

        # self.logger.debug("Rcp sequence encode ------Decode Done, self.offset = %d", self.offset)
        return True

    def compute_buffer_len(self):
        length = RCP_SEQUENCE_HDR_LEN
        # TODO add next TLVs which might occur inside the sequence
        length += RCP_OPERATION_LEN
        length += RCP_SEQUENCE_NUMBER_LEN

        length += gcp_packet.TLVData.compute_buffer_len(self)

        return length

    def get_configuration_paths(self):
        """Returns a dictionary including configuration paths."""
        paths = {}
        for val_fmt in self._ext_dict.itervalues():
            path_dict = val_fmt.get_sub_paths()
            if path_dict:
                paths.update(path_dict)
        return paths

    def _ut_compare(self, obj):  # pragma: no cover
        if not isinstance(obj, RCPSequence):
            raise TypeError()

        if self.operation != obj.operation:
            self.logger.error("RCP operation mismatch, this: %u, obj: %u",
                              self.operation, obj.operation)
            return False

        return gcp_packet.TLVData._ut_compare(self, obj)

    def clear_read(self):
        """Clear read flag."""
        for val_fmt in self._ext_dict.itervalues():
            val_fmt.clear_read()


class RCPMessage(gcp_object.GCPObject):

    __metaclass__ = AddLoggerToClass

    RCPSequenceClass = RCPSequence

    def __init__(self, gcp_message_id,
                 rcp_message_id=rcp_tlv_def.RCP_MSG_TYPE_NONE):
        self.gcp_message_id = gcp_message_id
        self.rcp_message_id = rcp_message_id

        super(RCPMessage, self).__init__()

        try:
            self.gcp_message_name = \
                gcp_msg_def.GCP_MSG_SET.child_dict_by_id[gcp_message_id]
        except:
            raise RCPException("Failed to find GCP message name for "
                               "GCP ID: {}".format(self.gcp_message_id))

        try:
            self.rcp_message_name = \
                rcp_tlv_def.RCP_MSG_DICT[self.rcp_message_id]
        except KeyError:
            self.rcp_message_name = None

        self.sequences = []
        self.rcp_message_len = 0

    def _decode_process(self):
        """Implements decoding of RCP message, decodes RCP message type and
        length and all RCP sequences.

        :raises RCPMessageDecodeError:

        """
        # Check the minimal length
        if self.get_max_len() < RCP_MSG_MIN_LEN:
            raise RCPMessageDecodeError(
                "The length of RCP message is too low: {}, expected minimal "
                "length: {}".format(self.get_max_len(), RCP_MSG_MIN_LEN))

        # decode RCP message header
        bulk = [
            ("rcp_msg_type",
             gcp_packet.TLVData.TLV_type_fmt, gcp_packet.TLVData.TLV_type_len),
            ("rcp_msg_len",
             gcp_packet.TLVData.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN)
        ]

        try:
            ret_bulk = self.unpack_bulk(bulk)
        except gcp_object.GCPDecodeError:
            self.logger.error("Failed to decode RCP message TLV header")
            raise RCPMessageDecodeError("Failed to decode RCP message "
                                        "TLV header")

        if not ret_bulk:
            raise RCPMessageDecodeError("Failed to decode RCP message header")

        # Check and set RCP message type and length
        rcp_msg_type = ret_bulk["rcp_msg_type"]
        if rcp_msg_type not in rcp_tlv_def.RCP_MSG_DICT:
            raise RCPMessageDecodeError("Unknown RCP message "
                                        "type: {}".format(rcp_msg_type))

        # check if the RCP msg type is expected in the GCP message
        if rcp_msg_type not in \
                gcp_msg_def.GCP_MSG_SET.child_dict_by_id[self.gcp_message_id]. \
                        tlvs.child_dict_by_id:
            raise RCPMessageDecodeError(
                "Unexpected RCP message: {} ({}) in "
                "the GCP message: {} ({})".format(
                    rcp_tlv_def.RCP_MSG_DICT[rcp_msg_type], rcp_msg_type,
                    self.gcp_message_name, self.gcp_message_id))

        self.rcp_message_id = rcp_msg_type
        self.rcp_message_name = rcp_tlv_def.RCP_MSG_DICT[rcp_msg_type]

        # check the length
        rcp_msg_len = ret_bulk["rcp_msg_len"]
        is_last_rcp_msg = False
        if rcp_msg_len > self.get_max_len():
            raise RCPMessageDecodeError(
                "RCP message {} ({}) length ({}) exceeds over"
                "the remaining length ({})".format(
                    self.rcp_message_name, self.rcp_message_id,
                    rcp_msg_len, self.get_max_len()))
        if rcp_msg_len < RCP_MSG_MIN_LEN:
            raise RCPMessageDecodeError(
                "Too short RCP message: {} bytes, min length "
                "is: {} bytes".format(
                    rcp_msg_len, RCP_MSG_MIN_LEN))

        if rcp_msg_len <= self.get_max_len():
            is_last_rcp_msg = True

        self.rcp_message_len = rcp_msg_len

        # decode sequences
        while rcp_msg_len > RCP_SEQUENCE_MIN_LEN:
            try:
                seq = self.RCPSequenceClass(self.gcp_message_id, self.rcp_message_id)
                ret = seq.decode(self.buffer, self.offset,
                                 self.offset + rcp_msg_len)
                if gcp_object.GCPObject.DECODE_FAILED == ret:
                    raise RCPMessageDecodeError(
                        "Failed to decode RCP sequence")

                decoded_bytes = seq.offset - self.offset
                if not decoded_bytes:
                    raise RCPMessageDecodeError("No any byte of the RCP "
                                                "sequence decoded.")

                # move offset and append the sequence
                rcp_msg_len -= decoded_bytes
                self.offset = seq.offset
                self.sequences.append(seq)

                self.logger.debug("RCP Message: %s (%u), Decoded RCP sequence, "
                                  "operation: %u",
                                  self.rcp_message_name, self.rcp_message_id,
                                  seq.operation)
                if gcp_object.GCPObject.DECODE_NEXT != ret:
                    break

            except Exception as ex:
                self.logger.exception("Failed to decode sequence of RCP msgs")
                raise RCPMessageDecodeError("Failed to decode sequence of RCP "
                                            "messages: {} ({}): {}".format(
                    self.rcp_message_name,
                    self.rcp_message_id,
                    ex))

        if 0 != rcp_msg_len:
            raise RCPMessageDecodeError("No all data of the RCP message were "
                                        "decoded: {} ({}), remaining "
                                        "bytes: {}".format(
                self.rcp_message_name,
                self.rcp_message_id,
                rcp_msg_len))

        if not is_last_rcp_msg:
            return gcp_object.GCPObject.DECODE_NEXT
        return gcp_object.GCPObject.DECODE_DONE

    def _encode_process(self):
        """Implements encoding of RCP message, encodes RCP message type and
        length and all RCP sequences."""
        original_offset = self.offset
        seq_offset = original_offset + 3
        self.offset = seq_offset
        for seq in self.sequences:
            try:
                ret = seq.encode(
                    self.buffer, self.offset,
                    gcp_packet.GCPPacket.PACKET_LEN_UNLIMITED)
            except gcp_object.GCPEncodeError as ex:
                self.logger.error("Failed to encode RCP sequence: %s", ex)
                return False

            if not ret:
                self.logger.error("Failed to encode RCP sequence")
                return False
            self.offset = seq.offset

        # check self.offset to get the encoded length
        encoded_len = self.offset - original_offset - 3
        self.offset = original_offset

        bulk = [
            (self.rcp_message_id, gcp_packet.TLVData.TLV_type_fmt, gcp_packet.TLVData.TLV_type_len),
            (encoded_len, gcp_packet.TLVData.TLV_len_fmts[rcp_tlv_def.RCP_TLV_LENGTH_LEN],
             rcp_tlv_def.RCP_TLV_LENGTH_LEN),
        ]

        try:
            ret = self.pack_bulk(bulk)
        except gcp_object.GCPEncodeError:
            self.logger.error("Failed to encode RCP message TLV header")
            raise RCPMessageEncodeError(
                "Failed to encode RCP message TLV header")

        if not ret:
            raise RCPMessageEncodeError("Failed to encode RCP message header")

        self.offset += encoded_len
        return True

    def compute_buffer_len(self):
        length = RCP_MSG_HDR_LEN

        for seq in self.sequences:
            length += seq.compute_buffer_len()

        return length

    def _ut_compare(self, obj):  # pragma: no cover
        if not isinstance(obj, RCPMessage):
            raise TypeError()

        ret = True

        if self.rcp_message_id != obj.rcp_message_id:
            self.logger.error("RCP message IDs mismatch, this: %u, obj: %u",
                              self.rcp_message_id, obj.rcp_message_id)
            ret = False

        if len(self.sequences) != len(obj.sequences):
            self.logger.error(
                "RCP message's number of sequences mismatch, "
                "this: %u, obj: %u", len(self.sequences), len(obj.sequences))
            ret = False

        if not ret:
            return ret

        for seq_this, seq_obj in zip(self.sequences, obj.sequences):
            ret = seq_this._ut_compare(seq_obj)
            if not ret:
                self.logger.error("RCP sequence of RCP message mismatch")
                return ret

        return ret


#
# RCP Specific classes
#
class RCP_TLVData(gcp_object.GCPObject):

    """Implements TLVData for RCP protocol.

    Stores RCP messages and implements encoding and decoding methods.

    """

    __metaclass__ = AddLoggerToClass

    RCPMessageClass = RCPMessage

    def __init__(self, gcp_message_id):

        super(RCP_TLVData, self).__init__()

        try:
            self.logger.debug("gcp_message_id: %d" % gcp_message_id)
            self.gcp_message_name = \
                gcp_msg_def.GCP_MSG_SET.child_dict_by_id[gcp_message_id]
        except:
            raise RCPException("Failed to assign GCP message name")

        self.gcp_message_id = gcp_message_id
        self.rcp_msgs = []

    def _decode_process(self):
        """Implements decoding of the RCP TLVData.

        :raises RCPDecodeError:

        """
        ret = gcp_object.GCPObject.DECODE_NEXT
        while ret == gcp_object.GCPObject.DECODE_NEXT:
            try:
                rcp_msg = self.RCPMessageClass(self.gcp_message_id)
                ret = rcp_msg.decode(self.buffer, self.offset,
                                     self.buf_data_len)

                if ret == gcp_object.GCPObject.DECODE_FAILED:
                    raise RCPDecodeError("Failed to decode RCP message")

                self.offset += (rcp_msg.rcp_message_len + RCP_MSG_HDR_LEN)
                self.rcp_msgs.append(rcp_msg)

                self.logger.debug(
                    "Decoded RCP message: %s (%u)",
                    rcp_msg.rcp_message_name, rcp_msg.rcp_message_id)

                if ((ret == gcp_object.GCPObject.DECODE_NEXT) and
                        (self.get_max_len() < RCP_MSG_MIN_LEN)):
                    raise RCPDecodeError(
                        "Next RCP message is too short, "
                        "remaining bytes: {}, minimum is: {}".format(
                            self.get_max_len(), RCP_MSG_MIN_LEN))

            except RCPDecodeError as ex:
                self.logger.exception("Failed to decode RCP message")
                raise RCPDecodeError(
                    "Failed to decode RCP message: {}".format(ex))

        if ret != gcp_object.GCPObject.DECODE_DONE:
            self.logger.error("Failed to decode RCP messages of the GCP "
                              "message %s (%u)" %
                              (self.gcp_message_name, self.gcp_message_id))
            return gcp_object.GCPObject.DECODE_FAILED

        return gcp_object.GCPObject.DECODE_DONE

    def _encode_process(self):
        """Implements encoding of the RCP TLVData.

        :raises RCPEncodeError:

        """
        for rcp_msg in self.rcp_msgs:
            ret = rcp_msg.encode(self.buffer, self.offset, gcp_packet.GCPPacket.PACKET_LEN_UNLIMITED)
            if not ret:
                self.logger.error(
                    "Failed to encode RCP message %s (%u)",
                    rcp_msg.rcp_message_name, rcp_msg.rcp_message_id)
                return False

            self.offset = rcp_msg.offset

        return True

    def compute_buffer_len(self):
        length = 0
        for rcp_msg in self.rcp_msgs:
            length += rcp_msg.compute_buffer_len()

        return length

    def _ut_compare(self, obj):  # pragma: no cover
        if not isinstance(obj, RCP_TLVData):
            raise TypeError()

        if len(self.rcp_msgs) != len(obj.rcp_msgs):
            self.logger.error("Number of RCP messages doesn't equal, "
                              "this: %u, obj: %u",
                              len(self.rcp_msgs), len(obj.rcp_msgs))
            return False

        ret = True
        for msg_this, msg_obj in zip(self.rcp_msgs, obj.rcp_msgs):
            if not msg_this._ut_compare(msg_obj):
                ret = False
                self.logger.error("RCP messages comparision failed: "
                                  "this: %s (%u), obj: %s (%u)",
                                  msg_this.rcp_message_name,
                                  msg_this.rcp_message_id,
                                  msg_obj.rcp_message_name,
                                  msg_obj.rcp_message_id)
        return ret


class Message(gcp_packet.Message):

    """Overrides GCP message's behavior of instantiating TLVData.

    RCP_TLVData class is used here.

    """
    __metaclass__ = AddLoggerToClass
    TLVDataClass = RCP_TLVData

    def __init__(self, message_id=0):
        super(Message, self).__init__(message_id)


class RCPPacket(gcp_packet.GCPPacket):

    """Overrides GCP packet's behavior of instantiating GCP messages.

    The overridden Message class is used here, because it uses RCP
    messages.

    """
    __metaclass__ = AddLoggerToClass
    # Use local Message class implementation
    MessageClass = Message

    def __init__(self, buffer=None, buf_data_len=None):
        super(RCPPacket, self).__init__(buffer, buf_data_len)


#
# RCP Packet Builder class
#
RCP_PROTOCOL_ID = 1  # TBD

RCP_RESPONSE_CODE_OK = 0  # TBD
RCP_RESPONSE_CODE_FAILED = 1  # TBD


class RCPPacketBuildError(RCPException):
    pass


class RCPPacketBuilder(object):

    """Defines functions which helps to build RCP packets including GCP and RCP
    messages."""
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.packets = []
        self.last_pkt = None
        self.last_gcp_msg = None
        self.last_rcp_msg = None
        self.last_rcp_sequence = None

    def add_packet(self, transaction_id=0,
                   protocol_id=RCP_PROTOCOL_ID,
                   unit_id=0):
        """Adds new packet into the list of built packets and sets attributes.
        The new packet is stored locally as the last packet and all next new
        GCP messages will be added there.

        :param transaction_id: Transaction identifier to be set for new packet.
        :param protocol_id: Protocol identifier to be set for new packet.
        :param unit_id: ID of unit to be set for new packet.
        :raises AttributeError: If the transaction_id is not specified.

        """
        if None is transaction_id:
            raise AttributeError()
        new_pkt = RCPPacket()
        new_pkt.transaction_identifier = transaction_id
        new_pkt.protocol_identifier = protocol_id
        new_pkt.unit_id = unit_id
        self.last_pkt = new_pkt
        self.packets.append(new_pkt)

    def add_gcp_msg(self, msg_id, transaction_id=None):
        """Adds new GCP message of the msg_id type into the last packet.
        The new message is stored locally as the last GCP message.

        :param msg_id: GCP Message ID.
        :param transaction_id: Transaction identifier to be set for new
         message. Transaction identifier of the last packet is used if the
         parameter is set to None.
        :raises AttributeError: If the msg_id parameter is not set.
        :raises RCPPacketBuildError: If there is not any packet added.

        """
        if None is msg_id:
            raise AttributeError()

        if None is self.last_pkt:
            raise RCPPacketBuildError(
                "Adding GCP message but there's not any packet in builder")

        if None is transaction_id:
            transaction_id = self.last_pkt.transaction_identifier

        new_gcp_msg = Message(msg_id)
        new_gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        self.last_gcp_msg = new_gcp_msg
        self.last_pkt.msgs.append(new_gcp_msg)

    def add_rcp_msg(self, msg_id):
        """Adds new RCP message of the msg_id type into the last GCP message.
        The new RCP message is stored also locally as the last RCP message.

        :param msg_id: The ID of the RCP message.
        :raises AttributeError: If the msg_id is None.
        :raises RCPPacketBuildError: If the is not any GCP message.

        """
        if None is msg_id:
            raise AttributeError()

        if None is self.last_gcp_msg:
            raise RCPPacketBuildError(
                "Adding RCP msg but there's not any GCP msg in builder")

        new_rcp_msg = RCPMessage(self.last_gcp_msg.message_id, msg_id)
        self.last_gcp_msg.tlv_data.rcp_msgs.append(new_rcp_msg)
        self.last_rcp_msg = new_rcp_msg

    def add_rcp_seq(self, seq_number, operation,
                    response_code=None, error_msg=None, gpb_config=None,
                    unittest=False):
        """Adds new RCP sequence in the last RCP message. The new RCP sequence
        is stored locally as the last RCP sequence.

        :param seq_number: The sequence number for the new sequence.
        :param operation: The RCP operation.
        :param response_code: The RCP response code. This argument is optional
         and should be used in responses only.
        :param error_msg: The RCP error message. This argument is optional and
         should be used in responses with some error code only.
        :type error_msg: String
        :param gpb_config: The configuration described as GPB. This will be
         used as the content of the new RCP sequence.
        :raises AttributeError: If the seq_number or operation argument is not
         passed.
        :raises RCPPacketBuildError: If there is not any RCP message in the
         builder.

        """
        if None in (seq_number, operation):
            raise AttributeError()

        if None is self.last_rcp_msg:
            raise RCPPacketBuildError(
                "Adding RCP sequence but there's not any RCP message "
                "in builder")

        new_seq = RCPSequence(self.last_gcp_msg.message_id,
                              self.last_rcp_msg.rcp_message_id,
                              seq_number, operation, gpb_config,
                              unittest=unittest)

        # set also response code and error message if exist
        if None is not response_code:
            new_seq.rcp_seq_ret_code = response_code

        if None is not error_msg:
            new_seq.ErrorMessage.set_val(error_msg)

        self.last_rcp_msg.sequences.append(new_seq)
        self.last_rcp_sequence = new_seq

    def append_rcp_seq(self, seq):
        """Appends already existing RCP sequence as the last added."""
        if not isinstance(seq, RCPSequence):
            raise TypeError()

        seq.rcp_message_id = self.last_rcp_msg.rcp_message_id
        seq.rcp_message_name = self.last_rcp_msg.rcp_message_name
        seq.gcp_message_id = self.last_rcp_msg.gcp_message_id
        seq.gcp_message_name = self.last_rcp_msg.gcp_message_name

        self.last_rcp_msg.sequences.append(seq)
        self.last_rcp_sequence = seq

    def clear(self):
        self.packets = []
        self.last_pkt = None
        self.last_gcp_msg = None
        self.last_rcp_msg = None
        self.last_rcp_sequence = None

    def get_packets(self):
        """Returns resulting list of packets."""
        packets = self.packets
        self.clear()
        return packets
