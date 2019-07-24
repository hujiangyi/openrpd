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


import ctypes
import struct

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.gpb.cfg_pb2 import config as gpb_cfg
from rpd.rcp.gcp.gcp_lib import gcp_tlv_def, gcp_object, gcp_data_description
from rpd.rcp.gcp.gcp_lib.gcp_msg_def import *
from array import array


class GCPTLVEncodeError(gcp_object.GCPEncodeError):
    pass


class GCPTLVDecodeError(gcp_object.GCPDecodeError):
    pass


class GCPMSGFieldsDecodeError(gcp_object.GCPDecodeError):
    pass


class GCPMSGFieldsEncodeError(gcp_object.GCPDecodeError):
    pass


class GCPMessageDecodeError(gcp_object.GCPDecodeError):
    pass


class GCPMessageEncodeError(gcp_object.GCPEncodeError):
    pass


class GCPPacketEncodeError(gcp_object.GCPEncodeError):
    pass


class GCPPacketDecodeError(gcp_object.GCPDecodeError):
    pass


#
# Classes implementing encoding / decoding of the Message and its data
# fields and TLVs.
#
class MessageFields(gcp_object.GCPObject):

    """Represents message fields of one GCP message and implements their
    encoding and decoding."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, message_id):
        if message_id not in GCP_MSG_SET.child_dict_by_id:
            raise AttributeError("Invalid message id passed: %d" % message_id)

        gcp_object.GCPObject.__init__(self)
        self.msg_id = message_id
        self.msg_name = GCP_MSG_SET.child_dict_by_id[message_id].name

        self._ext_dict = None
        try:
            d_add = gcp_object.ValueFormatFlat.create_dict_from_sequence(
                GCP_MSG_SET.child_dict_by_id[message_id].fields)
            if d_add:
                self.__dict__.update(d_add)
                # store the extending dictionary also in the local
                # variable for faster encoding / decoding purposes
                self._ext_dict = d_add

        except KeyError:
            self.logger.warning(
                "Invalid message fields definition or message "
                "id (%u)", message_id)

    def compute_buffer_len(self):
        length = 0
        for name, val_fmt in self._ext_dict.items():
            # use length regardless the value set,
            # because message fields have fixed size
            length += val_fmt.get_fmt().get_len()
        return length

    def _encode_process(self):
        """Implements the encoding of GCP message fields.

        :raises GCPMSGFieldsEncodeError: If encoding failed unexpectedly

        """
        msg_fields = GCP_MSG_SET.child_dict_by_id[self.msg_id].fields
        bulk = []

        # create bulk including all fields
        for field in msg_fields:
            val_fmt = self._ext_dict[field.name]
            if not val_fmt.is_set():
                self.logger.warning(
                    "Encoding message %s (%u) without value set, "
                    "missing field: %s",
                    self.msg_name, self.msg_id, field.name)
            bulk.append((val_fmt.get_val(),
                         val_fmt.get_fmt().format_str,
                         val_fmt.get_fmt().get_len()))

        try:
            ret = self.pack_bulk(bulk)
        except gcp_object.GCPEncodeError:
            self.logger.error("Encoding of message fields of the message "
                              "%s (%u) failed", self.msg_name, self.msg_id)
            raise GCPMSGFieldsEncodeError("Encoding failed")

        if not ret:
            raise GCPMSGFieldsEncodeError(
                "Failed to encode message fields of message: {} ({})".format(
                    self.msg_name, self.msg_id))
        return True

    def _encode_prologue(self, buffer=None, offset=None, buf_data_len=None):
        """Extends the _encode_prologue method of the superclass with check if
        all fields have been set."""
        if not super(MessageFields, self)._encode_prologue(buffer, offset,
                                                           buf_data_len):
            return False

        for field in self._ext_dict.values():
            if not field.is_set():
                raise GCPMSGFieldsEncodeError(
                    "Mandatory fields are not set for message: {} ({})".format(
                        self.msg_name, self.msg_id))
        return True

    def _decode_process(self):
        """Implements decoding of the GCP message fields.

        :raises GCPMSGFieldsDecodeError: If decoding failed unexpectedly.

        """
        msg_fields = GCP_MSG_SET.child_dict_by_id[self.msg_id].fields
        # None: Fragmentation is not considered at this level
        bulk = []

        # create bulk including all fields
        for field in msg_fields:
            val_fmt = self._ext_dict[field.name]
            if val_fmt.is_set():
                self.logger.warning(
                    "Decoding message fields %s (%u) with field %s "
                    "already set to value %s",
                    self.msg_name, self.msg_id,
                    val_fmt.get_fmt().name,
                    val_fmt.get_val())

            bulk.append((val_fmt.get_fmt().name,
                         val_fmt.get_fmt().format_str,
                         val_fmt.get_fmt().get_len()))

        try:
            ret_bulk = self.unpack_bulk(bulk)
        except gcp_object.GCPDecodeError:
            self.logger.error(
                "Decoding of message fields of the "
                "message %s (%u) failed", self.msg_name, self.msg_id)
            raise GCPMSGFieldsDecodeError("Decoding failed")

        if not bulk:
            raise GCPMSGFieldsDecodeError(
                "Decoding of message fields {} ({}) failed".format(
                    self.msg_name, self.msg_id))

        # set decoded values
        for name, value in ret_bulk.items():
            try:
                self._ext_dict[name].set_val(value)
            except gcp_data_description.GCPInvalidDataValueError as ex:
                self.logger.error("Received message %s (%u) "
                                  "with invalid value %u of %s field",
                                  self.msg_name, self.msg_id, value, name)
                return gcp_object.GCPObject.DECODE_FAILED

        return gcp_object.GCPObject.DECODE_DONE

    def _ut_compare(self, obj):  # pragma: no cover
        """Implements comparison of two instances of this class."""
        if not isinstance(obj, MessageFields):
            raise TypeError()

        if len(self._ext_dict) != len(obj._ext_dict):
            self.logger.error(
                "Number of fields doesn't match: this: %u, object: %u",
                len(self._ext_dict), len(obj._ext_dict))
            return False

        ret = True
        name = None
        try:
            for name, val_fmt in self._ext_dict.items():
                if val_fmt.is_set() != obj._ext_dict[name].is_set():
                    self.logger.error("Is_set of %s doesn't match: this: %s, "
                                      "object: %s",
                                      name, val_fmt.is_set(),
                                      obj._ext_dict[name].is_set())
                    ret = False

                if (val_fmt.is_set() and
                        (val_fmt.get_val() != obj._ext_dict[name].get_val())):
                    self.logger.error(
                        "Values of %s doesn't match: this: %s, "
                        "object: %s",
                        name, val_fmt.get_val(),
                        obj._ext_dict[name].get_val())
                    ret = False
        except KeyError as ex:
            self.logger.error("Failed to compare %s: %s", name, ex)
            return False

        return ret


class TLVData(gcp_object.GCPObject):
    """Represents TLV data of one message.

    Implements encoding and decoding of data described by instances of
    DataDescription class.

    """

    __metaclass__ = AddLoggerToClass
    TLV_type_fmt = "!B"
    TLV_type_len = 1  # Byte
    TLV_min_len = 2  # Bytes for type and length fields
    TLV_len_fmts = {
        1: "!B",
        2: "!H"
    }

    # create the buffer
    def _get_tlv_fmts(self):
        """Returns dictionary in format: {TLV_ID: DataDescription} of all TLVs
        which are allowed in the GCP message specified by self.msg_id."""
        return GCP_MSG_SET.child_dict_by_id[self.msg_id].tlvs.child_dict_by_id

    def __init__(self, message_id, parent_gpb=None, tlv_subset=None, unittest=False):
        """Extends the self.__dict__ according to the message_id."""
        if message_id not in GCP_MSG_SET.child_dict_by_id:
            raise AttributeError("Invalid message id passed")

        super(TLVData, self).__init__()
        self.msg_id = message_id  # for debugging
        self.msg_name = GCP_MSG_SET.child_dict_by_id[message_id].name
        self._ext_dict = {}
        if None is parent_gpb:
            # parent is the root of configuration
            if unittest:
                from rpd.rcp.gcp.gcp_lib.cfg_pb2 import config as gpb_cfg_ut
                self.parent_gpb = gpb_cfg_ut()
            else:
                self.parent_gpb = gpb_cfg()
        else:
            self.parent_gpb = parent_gpb

        if None is tlv_subset:
            try:
                tlv_subset = self._get_tlv_fmts()
            except KeyError:
                self.logger.warning(
                    "Failed to get TLV formats for message: %u, name: %s)",
                    self.msg_id, self.msg_name)
                return

        if tlv_subset:
            # Create dictionary to extend items
            self.logger.debug("generate the GPB from the tlv subset.")
            ext_d = gcp_object.ValueFormatGPB.create_dict_from_dict(
                tlv_subset, parent_gpb=self.parent_gpb)
            if not ext_d:
                self.logger.error(
                    "Empty dictionary created from the sequence of message's TLVs for %s (%u)",
                    self.msg_name, self.msg_id)
            else:
                self.__dict__.update(ext_d)
                # store the extending dictionary also in the local
                # variable for faster encoding / decoding purposes
                self._ext_dict = ext_d

    def compute_buffer_len(self):
        length = 0
        if not self._ext_dict:
            return length

        for tlv_name, val_fmt in self._ext_dict.items():
            if val_fmt.is_set() or val_fmt.is_child_set() or val_fmt.is_used:
                length += val_fmt.get_len()

        return length

    def __encode_tlv(self, tlv_val_fmt):
        """Recursively encodes TLVs according to passed format and values.
        True is returned if all TLVs were successfully encoded,
        False otherwise.

        :raises GCPTLVEncodeError: If the encoding failed unexpectedly.

        """
        ret = True
        tlv_type = tlv_val_fmt.get_fmt().id
        len_field_len = tlv_val_fmt.get_fmt().length_field_len
        len_fmt = self.TLV_len_fmts[len_field_len]
        bulk = list()
        bulk.append((tlv_type, self.TLV_type_fmt, self.TLV_type_len))

        self.logger.debug("Encoding TLV(%s): %s",
                          tlv_val_fmt.get_fmt().hierarchy_name,
                          tlv_val_fmt.get_fmt().name)

        # REPEATED FIELDS
        if tlv_val_fmt.is_repeated_fields():
            for repeated_child in tlv_val_fmt.get_repeated_children():
                bulk = list()
                length = tlv_val_fmt.get_fmt().get_len(
                    repeated_child) - self.TLV_type_len - self.TLV_type_len
                bulk.append((tlv_type, self.TLV_type_fmt, self.TLV_type_len))
                bulk.append((length, len_fmt, len_field_len))
                bulk.append((repeated_child,
                             tlv_val_fmt.get_fmt().format_str, length
                             ))
                ret = self.pack_bulk(bulk)

            return ret
        # LEAF
        if tlv_val_fmt.is_leaf():
            if tlv_val_fmt.is_set():
                tlv_len = tlv_val_fmt.get_fmt().get_tlv_length_val(
                    tlv_val_fmt.get_val())
                self.logger.debug("Encoding TLV Leaf: %s, len: %u, val: %s",
                                  tlv_val_fmt.get_fmt().name, tlv_len,
                                  repr(tlv_val_fmt.get_val()))
                bulk.append((tlv_len, len_fmt, len_field_len))
                bulk.append((tlv_val_fmt.get_val(),
                             tlv_val_fmt.get_fmt().format_str,
                             tlv_len))
            else:
                tlv_len = 0
                self.logger.debug("Encoding TLV Leaf without value: %s",
                                  tlv_val_fmt.get_fmt().name)
                bulk.append((tlv_len, len_fmt, len_field_len))

            ret = self.pack_bulk(bulk)
            if not ret:
                self.logger.error("Failed to pack TLV with value set: %s, len: %u, "
                                  "value: %s", tlv_val_fmt.get_fmt().name,
                                  tlv_len, repr(tlv_val_fmt.get_val()))
                return ret
            return ret

        # PARENT
        if tlv_val_fmt.is_nested_parent() or tlv_val_fmt.is_repeated_leaf():
            tlv_len = tlv_val_fmt.get_nested_children_len()
            bulk.append((tlv_len, len_fmt, len_field_len))

            self.logger.debug("Encoding TLV Parent or Repeated Leaf: %s, len: %u",
                              tlv_val_fmt.get_fmt().name, tlv_len)

            # save current offset value for exception handling
            old_offset = self.offset

            ret = self.pack_bulk(bulk)
            if not ret:
                self.logger.error("Failed to pack TLV with children set: %s, len: %u",
                                  tlv_val_fmt.get_fmt().name, tlv_len)
                return ret

            # call this method to pack also children
            if tlv_val_fmt.is_repeated_parent():
                children = tlv_val_fmt.get_repeated_children()
            else:
                children = tlv_val_fmt.get_nested_children()

            for name, child in children.iteritems():
                if child.is_set() or child.is_child_set() or child.is_used:
                    ret = self.__encode_tlv(child)
                    if not ret:
                        self.logger.error("Failed to encode child TLV: %s", name)
                        self.logger.debug("Setting the offset before parent TLV, "
                                          "failed at: %u, reverting to: %u",
                                          self.offset, old_offset)
                        # set the old offset back
                        self.offset = old_offset
                        return ret
            return ret

        # REPEATED
        if tlv_val_fmt.is_repeated_parent():
            tlv_len = tlv_val_fmt.get_repeated_children_len()

            self.logger.debug("Encoding repeated TLVs: %s, len: %u",
                              tlv_val_fmt.get_fmt().name, tlv_len)

            # save current offset value for exception handling
            old_offset = self.offset

            # call this method to pack children
            i = 0
            for repeated_child in tlv_val_fmt.get_repeated_children():
                if (repeated_child.is_set() or
                        repeated_child.is_child_set() or
                        repeated_child.is_used):
                    ret = self.__encode_tlv(repeated_child)
                    if not ret:
                        self.logger.error("Failed to encode child TLV: %u", i)
                        self.logger.debug(
                            "Setting the offset before repeated "
                            "TLV, failed at: %u, reverting to: %u",
                            self.offset, old_offset)
                        # set the old offset back
                        self.offset = old_offset
                        return ret
                i += 1
            return ret

        # this should never happen
        raise GCPTLVEncodeError("Invalid tlv_val_fmt")

    def _encode_process(self):
        """Implements the encoding of TLVs.

        :raises GCPTLVEncodeError: If the encoding failed unexpectedly.

        """
        old_offset = self.offset
        for tlv_name, val_fmt in self._ext_dict.items():
            if val_fmt.is_set() or val_fmt.is_child_set() or \
                    val_fmt.is_used:
                try:
                    ret = self.__encode_tlv(val_fmt)
                except gcp_object.GCPEncodeError:
                    self.logger.error("Encoding of the TLVs failed")
                    raise GCPTLVEncodeError("Encoding of TLVs failed")
                if not ret:
                    self.logger.error("Failed to encode TLV: %s",
                                      val_fmt.get_fmt().name)
                    return ret

        self.logger.debug("Encoded piece of TLV data of %u bytes",
                          self.offset - old_offset)
        return True

    def __get_tlv_format(self, tlv_type, parent_val_fmt):
        """Returns format of the TLV."""
        if None is parent_val_fmt:
            # this is the upper most TLV in the TLVDescriptions hierarchy
            try:
                fmt = self._get_tlv_fmts()[tlv_type]
            except KeyError as ex:
                self.logger.error("Unexpected TLV type (%u), %s", tlv_type, ex)
                raise GCPTLVDecodeError(
                    "Unexpected TLV type: {}".format(tlv_type))

            # check if the TLV is expected int this instance
            if fmt.name not in self._ext_dict:
                raise GCPTLVDecodeError(
                    "Unexpected TLV: {} ({}) for this message".format(
                        fmt.name, tlv_type))

            return fmt
        else:
            # walk all children of the parent and get the format from there
            try:
                fmt = parent_val_fmt.get_fmt().child_dict_by_id[tlv_type]
            except KeyError:
                raise GCPTLVDecodeError(
                    "Failed to find format for TLV type {} in "
                    "parent: {}, ({})".format(
                        tlv_type, parent_val_fmt.get_fmt().name,
                        parent_val_fmt.get_fmt().id))
            return fmt

    def __decode_tlv(self, parent_val_fmt, max_len):
        """Recursively decodes TLV and its subTLVs if exist.

        Decoded values are stored int this instance according to the name
        of TLV. Length of decoded data is returned when passed,
        GCPTLVDecodeError is raised otherwise.

        """
        # first decode the type and length fields
        tlv_type = self.unpack(TLVData.TLV_type_fmt, TLVData.TLV_type_len)
        fmt = self.__get_tlv_format(tlv_type, parent_val_fmt)
        name = fmt.name

        # set the name and tlv_val_fmt
        if None is not parent_val_fmt:
            if (parent_val_fmt.is_nested_parent() or
                    parent_val_fmt.is_repeated_leaf()):
                tlv_val_fmt = parent_val_fmt.get_nested_children()[name]
            elif parent_val_fmt.is_repeated_parent():
                # this is repeated, get the latest repeated child
                # get the latest child
                tlv_val_fmt = parent_val_fmt.get_repeated_children()[-1]
                if not tlv_val_fmt:
                    raise GCPTLVDecodeError("Failed to add new repeated TLV")

                if tlv_val_fmt.is_nested_parent():
                    raise GCPTLVDecodeError(
                        "Repeated parent nested in another repeated parent")

                # now get the concrete item
                tlv_val_fmt = tlv_val_fmt.get_nested_children()[name]
            else:
                raise GCPTLVDecodeError("Leaf TLV can't be a parent")

        else:
            tlv_val_fmt = self._ext_dict[name]

        if None is name or None is tlv_val_fmt:
            raise GCPTLVDecodeError(
                "Unknown TLV type: {}".format(tlv_type))

        len_field_len = tlv_val_fmt.get_fmt().length_field_len
        len_fmt = self.TLV_len_fmts[len_field_len]
        length = self.unpack(len_fmt, len_field_len)

        self.logger.debug("Decoding %s TLV(%s): %s (%u), len: %u",
                          tlv_val_fmt.get_fmt().get_desc_type(),
                          tlv_val_fmt.get_fmt().hierarchy_name,
                          name, tlv_type, length)

        decoded_len = TLVData.TLV_type_len + len_field_len
        if 0 == length:
            # no any value to decode, return length of decoded header
            tlv_val_fmt.set_is_used()
            fmt_str = tlv_val_fmt.get_fmt().format_str
            if fmt_str in DataDescription.DEFAULT_READ_VALUE:
                tlv_val_fmt.set_val(
                    DataDescription.DEFAULT_READ_VALUE[fmt_str], read_op=True)
            return decoded_len

        # check against parrent length constraints
        if length > max_len:
            raise GCPTLVDecodeError(
                "TLV %s (%u) length (%u) exceeds remaining expected "
                "length (%u)" % (name, tlv_type, length, max_len))

        # check agains the local buffer
        if length > self.get_max_len():
            raise GCPTLVDecodeError(
                "TLV %s (%u) length (%u) exceeds ramaing buffer "
                "data laength (%u)" % (name, tlv_type, length,
                                       self.get_max_len()))

        # check if the length is expected for this TLV
        expected_len = tlv_val_fmt.get_fmt().length
        fmt_str = tlv_val_fmt.get_fmt().format_str

        if DataDescription.VARIABLE_LEN == expected_len:
            # length is variable, all lengths higher than zero are expected
            if length == 0:
                # let's don't raise exception, just log warning
                # raise GCP_TLV.GCPTLVDecodeError(
                self.logger.warning(
                    "TLV %s (%u) with unexpected length (%u), more than "
                    "zero is expected", name, tlv_type, length)
            else:
                # set expected_len to length and format to string
                expected_len = length
                fmt_str = "!%us" % length

        elif DataDescription.MAC_FMT == fmt_str:
            if length != expected_len:
                raise GCPTLVDecodeError(
                    "TLV {} ({}) with unexpected length ({}), "
                    "expected {}".format(name, tlv_type, length,
                                         str(expected_len)))

        elif DataDescription.IP_FMT == fmt_str:
            if length not in [DataDescription.B_SEQ_IPv4_LEN,
                              DataDescription.B_SEQ_IPv6_LEN]:
                raise GCPTLVDecodeError(
                    "TLV {} ({}) with unexpected length ({}), "
                    "expected {}".format(name, tlv_type, length,
                                         str(expected_len)))
            expected_len = length

        elif None is expected_len:
            # length is set to None, any length is expected
            pass
        else:
            if length != expected_len:
                raise GCPTLVDecodeError(
                    "TLV {} ({}) with unexpected length ({}), "
                    "expected: {}".format(
                        (name, tlv_type, length, expected_len)))
        if tlv_val_fmt.is_repeated_fields():
            val = self.unpack(fmt_str, length)
            tlv_val_fmt.append_repeated(val)
            decoded_len += length
            self.logger.debug("Decoded %s TLV(%s): %s (%u), len: %u, value: %s",
                              tlv_val_fmt.get_fmt().get_desc_type(),
                              tlv_val_fmt.get_fmt().hierarchy_name,
                              name, tlv_type, length, repr(val))
            return decoded_len

        # Decode the TLV according it's description type
        if tlv_val_fmt.is_leaf():
            # decode value of the TLV
            val = self.unpack(fmt_str, length)
            tlv_val_fmt.set_val(val)
            decoded_len += length
            self.logger.debug("Decoded %s TLV(%s): %s (%u), len: %u, value: %s",
                              tlv_val_fmt.get_fmt().get_desc_type(),
                              tlv_val_fmt.get_fmt().hierarchy_name,
                              name, tlv_type, length, repr(val))
            return decoded_len
        else:
            # decode children of the TLV
            if tlv_val_fmt.is_repeated_parent():
                # create new repeated TLV
                tlv_val_fmt = tlv_val_fmt.add_new_repeated()
                if not tlv_val_fmt:
                    raise GCPTLVDecodeError("Failed to add new repeated TLV")

            decoded_len += length

            while length:
                ret = self.__decode_tlv(tlv_val_fmt, length)
                if ret > length or ret == 0:
                    raise GCPTLVDecodeError(
                        "Unexpected decoded length ({}) returned, remaining "
                        "length: {}, total length: {}".format(
                            (ret, length, decoded_len)))
                length -= ret
            return decoded_len

        # this should never happen
        raise GCPTLVDecodeError("Internal decoding error")

    def _decode_process(self):
        """Implements decoding of TLVs according to their formats.

        Calls __decode_tlv() till all data are decoded.

        :raises GCPTLVDecodeError: If decoding failed unexpectedly

        """
        while self.offset != self.buf_data_len:
            if self.get_max_len() < self.TLV_min_len:
                raise GCPTLVDecodeError(
                    "Remaining TLV data length ({}) is lower than minimal "
                    "length ({})".format(self.get_max_len(), self.TLV_min_len))

            try:
                ret = self.__decode_tlv(None, self.get_max_len())
            except gcp_object.GCPDecodeError:
                self.logger.error("Decoding of TLVs failed")
                raise GCPTLVDecodeError("Failed to decode TLVs")
            except gcp_data_description.GCPInvalidDataValueError:
                self.logger.error("Decoding of TLVs failed, "
                                  "Invalid value received in TLV")
                return gcp_object.GCPObject.DECODE_FAILED

            self.logger.debug("Decoded piece of TLV data of %u bytes", ret)

        return gcp_object.GCPObject.DECODE_DONE

    def __ut_compare_tlv(self, name_self, t_self, t_obj):
        """Recursively compares TLVs."""
        ret = True

        if t_self.get_fmt() != t_obj.get_fmt():
            self.logger.error("TLV %s: formats are not equal", name_self)
            return False

        if t_self.is_set() != t_obj.is_set():
            self.logger.error("TLV %s: is_set doesn't equal", name_self)
            return False

        if t_self.get_fmt() is not t_obj.get_fmt():
            self.logger.error(
                "TLV: different format descriptions for the same "
                "TLV type: this: %s, obj: %s", t_self.get_fmt().name,
                t_obj.get_fmt().name)
            return False

        if (t_self.is_set() and
                (t_self.get_val() != t_obj.get_val())):
            self.logger.error(
                "TLV %s: values doesn't equal: this: %s, obj: %s",
                name_self, t_self.get_val(), t_obj.get_val())
            ret = False

        # compare GPBs
        if ((not t_self.parent_gpb and t_obj.parent_gpb) or
                (t_self.parent_gpb and not t_obj.parent_gpb)):
            self.logger.error(
                "TLV %s: parent gpb inconsistency: this: %s, obj: %s ",
                name_self, t_self.parent_gpb, t_obj.parent_gpb)
            return False

        if not t_self.has_children():
            return ret

        #
        # compare children
        #

        # Leaf
        if t_self.is_leaf():
            self.logger.error("TLV %s: Leaf with children", name_self)
            return False

        # Parent
        if t_self.is_nested_parent() or t_self.is_repeated_leaf():
            if t_self.has_children() != t_obj.has_children():
                self.logger.error(
                    "TLV %s: has_children() doesn't equal", name_self)
                return False

            len_self = len(t_self.get_nested_children())
            len_obj = len(t_obj.get_nested_children())
            if len_self != len_obj:
                self.logger.error(
                    "TLV %s: numbers of children doesn't equal: "
                    "this: %u, obj: %u", name_self, len_self, len_obj)
                return False

            for name, child in t_self.get_nested_children().items():
                try:
                    child_obj = t_obj.get_nested_children()[name]
                except KeyError:
                    self.logger.error(
                        "TLV %s: the compared object has not child: %s",
                        name_self, name)
                    ret = False
                    continue

                r_ret = self.__ut_compare_tlv(name, child, child_obj)
                if not r_ret:
                    self.logger.error("TLV %s: failed compare of child: %s",
                                      name_self, name)
                    ret = False

        # Repeated
        elif t_self.is_repeated_parent():
            # compute number of children which has set value
            len_self = len(t_self.get_repeated_children())
            len_obj = len(t_obj.get_repeated_children())

            if len_self != len_obj:
                self.logger.error(
                    "TLV %s: numbers of repeated children don't "
                    "equal: this: %u, obj: %u",
                    name_self, len_self, len_obj)
                return False

            if len_self == 0:
                return ret

            for this_leaf, obj_leaf in zip(t_self.get_repeated_children(),
                                           t_obj.get_repeated_children()):

                for name, val_fmt in this_leaf.get_nested_children().items():
                    try:
                        obj_val_fmt = obj_leaf.get_nested_children()[name]
                    except KeyError:
                        self.logger.error("TLV %s: compared repeated subTLVs "
                                          "don't have common sutTLV: %s",
                                          name_self, name)
                        ret = False
                        continue

                    # compare the val_fmts of children
                    r_ret = self.__ut_compare_tlv(name, val_fmt, obj_val_fmt)
                    if not r_ret:
                        self.logger.error("TLV %s: Failed to compare child: %s",
                                          name_self, name)
                        ret = False
        # Undefined
        else:
            self.logger.error("TLV %s: Invalid data description type: %s",
                              name_self, t_self.get_fmt().get_desc_type())
            return False
        return ret

    def _ut_compare(self, obj):  # pragma: no cover
        if not isinstance(obj, TLVData):
            raise TypeError()

        if obj is self:
            self.logger.warning("Comparing the same instance")

        # walks all TLVs and subTLVs and compares values
        ret = True

        len_self = len(self._ext_dict)
        len_obj = len(obj._ext_dict)
        if len_self != len_obj:
            self.logger.error("Different number of TLVs, this: %u, obj: %u",
                              len_self, len_obj)
            return False

        for name, tlv in self._ext_dict.items():
            if name not in obj._ext_dict:
                self.logger.error(
                    "There's not TLV named %s in the object", name)
                ret = False
                continue

            tlv_obj = obj._ext_dict[name]
            r_ret = self.__ut_compare_tlv(name, tlv, tlv_obj)
            if not r_ret:
                self.logger.error("Comparison of TLVs named %s FAILED", name)
                ret = False

        return ret


class Message(gcp_object.GCPObject):

    """Class implements GCP message's encoding and decoding."""
    __metaclass__ = AddLoggerToClass
    MSGIDLen = 1  # Byte
    MSGIDFmt = '!B'
    MSGLengthLen = 2  # Bytes
    MSGLengthFmt = '!H'

    MSGMinLen = MSGIDLen + MSGLengthLen

    # set used TLVData class
    TLVDataClass = TLVData

    def __init__(self, message_id=0, base=gcp_tlv_def.GCP_TLV_SET):
        super(Message, self).__init__()
        self.message_id = message_id
        self.message_name = None
        # computed at encode time dynamically
        self.message_len = None
        # Fixed MSG fields object of the MessageFields class
        self.msg_fields = None

        # TLVs included in message, one object of the TLVData class
        self.tlv_data = None

        if 0 != message_id:
            self.logger.debug("New GCP message, message_id %u", message_id)
            self.message_name = GCP_MSG_SET.child_dict_by_id[message_id].name
            self.msg_fields = MessageFields(message_id)
            self.tlv_data = self.TLVDataClass(message_id)

    def compute_buffer_len(self):
        length = self.MSGIDLen + self.MSGLengthLen

        if None is not self.msg_fields:
            length += self.msg_fields.compute_buffer_len()

        if None is not self.tlv_data:
            length += self.tlv_data.compute_buffer_len()

        return length

    def _encode_process(self):
        """Implements encoding of GCP messages.

        :raises GCPMessageEncodeError: If encoding failed unexpectedly.

        """
        # store current offset for exception handling
        old_offset = self.offset
        self.offset += self.MSGIDLen +self.MSGLengthLen

        # encode message fields
        fields_len = 0
        if None is not self.msg_fields:
            fields_len = self.msg_fields.compute_buffer_len()
            try:
                ret = self.msg_fields.encode(self.buffer, self.offset,
                                             self.offset + fields_len)
            except gcp_object.GCPEncodeError as ex:
                self.logger.error("Failed to encode message fields: %s", ex)
                self.offset = old_offset
                return False

            if None is ret:
                self.logger.error(
                    "Failed to encode message fields, nothing encoded")
                self.offset = old_offset
                return False

            self.offset = self.msg_fields.offset

        # encode TLVData
        if None is not self.tlv_data:
            try:
                ret = self.tlv_data.encode(
                    self.buffer, self.offset, GCPPacket.PACKET_LEN_UNLIMITED)
            except gcp_object.GCPEncodeError as ex:
                self.logger.error("Failed to encode message TLV data: %s", ex)
                self.offset = old_offset
                return False

            if None is ret:
                self.logger.error("Failed to encode message's TLV data, "
                                  "nothing encoded")
                self.offset = old_offset
                return False

            self.offset = self.tlv_data.offset

        encoded_len = self.offset - old_offset - self.MSGIDLen - self.MSGLengthLen

        # pack ID and length
        self.offset = old_offset
        try:
            self.pack(self.message_id, self.MSGIDFmt, self.MSGIDLen)
            self.pack(encoded_len, self.MSGLengthFmt, self.MSGLengthLen)
            self.message_len = encoded_len
        except gcp_object.GCPEncodeError:
            self.logger.error("Failed to encode message ID and length")
            raise GCPMessageDecodeError(
                "Failed to encode message ID and length")

        # Done
        self.offset = old_offset+ encoded_len + self.MSGIDLen + self.MSGLengthLen
        return True

    def _decode_process(self):
        """Implements decoding of GCP messages.

        :raises GCPMessageDecodeError: If decoding of message failed
         unexpectedly

        """
        if self.get_max_len() < self.MSGMinLen:
            self.logger.debug(
                "Remaining buffer length (%u) is lower than minimal msg "
                "length (%u), handling as fragmented message",
                self.get_max_len(), self.MSGMinLen)
            return gcp_object.GCPObject.DECODE_FRAGMENTED

        # decode MSG id and length
        try:
            self.message_id = self.unpack(self.MSGIDFmt, self.MSGIDLen)
            try:
                self.message_name = \
                    GCP_MSG_SET.child_dict_by_id[self.message_id].name
            except KeyError:
                self.logger.error("Unknown message ID: %u", self.message_id)
                return gcp_object.GCPObject.DECODE_FAILED

            self.message_len = self.unpack(
                self.MSGLengthFmt, self.MSGLengthLen)
            if self.get_max_len() < self.message_len:
                self.logger.debug(
                    "MSG: %s (%u), Remaining buffer length (%u) is lower "
                    "than message length (%u), handling as fragmented message",
                    self.message_name, self.message_id, self.get_max_len(),
                    self.message_len)
                return gcp_object.GCPObject.DECODE_FRAGMENTED
        except gcp_object.GCPDecodeError:
            self.logger.error("Failed to decode message ID and length")
            raise GCPMessageDecodeError("Failed to decode message ID "
                                        "and length")

        self.logger.debug("Decoding message: %s (%u), len: %u",
                          self.message_name, self.message_id, self.message_len)

        # create message fields and TLVData
        self.msg_fields = MessageFields(self.message_id)
        self.tlv_data = self.TLVDataClass(self.message_id)

        # Decode message fields
        msg_remaining_len = self.message_len
        if None is not self.msg_fields:
            # msg fields have fixed length, we can use the
            # compute_length
            fields_len = self.msg_fields.compute_buffer_len()
            try:
                ret = self.msg_fields.decode(self.buffer, self.offset,
                                             self.offset + fields_len)
            except gcp_object.GCPDecodeError as ex:
                self.logger.error(
                    "MSG: %s (%u), Failed to decode message fields: %s",
                    self.message_name, self.message_id, ex)
                return gcp_object.GCPObject.DECODE_FAILED

            if gcp_object.GCPObject.DECODE_DONE != ret:
                # fragmentation at msg fields level is considered as internal
                # error
                self.logger.error(
                    "MSG: %s (%u), Failed to decode message fields,"
                    "returned status: %s",
                    self.message_name, self.message_id,
                    gcp_object.GCPObject.get_result_str(ret))
                return gcp_object.GCPObject.DECODE_FAILED

            msg_remaining_len = (self.message_len - fields_len)
            self.offset += fields_len

        # Decode message TLVs
        try:
            if 0 != msg_remaining_len:
                if msg_remaining_len < TLVData.TLV_min_len:
                    self.logger.error(
                        "MSG: %s (%u), Remaining message length (%u) is "
                        "lower than minimal TLV length (%u)",
                        self.message_name, self.message_id,
                        msg_remaining_len, TLVData.TLV_min_len)
                    return gcp_object.GCPObject.DECODE_FAILED

                if None is self.tlv_data:
                    self.logger.warning(
                        "MSG: %s (%u), Unexpected TLV data received, "
                        "length: %u, skipping",
                        self.message_name, self.message_id,
                        msg_remaining_len)
                    self.offset += msg_remaining_len

                try:
                    ret = self.tlv_data.decode(self.buffer, self.offset,
                                               self.offset + msg_remaining_len)
                except gcp_object.GCPDecodeError as ex:
                    self.logger.error(
                        "MSG: %s (%u), failed to decode message "
                        "TLV data: %s",
                        self.message_name, self.message_id, ex)
                    return gcp_object.GCPObject.DECODE_FAILED

                if gcp_object.GCPObject.DECODE_DONE != ret:
                    self.logger.error(
                        "MSG: %s (%u), invalid result of TLV data "
                        "decoding: %s",
                        self.message_name, self.message_id,
                        gcp_object.GCPObject.get_result_str(ret))
                    return gcp_object.GCPObject.DECODE_FAILED
                '''
                if msg_remaining_len != self.tlv_data.compute_buffer_len():
                    self.logger.error("MSG: %s (%u), invalid tlv data length "
                              "decoded: %u, expected: %u",
                              self.message_name, self.message_id,
                              self.tlv_data.compute_buffer_len(),
                              msg_remaining_len)
                    return gcp_object.GCPObject.DECODE_FAILED
                '''
            else:
                self.logger.debug("MSG: %s (%u) No any TLV to decode",
                                  self.message_name, self.message_id)
                ret = gcp_object.GCPObject.DECODE_DONE

        except GCPTLVEncodeError:
            self.logger.exception("TLV Data decoding failed")
            return gcp_object.GCPObject.DECODE_FAILED

        self.offset += msg_remaining_len
        if self.offset < self.buf_data_len:
            if self.get_max_len() >= self.MSGMinLen:
                self.logger.debug("There's some next message to decode")
                ret = gcp_object.GCPObject.DECODE_NEXT

        return ret

    def _ut_compare(self, obj):  # pragma: no cover
        if not isinstance(obj, Message):
            raise TypeError()

        # compare name and ID
        if ((self.message_id != obj.message_id) or
                (self.message_name != obj.message_name)):
            self.logger.error("Comparing different messages: this: "
                              "%s (%u), object: %s (%u)",
                              self.message_name, self.message_id,
                              obj.message_name, obj.message_id)
            return False

        # compare lengths
        if self.message_len != obj.message_len:
            self.logger.error("MSG: %s (%u) lengths of messages are not equal: "
                              "this: %u, object: %u",
                              self.message_name, self.message_id,
                              self.message_len, obj.message_len)
            return False

        # compare computed lengths
        comp_len_self = self.compute_buffer_len()
        comp_len_obj = obj.compute_buffer_len()
        if comp_len_obj != comp_len_self:
            self.logger.error("MSG: %s (%u) computed lengths are not equal: "
                              "this: %u, object: %u",
                              self.message_name, self.message_id,
                              comp_len_self, comp_len_obj)
            return False

        # compare fields
        if ((None is self.msg_fields or None is obj.msg_fields) and
                (self.msg_fields != obj.msg_fields)):
            self.logger.error("MSG: %s (%u), one of msg_fields is set to None: "
                              "this: %s, object: %s",
                              self.message_name, self.message_id,
                              self.msg_fields, obj.msg_fields)
            return False

        if None is not self.msg_fields:
            ret = self.msg_fields._ut_compare(obj.msg_fields)
            if not ret:
                self.logger.error("MSG: %s (%u), message fields are not equal",
                                  self.message_name, self.message_id)
                return False

        # compare TLV data
        if ((None is self.tlv_data or None is obj.tlv_data) and
                (self.tlv_data != obj.tlv_data)):
            self.logger.error("MSG: %s (%u) one of tlv data is set to None: "
                              "this: %s, object: %s",
                              self.message_name, self.message_id,
                              self.tlv_data, obj.tlv_data)
            return False

        if None is not self.tlv_data:
            ret = self.tlv_data._ut_compare(obj.tlv_data)
            if not ret:
                self.logger.error("MSG: %s (%u), tlv data are not equal",
                                  self.message_name, self.message_id)
                return False

        return True


class GCPPacket(gcp_object.GCPObject):

    """Represents a GCP packet with it's GCP header and GCP messages.

    Implements GCP packet's encoding and decoding.

    """

    __metaclass__ = AddLoggerToClass
    # Minimal length of the packet is 6 bytes, what is the sum of lengths of
    # the GCP packet header items: Transaction Identifier (2),
    # Protocol Identifier (2) and Length (2).

    PKT_TID_FMT = '!H'
    PKT_TID_LEN = 2  # B
    PKT_PID_FMT = '!H'
    PKT_PID_LEN = 2  # B
    PKT_LEN_FMT = '!H'
    PKT_LEN_LEN = 2  # B
    PKT_UID_FMT = '!B'
    PKT_UID_LEN = 1  # B

    MIN_PACKET_LEN = (PKT_TID_LEN + PKT_PID_LEN + PKT_LEN_LEN + PKT_UID_LEN)
    MAX_PACKET_LEN = 65536
    PACKET_LEN_UNLIMITED = MAX_PACKET_LEN

    PKT_LEN_DIF = 6

    # set used Message class
    MessageClass = Message

    def __init__(self, buffer=None, buf_data_len=None):
        """Buffer including the received GCPPacket may be passed as an
        argument."""
        gcp_object.GCPObject.__init__(self)
        if (None is not buffer) and (None is not buf_data_len):
            # Create the string buffer
            self.buffer = ctypes.create_string_buffer(self.MAX_PACKET_LEN)
            if isinstance(buffer, array):
                self.buffer = buffer[:]
            else:
                ctypes.memmove(self.buffer, buffer, buf_data_len)
            self.buf_data_len = buf_data_len

        # GCP header items
        self.transaction_identifier = None
        self.protocol_identifier = None
        # The Length value from the GCP packet header specifies length of data
        # starting after the Length field of the GCP packet header.
        # (The first field included is the unit_id.)
        self.length = None  # is set during encoding/decoding
        self.unit_id = None

        # List of GCP messages (objects of the Message class)
        self.msgs = []

    def get_missing_len(self):
        """Returns missing length of the data of this GCP packet.

        :raises GCPException: For unexpected packet length

        """
        if ((self.length > self.MAX_PACKET_LEN) or
                (self.length > self.get_buffer_remaining_len())):
            raise GCPException("Unexpected packet length")

        return (self.length + self.PKT_LEN_DIF) - self.buf_data_len

    def get_debug_str(self):
        msgs = (0 if None is self.msgs else len(self.msgs))
        m_str = ""
        if self.msgs:
            m_list = ["{} ({})".format(msg.message_name, msg.message_id)
                      for msg in self.msgs]
            m_str = ', '.join(m_list)

        return "P_ID: {}, T_ID: {}, msgs: {}: {}".format(
            self.protocol_identifier, self.transaction_identifier,
            msgs, m_str)

    def compute_buffer_len(self):
        """Implements the method from GCPObject class."""
        length = self.PKT_TID_LEN + self.PKT_PID_LEN + \
                 self.PKT_LEN_LEN + self.PKT_UID_LEN

        for msg in self.msgs:
            length += msg.compute_buffer_len()
        return length

    def _encode_process(self):
        """Implements the encoding of GCP packets.

        :raises GCPPacketEncodeError: If encoding failed unexpectedly.

        """
        original_offset = self.offset

        self.offset += self.PKT_TID_LEN + self.PKT_PID_LEN + self.PKT_LEN_LEN + self.PKT_UID_LEN
        # encode messages
        for msg in self.msgs:
            try:
                ret = msg.encode(
                    self.buffer, self.offset, self.PACKET_LEN_UNLIMITED)
            except gcp_object.GCPEncodeError as ex:
                self.logger.error("Failed to encode message: %s (%u): %s",
                                  msg.message_name, msg.message_id, ex)
                self.offset = 0
                return False

            if not ret:
                self.logger.error("Failed to encode message %s (%u), nothing "
                                  "encoded.", msg.message_name, msg.message_id)
                self.offset = 0
                return False

            self.offset = msg.offset
            self.logger.debug(
                "Encoded message: %s (%u)", msg.message_name, msg.message_id)

        encoded_len = self.offset - original_offset
        self.length = encoded_len
        self.buf_data_len = self.length
        self.offset = original_offset
        encoded_len -= self.PKT_TID_LEN + self.PKT_PID_LEN + self.PKT_LEN_LEN

        # packet header
        bulk = [
            (self.transaction_identifier, self.PKT_TID_FMT, self.PKT_TID_LEN),
            (self.protocol_identifier, self.PKT_PID_FMT, self.PKT_PID_LEN),
            (encoded_len, self.PKT_LEN_FMT, self.PKT_LEN_LEN),
            (self.unit_id, self.PKT_UID_FMT, self.PKT_UID_LEN)
        ]

        try:
            ret = self.pack_bulk(bulk)
        except gcp_object.GCPEncodeError:
            self.logger.error("Failed to encode packet header")
            raise GCPPacketEncodeError("Failed to encode packet header")

        if not ret:
            self.logger.error("Failed to encode packet header")
            self.buffer = 0
            return False

        self.offset = original_offset + self.length
        return True

    def fast_decode_msg_type(self):
        if self.get_max_len() < self.MIN_PACKET_LEN + 2:
            raise GCPPacketDecodeError(
                "Too short packet to decode: {}, expected: {} bytes".format(
                    self.get_max_len(), self.MIN_PACKET_LEN + 2))
        ret = struct.unpack_from("!B", self.buffer, self.MIN_PACKET_LEN)

        return ret[0]

    @staticmethod
    def is_gdm_msg(msg):
        return msg == M_ManagementREQ.message_id

    def _decode_process(self):
        """Decode GCP packets.

        :return:
         * GCPObject.DECODE_FRAGMENTED if packet is fragmented
         * GCPObject.DECODE_FAILED if error occurred
         * GCPObject.DECODE_DONE if the decoding was successful
         * GCPObject.DECODE_NEXT if decoding was successful with next packet
           in the buffer.
        :raises GCPPacketDecodeError: If decoding failed unexpectedly.

        """

        if self.get_max_len() < self.MIN_PACKET_LEN:
            raise GCPPacketDecodeError(
                "Too short packet to decode: {}, expected: {} bytes".format(
                    self.get_max_len(), self.MIN_PACKET_LEN))

        # create a bulk to be decoded, use an order as IDs
        bulk = list()
        bulk.append((0, self.PKT_TID_FMT, self.PKT_TID_LEN))
        bulk.append((1, self.PKT_PID_FMT, self.PKT_PID_LEN))
        bulk.append((2, self.PKT_LEN_FMT, self.PKT_LEN_LEN))
        bulk.append((3, self.PKT_UID_FMT, self.PKT_UID_LEN))
        try:
            values = self.unpack_bulk(bulk)
        except gcp_object.GCPDecodeError:
            self.logger.error("Failed to decode packet header")
            raise GCPPacketDecodeError("Failed to decode packet header")

        if not values:
            self.logger.error("Failed to unpack packet header")
            return gcp_object.GCPObject.DECODE_FAILED

        self.transaction_identifier = values[0]
        self.protocol_identifier = values[1]
        self.length = values[2]
        self.unit_id = values[3]

        # check if the packet is complete
        if (self.length + self.PKT_LEN_DIF) > self.buf_data_len:
            self.logger.debug(
                "Packet is fragmented, waiting for remaining data.")
            self.offset = 0
            return gcp_object.GCPObject.DECODE_FRAGMENTED

        # decode messages if exists
        expected_offset = (self.offset + (self.length - self.PKT_UID_LEN))
        while self.get_max_len() >= Message.MSGMinLen:

            msg = self.MessageClass()
            ret = msg.decode(self.buffer, self.offset,
                             self.buf_data_len)
            if ret != msg.DECODE_DONE and ret != msg.DECODE_NEXT:
                self.logger.error("Message decode failed, result: %s",
                                  gcp_object.GCPObject.get_result_str(ret))
                return gcp_object.GCPObject.DECODE_FAILED

            self.logger.debug("Decoded message: %s (%u)",
                              msg.message_name, msg.message_id)

            self.msgs.append(msg)
            self.offset += \
                (msg.message_len + Message.MSGIDLen + Message.MSGLengthLen)

            if expected_offset == self.offset:
                break
            elif expected_offset < self.offset:
                raise GCPPacketDecodeError(
                    "Buffer overflow when decoding packet's message")
            self.logger.debug(
                "Continue with decoding of next message, "
                "remaining length: %d", (expected_offset - self.offset))

        # check if all data from current packet are
        if self.offset != expected_offset:
            raise GCPPacketDecodeError(
                "Invalid offset value after the decoding: offset: {}, "
                "expected: {}".format(self.offset, expected_offset))

        if self.MIN_PACKET_LEN <= self.get_max_len():
            self.logger.debug("There is next packet in the buffer.")
            return gcp_object.GCPObject.DECODE_NEXT

        return gcp_object.GCPObject.DECODE_DONE

    def _ut_compare(self, obj):  # pragma: no cover
        if not isinstance(obj, GCPPacket):
            raise TypeError()

        ret = True

        if self.transaction_identifier != obj.transaction_identifier:
            self.logger.error("Transaction ID mismatch: this: %u, object: %u",
                              self.transaction_identifier,
                              obj.transaction_identifier)
            ret = False

        if self.protocol_identifier != obj.protocol_identifier:
            self.logger.error("Protocol ID mismatch: this: %u, object: %u",
                              self.protocol_identifier, obj.protocol_identifier)
            ret = False

        if self.length != obj.length:
            self.logger.error("Lengths mismatch: this: %u, object: %u",
                              self.length, obj.length)
            ret = False

        if self.unit_id != obj.unit_id:
            self.logger.error("Unit IDs mismatch: this: %u, object: %u",
                              self.unit_id, obj.unit_id)
            ret = False

        if not ret:
            return ret

        # compare all messages if exists
        if (self.msgs and not obj.msgs) or (not self.msgs and obj.msgs):
            self.logger.error("Messages mismatch: this: %s, obj: %s",
                              (None if None is self.msgs else len(self.msgs)),
                              (None if None is obj.msgs else len(obj.msgs)))
            return False

        if self.msgs:
            if len(self.msgs) != len(obj.msgs):
                self.logger.error("Number of messages mismatch: this: %u, object: %u",
                                  len(self.msgs), len(obj.msgs))
                return False

        for msg_self, msg_obj in zip(self.msgs, obj.msgs):
            ret = msg_self._ut_compare(msg_obj)
            if not ret:
                self.logger.error("Message %s (%u) mismatch, object: %s (%u).",
                                  msg_self.message_name, msg_self.message_id,
                                  msg_obj.message_name, msg_obj.message_id)
                ret = False

        return ret
