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

import numbers


class GCPException(Exception):
    """GCP general exception."""


class GCPInternalException(GCPException):
    """GCP internal implementation error exception, indicating bugs in code."""


class GCPInvalidDataValueError(ValueError, GCPException):
    """GCP invalid data value exception."""


class ValueConstraint(object):
    """Class describes interface for constraints of values encoded by GCP
    protocol."""

    def is_value_valid(self, value_to_check):
        """Returns True for valid values, False is returned otherwise."""
        raise NotImplementedError()


class IntValueConstraint(ValueConstraint):
    """Class implements check if the value is unsigned integer number."""

    def is_value_valid(self, value_to_check):
        """Returns True for integer values, False otherwise."""
        if not isinstance(value_to_check, numbers.Integral):
            return False
        return True


class UintValueConstraint(IntValueConstraint):
    """Class implements check if the value is unsigned integer number."""

    def is_value_valid(self, value_to_check):
        """Returns True for unsigned integer values, False otherwise."""
        if not super(UintValueConstraint, self).is_value_valid(value_to_check):
            return False

        if value_to_check < 0:
            return False
        return True


class BitLengthUintConstraint(UintValueConstraint):
    """Class implements check if the value is unsigned integer number with bit
    length lower than or equal to the specified bit length."""

    def __init__(self, bit_length):
        """Stores the maximal bit length."""
        if bit_length <= 0:
            raise AttributeError(
                "Invalid bit_length passed: {}".format(bit_length))
        self.bit_length = bit_length

    def is_value_valid(self, value_to_check):
        """Returns True if the value meets constraints, False otherwise."""
        if not super(BitLengthUintConstraint, self).is_value_valid(
                value_to_check):
            return False
        return value_to_check.bit_length() <= self.bit_length


class EvenConstraint(UintValueConstraint):
    """Class implements check for even values."""

    def __init__(self):
        pass

    def is_value_valid(self, value_to_check):
        """Returns True when the value is even, False is returned for odd
        values."""
        if not super(EvenConstraint, self).is_value_valid(value_to_check):
            return False

        return (value_to_check % 2) == 0


class RangeConstraint(IntValueConstraint):
    """Class implements check for values from some range specified by minimum
    and maximum, both inclusive."""

    def __init__(self, min_val, max_val):
        """Sets boundaries of the range."""
        self.min_val = min_val
        self.max_val = max_val

    def is_value_valid(self, value_to_check):
        """Returns True if the value is included in the range, False
        otherwise."""
        if not super(RangeConstraint, self).is_value_valid(value_to_check):
            return False

        return self.min_val <= value_to_check <= self.max_val


class RangeConstraint2(ValueConstraint):
    """Class implements check for values which can come from two disjunctive
    ranges."""

    def __init__(self, min_val, max_val, min_val2, max_val2,):
        """Stores boundaries of all two ranges."""
        self.range1 = RangeConstraint(min_val, max_val)
        self.range2 = RangeConstraint(min_val2, max_val2)

    def is_value_valid(self, value_to_check):
        """Returns True if the value is included in at least one of ranges.

        False is returned othewise.

        """
        return (self.range1.is_value_valid(value_to_check) or
                self.range2.is_value_valid(value_to_check))


class ByteSequenceConstraint(ValueConstraint):
    """Class implements check if the value is a byte sequence of specified
    length and each item is checked if it's 8bit unsigned integer number."""

    def __init__(self, lengths):
        """Stores number of lengths of the byte sequence.

        :param lengths: One or more allowed lengths of value in bytes.
        :type lengths: int, list(int) or tuple(int)
        :raises AttributeError: invalid length found

        """
        if isinstance(lengths, int):
            lengths = (lengths,)
        if isinstance(lengths, (list, tuple)):
            for length in lengths:
                if length <= 0:
                    raise AttributeError(
                        "Invalid number of lengths passed: {}".format(lengths))
        self.lengths = lengths

    def is_value_valid(self, value_to_check):
        """Returns True if the passed byte sequence is a sequence of N unsigned
        integer bytes (8bit values), where N == self.bytes."""
        if not isinstance(value_to_check, tuple):
            return False

        if len(value_to_check) not in self.lengths:
            return False

        for byte in value_to_check:
            if not BYTE_CONSTR.is_value_valid(byte):
                return False
        return True


class EnumConstraint(ValueConstraint):
    """Implements check if the value is some value form allowed values."""

    def __init__(self, allowed_values):
        self.allowed_values = allowed_values

    def is_value_valid(self, value_to_check):
        return value_to_check in self.allowed_values


class FlagsConstraint(ValueConstraint):
    """Implements check if the value includes only flags specified byt mask."""

    def __init__(self, mask):
        self.mask = mask

    def is_value_valid(self, value_to_check):
        return 0 == value_to_check & ~self.mask


class StringLenConstraint(ValueConstraint):
    """Implements check if the length of string is lower or equal to the
    specified length."""

    def __init__(self, length):
        self.len = length

    def is_value_valid(self, value_to_check):
        return self.len >= len(value_to_check)


class StringLenRangeConstraint(ValueConstraint):
    """Implements check if the length of string is from range specified by
    minimum and maximum both inclusive."""

    def __init__(self, min_len, max_len):
        self.min = min_len
        self.max = max_len

    def is_value_valid(self, value_to_check):
        str_len = len(value_to_check)
        return self.min <= str_len <= self.max


#
# Well Known constraints
#
BOOL_CONSTR = EnumConstraint(allowed_values={0: "False", 1: "True"})
BYTE_CONSTR = BitLengthUintConstraint(bit_length=8)
UINT16_CONSTR = BitLengthUintConstraint(bit_length=16)
UINT32_CONSTR = BitLengthUintConstraint(bit_length=32)
UINT64_CONSTR = BitLengthUintConstraint(bit_length=64)
MAC_CONSTR = ByteSequenceConstraint(lengths=6)
IP_CONSTR = ByteSequenceConstraint(lengths=(4, 16))


class DataDescription(object):
    """Class describes format of data for validation, encoding and decoding
    operations."""
    RW_FLAG_row = "ROW"
    RW_FLAG_key = "KEY"
    RW_FLAG_r = "READ"
    RW_FLAG_rw = "READWRITE"
    RW_FLAG_repeatedFields = "REPEATED FIELD"
    RW_FLAG_row_key = "ROW_KEY"
    RW_FLAG = (RW_FLAG_row,
               RW_FLAG_key,
               RW_FLAG_r,
               RW_FLAG_rw,
               RW_FLAG_repeatedFields,
               RW_FLAG_row_key)

    VARIABLE_LEN = "var"
    # BYTE_SEQ_FMT = "B_SEQ"
    MAC_FMT = "MAC"
    IP_FMT = "IPAddr"
    BYTES_STRING = "bytes"

    B_SEQ_MAC_LEN = 6  # don't use in WELL_KNOWN_LEN
    B_SEQ_IPv4_LEN = 4  # don't use in WELL_KNOWN_LEN
    B_SEQ_IPv6_LEN = 16  # don't use in WELL_KNOWN_LEN

    # well known format : len mapping
    WELL_KNOWN_LEN = {
        "!b": 1,  # signed char
        "!B": 1,  # unsigned char
        "!h": 2,  # short
        "!H": 2,  # unsigned short
        "!i": 4,  # int
        "!I": 4,  # unsigned int
        "!l": 4,  # long
        "!L": 4,  # unsigned long
        "!q": 8,  # long long
        "!Q": 8,  # unsigned long long
        "!2s": 2,
        VARIABLE_LEN: VARIABLE_LEN,  # "!%s" % len(value)
        BYTES_STRING: VARIABLE_LEN,
        # BYTE_SEQ_FMT: BYTE_SEQ_FMT,
        MAC_FMT: B_SEQ_MAC_LEN,
        IP_FMT: IP_FMT,
    }

    # well known format : well known constraint
    WELL_KNOWN_CONSTRAINS = {
        "!B": BYTE_CONSTR,  # unsigned char
        "!H": UINT16_CONSTR,  # unsigned short
        "!I": UINT32_CONSTR,  # unsigned int
        "!Q": UINT64_CONSTR,  # unsigned long long
        MAC_FMT: MAC_CONSTR,
        IP_FMT: IP_CONSTR,
    }

    DEFAULT_WELL_VALUE = {
        "!b": 1,  # signed char
        "!B": 1,  # unsigned char
        "!h": 1,  # short
        "!H": 1,  # unsigned short
        "!i": 1,  # int
        "!I": 1,  # unsigned int
        "!l": 1,  # long
        "!L": 1,  # unsigned long
        "!q": 1,  # long long
        "!Q": 1,  # unsigned long long
        "!2s": 'NA',
        VARIABLE_LEN: "variable",  # "!%s" % len(value)
        BYTES_STRING: "bytes",
        MAC_FMT: (170, 170, 170, 170, 170, 170),
        IP_FMT: (1, 1, 1, 1),
    }
    DEFAULT_READ_VALUE = {
        "!b": 0,
        "!B": 1,  # cannot set 0 due to tlv constraint, EnumConstraint(CHANNEL_TYPE_DICT)
        "!h": 0,
        "!H": 0,
        "!i": 0,
        "!I": 0,
        "!l": 0,
        "!L": 0,
        "!q": 0,
        "!Q": 0,
        "!2s": 'NA',
        VARIABLE_LEN: "",  # read dummy
        BYTES_STRING: "",  # read dummy
        MAC_FMT: (0, 0, 0, 0, 0, 0),
        IP_FMT: (0, 0, 0, 0),
    }
    #
    # Types of the DataDescription instance
    # The DataDescription uses only the LEAF type, because it's not intended
    # to be structured but it might be overridden in subclasses
    #
    # LEAF doesn't have children, can have value
    TYPE_LEAF = 1
    # PARENT has children, which are not repeated, can't have value
    TYPE_PARENT = 2
    # REPEATED has children, which are repeated, can't have value
    TYPE_REPEATED = 3

    TYPE_REPEATED_FIELDS = 4

    def value_is_mac(self):
        """Returns True if the value is a MAC address, False otherwise."""
        if self.format_str == self.MAC_FMT:
            return True
        return False

    def value_is_ip_addr(self):
        """Returns True if the value is a IP address, False otherwise."""
        return self.format_str == self.IP_FMT

    def has_child(self):
        """Returns True for structured instances with some child."""
        return False

    def has_parent(self):
        """Returns True for structured instances with some parent."""
        return False

    def is_repeated(self):
        """Returns True for structured instances which may have more than one
        child."""
        return False

    def get_desc_type(self):
        """Returns the type of instance."""
        return self.TYPE_LEAF

    def __init__(self, identifier, name, format_str, length=None,
                 constraint=None):
        """
        :param identifier: Unique ID of the instance for the current
        hierarchy level
        :param name: Unique name of the instance for the current
        hierarchy level
        :param format_str: String used for packing / unpacking value
        :param length: Expected length of the value, may be passed as tuple
        of expected lengths
        :param constraint: Instance of the ValueConstraint class describing
        which values are allowed

        """
        self.id = identifier
        self.name = name
        self.format_str = format_str
        self.constraint = constraint
        self.length = None
        if None is length:
            if self.format_str in self.WELL_KNOWN_LEN:
                self.length = self.WELL_KNOWN_LEN[self.format_str]
        else:
            self.length = length

    def validate(self, value, implicit_constr=True):
        """Uses constraints to validate the value and raises exception for
        invalid values.

        If the implicit_constr argument is set to True, then if there are not
        explicitly specified constraints the implicit one is used.

        If the implicit_constr is set to False and there are not any explicit
        constraints then the value is not validated.

        If both explicit and implicit constraints exists, only the explicit
        constraints are used for validation.

        :param value: The value to be validated against constraints.
        :param implicit_constr: If set to True, then validation against
         implicit constraints is allowed if the explicit constraints doesn't
         exist.
        :raises InvalidDataValueError: When the value is invalid according to
        constraints.

        """

        # use the explicitly specified constraints if exist
        if None is not self.constraint:
            if not self.constraint.is_value_valid(value):
                raise GCPInvalidDataValueError(
                    "Value {} is not valid according to explicit "
                    "constraints".format(value))

        if implicit_constr and self.format_str in self.WELL_KNOWN_CONSTRAINS:
            constr = self.WELL_KNOWN_CONSTRAINS[self.format_str]
            if not constr.is_value_valid(value):
                raise GCPInvalidDataValueError(
                    "Value {} is not valid according to implicit "
                    "constraints".format(value))

    def get_len(self, value=None):
        """Returns length of the data described by instance of this class. Zero
        is returned for unknown/unspecified length.

        If the length is variable, then the length of value argument is
        returned if exists.

        """

        if None is not value:
            # return length of the value if set and if the length is variable
            if self.VARIABLE_LEN == self.length:
                return len(value)

            if self.format_str in [self.MAC_FMT, self.IP_FMT]:
                return len(value)

        return self.length if self.length is not None else 0

    def get_nested_descriptions(self):
        """Returns list or dictionary of nested descriptions if exists."""
        return None


class DescriptionSet(object):
    """Class represents a set of descriptions of the same level with some
    common characteristic."""

    def __init__(self, hierarchy_name="Base", id=0):
        self.child_dict_by_name = {}
        self.child_dict_by_id = {}
        self.hierarchy_name = hierarchy_name
        self.name = hierarchy_name # name is used within _fast_decode
        self.id = id

    def insert_description(self, desc_id, desc_name, desc):
        """Inserts new data description into the dictionaries. Sanity checks
        are performed before the insertion.

        :param desc_id: Identifier of the description
        :param desc_name: Name of the description (human readable)
        :raises AttributeError: If the desc parameter is not object of the
         DataDescription class.
        :raises GCPInternalException: If the description is already inserted in
        some dictionary.

        """

        if not isinstance(desc, DataDescription):
            raise AttributeError()

        if desc_id in self.child_dict_by_id:
            raise GCPInternalException(
                "Description %s, (%u) already inserted in ID mapping for %s",
                desc_name, desc_id, self.hierarchy_name)

        if desc_name in self.child_dict_by_name:
            raise GCPInternalException(
                "Description %s, (%u) already inserted in name mapping for %s",
                desc_name, desc_id, self.hierarchy_name)

        self.child_dict_by_id[desc_id] = desc
        self.child_dict_by_name[desc_name] = desc

    def update_descriptions(self, description_set):
        """Updates dictionaries with dictionaries of another instance of the
        DescriptionSet class.

        :param description_set: Instance of the DescriptionSet class.
        :raises AttributeError: If the parameter is not instance of the
         DescriptionSet class.
        :raises GCPInternalException: If some description from the description
        set is already stored in this instance (self).

        """

        if not isinstance(description_set, DescriptionSet):
            raise AttributeError()

        for desc_id, desc in description_set.child_dict_by_id.iteritems():
            if desc_id in self.child_dict_by_id:
                raise GCPInternalException(
                    "Description %s, (%u) already in ID mapping "
                    "for %s", desc.name, desc_id, self.hierarchy_name)

        for desc_name, desc in description_set.child_dict_by_name.iteritems():
            if desc_name in self.child_dict_by_name:
                raise GCPInternalException(
                    "Description %s, (%u) already in name mapping for %s",
                    desc_name, desc.id, self.hierarchy_name)

        self.child_dict_by_id.update(description_set.child_dict_by_id)
        self.child_dict_by_name.update(description_set.child_dict_by_name)
