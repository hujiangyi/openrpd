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
from rpd.rcp.gcp.gcp_lib.gcp_data_description import DataDescription, GCPException, GCPInternalException
from rpd.common.utils import Convert
from rpd.common.rpd_logging import AddLoggerToClass


class GCPInternalValueFormatError(GCPInternalException):
    """Exception is used in case of internal error related to the ValueFormat
    class instances."""


class GCPEncodeDecodeError(GCPException):
    """General exception for encoding and decoding of GCP protocol data."""


class GCPEncodeError(GCPEncodeDecodeError):
    """Exception for encoding of GCP protocol data."""


class GCPDecodeError(GCPEncodeDecodeError):
    """Exception for decoding of GCP protocol data."""


class ValueFormatStorage(object):  # pragma: no cover
    """Class describes hierarchical storage for values and their data formats.

    This class is not intended to be directly instantiated.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self, fmt):
        """
        :param fmt: Format of the data described by DataDescription
        instance.

        """
        if not isinstance(fmt, DataDescription):
            raise TypeError()

        self.format = fmt
        self.format_desc = self.format.get_desc_type()

    def get_fmt(self):
        """Returns description of the data format of the value."""
        return self.format

    def get_format(self):
        """Returns description of the data format of the value."""
        return self.format

    def get_val_len(self):
        """Returns number of bytes which are needed to encode only the
        value."""
        raise NotImplementedError()

    def get_len(self):
        """Returns number of bytes which are needed to encode the value and all
        related values."""
        raise NotImplementedError()

    def is_set(self):
        """Returns True if the value is set, False otherwise."""
        raise NotImplementedError()

    def set_val(self, value=None):
        """Sets the value."""
        raise NotImplementedError()

    def unset_val(self):
        """Unsets the value."""
        raise NotImplementedError()

    def get_val(self):
        """Returns the value."""
        raise NotImplementedError()

    @staticmethod
    def create_dict_from_sequence(fmt_sequence):
        """Creates dictionary from the sequence of DataDescription objects.

        Name of every object is used as key and instance of ValueFormat class
        is value.

        Returns: dict(name : ValueFormat)

        """
        raise NotImplementedError()

    @staticmethod
    def create_dict_from_dict(fmt_dict):
        """Creates dictionary from the dictionary of DataDescription objects.

        Name of every object is used as key and instance of ValueFormat class
        is value.

        Returns: dict(name : ValueFormat)

        """
        raise NotImplementedError()


class ValueFormatFlat(ValueFormatStorage):  # pragma: no cover
    """Class stores values with related format described by instances of the
    DataDescription class.

    Describes non-hierarchical data.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self, fmt):
        """
        :param fmt: Format of the data
        :type fmt: DataDescription

        """
        super(ValueFormatFlat, self).__init__(fmt)

        self.value = None
        self.is_val_set = False

    def __str__(self):
        return "(is_set: {}, val: {})".format(self.is_val_set, self.value)
    __repr__ = __str__

    def get_len(self):
        """Returns number of bytes which are needed to encode the value and all
        related values."""
        return self.get_val_len()

    def get_val_len(self):
        """Returns number of bytes which are needed to encode only the
        value."""
        if self.is_val_set:
            return self.format.get_len(self.value)
        return 0

    def is_set(self):
        """Returns True if the value is set, False otherwise."""
        return self.is_val_set

    def set_val(self, value=None):
        """The value is validated and is stored locally, if it's valid.

        :raises GCPInvalidDataValueError: For invalid values.

        """
        self.format.validate(value)
        self.value = value
        self.is_val_set = True

    def unset_val(self):
        self.value = None
        self.is_val_set = False

    def get_val(self):
        if self.is_val_set:
            return self.value
        else:
            return None

    @staticmethod
    def create_dict_from_sequence(fmt_sequence):
        """Creates dictionary from the sequence of DataDescription objects.

        Name of every object is used as key and instance of ValueFormat class
        is value.

        Returns: dict(name : ValueFormat)

        """
        if (not isinstance(fmt_sequence, list) and
                not isinstance(fmt_sequence, tuple)):
            raise TypeError()

        d = dict()
        for fmt in fmt_sequence:
            val_fmt = ValueFormatFlat(fmt=fmt)
            d[fmt.name] = val_fmt

        return d

    @staticmethod
    def create_dict_from_dict(fmt_dict):
        """Creates dictionary from the dictionary of DataDescription objects.

        Name of every object is used as key and instance of ValueFormat class
        is value.

        Returns: dict(name : ValueFormat)

        """
        if not isinstance(fmt_dict, dict):
            raise TypeError()

        d = dict()
        for fmt in fmt_dict.values():
            val_fmt = ValueFormatFlat(fmt=fmt)
            d[fmt.name] = val_fmt

        return d


class ValueFormatGPB(object):  # pragma: no cover
    """Class stores values with related format described by instances of the
    DataDescription class.

    Instances can create a hierarchy in which several types of instances
    are defined:
    * Leaf: Has a value, has one parent of type
      NestedParent or RepeatedLeaf
      and doesn't have any child.
    * NestedParent: Can't have value set, has at least one child,
      may have one parent of type NestedParent or RepeatedLeaf.
    * RepeatedParent: Can't have value set, may have multiple children of
      the type RepeatedLeaf and they must have common format.
      It's children are not created in advance. They must be
      added dynamically by add_new_repeated() method.
      May have one parent NestedParent or RepeatedLeaf.
    * RepeatedLeaf:
      Can't have value set, may have multiple children.
      It must have one parent of the RepeatedLeaf type.
      Format of the data is set to the parent's format.

    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, fmt, parent_gpb, parent=None):
        """
        :param fmt: Format of the data described by DataDescription
        :param parent: Instance of this class which is a parent for this
         instance.
        :param parent_gpb: GPB message including parent's data
        :raises GCPInternalValueFormatError: If the parent_gpb is not set.
        :raises GCPInvalidDataValueError: For invalid values set in the
         parent_gpb.
        """
        self.format = fmt
        self._children_used = 0  # how many children are set
        # reference to the parent instance, if this is it's child
        self.parent = parent
        self._nested_vals = None  # children

        # FixMe: add for identify Reading operation
        self.read_used = False
        self.is_used = False
        self.value = None
        self.format_desc = self.format.get_desc_type()
        self.is_set_cache = False

        if None is parent_gpb or not hasattr(parent_gpb, fmt.name):
            self.logger.debug("Parent GPB without attribute: %s", fmt.name)
            self.parent_gpb = None
        else:
            self.parent_gpb = parent_gpb

            # If this is a leaf, then check if the value is set in the GPB and
            # set the is_val_set flag and set also the self.value
            if DataDescription.TYPE_LEAF == self.format_desc:
                if self.parent_gpb.HasField(fmt.name):
                    self.set_is_used()

                    # Validate the value
                    val = getattr(self.parent_gpb, fmt.name)
                    self.format.validate(val, implicit_constr=False)

    def __str__(self):
        return "(is_set: {}, nest: {}, val: {})".format(
            self.is_set(),
            (None if None is self.format else
                not not self.format.get_nested_descriptions()),
            self.get_val())
    __repr__ = __str__

    def get_fmt(self):
        """Returns description of the data format of the value."""
        return self.format

    def get_format(self):
        """Returns description of the data format of the value."""
        return self.format

    def _to_gpb_value(self, value):
        """Converts the value into the GPB representation according to
        format."""
        if self.format.value_is_mac():
            return Convert.bytes_to_mac_str(value)
        if self.format.value_is_ip_addr():
            return Convert.bytes_to_ip_addr(value)
        return value

    def get_sub_paths(self):
        """Creates a config path from itself."""
        if not (self.is_used or self.is_set() or self.is_child_set()):
            return None

        res_sub_dict = {}
        res_dict = {self.format.name: res_sub_dict}

        if self.is_leaf():
            return {self.format.name: None}
        elif self.is_nested_parent() or self.is_repeated_leaf():
            if self.is_repeated_parent():
                children = self.get_repeated_children()
            else:
                children = self.get_nested_children()

            for child in children.itervalues():
                res = child.get_sub_paths()
                if None is not res:
                    res_sub_dict.update(res)

            if not res_sub_dict:
                res_dict[self.format.name] = None

            return res_dict
        elif self.is_repeated_parent():
            if not self.get_repeated_children_len():
                res_dict[self.format.name] = None
                return res_dict

            for child in self.get_repeated_children():
                res = child.get_sub_paths()
                if None is not res:
                    res_sub_dict.update(res)

            if not res_sub_dict:
                res_dict[self.format.name] = None
            return res_dict

        # this should never happen
        raise GCPInternalException("Invalid ValueFormat node type")

    def clear_read(self):
        """Clear the read_used from itself."""
        if not (self.is_used or self.is_set() or self.is_child_set()):
            return

        if self.is_leaf():
            self.unset_read()
            return
        elif self.is_nested_parent() or self.is_repeated_leaf():
            if self.is_repeated_parent():
                children = self.get_repeated_children()
            else:
                children = self.get_nested_children()

            for child in children.itervalues():
                child.clear_read()
            return
        elif self.is_repeated_parent():
            if not self.get_repeated_children_len():
                return

            for child in self.get_repeated_children():
                child.clear_read()
            return

    def is_repeated_leaf(self):
        """Returns True if this instance is RepeatedLeaf, False otherwise."""
        if (self.format_desc == DataDescription.TYPE_REPEATED and
                self.parent and
                self.parent.format == self.format):
            return True
        return False

    def is_repeated_parent(self):
        """Returns True if this instance is RepeatedParent, False otherwise."""
        if self.format_desc == DataDescription.TYPE_REPEATED:
            if not self.parent:
                return True
            if self.parent.format != self.format:
                return True
        return False

    def is_repeated_fields(self):
        if self.format_desc == DataDescription.TYPE_REPEATED_FIELDS:
            return True
        return False

    def is_nested_parent(self):
        """Returns True if this instance is NestedParent, False otherwise."""
        if self.format_desc == DataDescription.TYPE_PARENT:
            return True
        return False

    def is_leaf(self):
        """Returns True if this instance is Leaf, False otherwise"""
        if self.format_desc == DataDescription.TYPE_LEAF:
            return True
        return False

    def get_len(self):
        """Returns sum of its length and lengths of all its children."""
        length = 0
        if self.is_leaf():
            if self.is_set() and not self.is_read():
                length = self.get_val_len()
            else:
                length = self.get_fmt().TLV_TYPE_LEN + self.get_fmt().length_field_len
            return length

        if self.is_nested_parent() or self.is_repeated_leaf():
            length = self.get_val_len()
            length += self.get_nested_children_len()
            return length

        if self.is_repeated_parent():
            length += self.get_repeated_children_len()
            return length

        if self.is_repeated_fields():
            for v in self._nested_vals:
                length += self.get_fmt().get_len(v)

            return length

    def get_nested_children_len(self):
        """Returns sum of lengths of its children. May be called only for
        NestedParent or RepeatedLeaf instance.

        :raises GCPInternalValueFormatError: If this method is called for
         invalid type of instance.

       """
        if not self.is_nested_parent() and not self.is_repeated_leaf():
            self.logger.error("Unexpected type of instance")
            raise GCPInternalValueFormatError(
                "Method called for invalid type of instance")
        length = 0
        if self.has_children() and self.is_child_set():
            for name, child in self._nested_vals.items():
                if child.is_set() or child.is_child_set() or child.is_used:
                    length += child.get_len()
        return length

    def get_repeated_children_len(self):
        """Returns sum of lengths of its children. May be called only for
        RepeatedParent instance.

        :raises GCPInternalValueFormatError: If this method is called for
         invalid type of instance.

        """
        if not self.is_repeated_parent():
            self.logger.error("Unexpected type of instance")
            raise GCPInternalValueFormatError(
                "Method called for invalid type of instance")
        length = 0
        if self.has_children() and self.is_child_set():
            for repeated_val_fmt in self._nested_vals:
                if (repeated_val_fmt.is_set() or
                        repeated_val_fmt.is_child_set() or
                        repeated_val_fmt.is_used):
                    length += repeated_val_fmt.get_len()
        return length

    def get_val_len(self):
        # TODO this should return only a length of the value
        # but for TLVs it returns length of complete TLV
        if self.is_set() or self.has_children():
            return self.format.get_len(self.get_val())
        return 0

    def get_parent(self):
        return self.parent

    def is_set_inline(self):
        if not self.is_leaf():
            return False
        if None is not self.parent_gpb:
            return self.parent_gpb.HasField(self.format.name)
        else:
            return None is not self.value

    def is_set(self):
        return self.is_set_cache

    def is_read(self):
        """Return True if the operation is Read."""
        return self.read_used

    def unset_read(self):
        """Unset this read request flag after decoding."""
        self.read_used = False

    def has_children(self):
        """Returns True if the instance has any child (Nested or Repeated)."""
        return not not self._nested_vals

    def is_child_set(self):
        """Returns True if there's at least one child set (Nested or Repeated).
        """
        return not (0 == self._children_used)

    def get_nested_children(self):
        """Returns Nested children of the NestedParent

        :raises GCPInternalValueFormatError: If this method is called for
         invalid type of instance.

        """
        if not self.is_nested_parent() and not self.is_repeated_leaf():
            self.logger.error("Unexpected type of instance")
            raise GCPInternalValueFormatError(
                "Method called for invalid type of instance")
        return self._nested_vals

    def get_repeated_children(self):
        """Returns Repeated children of the RepeatedParent.

        :raises GCPInternalValueFormatError: If this method is called for
         invalid type of instance.

        """
        if not self.is_repeated_parent() and not self.is_repeated_fields():
            self.logger.error("Unexpected type of instance")
            raise GCPInternalValueFormatError(
                "Method called for invalid type of instance")
        return self._nested_vals

    def set_val(self, value=None, read_op=False):
        """Sets the value into the parent GPB. The value is converted into the
        GPB's representation if needed.

        :raises GCPInvalidDataValueError: For invalid values.
        :raises GCPInternalValueFormatError: If this method is called for
         invalid type of instance.

        """
        if self.has_children():
            # this restriction might be removed if needed
            raise GCPInternalValueFormatError(
                "Setting value for instance with children is not allowed.")

        # TODO implicit constraint checks might be turned off for
        # better performance (need to verify real impact)
        self.format.validate(value, implicit_constr=True)

        if None is not self.parent_gpb:
            val = self._to_gpb_value(value)
            setattr(self.parent_gpb, self.get_fmt().name, val)
        else:
            self.value = value

        self.set_is_used()
        self.read_used = read_op

    def unset_val(self):
        """Recursively unsets value of the current instance or in all children.

        if exist. All parents in hierarchy have decreased number of
        children with some value set.

        """
        if self.is_leaf():
            self.value = None
            if self.parent_gpb:
                self.parent_gpb.ClearField(self.format.name)
        else:
            if isinstance(self._nested_vals, list):
                nested_list = self._nested_vals
            else:
                nested_list = self._nested_vals.values()

            for nested in nested_list:
                nested.unset_val()

            if self.parent_gpb:
                self.parent_gpb.ClearField(self.format.name)

        self.unset_is_used()

        self.is_set_cache = self.is_set_inline()

    def set_is_used(self):
        """Sets all parents in hierarchy."""
        self.is_used = True
        parent = self.parent
        while parent is not None:
            parent._child_use()
            # next parent in hierarchy
            parent = parent.parent

        self.is_set_cache = self.is_set_inline()

    def unset_is_used(self):
        """Current instance and all parents in hierarchy have decreased number
        of children with some value set."""
        self.is_used = False
        parent = self.parent
        while parent is not None:
            parent._child_unset_use()
            parent = parent.parent

        self.is_set_cache = self.is_set_inline()

    def _from_gpb_value(self, value):
        """Translates value from GPB's representation into the internal
        representation suitable for encoding."""
        if self.format.format_str == DataDescription.MAC_FMT:
            return Convert.mac_to_tuple_of_bytes(value)
        elif self.format.format_str == DataDescription.IP_FMT:
            return Convert.ipaddr_to_tuple_of_bytes(value)
        elif isinstance(value, unicode):
            return str(value)
        return value

    def get_val(self):
        if self.is_repeated_fields():
            return self._nested_vals

        if not self.is_set():
            return None

        if ((None is not self.parent_gpb) and
                (hasattr(self.parent_gpb, self.format.name))):
            val = getattr(self.parent_gpb, self.format.name)
            val = self._from_gpb_value(val)
        else:
            val = self.value
        return val

    def _child_use(self):
        """Increments number of children which have their value set."""
        self._children_used += 1
        #self.is_set_cache = self.is_set_inline()

    def _child_unset_use(self):
        if self._children_used:
            self._children_used -= 1
            if self._children_used == 0:
                self.unset_is_used()

        #self.is_set_cache = self.is_set_inline()

    def get_nested_dict(self):
        """Returns dictionary of nested values."""
        return self._nested_vals

    def append_repeated(self, val, parent_gpb=None):
        if not self.is_repeated_fields():
            self.logger.error("Unexpected type of instance")
            raise GCPInternalValueFormatError(
                "Method called for invalid type of instance")
        if None is parent_gpb:
            if ((None is not self.parent_gpb) and
                    (hasattr(self.parent_gpb, self.format.name))):
                parent_gpb = getattr(self.parent_gpb, self.format.name)
            else:
                raise GCPInternalValueFormatError(
                    "No Parent ofr parent does not have this field")
        parent_gpb.append(val)
        self.set_is_used()
        # update the self
        self._nested_vals.append(val)

        self.is_set_cache = self.is_set_inline()

    def add_new_repeated(self, parent_gpb=None):
        """This method must be used to add new instance of the RepetedLeaf
        type so it may be called for RepeatedParent only.

        :raises GCPInternalValueFormatError: For internal failure.

        """
        if not self.is_repeated_parent():
            self.logger.error("Unexpected type of instance")
            raise GCPInternalValueFormatError(
                "Method called for invalid type of instance")

        if None is parent_gpb:
            if ((None is not self.parent_gpb) and
                    (hasattr(self.parent_gpb, self.format.name))):
                parent_gpb = getattr(self.parent_gpb, self.format.name).add()

        repeated_leaf = ValueFormatGPB(self.format, parent_gpb, self)

        child_dict = self.create_dict_from_dict(
            self.format.get_nested_descriptions(), repeated_leaf, parent_gpb)
        if not child_dict:
            raise GCPInternalValueFormatError(
                "Empty dictionary created for the new repeated object")

        repeated_leaf._nested_vals = child_dict
        repeated_leaf.__dict__.update(child_dict)
        self._nested_vals.append(repeated_leaf)

        self.is_set_cache = self.is_set_inline()
        return repeated_leaf

    @staticmethod
    def __add_fmt_val(d, fmt, parent, parent_gpb):
        """Adds new instance into the dictionary d for format fmt.

        :param d: Dictionary, where the new instance will be inserted.
        :param fmt: Data description of the format of data.
        :param parent: Parental instance in hierarchy.
        :param parent_gpb: GPB of the parent.
        :raises GCPInternalValueFormatError: For internal failures.

        """
        if not isinstance(fmt, DataDescription):
            return
        val_fmt = ValueFormatGPB(fmt=fmt, parent=parent, parent_gpb=parent_gpb)
        d[fmt.name] = val_fmt

        # TYPE_LEAF
        fmt_desc = fmt.get_desc_type()
        if fmt_desc == DataDescription.TYPE_LEAF:
            # done
            return

        if fmt_desc == DataDescription.TYPE_REPEATED_FIELDS:
            # process repeated values if exists
            if None is not parent_gpb:
                val_fmt._nested_vals = []
            return

        # TYPE_REPEATED
        if fmt_desc == DataDescription.TYPE_REPEATED:
            # process repeated values if exists
            if None is not parent_gpb:
                val_fmt._nested_vals = []

                if not hasattr(parent_gpb, fmt.name):
                    return

                repeated_vals_list = getattr(parent_gpb, fmt.name)
                for repeated_val in repeated_vals_list:
                    val_fmt.add_new_repeated(parent_gpb=repeated_val)
            return

        # TYPE_PARENT
        if fmt_desc == DataDescription.TYPE_PARENT:
            # get child GPB
            gpb_child = None

            if None is not parent_gpb:
                try:
                    if not hasattr(parent_gpb, fmt.name):
                        gpb_child = None
                    else:
                        gpb_child = getattr(parent_gpb, fmt.name)
                except Exception as ex:
                    ValueFormatGPB.logger.error(
                        "Failed to get GPB child with name %s, GPB: %s, "
                        "exception: %s", fmt.name, parent_gpb, ex)
                    raise GCPInternalValueFormatError(
                        "Unable to get GPB: {}".format(fmt.name))

            # process nested values
            nest = fmt.get_nested_descriptions()
            nested_d = None
            if nest:
                # need to handle also nested descriptions
                if isinstance(nest, list) or isinstance(nest, tuple):
                    nested_d = ValueFormatGPB.create_dict_from_sequence(
                        nest,
                        parent=val_fmt,
                        parent_gpb=gpb_child)
                elif isinstance(nest, dict):
                    nested_d = ValueFormatGPB.create_dict_from_dict(
                        nest,
                        parent=val_fmt,
                        parent_gpb=gpb_child)
            if nested_d:
                val_fmt.__dict__.update(nested_d)
                val_fmt._nested_vals = nested_d

    @staticmethod
    def create_dict_from_sequence(fmt_sequence, parent=None,
                                  parent_gpb=None):
        """Creates dictionary from the sequence of DataDescription objects.
        Name of every object is used as key and instance of ValueFormat class
        is value.

        :returns: dict(name : ValueFormat)
        :raises GCPInternalValueFormatError: For internal failures.

        """
        if (not isinstance(fmt_sequence, list) and
                not isinstance(fmt_sequence, tuple)):
            raise TypeError()

        d = dict()
        for fmt in fmt_sequence:
            ValueFormatGPB.__add_fmt_val(d, fmt, parent, parent_gpb)

        return d

    @staticmethod
    def create_dict_from_dict(fmt_dict, parent=None, parent_gpb=None):
        """Creates dictionary from the dictionary of DataDescription objects.
        Name of every object is used as key and instance of ValueFormat class
        is value.

        :returns: dict(name : ValueFormat)
        :raises GCPInternalValueFormatError: For internal failures.

        """
        if not isinstance(fmt_dict, dict):
            raise TypeError()

        d = dict()
        for k, fmt in fmt_dict.items():
            ValueFormatGPB.__add_fmt_val(d, fmt, parent, parent_gpb)
        return d


class GCPObject(object):
    """Class describes a general object of GCP protocol which is able to be
    encoded and decoded.

    This class is not intended to be instantiated, should be used as a
    superclass.

    """

    __metaclass__ = AddLoggerToClass
    # Return codes for decoding
    DECODE_INIT = 0
    DECODE_DONE = 1
    DECODE_FAILED = 2
    DECODE_FRAGMENTED = 3
    DECODE_UNKNOWN_FORMAT = 4
    DECODE_INCORRECT_FORMAT = 5
    DECODE_DATA_TOO_SHORT = 6
    DECODE_UNKNOWN_FIELD = 7
    # Means Done, but is returned when all data of current object are
    # processed, but there's next object of the same level in the buffer
    DECODE_NEXT = 8

    decode_result_str = {
        DECODE_INIT: "INIT",
        DECODE_DONE: "DONE",
        DECODE_FAILED: "FAILED",
        DECODE_FRAGMENTED: "FRAGMENTED",
        DECODE_UNKNOWN_FORMAT: "UNKNOWNFORMAT",
        DECODE_INCORRECT_FORMAT: "INCORRECTFORMAT",
        DECODE_DATA_TOO_SHORT: "DATATOOSHORT",
        DECODE_UNKNOWN_FIELD: "UNKNOWNFIELD",
        DECODE_NEXT: "NEXT"
    }

    @staticmethod
    def get_result_str(result):
        """Translate result code of decoding into its string
        representation."""
        return GCPObject.decode_result_str[result]

    def __init__(self):
        self.buffer = None
        self.offset = 0
        # length of data which are written in the buffer
        self.buf_data_len = 0  # length of valid data written into the buffer
        self.decoding_result = self.DECODE_INIT

    def reinit(self):
        """Sets context used in encoding/decoding to default values."""
        self.buffer = None
        self.offset = 0
        self.buf_data_len = 0
        self.decoding_result = self.DECODE_INIT

    def compute_buffer_len(self):
        """Method computes buffer length which will be needed to encode this
        GCPObject."""
        raise NotImplementedError()

    def get_empty_sub_buffer(self):
        """Returns remaining memory from the buffer which starts where the
        current data ends."""
        return (ctypes.c_char * (len(self.buffer) - self.buf_data_len)).\
            from_buffer(self.buffer, self.buf_data_len)

    def get_data_sub_buffer(self, offset=0):
        """Returns the memory from the buffer which includes encoded data."""
        return (ctypes.c_char * (self.buf_data_len - offset)).\
            from_buffer(self.buffer, offset)

    def get_buffer_remaining_len(self):
        """Returns remaining length of data which could be encoded into the
        buffer."""
        return len(self.buffer) - self.buf_data_len

    def get_max_len(self):
        """Returns remaining length from offset."""
        return self.buf_data_len - self.offset

    # Reduce the buffer length by the specified number of bytes
    def trim_max_len(self, reduce_length):
        # Make sure number of bytes to trim is more than the available bytes
        if (reduce_length > self.buf_data_len):
            raise GCPDecodeError(
                "Attempted to reduce the buffer size to less than zero "
                "({} > {})".format(reduce_length, self.buf_data_len))

        # Make sure the buffer's offset will be beyond the new buffer size
        if (self.buf_data_len - reduce_length) < self.offset:
            raise GCPDecodeError(
                "Attempted to reduce the buffer size to less than the current "
                "offset ()")

        # Trim the length
        self.buf_data_len = self.buf_data_len - reduce_length

    def _decode_prologue(self, buffer, offset, buf_data_len):
        """Implements checks and settings needed before the decoding starts.
        Should initialize all attributes of this object.

        Uses local buffer as input if new buffer is not passed as argument.
        Returns True when object is prepared, False otherwise.

        """
        if None is not buffer:
            self.buffer = buffer

        if None is not offset:
            self.offset = offset

        if None is not buf_data_len:
            self.buf_data_len = buf_data_len

        if None is self.buffer:
            self.logger.error("No any buffer to be decoded")
            return False

        if self.buf_data_len <= self.offset:
            self.logger.error("Invalid offset (%u) and max_len (%u) values.",
                              self.offset, self.buf_data_len)
            return False

        # Store the starting offset for further checks and error handling
        self.prologue_offset = self.offset
        return True

    def _decode_process(self):
        """Implements the decoding of the local buffer and sets local
        attributes according to decoded data. The offset must be set to the
        end of buffer after successful decoding.

        :return: DECODE_FAILED, DECODE_FRAGMENTED, DECODE_DONE or DECODE_NEXT
        :raises GCPDecodeError

        """
        raise NotImplementedError()

    def _decode_epilogue(self):
        """Performs checks if the decoding process finished correctly.
        Returns True when decoding was successful, False otherwise."""
        # decoding process must results with the offset set to the max_len
        # value
        if not self.offset == self.buf_data_len:
            self.logger.error("Decoding failed, offset (%u) doesn't equal max_len (%u)",
                              self.offset, self.buf_data_len)
            return False

        # now the computed buffer lent must match with the max_len
        '''
        length = self.compute_buffer_len()
        if length > (self.buf_data_len - self.prologue_offset):
            self.logger.error("There were probably more data decoded than expected: "
                              "max_len: %u, computed length of received data: %u" %
                      (self.buf_data_len, length))
            return False

        if length < (self.buf_data_len - self.prologue_offset):
            self.logger.error("No all data were decoded: max_len: %u, computed length "
                              "of received data: %u" % (self.buf_data_len, length))
            return False
        '''
        return True

    def decode(self, buffer=None, offset=None, buf_data_len=None):
        """Calls prologue, process and epilogue methods for decoding.

        :param buffer: Buffer including data to be decoded
         The self.buffer is used when the parameter is set to None.
        :param offset: The offset in the buffer the decoding will start from.
         The self.offset is used when the parameter is set to None.
        :param buf_data_len: Length of the data stored in buffer
         (The len(buffer) may be higher value)
         The self.buf_data_len is used when the paramter is set to None.
        :raises GCPDecodeError: No any execepions are catched. All exceptions
         raised by _decode_process() method can be raised.
        :returns:
            DECODE_INIT: Failed to start decoding.
            DECODE_FAILED: Decoding failed.
            DECODE_FRAGMENTED: Decoded message is fragmented, need to continue.
            DECODE_DONE: Decoding was successful.
            DECODE_NEXT: All data have been decoded, but there are some next
                         data in the buffer.

        """
        if not self._decode_prologue(buffer, offset, buf_data_len):
            self.logger.error("Failed to start decoding")
            return self.DECODE_INIT

        result = self._decode_process()
        if result == self.DECODE_FAILED:
            self.logger.error("Decoding failed")
            return result

        if result == self.DECODE_FRAGMENTED:
            self.logger.debug("Decoding fragmented GCP message")
            return result

        if result == self.DECODE_NEXT:
            self.logger.debug("Decoding should continue")
            return result

        if not self._decode_epilogue():
            self.logger.error("Post decoding check failed")
            return self.DECODE_FAILED

        return self.DECODE_DONE

    def _encode_prologue(self, buffer=None, offset=None, buf_data_len=None):
        """Implements checks and settings needed before the encoding process
        starts.

        Should initialize all attributes of this object. Creates new
        buffer for encoded data if not passed. Returns True when this
        instance is prepared, False otherwise.

        """
        if None is not buffer:
            self.buffer = buffer

        if None is not offset:
            self.offset = offset

        if None is not buf_data_len:
            self.buf_data_len = buf_data_len

        if None is self.buffer:
            length = self.compute_buffer_len()
            if length == 0:
                self.logger.error("Zero buffer length computed, can't continue")
                return False

            self.buffer = ctypes.create_string_buffer(length)
            if None is self.buffer:
                self.logger.error("Failed to create new buffer")
                return False

            self.buf_data_len = length
            self.offset = 0
        else:
            self.buf_data_len = buf_data_len
            self.offset = offset

        if self.buf_data_len <= self.offset:
            self.logger.error("Invalid offset (%u) and max_len (%u) values.",
                              self.offset, self.buf_data_len)
            return False

        return True

    def _encode_process(self):
        """Implements the encoding of the local attributes into the local
        buffer. The offset value must be set to the end of the buffer after
        successful encoding and True is returned, False otherwise.

        :raises GCPEncodeError

        """
        raise NotImplementedError()

    def _encode_epilogue(self):
        """Performs checks, if the encoding process finished correctly.

        Returns True, when encoding was successful, False otherwise.

        """
        # encoding process must results with the offset set to the max_len
        # value
        '''
        if self.offset != self.buf_data_len:
            self.logger.error("Encoding failed, offset (%u) doesn't equal max_len (%u)", self.offset, self.buf_data_len)
            return False
        '''

        return True

    def encode(self, buffer=None, offset=None, buf_data_len=None):
        """Calls prologue, process and epilogue methods for encoding.

        :param buffer: The buffer where the encoded data will be stored.
         New buffer of the length == self.compute_buffer_len() is created if
         the parameter is set to none.
        :param offset: The offset to the buffer where the first byte of
         encoded data will be stored.
         Zero is used if the parameter is set to None.
        :param buf_data_len: The length of data which is allowed to encode
         into the buffer. The returned value from self.compute_buffer_len() is
         used if the parameter is set to None.
        :raises GCPEncodeError: No any excetion is catched by this method.
         All exceptions raised by _encode_process() can be raised.
        :returns a buffer including the encoded data when encoding was
         successful, False otherwise.

        """
        if not self._encode_prologue(buffer, offset, buf_data_len):
            self.logger.error("Failed to start encoding")
            return None

        if not self._encode_process():
            self.logger.error("Encoding failed")
            return None

        if not self._encode_epilogue():
            self.logger.error("Post encoding check failed")
            return None

        return self.buffer

    def __pack(self, val, fmt, length):
        try:
            if (DataDescription.MAC_FMT == fmt or
                    DataDescription.IP_FMT == fmt):
                fmt = "!%uB" % length
                struct.pack_into(fmt, self.buffer, self.offset, *val)
            else:
                if (DataDescription.VARIABLE_LEN == fmt or
                        DataDescription.BYTES_STRING == fmt):
                    # encode as string if the length is variable
                    fmt = "!%us" % length

                struct.pack_into(fmt, self.buffer, self.offset, val)
        except:
            self.logger.error("Failed to pack value with format: %s, length: %u",
                              fmt, length)
            raise GCPEncodeError("Failed to pack the value")

        self.offset += length

    def pack(self, val, fmt, length):
        """Packs one value according to fmt string.

        :param val: The value to be packed into the buffer.
        :param fmt: Formatting string used for packing.
        :type fmt: String
        :param length: Length of packed data in bytes.
        :raises GCPEncodeError: If the packing fails.

        """
        if (length + self.offset) >= self.buf_data_len:
            raise GCPEncodeError("Not enough space in buffer: "
                                 "offset: {}, buf_data_len: {}, "
                                 "next_data_len: {}".format(
                                     self.offset, self.buf_data_len, length))
        self.__pack(val, fmt, length)

    def pack_bulk(self, bulk):
        """The bulk argument includes list of tuples: (val, fmt, length) which
        are then processed if it's possible to write the bulk into the buffer.

        False is returned if the packing is not possible, True
        otherwise.

        """
        # compute total length
        total = sum([length for (val, fmt, length) in bulk])
        if (total + self.offset) > self.buf_data_len:
            self.logger.debug("Unable to pack bulk of data of length: %u, available memory: %u",
                              total, self.get_max_len())
            return False

        # store current offset for exception handling
        old_offset = self.offset

        val = None
        fmt = None
        length = None
        try:
            for (val, fmt, length) in bulk:
                self.__pack(val, fmt, length)
        except Exception as ex:
            self.logger.error("Failed to pack bulk of data (val: %s, fmt: %s, len: %u): %s", val, fmt, length, ex)
            self.offset = old_offset
            return False
        return True

    def _unpack(self, fmt, length):
        if (DataDescription.MAC_FMT == fmt or
                DataDescription.IP_FMT == fmt):
            fmt = "!%uB" % length
            try:
                val = struct.unpack_from(fmt, self.buffer, self.offset)
            except:
                self.logger.error("Unpacking of data with format: %s and length: %u failed", fmt, length)
                raise GCPDecodeError("Failed to decode value")

            if length != len(val):
                raise GCPDecodeError(
                    "Expected length: {} - unpack len {}".format(length,
                                                                 len(val)))
        else:
            try:
                val = struct.unpack_from(fmt, self.buffer, self.offset)
            except:
                self.logger.error("Unpacking of data with format: %s and length: %u failed", fmt, length)
                raise GCPDecodeError("Failed to decode value")

            # only tuple of one value is expected
            if 1 != len(val):
                raise GCPDecodeError(
                    "Only one unpacked value expected: {}".format(val))
            val = val[0]

        self.offset += length
        return val

    def unpack(self, fmt, length):
        """Unpacks value with passed format and length and returns the value.
        None is returned if failed.

        :param fmt: Formatting sting used for unpacking.
        :type fmt: String
        :param length: Number of bytes to be unpacked from the buffer.
        :raises GCPDecodeError: If the unpacking fails.

        """
        if (self.offset + length) > self.buf_data_len:
            raise GCPDecodeError("Not enough data in buffer: "
                                 "buf_data_len: {}, offset: {}, "
                                 "next_data_len: {}".format(
                                     self.buf_data_len, self.offset, length))

        val = self._unpack(fmt, length)
        return val

    def unpack_bulk(self, bulk):
        """Unpacks bulk of data described as s list of tuples of this format:

        (data_id, fmt, length).
        Returns dictionary in this format {id : value}.
        None is returned if failed.

        """
        # compute total length needed
        total = sum([length for (data_id, fmt, length) in bulk])
        if total > self.get_max_len():
            return None

        # store current offset for exception handling
        old_offset = self.offset
        bulk_out = dict()

        data_id = None
        fmt = None
        length = None
        try:
            for data_id, fmt, length in bulk:
                val = self._unpack(fmt, length)
                bulk_out[data_id] = val
        except Exception as ex:
            self.logger.error("Failed to unpack bulk of data (id: %s, fmt: %s, len: %u): %s", data_id, fmt, length, ex)
            self.offset = old_offset
            return None

        return bulk_out

    @staticmethod
    def default_gpb(gpb):
        """
        This function is to set the google proto buffer to default value
        :return:
        """
        for descriptor in gpb.DESCRIPTOR.fields:
            value = getattr(gpb, descriptor.name)
            if descriptor.type == descriptor.TYPE_MESSAGE:
                if descriptor.label == descriptor.LABEL_REPEATED:
                    map(GCPObject.default_gpb, value)
                else:
                    GCPObject.default_gpb(value)
            else:
                setattr(gpb, descriptor.name, value)

    def _ut_compare(self, obj):  # pragma: no cover
        """Compares two objects of the same class if they have set the same
        data.

        Should be used in unit tests. Returns True when equals, False
        otherwise.

        """
        raise NotImplementedError()
