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

from rpd.rcp.gcp.gcp_lib.gcp_data_description import *


class GCPTLVAlreadyDefined(GCPInternalException):
    pass


class TLVDescriptionSet(DescriptionSet):

    def __init__(self, hierarchy_name="TLVBase"):
        super(TLVDescriptionSet, self).__init__(hierarchy_name)


class TLVDesc(TLVDescriptionSet, DataDescription):
    """Implements description of the data format of TLVs.

    Dictionaries mapping TLV name and TLV id to the DataDescription are
    inherited from the TLV_Base class.

    """
    TLV_TYPE_LEN = 1  # type field of every TLV is 1 byte long
    TLV_LENGTH_LENS = (1, 2)  # expected TLV length field lengths in bytes

    def __init__(self, identifier, name, parent=None, format_str=None,
                 length=None, constraint=None, length_field_len=1,
                 rw=DataDescription.RW_FLAG_rw):

        # identifier, name and parent must be specified
        if None in (identifier, name, parent):
            raise AttributeError()

        # initialize hierarchy name to None because it must be set later
        TLVDescriptionSet.__init__(self, hierarchy_name=None)
        DataDescription.__init__(self, identifier=identifier, name=name,
                                 format_str=format_str, length=length,
                                 constraint=constraint)

        if length_field_len not in self.TLV_LENGTH_LENS:
            raise AttributeError()

        self.length_field_len = length_field_len
        self.child_dict_by_name = {}
        self.child_dict_by_id = {}
        self.TLV_name = str(identifier) + "_" + name
        self.TLV_rw_flag = rw
        self.TLV_child_key_list = []

        self.parent = parent
        # Store the parent as a tuple if isn't already a tuple or list
        if not isinstance(parent, (tuple, list)):
            parent = (parent, )
            self.parent = parent

        for parent in self.parent:
            parent.insert_description(identifier, name, self)
            self.hierarchy_name =\
                parent.hierarchy_name + "." + str(self.id)

            if DataDescription.RW_FLAG_key == self.TLV_rw_flag:
                parent.TLV_child_key_list.append((self.id, self.name))
                parent.desc_type = parent.get_desc_type_inline()
            if DataDescription.RW_FLAG_row_key == self.TLV_rw_flag:
                self.TLV_child_key_list.append((self.id, self.name))

        self.desc_type=self.get_desc_type_inline()

    def has_child(self):
        return not not self.child_dict_by_name

    def has_parent(self):
        return not not self.parent

    def is_repeated(self):
        return not not self.TLV_child_key_list

    def get_desc_type_inline(self):
        if self.is_tlv_repeated_fields():
            return self.TYPE_REPEATED_FIELDS

        if self.is_repeated():
            return self.TYPE_REPEATED

        if not self.has_child():
            return self.TYPE_LEAF

        return self.TYPE_PARENT

    def get_desc_type(self):
        return self.desc_type

    def get_len(self, value=None):
        """Returns length of the value + length of TLV header (type + length
        fields length).

        return len(type) + len(length) + len(value)

        """
        val_len = self.get_tlv_length_val(value)
        return val_len + self.TLV_TYPE_LEN + self.length_field_len

    def get_tlv_length_val(self, value=None):
        """Returns length of the value field of the TLV."""
        return DataDescription.get_len(self, value)

    def get_nested_descriptions(self):
        return self.child_dict_by_name

    def is_tlv_read(self):
        return DataDescription.RW_FLAG_r == self.TLV_rw_flag

    def is_tlv_readwrite(self):
        return DataDescription.RW_FLAG_rw == self.TLV_rw_flag

    def is_tlv_key(self):
        return DataDescription.RW_FLAG_key == self.TLV_rw_flag

    def is_tlv_row(self):
        return DataDescription.RW_FLAG_row == self.TLV_rw_flag or \
            DataDescription.RW_FLAG_row_key == self.TLV_rw_flag

    def is_tlv_row_key(self):
        return DataDescription.RW_FLAG_row_key == self.TLV_rw_flag

    def is_tlv_repeated_fields(self):
        return DataDescription.RW_FLAG_repeatedFields == self.TLV_rw_flag

    def insert_description(self, desc_id, desc_name, desc):
        TLVDescriptionSet.insert_description(self, desc_id, desc_name, desc)
        self.desc_type=self.get_desc_type_inline()

    def update_descriptions(self, description_set):
        TLVDescriptionSet.update_descriptions(
            self, description_set=description_set)
        self.desc_type=self.get_desc_type_inline()

# global GCP TLV database
GCP_TLV_SET = TLVDescriptionSet(hierarchy_name="GCP_TLVs")


class GCP_TLV(TLVDesc):
    """Implements description of the GCP TLV data format.

    Used to enforce usage of 1B long TLV length field for GCP TLVs.

    """
    def __init__(self, tlv_id, name, parent=GCP_TLV_SET,
                 format_str=None, length=None, constraint=None,
                 rw=DataDescription.RW_FLAG_rw):
        super(GCP_TLV, self).__init__(tlv_id, name, parent, format_str,
                                      length, constraint,
                                      length_field_len=1, rw=rw)
