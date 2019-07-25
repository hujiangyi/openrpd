#
# Copyright (c) 2018 Cisco and/or its affiliates, and
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
from .rcpRecord import RCPRecord
from .rcp_tlv_def import RCPTLV
from rpd.rcp.gcp.gcp_lib.gcp_tlv_def import DataDescription
from rpd.rcp.gcp.gcp_lib.gcp_data_description import GCPInvalidDataValueError
from rpd.common.utils import Convert
from rpd.common.rpd_logging import AddLoggerToClass


class ArrayTLVReadException(Exception):
    pass


class ArrayTLVRead(object):
    __metaclass__ = AddLoggerToClass

    def __init__(self, gpb, rcptlv):
        """
        :param gpb: the requested protobuf, after array_read, the gpb is the requested result data.
        :param rcptlv: the rcptlv instance related with the gpb
        """
        if not isinstance(rcptlv, RCPTLV):
            raise ArrayTLVReadException("rcptlv is not an instance of RCPTLV")
        if rcptlv.desc_type != DataDescription.TYPE_REPEATED:
            raise ArrayTLVReadException("rcptlv is not Array instance")
        self.gpb = gpb
        self.rcptlv = rcptlv

    def array_read(self, record, read_count=None):
        """
        This is the only API this class provided, it fills the gpb data by the record input
        :param record: the RCPRecord instance, in order to fill the gpb data
        :param read_count: if not default, read_count is requested to be an integer
        :return: the item number of filled value
        """

        if not isinstance(record, RCPRecord):
            raise ArrayTLVReadException("record is not instance of RCPRecord")

        if read_count:
            return self._read_array_with_read_count(record, read_count)
        else:
            return self._read_array_without_read_count(record)

    def _read_array_with_read_count(self, record, read_count):
        idx = self._gen_array_lowest_req_idx(record)
        if not idx:
            # the db is null
            return 0
        leaf_list = self._gen_req_fields()
        self._clear_array_request()
        count = 0
        for dbrec in record.get_next_n(idx, read_count):
            item = self.gpb.add()
            self._fill_array_item(item, dbrec, leaf_list)
            count += 1
        if not count:
            # just add an empty field
            self.gpb.add()
        return count

    def _read_array_without_read_count(self, record):
        # check if read all of the TLV
        if self._check_read_all():
            return self._read_array_all(record)

        # check request list
        request_record_list = self._gen_array_sorted_req_idx(record)

        if not len(request_record_list):
            return 0

        leaf_list = self._gen_req_fields()
        self._clear_array_request()
        count = 0
        for idx in request_record_list:
            item = self.gpb.add()
            record.set_index(idx)
            record.read()
            self._fill_array_item(item, record, leaf_list)
            count += 1
        if not count:
            # just add an empty field
            self.gpb.add()
        return count

    def _gen_array_lowest_req_idx(self, record):
        idx_list = self._gen_array_sorted_req_idx(record)
        if idx_list and len(idx_list) >= 1:
            return idx_list[0]
        else:
            return None

    def _gen_req_fields(self):
        # if no specific request leaf mentioned, return all the leaf
        all_leaf_names = self._get_all_leaf_names()
        leaf_list = []
        for item in self.gpb:
            has_leaf_field = False
            for name in all_leaf_names:
                if item.HasField(name):
                    has_leaf_field = True
                    if name not in leaf_list:
                        leaf_list.append(name)
            if not has_leaf_field:
                # there is one request that is request all of the leaf nodes, no need to check the others
                leaf_list.extend(all_leaf_names)
                return leaf_list
        return leaf_list

    def _clear_array_request(self):
        idx = len(self.gpb)
        while idx:
            del self.gpb[idx - 1]
            idx -= 1

    def _fill_array_item(self, item, record, leaf_list):
        # fill the keys
        for child_id, name in self.rcptlv.TLV_child_key_list:
            value = record.get_idx_attr(name)
            try:
                if self._is_valid(value, name):
                    setattr(item, name, value)
            except TypeError:
                # TypeError happened when setattr
                self.logger.warn("TypeError happened when fill arraytlv %s subtlv:%s, value:%s", self.rcptlv.TLV_name,
                                 name, str(value))
                continue
        # fill the leaf
        for name in leaf_list:
            value = record.get_leaf_attr(name)
            try:
                if self._is_valid(value, name):
                    setattr(item, name, value)
            except TypeError:
                # TypeError happened when setattr
                self.logger.warn("TypeError happened when fill arraytlv %s subtlv:%s, value:%s", self.rcptlv.TLV_name,
                                 name, str(value))
                continue

    def _check_read_all(self):
        return (len(self.gpb) == 1) and (len(self.gpb[0].ListFields()) == 0)

    def _read_array_all(self, record):
        # read all under this gpb
        del self.gpb[0]
        leaf_list = self._get_all_leaf_names()
        count = 0
        for dbrec in record.get_all():
            item = self.gpb.add()
            self._fill_array_item(item, dbrec, leaf_list)
            count += 1
        if not count:
            self.gpb.add()
        return count

    def _gen_array_sorted_req_idx(self, record):
        # return a list that is sorted from lowest significant
        from sortedcontainers import SortedList
        idx_list = SortedList()
        all_key_names = self._get_all_key_names()
        record_idx_list = record.get_sorted_key_list()
        for item in self.gpb:
            has_key_field = False
            present_list = []
            req_idx = record.create_index()
            for name in all_key_names:
                if not item.HasField(name):
                    continue
                default_value = getattr(item.__class__(), name)
                current_value = getattr(item, name)
                if default_value != current_value:
                    # if not the default value
                    record.set_idx_attr_by_obj(req_idx, name, current_value)
                    present_list.append(name)
                    has_key_field = True
            if not has_key_field:
                idx_list.extend(record_idx_list)
                return idx_list

            if len(present_list) == len(all_key_names):
                # all keys present
                idx_list.add(req_idx)
            else:
                # loop all in the db, the performance is not good at, be careful, if the request hit this situation
                for idx in record_idx_list:
                    match = True
                    for name in present_list:
                        val = record.get_idx_attr_by_obj(idx, name)
                        req_val = record.get_idx_attr_by_obj(req_idx, name)
                        if val != req_val:
                            match = False
                            break
                    if match:
                        idx_list.add(idx)
        return idx_list

    def _get_all_leaf_names(self):
        key_names = self._get_all_key_names()
        return tuple(set(self.rcptlv.child_dict_by_name.keys()).difference(set(key_names)))

    def _is_valid(self, value, name):
        try:
            fmt = self.rcptlv.child_dict_by_name[name]
            if fmt.value_is_mac():
                value = Convert.mac_to_tuple_of_bytes(value)
            elif fmt.value_is_ip_addr():
                value = Convert.ipaddr_to_tuple_of_bytes(value)
            fmt.validate(value)
            return True
        except GCPInvalidDataValueError:
            return False
        except ValueError:
            return False
        except TypeError:
            return False

    def _get_all_key_names(self):
        key_names = []
        for id, name in self.rcptlv.TLV_child_key_list:
            key_names.append(name)
        return key_names
