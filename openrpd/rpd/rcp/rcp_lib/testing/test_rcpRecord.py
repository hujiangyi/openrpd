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


import unittest
from rpd.rcp.rcp_lib.rcpRecord import RCPRecord
from rpd.confdb.rpd_rcp_db_record import RCPDBRecord
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging


class BasicIdxRecord(RCPRecord):

    def __init__(self, index=None):
        self.index = index

    def __cmp__(self, other):
        if not hasattr(other, "index"):
            return 0
        return cmp(self.index, other.index)

    def create_index(self):
        return self.__class__()

    @classmethod
    def set_idx_attr_by_obj(cls, idx, name, value):
        if name == "Index":
            idx.index = value
            return

        setattr(idx, name, value)


class ComplexIdx(object):

    def __init__(self, init_str=None):
        pass


class ComplexIdxRecord(RCPDBRecord):

    def __init__(self, index=None):
        if not index:
            self.index = ComplexIdx()


class test_Record(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    @classmethod
    def setUpClass(cls):
        setup_logging("GCP", "gcp.log")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_create_index(self):
        test = BasicIdxRecord(6)
        ret = test.create_index()
        test.set_idx_attr_by_obj(ret, 'Index', 1)
        self.assertEqual(ret.index, 1)

        test = ComplexIdxRecord()
        ret = test.create_index()
        test.set_idx_attr_by_obj(ret, 'Index', 1)
        self.assertEqual(ret.Index, 1)
        self.assertEqual(test.get_idx_attr_by_obj(ret, 'Index'), 1)
        test.set_index(ret)
        self.assertEqual(test.get_index(), ret)
        setattr(test, 'leaf', 2)
        self.assertEqual(test.get_leaf_attr('leaf'), 2)
        self.assertEqual(test.get_idx_attr('Index'), 1)

    def test_Not_implemented(self):
        try:
            RCPRecord.get_sorted_key_list()
        except NotImplementedError:
            pass

        try:
            RCPRecord.get_all()
        except NotImplementedError:
            pass

        try:
            RCPRecord.get_next_n()
        except NotImplementedError:
            pass

        try:
            test = RCPRecord()
            test.read()
        except NotImplementedError:
            pass


if __name__ == "__main__":
    unittest.main()
