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


class RCPRecord(object):

    @classmethod
    def get_sorted_key_list(cls):
        raise NotImplementedError

    @classmethod
    def get_all(cls):
        raise NotImplementedError

    @classmethod
    def get_next_n(cls, key=None, count=0):
        raise NotImplementedError

    def create_index(self):
        return self.index.__class__()

    @classmethod
    def set_idx_attr_by_obj(cls, idx, name, value):
        setattr(idx, name, value)

    @classmethod
    def get_idx_attr_by_obj(cls, idx, name):
        return getattr(idx, name)

    def get_index(self):
        return self.index

    def set_index(self, idx):
        self.index = idx

    def read(self):
        # fill leaf by index
        raise NotImplementedError

    def get_idx_attr(self, name):
        return getattr(self.get_index(), name)

    def get_leaf_attr(self, name):
        return getattr(self, name)
