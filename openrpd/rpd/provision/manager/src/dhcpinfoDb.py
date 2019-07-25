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
from rpd.confdb.rpd_redis_db import DBRecord


class DhcpInfoKey(object):
    """
    :param init_str: need to follow below format:
    str(interface)
    """

    def __init__(self, initStr=None):
        self.interface = initStr

    def __str__(self):
        return str(self.interface)

    def __cmp__(self, other):
        if not hasattr(other, "interface"):
            return 0
        if self.interface <= other.interface:
            return 1
        else:
            return 0

    def isDefault(self):
        return '' == self.interface


class DhcpInfoRecord(DBRecord):
    def __init__(self, index=None):
        if index and isinstance(index, DhcpInfoKey):
            self.index = index
        else:
            self.index = DhcpInfoKey()
        self.createdTime = 0

    @classmethod
    def decode_index(cls, init_str):
        return DhcpInfoKey(init_str)

    def updateDhcpInfoKey(self, interface=''):
        self.index.interface = interface

    def updateDhcpInfoRecordData(self, CreatedTime=0):
        self.createdTime = CreatedTime

    def deleteAll(self):
        for idx in self.get_keys():
            sess = DhcpInfoRecord(idx)
            sess.delete()

    def getDhcpInfoCreatedTime(self):
        return self.createdTime
