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

from rpd.common.utils import Convert
from rpd.confdb.rpd_redis_db import DBRecord


class IpNettophyKey(object):

    def __init__(self, init_str=None):
        self.EnetPortIndex = 0
        self.AddrType = 0
        self.IpAddress = ""
        if isinstance(init_str, str):
            values = init_str.split('&&')
            if len(values) == 3:
                self.EnetPortIndex = int(values[0])
                self.AddrType = int(values[1])
                self.IpAddress = str(values[2])

    def __str__(self):
        return str(self.EnetPortIndex) + "&&" + str(self.AddrType) +\
            "&&" + str(self.IpAddress)

    def __cmp__(self, other):
        if not hasattr(other, "EnetPortIndex"):
            return 0

        if self.EnetPortIndex != other.EnetPortIndex:
            return self.EnetPortIndex - other.EnetPortIndex

        if not hasattr(other, "AddrType"):
            return 0

        if self.AddrType != other.AddrType:
            return self.AddrType - other.AddrType

        if not hasattr(other, "IpAddress"):
            return 0

        if self.IpAddress != other.IpAddress:
            return Convert.compare_ip(self.IpAddress, other.IpAddres)

        return 0


class IpNettophyRec(DBRecord):
    MAX_RECORD_NUM = 0xFFFF
    INVALID_IP = '127.0.0.1'
    INVALID_PHYSADDR = '00:00:00:00:00:00'
    IpNeighbStateDict = {
        'REACHABLE': 1,
        'STALE': 2,
        'DELAY': 3,
        'PROBE': 4,
        'INVALID': 5,
        'UNKNOWN': 6,
        'INCOMPLETE': 7,
    }

    NEIGH_IP_INDEX = 0
    NEIGH_ENET_INDEX = 2
    NEIGH_MAC_INDEX = 4
    NEIGH_STATE_INDEX = -1
    NEIGH_ITEM_MIN_LEN = 4
    NEIGH_TYPE_INVALID = 2
    NEIGH_TYPE_DYNAMIC = 3
    NEIGH_STATE_PERM = 'PERMANENT'

    def __init__(self, index=None):
        if index and isinstance(index, IpNettophyKey):
            self.index = index
        else:
            self.index = IpNettophyKey()

        self.PhysAddress = IpNettophyRec.INVALID_PHYSADDR
        self.LastUpdated = 0
        self.Type = 0
        self.State = 0

    @classmethod
    def decode_index(cls, init_str):
        return IpNettophyKey(init_str)

    def markAsDel(self):
        self.Type = IpNettophyRec.NEIGH_TYPE_INVALID
        self.write()

    def updateKey(self, enet=0, addrType=0, ipAddr=""):
        self.index.EnetPortIndex = enet
        self.index.AddrType = addrType
        self.index.IpAddress = ipAddr

    def updateRec(self, item):
        if 'EnetPortIndex' in item:
            self.index.EnetPortIndex = item['EnetPortIndex']
        if 'AddrType' in item:
            self.index.AddrType = item['AddrType']
        if 'IpAddress' in item:
            self.index.IpAddress = item['IpAddress']
        if 'PhysAddress' in item:
            self.PhysAddress = item['PhysAddress']
        if 'LastUpdated' in item:
            self.LastUpdated = item['LastUpdated']
        if 'Type' in item:
            self.Type = item['Type']
        if 'State' in item:
            self.State = item['State']

    def delete_all(self):
        for key in self.get_keys():
            rec = IpNettophyRec(key)
            rec.delete()
