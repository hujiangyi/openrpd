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


from rpd.confdb.rpd_rcp_db_record import RCPDBRecord
from rpd.common.utils import Convert
import socket
from rpd.rcp.rcp_lib.rcp_tlv_def import INETADDRESSTYPE_IPV4, INETADDRESSTYPE_IPV6, INETADDRESSTYPE_UNKNOWN


class DepiMcastSessionKey(object):

    def __init__(self, init_str=None):
        """
        :param init_string: need follow the format "str(IpAddrType)&&GroupIpAddr&&SrcIpAddr&&str(SessionId)"
                            refer to the function __str__
        """
        self.IpAddrType = 0
        self.GroupIpAddr = ""
        self.SrcIpAddr = ""
        self.SessionId = 0
        if isinstance(init_str, str):
            values = init_str.split('&&')
            if len(values) == 4:
                self.IpAddrType = int(values[0])
                self.GroupIpAddr = str(values[1])
                self.SrcIpAddr = str(values[2])
                self.SessionId = int(values[3])

    def __str__(self):
        """
        :return:  it is used when redius db set the key
        """
        return str(self.IpAddrType) + "&&" + self.GroupIpAddr +\
            "&&" + self.SrcIpAddr + "&&" + str(self.SessionId)

    def __cmp__(self, other):
        """
        the function is used for comparation, the compared sequence is defined in TLV definition.
        :param other: the object who has the IpAddrType, GroupIpAddr, SrcIpAddr, SessionId
        :return:
        """
        if not hasattr(other, "IpAddrType"):
            return 0

        if self.IpAddrType != other.IpAddrType:
            return self.IpAddrType.__cmp__(other.IpAddrType)

        if not hasattr(other, "GroupIpAddr"):
            return 0

        if self.GroupIpAddr != other.GroupIpAddr:
            return Convert.compare_ip(self.GroupIpAddr, other.GroupIpAddr)

        if not hasattr(other, "SrcIpAddr"):
            return 0

        if self.SrcIpAddr != other.SrcIpAddr:
            return Convert.compare_ip(self.SrcIpAddr, other.SrcIpAddr)

        if not hasattr(other, "SessionId"):
            return 0

        return self.SessionId.__cmp__(other.SessionId)


class DepiMcastSessionRecord(RCPDBRecord):

    def __init__(self, index=None):
        if index and isinstance(index, DepiMcastSessionKey):
            self.index = index
        else:
            self.index = DepiMcastSessionKey()
        self.LocalLcceIpAddr = ""
        self.RemoteLcceIpAddr = ""
        # JoinTime should be bytes of the timestamp,
        # use Convert.pack_timestamp_to_string(timestamp) to convert the timestamp to bytes
        self.JoinTime = ""

    @classmethod
    def decode_index(cls, init_str):
        return DepiMcastSessionKey(init_str)

    @staticmethod
    def get_inetaddr_type(address):
        local_addrinfo = socket.getaddrinfo(address, None)[0]
        family = local_addrinfo[0]
        if family == socket.AF_INET:
            return INETADDRESSTYPE_IPV4[0]
        elif family == socket.AF_INET6:
            return INETADDRESSTYPE_IPV6[0]
        else:
            return INETADDRESSTYPE_UNKNOWN[0]

    def delete_all(self):
        for dbindex in self.get_keys():
            ses = DepiMcastSessionRecord(dbindex)
            ses.delete()

    def updateDepiMcastSessionKey(self, IpAddrType=0, GroupIpAddr="", SrcIpAddr="", SessionId=0):
        self.index.IpAddrType = IpAddrType
        self.index.GroupIpAddr = GroupIpAddr
        self.index.SrcIpAddr = SrcIpAddr
        self.index.SessionId = SessionId

    def updateDepiMcastSessionData(self, LocalLcceIpAddr="", RemoteLcceIpAddr="", JoinTime=""):
        """
        :param LocalLcceIpAddr: the str format of ipaddress 10.1.1.1 or 2001::1
        :param RemoteLcceIpAddr: the str format of ipaddress 10.1.1.1 or 2001::1
        :param JoinTime: the bytes format JoinTime:
                         use Convert.pack_timestamp_to_string(timestamp) to convert the timestamp to bytes
        :return:
        """
        self.LocalLcceIpAddr = LocalLcceIpAddr
        self.RemoteLcceIpAddr = RemoteLcceIpAddr
        self.JoinTime = JoinTime
