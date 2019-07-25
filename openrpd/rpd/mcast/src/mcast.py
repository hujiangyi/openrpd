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

import socket
import struct
import psutil
import time
from rpd.common.utils import SysTools
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.rpd_logging import setup_logging
import platform
from DepiMcastSessionRecord import DepiMcastSessionRecord
from rpd.common.utils import Convert


class McastException(Exception):
    """Mcast session general exception."""


class Mcast(object):
    """
    address = (local_ip, src_ip, grp_ip, port)

    """
    JOINED = 1  # has been joined
    NOT_JOINED = 2  # the socket has been established, but not join
    LEAVED = 3  # join and then leave

    SOCKET_IP_ADD_SOURCE_MEMBERSHIP = 39
    MCAST_JOIN_SOURCE_GROUP = 46
    MCAST_LEAVE_SOURCE_GROUP = 47
    McastDb = dict()

    """added for interface flap case"""
    interfaceList = dict()
    interface_up = "UP"
    interface_down = "DOWN"

    __metaclass__ = AddLoggerToClass

    def __init__(self, address):
        """
        address = (local_ip, src_ip, grp_ip, port)

        """
        self.local_ip = None
        self.src_ip = None
        self.port = None
        self.grp_ip = None
        self.sessionList = []

        try:
            (local_ip, src_ip, grp_ip, port) = address
            self.grp_ip = grp_ip
            self.local_ip = local_ip
            self.src_ip = src_ip
            self.port = port
        except Exception as e:
            raise McastException("init address %s is not expected" % str(address))

        if address in self.McastDb.keys():
            raise McastException("init address %s was already initiated" % str(address))

        """added for interface flap situation"""
        interface_found = False
        local_addrinfo = socket.getaddrinfo(self.local_ip, None)[0]
        family = local_addrinfo[0]
        if_addrs = psutil.net_if_addrs()
        for interface in if_addrs:
            for snic in if_addrs[interface]:
                if snic.family == family:
                    if local_addrinfo[4][0] == snic.address:
                        self.interfaceList[interface] = self.interface_up
                        self.interface = interface
                        interface_found = True
            if interface_found:
                break
        if not interface_found:
            raise McastException("no interface configured with local address %s, addr:%s" %
                                 (str(self.local_ip), str(address)))

        # mcast parameter
        self.ttl = 32
        self.loop = 0  # we did not support the loop feature

        # set the mcast
        try:
            self._socket = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if family == socket.AF_INET:
                self._socket.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
                self._socket.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, self.loop)
            else:
                pass

        except Exception as e:
            self.logger.warning(
                "exception happen when create socket grp_ip[%s],src_ip[%s],local[%s], exception:%s",
                self.grp_ip, self.src_ip, self.local_ip, str(e))
            self._socket = None
        self.status = self.NOT_JOINED
        self.lastchange = time.time()
        self.McastDb[(self.local_ip, self.src_ip, self.grp_ip, self.port)] = self
        self.logger.info('setup a new Mcast instance %s' % str(address))

    def __str__(self):
        return "Mcast: (" \
               + str(self.grp_ip) + " " + str(self.src_ip) + " " + str(self.local_ip) + " " + str(self.port) + ")"

    @staticmethod
    def findMcastInstance(address):
        if address is None:
            raise McastException("init address is None")
        else:
            try:
                (local_ip, src_ip, grp_ip, port) = address
            except Exception:
                raise McastException("init address %s is not expected" % (str(address)))

        if address in Mcast.McastDb.keys():
            return Mcast.McastDb[address]
        else:
            return None

    def join(self, session):
        """ Mcast join.


        :param session: (local_ip, remote_ip, local_session, remote_session)
        :return:
        """
        self.lastchange = time.time()
        if session not in self.sessionList:
            self.sessionList.append(session)
            self.update_mcast_session_to_db(session)
            self.logger.info('%s session(local_ip, remote_ip, local_session, remote_session):%s  is  joined',
                             str(self), str(session))

        if self.status != self.JOINED:
            self._join()

    def leave(self, session):
        """

        :param session: (local_ip, remote_ip, local_session, remote_session)
        :return:
        """

        if session in self.sessionList:
            self.sessionList.remove(session)
            self.delete_mcast_session_from_db(session)
            self.logger.info('%s, session(local_ip, remote_ip, local_session, remote_session):%s  is  leaved',
                             str(self), str(session))

        if not len(self.sessionList):
            self.close()
        return

    def _pack_mcast_group_source_req(self):
        try:
            grp_addrinfo = socket.getaddrinfo(self.grp_ip, None)[0]
            family = grp_addrinfo[0]
            src_addrinfo = socket.getaddrinfo(self.src_ip, None)[0]
            ifindex = SysTools.if_nametoindex(self.interface)
            if ifindex is None:
                raise McastException("ifindex is None for %s" % self.interface)

            """ mcast_req as :
            uint32_t interface;
            struct sockaddr_storage group_req; (128 bytes);
            struct sockaddr_storage source_req; (128 bytes);

            for the sockaddr_storage:
            if this is INET6 family first 28 bytes are struct sockaddr_in6 type:
                sa_family_t sin6_family (2byte);
                in_port_t   sin6_port (2byte);
                uint32_t    sin6_flowinfo (4byte);
                struct in6_addr sin6_addr (16 bytes);
                uint32_t    sin6_scope_id; (4 byte)

            if this is the INET family first 16 bytes are struct sockaddr_in type:
                sa_family_t sa_family (2byte)
                in_port_t   sin_port (2byte)
                struct in_addr  sin_addr (4byte)
                padding (8 bytes)
            char sa_data[14]
            """
            if family == socket.AF_INET:
                group_ip_bin = socket.inet_aton(self.grp_ip)
                group_req = struct.pack('HH', family, self.port) + group_ip_bin + struct.pack('120s', "")
                source_ip_bin = socket.inet_aton(self.src_ip)
                source_req = struct.pack('HH', family, 0) + source_ip_bin + struct.pack('120s', "")
                proto = socket.IPPROTO_IP
            else:
                group_ipv6_bin = socket.inet_pton(family, grp_addrinfo[4][0])
                group_req = struct.pack('HHI', family, self.port, 0) + group_ipv6_bin + struct.pack('I100s', 0, "")
                source_ipv6_bin = socket.inet_pton(family, src_addrinfo[4][0])
                source_req = struct.pack('HHI', family, 0, 0) + source_ipv6_bin + struct.pack('I100s', 0, "")
                proto = socket.IPPROTO_IPV6

            """ for alignment, 64bit total size is 264, 32bit system, total size is 260 """
            arch = platform.architecture()
            if arch[0] == "32bit":
                mcast_req = struct.pack('I', ifindex) + group_req + source_req
            else:
                mcast_req = struct.pack('II', ifindex, 0) + group_req + source_req
            return (mcast_req, proto)
        except Exception as e:
            self.logger.warning(
                "exception happen when prepare mcast_grp_src_req grp_ip[%s],src_ip[%s],local[%s]: %s",
                self.grp_ip, self.src_ip, self.local_ip, str(e))
            return (None, None)

    def rejoin(self):
        if self.status != self.JOINED:
            return True
        try:
            self.lastchange = time.time()
            self._socket.close()

            grp_addrinfo = socket.getaddrinfo(self.grp_ip, None)[0]
            family = grp_addrinfo[0]
            self._socket = socket.socket(family,
                                         socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if family == socket.AF_INET:
                self._socket.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
                self._socket.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, self.loop)

            (mcast_req, proto) = self._pack_mcast_group_source_req()
            self._socket.setsockopt(proto, self.MCAST_JOIN_SOURCE_GROUP, mcast_req)

            if self.port:
                self._socket.bind(('', self.port))

        except Exception as e:
            self.logger.warning(
                "Exception happened when rejoin %s: %s", str(self), str(e))
            return False
        self.logger.info('Successfully rejoin %s', str(self))
        return True

    def _join(self):
        # Join the address
        try:
            (mcast_req, proto) = self._pack_mcast_group_source_req()
            self._socket.setsockopt(proto, self.MCAST_JOIN_SOURCE_GROUP, mcast_req)

            if self.port:
                self._socket.bind(('', self.port))
        except Exception as e:
            self.logger.warning(
                "Exception happened when join %s: %s", str(self), str(e))
            return

        self.status = self.JOINED
        self.logger.info('Successfully create Mcast %s', str(self))

    def _leave(self):
        if self.status == self.JOINED:
            (mcast_req, proto) = self._pack_mcast_group_source_req()
            try:
                self._socket.setsockopt(proto, self.MCAST_LEAVE_SOURCE_GROUP, mcast_req)
            except Exception as e:
                self.logger.warning(
                    "Exception happened when leave %s: %s", str(self), str(e))
                return
            self.logger.info('Successfully leave group %s', str(self))
            self.status = self.LEAVED
        else:
            self.logger.warning(
                '%s is not in joined state', str(self))

    def close(self):
        """Leave current group and close the socket. for internal call"""
        self.delete_grp_from_db()
        self._leave()
        self._socket.close()
        self.McastDb.pop((self.local_ip, self.src_ip, self.grp_ip, self.port))

    @staticmethod
    def interface_state_change(interface, state):
        """

        Args:
            interface: string, the interface name
            status: string "UP" "DOWN"

        Returns:

        """
        if interface in Mcast.interfaceList.keys():
            """ interface change to up"""
            if state == Mcast.interface_up and Mcast.interfaceList[interface] == Mcast.interface_down:
                """ rejoin all the socket"""
                Mcast.interfaceList[interface] = Mcast.interface_up
                for key in Mcast.McastDb.keys():
                    if Mcast.McastDb[key].interface == interface:
                        Mcast.McastDb[key].rejoin()
            elif state == Mcast.interface_down:
                Mcast.interfaceList[interface] = Mcast.interface_down
            else:
                pass

    def update_mcast_session_to_db(self, session):
        """

        :param session: (local_ip, remote_ip, local_session, remote_session)
        :return:
        """
        try:
            local_ip, remote_ip, local_session, remote_session, = session
            record = DepiMcastSessionRecord()
            record.updateDepiMcastSessionKey(IpAddrType=DepiMcastSessionRecord.get_inetaddr_type(self.grp_ip),
                                             GroupIpAddr=self.grp_ip,
                                             SrcIpAddr=self.src_ip,
                                             SessionId=local_session)

            record.updateDepiMcastSessionData(LocalLcceIpAddr=local_ip,
                                              RemoteLcceIpAddr=remote_ip,
                                              JoinTime=Convert.pack_timestamp_to_string(self.lastchange))
            record.write()
        except Exception as e:
            self.logger.warning("%s failed to update ses:%s into db for exception %s",
                                str(self), str(session), str(e))

    def delete_mcast_session_from_db(self, session):
        """

        :param session: (local_ip, remote_ip, local_session, remote_session)
        :return:
        """
        try:
            local_ip, remote_ip, local_session, remote_session, = session
            record = DepiMcastSessionRecord()
            record.updateDepiMcastSessionKey(IpAddrType=DepiMcastSessionRecord.get_inetaddr_type(self.grp_ip),
                                             GroupIpAddr=self.grp_ip,
                                             SrcIpAddr=self.src_ip,
                                             SessionId=local_session)
            record.delete()
        except Exception as e:
            self.logger.warning("%s failed to delete ses:%s from db for exception %s",
                                str(self), str(session), str(e))

    def delete_grp_from_db(self):
        for session in self.sessionList:
            self.delete_mcast_session_from_db(session)
