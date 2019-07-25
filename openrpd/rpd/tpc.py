#!/usr/bin/python
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

"""UDP client for TIME PROTOCOL(RFC868)"""
import time  # LOCAL TIME
import calendar  # UTC
import socket
import argparse
import zmq
from struct import unpack
from os import EX_OK, EX_UNAVAILABLE, EX_OSERR, EX_DATAERR
from select import select
from random import randint

from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import Convert
from rpd.gpb.tpc_pb2 import t_TpcMessage
from rpd.common import rpd_event_def

__all__ = ['TimeClient']


class TimeClient(object):
    PORT = 37
    SOCK_TIMEOUT = 1
    COLLISION_MAX_DEFAULT = 7
    RESPONSE_DATA_LEN = 4
    EXIT_TIMEOUT = 5

    __metaclass__ = AddLoggerToClass

    def __init__(self, collisions=COLLISION_MAX_DEFAULT, ipv6=False,
                 ipc_sock_addr=None, port=PORT):
        self.collision_max = collisions
        self.family = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.port = port
        self.ipc_sock = None
        self.valid_timeserver = []
        self.server_list = []
        if ipc_sock_addr is not None:
            try:
                context = zmq.Context.instance()
                self.ipc_sock = context.socket(zmq.PUSH)
                self.ipc_sock.connect(ipc_sock_addr)
            except zmq.ZMQError:
                self.logger.error("Failed to open IPC socket")
                exit(EX_OSERR)

    def get_time(self, server_list):
        """Connect to list of time-servers and wait for first reply.

        :param server_list: list of time-servers
        :type server_list: list of strings
        :return: timestamp from time-server or 0 (in case of failure)
        :rtype: int

        """
        sock_list = []
        # connect to all time servers
        for server in server_list:
            self.logger.debug("Opening socket to time server: %s", server)
            try:
                sock = socket.socket(self.family, socket.SOCK_DGRAM)
                self.logger.debug("Sending request to server: %s", server)
                sock.sendto("", (server, self.port))
            except socket.error as message:
                self.logger.error("Failed connection to server %s: %s ",
                                  server, message)
                continue
            sock_list[len(sock_list):] = [sock]

        # wait for first response
        try:
            readable_list, _, _ = select(sock_list, [], [], self.SOCK_TIMEOUT)
        except socket.error as message:
            self.logger.error("Select failed: %s ", message)
            for sock in sock_list:
                sock.close()
            return 0

        # read data from reply
        timestamp = 0
        for ready in readable_list:
            try:
                data, server_address = ready.recvfrom(self.RESPONSE_DATA_LEN)
            except socket.error as message:
                self.logger.error("Recvfrom failed: %s ", message)
                for sock in sock_list:
                    sock.close()
                return 0

            # convert TIME PROTOCOL(RFC868) time
            # (which is starting since 1900-01-01 00:00.00 UTC)
            # to EPOCH time (which is starting since 1970-01-01 00:00.00 UTC)

            # Number of seconds after 1900
            utc_timestamp = unpack("!I", data)
            # Get epoch timestamp from TP null time
            tp_null_time = (1900, 1, 1, 0, 0, 0, 0, 0, 0)
            tp_null_time = calendar.timegm(tp_null_time)
            # Sum to get current epoch timestamp
            timestamp = utc_timestamp[0] + tp_null_time
            break

        # is it valid result?
        if timestamp != 0:
            self.valid_timeserver.append(server_address[0])
            self.logger.info("Received value from '%s' utc epoch %s",
                             server_address, time.asctime(time.gmtime(timestamp)))
        # cleanup
        for sock in sock_list:
            sock.close()

        return timestamp

    def get_time_with_retries(self, server_list):
        """Get time from list of time-servers with backoff retry mechanism.

        :param server_list: list of time-servers IP addresses
        :type server_list: list of strings
        :return: timestamp from time-server or 0 (in case of failure)
        :rtype: int

        """
        init_value = 1
        for collision in range(1, self.collision_max):

            timestamp = self.get_time(server_list)

            self.logger.info("Attempt[%d]: result: %d", collision, timestamp)

            # Have valid timestamp
            if timestamp != 0:
                return timestamp

            # Reset system time after first failed attempt
            if collision == 1 and self.ipc_sock is not None:
                msg = t_TpcMessage()
                msg.Status = msg.FIRST_ATTEMPT_FAILED
                msg.Validtimeserver = ';'.join(self.server_list)
                self.send_ipc_msg(msg)

            # In case of fail we will sleep some time based on random backoff
            rand_max = 2 ** collision - 1
            sleep_time = randint(init_value, rand_max)
            init_value = rand_max
            self.logger.info("Sleeping for %u sec", sleep_time)
            time.sleep(sleep_time)

        self.notify.error(rpd_event_def.RPD_EVENT_TOD_NO_RESPONSE[0], '')
        return 0

    def process_system_time(self, server_list, time_offset):
        """Try to get current time from list of time-servers with backoff retry
        logic. When valid timestamp is received, time-offset is added and
        result is send to manager process.

        :param server_list: List of time-server IP addresses (IPv4 or IPv6)
        :type: list of strings
        :param time_offset: number of seconds to be added to received timestamp
        :type time_offset: int
        :return:

        """
        self.server_list = server_list
        if len(server_list) == 0:  # pragma: no cover
            self.send_error_ipc_msg("Empty list of time-servers")
            exit(EX_DATAERR)

        timestamp = self.get_time_with_retries(server_list)
        if 0 == timestamp:
            self.send_error_ipc_msg("Failed to get timestamp")
            exit(EX_UNAVAILABLE)

        if self.ipc_sock is not None:
            # Valid timestamp
            msg = t_TpcMessage()
            msg.Status = msg.SUCCESS
            msg.Timestamp = timestamp + time_offset
            msg.Validtimeserver = ';'.join(self.valid_timeserver)
            self.send_ipc_msg(msg)

    def send_ipc_msg(self, ipc_msg):
        """Notify manager about progress in getting of ToD.

        :param ipc_msg: GPB message to be sent
        :type ipc_msg: t_TpcMessage
        :return:

        """
        if ipc_msg is None or not ipc_msg.IsInitialized():  # pragma: no cover
            self.logger.error('Invalid IPC message provided')
            return
        msg_str = ipc_msg.SerializeToString()
        if 0 == len(msg_str):  # pragma: no cover
            self.logger.warn('Empty IPC msg, dropping ...')
            return
        self.ipc_sock.send(msg_str)
        self.logger.info("TPC data sent to manager, length[%d]", len(msg_str))

    def send_error_ipc_msg(self, error_msg):
        """Notify manager about failures occurred during getting of ToD.

        :param error_msg: Description of occurred error, will be used for syslog
        :type error_msg: string
        :return:

        """
        if self.ipc_sock is None:  # pragma: no cover
            return
        msg = t_TpcMessage()
        msg.Status = msg.ALL_ATTEMPTS_FAILED
        msg.Validtimeserver = ';'.join(self.server_list)
        if error_msg is not None:
            msg.ErrorMessage = error_msg
        self.send_ipc_msg(msg)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--port', type=int, help='connection port')
    parser.add_argument('--collisions', type=int, help='collisions')
    parser.add_argument(
        '--offset', type=int, required=True, help='Time offset')
    parser.add_argument('--servers', nargs='+', required=True,
                        help='List of time-servers addresses')
    parser.add_argument('--ipc-address', required=True,
                        help='Address for IPC communication')
    args = parser.parse_args()
    # Check IP addresses
    for server in args.servers:
        check_fn = Convert.is_valid_ipv4_address
        if args.ipv6:
            check_fn = Convert.is_valid_ipv6_address

        if not check_fn(server):
            parser.error("Not valid ip address: {}".format(server))
    if args.collisions == None:
        args.collisions = TimeClient.COLLISION_MAX_DEFAULT
    if args.port == None:
        args.port = TimeClient.PORT
    # Start time client
    client = TimeClient(ipv6=args.ipv6, collisions=args.collisions,
                        ipc_sock_addr=args.ipc_address, port=args.port)
    client.process_system_time(args.servers, args.offset)

    # let the manager to receive message till exit
    time.sleep(client.EXIT_TIMEOUT)
    exit(EX_OK)


if __name__ == "__main__":
    # setup logging, will search the config files
    setup_logging("TPC", filename="tpc.log")

    main()
