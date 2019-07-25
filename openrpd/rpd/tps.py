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

"""Simple UDP server for TIME PROTOCOL(RFC868)"""

import time      # LOCAL TIME
import calendar  # UTC
import socket
import struct
import os
import argparse
from sys import argv

from subprocess import call
from rpd.common.utils import SysTools
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass


class TimeServer(object):
    PORT = 37

    __metaclass__ = AddLoggerToClass

    def __init__(self, family=socket.AF_INET, port=PORT):
        self.family = family
        self.port = port

    @staticmethod
    def get_current_time():
        """Get current system time and convert it to TimeProtocol timestamp.

        :return: TimeProtocol timestamp
        :rtype: float

        """
        curr_time = time.time()  # UTC in sec
        TimeServer.logger.info(
            'Sending time: local[%s] UTCp[%s]', time.ctime(curr_time),
            time.asctime(time.gmtime(curr_time)))

        # convert EPOCH time (which is starting since 1970-01-01 00:00.00 UTC)
        # to TIME PROTOCOL(RFC868) time (starting since 1900-01-01 00:00.00
        # UTC)
        tp_null_time = (1900, 1, 1, 0, 0, 0, 0, 0, 0)
        # Difference 1970 - 1900
        diff_null_time = calendar.timegm(tp_null_time)  # tp_null = -2208988800
        # Current epoch time + difference (inverted, because it's negative)
        # to get current time in TP format
        tp_current = curr_time + (-diff_null_time)
        TimeServer.logger.info(
            "Sending UTCsec(%u) result (%u)", curr_time, tp_current)
        return tp_current

    def listen(self):
        """Start listening on port 37 and reply to each request with current
        timestamp encoded as unsigned integer.

        :return:

        """
        soc = socket.socket(family=self.family, type=socket.SOCK_DGRAM)
        if self.family == socket.AF_INET6:
            soc.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        soc.bind(('', self.port))

        TimeServer.logger.info(
            'Listening for time-requests on port %d ...', self.port)

        while 1:
            _, address = soc.recvfrom(256)
            TimeServer.logger.info(
                'Sending response to IP-address: %s', address[0])
            current_time = TimeServer.get_current_time()
            soc.sendto(struct.pack("!I", current_time), address)


class TimeServerManager(object):
    SCRIPT_FILE_NAME = __name__.split('.')[-1] + ".py"

    def __init__(self):
        if SysTools.is_system_openwrt():
            self.path_bin = '/usr/lib/python2.7/site-packages/rpd/'
        else:
            # self.path_bin = './'
            self.path_bin = os.path.split(os.path.realpath(__file__))[0]

    def is_server_running(self):
        """Check if any instance of time server is running.

        :return: True if at least one instance is running
        :rtype: bool

        """
        return 0 == call(["pgrep", '-f', self.SCRIPT_FILE_NAME])

    def start_server(self, delay=0, ipv6=False, port=TimeServer.PORT):
        """Start time server in background.

        :param delay: start will be delayed specified number of seconds
        :type delay: integer
        :param ipv6: if false ipv4 is used else ipv6
        :return: True if success
        :rtype: bool

        """
        port_opt = "--port " + str(port)
        cmd = "python {}/{} {} {}&".format(self.path_bin, self.SCRIPT_FILE_NAME,
                                           "--ipv6" if ipv6 else "", port_opt)
        if 0 != delay:
            sleep_cmd = "sleep {} && ".format(delay)
            cmd = sleep_cmd + cmd

        if self.is_server_running():
            self.stop_server()

        success = (0 == call(cmd, shell=True))
        # Wait a sec to be sure server is initialized
        if success:
            time.sleep(1)
        return success

    def stop_server(self):
        """Stop time server if it is running.

        :return: True if success
        :rtype: bool

        """
        if self.is_server_running():
            kill_cmd = "kill -9 `pgrep -f {}`".format(self.SCRIPT_FILE_NAME)
            call(kill_cmd, shell=True)
        time.sleep(1)
        # If it is still running, then something failed
        return not self.is_server_running()


def main(arg_list):
    """Process arguments and start TimeProtocol server accepted arguments:

    --ipv6: Start listening on ipv6 addresses instead of ipv4 (default)

    :param arg_list: list of arguments passed to script
    :return:

    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--port', type=int, help='connection port')
    ip_version = socket.AF_INET
    args = parser.parse_args()
    if args.ipv6:
        ip_version = socket.AF_INET6
    TimeServer(ip_version, args.port).listen()


if __name__ == "__main__":
    # setup logging, will search the config files
    setup_logging("TPS", filename="tps.log")

    main(argv[1:])
