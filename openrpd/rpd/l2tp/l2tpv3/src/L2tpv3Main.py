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

import sys
import os
#import daemon
import json
import fcntl
import logging
import argparse
import re

# Setting the python path
currentPath = os.path.dirname(os.path.realpath(__file__))
dirs = currentPath.split("/")
rpd_index = 0
l2tp_index = 0
for i in range(len(dirs)):
    if dirs[i] == 'rpd':
        rpd_index = i

    if dirs[i] == 'l2tp':
        l2tp_index = i

if rpd_index == 0 or l2tp_index == 0:
    print "Cannot find the openrpd/l2tp directory, please correct it"
    sys.exit(-1)

sys.path.append('/'.join(dirs[:rpd_index + 1]))
sys.path.append('/'.join(dirs[:l2tp_index + 1]))

import L2tpv3API
import L2tpv3Dispatcher
from rpd.dispatcher.dispatcher import Dispatcher
import L2tpv3GlobalSettings
from L2tpv3Hal import L2tpHalClient
# Please don't remove this, the avp will register when we import them
import L2tpv3RFC3931AVPs
import docsisAVPs.src.L2tpv3CableLabsAvps
import L2tpv3CiscoAVPs
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.common.rpd_logging import setup_logging


def _main():
    """The _main function, setup the dispatcher and the API part.

    :return: None

    """
    global_dispatcher = Dispatcher()
    l2tp_dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(global_dispatcher,
                                                        L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress)
    L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = l2tp_dispatcher

    # setup the halclient

    hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                               "the HAL client of L2TP feature",
                               "1.0", tuple(L2tpHalClient.notification_list.keys()), global_dispatcher,
                               L2tpHalClient.supportmsg_list)
    L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client = hal_client
    hal_client.start(l2tp_dispatcher.receive_hal_message)
    # Construct the API transport path
    ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
    print ApiPath
    api = L2tpv3API.L2tpv3API(ApiPath)
    l2tp_dispatcher.register_zmq(api)
    l2tp_dispatcher.register_remote_address()
    global_dispatcher.loop()


class _daemonPidFile(object):

    def __init__(self, PidFilePath="/tmp/l2tp.pid"):
        self._pidFilePath = PidFilePath
        self._pidFileObj = None

    def __enter__(self):
        self._pidFileObj = open(self._pidFilePath, "a+")
        try:
            fcntl.flock(
                self._pidFileObj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as e:
            raise Exception("Already running according to:%s, error:%s" %
                            (self._pidFilePath, str(e)))

        # We have lock the file, write the pid into the file
        pid = os.getpid()
        pid = str(pid)

        self._pidFileObj.seek(0)
        self._pidFileObj.truncate()
        self._pidFileObj.write(pid)
        self._pidFileObj.flush()
        # we need this since we want to readback the pid

        return self._pidFileObj

    def __exit__(self, type=None, value=None, tb=None):
        try:
            self._pidFileObj.close()
        except IOError as err:
            if err.errno != 9:
                raise Exception("Cannot close the pid file:%s, reason:%s" %
                                (self._pidFilePath, str(err)))

        # remove the file
        os.remove(self._pidFilePath)


def main():
    parser = argparse.ArgumentParser(description="L2tp control process")
    # parse the daemon settings.
    parser.add_argument("-d", "--daemon",
                        action="store_true",
                        help="run the program with daemon mode")

    # parse the local bind IP address
    parser.add_argument("-i", "--ip",
                        action="store",
                        help="Host Ip address")

    # parse the API sock file
    parser.add_argument("-s", "--sockFile",
                        action="store",
                        help="sockFile is used by the client to communicate with daemon.")

    # parse the logfile path
    parser.add_argument("-f", "--debugDir",
                        action="store",
                        help="debugDir flag indicates the debug file directory.")

    # parse the deemon file directory
    parser.add_argument("-F", "--daemonDir",
                        action="store",
                        help="daemonDir flag indicates the daemon files directory")
    arg = parser.parse_args()

    if arg.sockFile is not None:
        print "The API socket file is:%s" % arg.sockFile
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath = "ipc://" + \
            arg.sockFile
    else:
        print "Cannot get the API path from the args, use the default " \
              "value:%s" % L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath

    if arg.debugDir is not None:
        print "The debug file directory is:%s" % arg.debugDir
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.DebugFileDir = arg.debugDir
    else:
        print "Cannot get the debug directory from args, use the default " \
              "value:%s" % L2tpv3GlobalSettings.L2tpv3GlobalSettings.DebugFileDir

    if arg.daemonDir is not None:
        print "The daemon file directory is %s" % arg.daemonDir
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.DaemonFileDir = arg.daemonDir
    else:
        print "Cannot get the daemon directory from args, use the default " \
              "value:%s" % L2tpv3GlobalSettings.L2tpv3GlobalSettings.DaemonFileDir

    if arg.ip is not None:
        ipPattern = "(\d{1,3}\.){3}\d{1,3}"
        matches = re.match(ipPattern, arg.ip)
        if matches:
            print "The local IP address is:", arg.ip
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress = arg.ip
        else:
            print "IP address[%s] format error, please specify a correct IP address" % arg.ip
            sys.exit(-1)
    else:
        print "No Ip address are specified, use the local host address:127.0.0.1"
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.LocalIPAddress = "127.0.0.1"

    # The reason to pull out this part code is for the daemon, we have to keep
    # the fd.

    _context = daemon.DaemonContext(
        working_directory=L2tpv3GlobalSettings.L2tpv3GlobalSettings.DaemonFileDir,
        pidfile=_daemonPidFile(
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.DaemonFileDir + "l2tp.pid"),
        stdout=open(
            L2tpv3GlobalSettings.L2tpv3GlobalSettings.DaemonFileDir + "l2tp.out", "w+")
    )

    if arg.daemon:
        # Keep the logging FD
        keepFD = []
        for h in logging._handlers:
            handler = logging._handlers[h]
            if isinstance(handler, logging.FileHandler):
                fd = logging._handlers[h].stream
                keepFD.append(fd)
        _context.files_preserve = keepFD
        with _context:
            _main()
    else:
        _main()


if __name__ == "__main__":
    setup_logging('L2TP', filename="l2tp_main.log")
    _main()
