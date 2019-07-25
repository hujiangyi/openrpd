#
# Copyright (c) 2016 Cisco and/or its affiliates, and
#                    Teleste Corporation, and
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
"""This is the simulate peer file, Ut will not cover this packet."""
import os
import sys
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

from random import randint
import l2tpv3.src.L2tpv3Connection as L2tpv3Connection
import l2tpv3.src.L2tpv3Dispatcher as L2tpv3Dispatcher
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
import l2tpv3.src.L2tpv3Session as L2tpv3Session
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging
from psutil import net_if_addrs
from rpd.common.utils import Convert

setup_logging('L2TP', filename="l2tp_master_sim.log")


def is_valid_ip(ipaddr):
    ip_bytes = ipaddr.split(".")
    if len(ip_bytes) == 4 and int(ip_bytes[0]) < 224 and \
       int(ip_bytes[3]) > 0 and int(ip_bytes[3]) != 255:
        return True
    return False


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print "Please specify ipv4 or ipv6\n"
        print "EXAMPLE:\n"
        print "python L2tpv3MasterSim.py ipv4 <remote IP> <local IP>\n"
        sys.exit(False)
    if sys.argv[1] != 'ipv4' and sys.argv[1] != 'ipv6':
        print "Please specify ipv4 or ipv6"
        sys.exit(False)
    if sys.argv[1] == 'ipv4':
        if len(sys.argv) > 2 and Convert.is_valid_ipv4_address(sys.argv[2]):
            RemoteIPAddress = sys.argv[2]
        else:
            RemoteIPAddress = "127.0.0.1"
        if len(sys.argv) > 3 and Convert.is_valid_ipv4_address(sys.argv[3]):
            LocalIPAddress = sys.argv[3]
        else:
            LocalIPAddress = "127.0.0.1"

        for intf in net_if_addrs().values():
            (family, addr, mask) = (intf[0][0], intf[0][1], intf[0][2])
            if family == 2:
                addr_b = addr.split(".")
                mask_b = mask.split(".")
                raddr_b = RemoteIPAddress.split(".")
                if int(addr_b[0]) & int(mask_b[0]) == int(raddr_b[0]) & int(mask_b[0]) and \
                   int(addr_b[1]) & int(mask_b[1]) == int(raddr_b[1]) & int(mask_b[1]) and \
                   int(addr_b[2]) & int(mask_b[2]) == int(raddr_b[2]) & int(mask_b[2]) and \
                   int(addr_b[3]) & int(mask_b[3]) == int(raddr_b[3]) & int(mask_b[3]):
                    LocalIPAddress = addr
                    break
    else:
        if len(sys.argv) > 2 and Convert.is_valid_ipv6_address(sys.argv[2]):
            RemoteIPAddress = sys.argv[2]
        else:
            RemoteIPAddress = "::1"
        if len(sys.argv) > 3 and Convert.is_valid_ipv6_address(sys.argv[3]):
            LocalIPAddress = sys.argv[3]
        else:
            LocalIPAddress = "::1"

    print "RemoteIPAddress ", RemoteIPAddress
    print "LocalIPAddress ", LocalIPAddress

    global_dispatcher = Dispatcher()
    l2tp_dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(global_dispatcher,
                                                        LocalIPAddress,
                                                        create_global_listen=False)
    L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = l2tp_dispatcher

    l2tp_dispatcher.register_remote_address(RemoteIPAddress)

    # we need to create connection
    connection = L2tpv3Connection.L2tpConnection(
        0, 0, RemoteIPAddress, LocalIPAddress)

    def create_session_and_fire(connection):

        fsm = connection.fsm

        if fsm.fsm.current != 'established':
            return

        session = L2tpv3Session.L2tpv3Session(
            randint(1, 0xFFFFFFFF), 0, "sender", connection)
        connection.addSession(session)
        session.LocalRequest()

    l2tp_dispatcher.testPlan = dict()
    l2tp_dispatcher.testPlan[15] = {  # will execute it after 15 s
        'name': "Create a session and triger the session initial process",
        'handler': create_session_and_fire,
        'arg': connection
    }

    print "Connect from " + LocalIPAddress + " to " + RemoteIPAddress
    connection.localRequest(RemoteIPAddress)

    global_dispatcher.loop()
