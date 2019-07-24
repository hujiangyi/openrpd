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
import os
import logging
import psutil
import socket
import zmq
import traceback
import struct
from time import time
import argparse
import rpd.python_path_resolver
import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
import l2tpv3.src.L2tpv3API as L2tpv3API
import l2tpv3.src.L2tpv3Dispatcher as L2tpv3Dispatcher
import l2tpv3.src.L2tpv3GlobalSettings as L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3Connection import L2tpConnection

from l2tpv3.src.L2tpv3Hal import L2tpHalClient
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.mcast.src.mcast import Mcast
from rpd.common.utils import Convert, SysTools


class L2tpAgent(agent.ProcessAgent):

    """This class defines a l2tp process agent.

    the main logic is to start the l2tp feature. Also it is responsible
    for handling the event from mgr.

    """

    UP = "UP"
    DOWN = "DOWN"
    NA = "NA"
    RTMGRP_LINK = 1

    NLMSG_NOOP = 1
    NLMSG_ERROR = 2

    RTM_NEWLINK = 16
    RTM_DELLINK = 17

    IFLA_IFNAME = 3
    IFLA_OPERSTATE = 16
    states = ('UNKNOWN',
              'NOTPRESENT',
              'DOWN',
              'LOWERLAYERDOWN',
              'TESTING',
              'DORMANT',
              'UP')
    state_by_name = dict(((i[0], i[1]) for i in enumerate(states)))

    __metaclass__ = AddLoggerToClass

    def __init__(self, simulate_mode=False, agent_id=agent.ProcessAgent.AGENTTYPE_L2TP):

        super(L2tpAgent, self).__init__(agent_id)
        # The follow code is used to initialize l2tp
        # get the l2tp configuration path

        dispatcher = self.dispatcher
        l2tp_dispatcher = L2tpv3Dispatcher.L2tpv3Dispatcher(
            dispatcher,
            local_addr=None,
            # since we don't create global listen, set it to None
            create_global_listen=False)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.Dispatcher = l2tp_dispatcher

        # setup the halclient
        hal_client = L2tpHalClient("L2TP_HAL_CLIENT",
                                   "the HAL client of L2TP feature",
                                   "1.0", tuple(L2tpHalClient.notification_list.keys()), dispatcher,
                                   L2tpHalClient.supportmsg_list)
        L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client = hal_client
        hal_client.start(l2tp_dispatcher.receive_hal_message)
        if L2tpv3GlobalSettings.L2tpv3GlobalSettings.l2tp_hal_client:
            self.logger.info("setup l2tp hal client successfully")

        # Construct the API transport path
        ApiPath = L2tpv3GlobalSettings.L2tpv3GlobalSettings.APITransportPath
        api = L2tpv3API.L2tpv3API(ApiPath)
        l2tp_dispatcher.register_zmq(api)

        self.l2tp_dispatcher = l2tp_dispatcher

        # the l2tp connection which will be checked, the schema is as follows:
        # (local_addr, remote_addr): {
        #   "status" : UP/DOWN
        #   "lastChangeTime": time()
        #   "id":core id
        # }
        self.l2tp_status = dict()

        self.register_poll_timer(1, self._check_l2tp_status_callback, None)
        self.counter = 0

        # setup link sock to get the link state change
        self.linksock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        self.linksock.bind((os.getpid(), self.RTMGRP_LINK))
        self.dispatcher.fd_register(self.linksock.fileno(),
                                    zmq.POLLIN, self.process_link_status)

    def process_event_action(self, action):
        """Process the request from the client. Currently, we will support the
        following event: start/check status/stop.

        :param action: the protobuf object, which contains the event information.
        :return: the function will return an message to remote, success or fail.

        """
        ccap_id = action.ccap_core_id
        event_action = action.action

        self.logger.debug("CCAP core[%s] issued an event action:%s", ccap_id, action)
        if ccap_id not in self.ccap_cores:
            self.logger.warn("Cannot process the event action for id %s, reason: id is not registered" % ccap_id)
            self._send_event_notification(ccap_id,
                                          protoDef.msg_core_event_notification.FAIL,
                                          "CCAP core ID is not registered")
            return

        if not action.HasField("parameter"):
            self.logger.warn(
                "Cannot process the event action for id %s, reason:Parameter is not set" % ccap_id)
            # return error
            self._send_event_notification(
                ccap_id,
                protoDef.msg_core_event_notification.FAIL,
                "Parameter is not set")
            return
        parameter = action.parameter

        # parameter is a string, we need to parse the string
        parameters = parameter.split(";")
        interface = parameters[0].strip()
        ccap_ip = parameters[1].strip()

        is_ipv6 = Convert.is_valid_ipv6_address(ccap_ip)
        family = (socket.AF_INET, socket.AF_INET6)[is_ipv6]
        # Get the interface IP address
        ip_addr = SysTools.get_ip_address(str(interface), family)

        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            if ip_addr is None:
                self.logger.warn(
                    "Cannot start/check l2tp status for id %s, "
                    "reason:cannot find the ip addr for interface %s" %
                    (ccap_id, interface))
                self._send_event_notification(
                    ccap_id,
                    protoDef.msg_core_event_notification.FAIL,
                    "cannot find the ip addr for interface %s" % interface)
                return

            # check if we have start the l2tp address for this IP address
            ret, reason = self.l2tp_dispatcher.register_local_address(ip_addr)
            if not ret:
                self.logger.warn("Cannot start/check l2tp status for id %s, "
                                  "reason:%s" %
                                  (ccap_id, reason))
                self._send_event_notification(
                    ccap_id, protoDef.msg_core_event_notification.FAIL, reason)
                return

            # check if we are in the requester list, if yes, we just
            # send a current status to it
            if (ip_addr, ccap_ip) not in self.l2tp_status:
                # create a interface in self interfaces
                self.l2tp_status[(ip_addr, ccap_ip)] = {
                    "status": self.DOWN,
                    "lastChangeTime": time(),
                    "ccap_core_id": ccap_id,
                }
                self.l2tp_dispatcher.register_remote_address(ccap_ip)

            # check the l2tp status
            for k in L2tpConnection.ConnectionDb:
                connection = L2tpConnection.ConnectionDb[k]
                if connection.remoteAddr == ccap_ip and connection.localAddr == ip_addr:
                    self.l2tp_status[(ip_addr, ccap_ip)]['status'] = self.UP
                    break

            self._send_event_notification(
                ccap_id, protoDef.msg_core_event_notification.OK,
                reason="Id has been issue this action, send current status to you",
                result=self.l2tp_status[(ip_addr, ccap_ip)]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            for k in L2tpConnection.ConnectionDb:
                connection = L2tpConnection.ConnectionDb[k]
                """
                we only get a single connection for the same remoteAddr,
                Do not check the local ip address in case ip_addr is none for now
                """
                if connection.remoteAddr == ccap_ip:
                    ip_addr = connection.localAddr
                    connection.StopConnection()
                    break
            if (ip_addr, ccap_ip) in self.l2tp_status:
                self.l2tp_status.pop((ip_addr, ccap_ip))
                self.l2tp_dispatcher.unregister_remote_address(ccap_ip)
                if len(self.l2tp_status) == 0:
                    ret, reason = self.l2tp_dispatcher.request_unregister(
                        {"unregType": "localaddress", "value": ip_addr})
                    if not ret:
                        self.logger.warn(
                            "l2tp stop CCAP core[%s], unregister ip %s failed for %s",
                            ccap_id, ip_addr, reason)
                self._send_event_notification(
                    ccap_id, protoDef.msg_core_event_notification.OK,
                    reason="Successful stop event.")
            else:
                self._send_event_notification(
                    ccap_id, protoDef.msg_core_event_notification.FAIL,
                    reason="Cannot stop event since can not find it.")

            return

    def _check_l2tp_status_callback(self, arg):
        """This function will poll the l2tp connection DB, check the connection
        status and update the core L2TP status.

        :param arg: Not used by this function.
        :return: None

        """
        # every 60 enter, show a debug log
        self.counter += 1
        show_log = False
        if self.counter == 60:
            show_log = 1
            self.counter = 0
        if show_log:
            self.logger.debug("Check the l2tp status...")

        if len(self.l2tp_status) == 0:
            return

        for (local_ip, remote_ip) in self.l2tp_status:
            if show_log:
                self.logger.debug(
                    "Check the connection(%s,%s) status..." %
                    (local_ip, remote_ip))
            ccap_l2tp_status = self.DOWN
            for k in L2tpConnection.ConnectionDb:
                connection = L2tpConnection.ConnectionDb[k]
                if connection.remoteAddr == remote_ip and connection.localAddr == local_ip:
                    ccap_l2tp_status = self.UP
                    break

            if self.l2tp_status[(local_ip, remote_ip)]['status'] != ccap_l2tp_status:
                self.logger.info(
                    "ccap (%s, %s) status is changed to %s" %
                    (local_ip, remote_ip, ccap_l2tp_status))
                ccap_id = self.l2tp_status[(local_ip, remote_ip)]['ccap_core_id']
                self._send_event_notification(
                    ccap_id, protoDef.msg_core_event_notification.OK,
                    reason="Status changed",
                    result=ccap_l2tp_status)

                self.l2tp_status[(local_ip, remote_ip)]['status'] = ccap_l2tp_status
        return

    def _decode_link_state(self, data):
        """

        Args:
            data: the data receive by AF_NETLINK sock

        Returns: (interface, state) example ("eth1", "UP")("eth1", "DOWN")(None, None)

        """
        if len(data) <= 16:
            return None, "Data lengh is %d <= 16" % len(data)
        interface = None
        state = None
        try:
            msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", data[:16])
            if msg_type != self.RTM_NEWLINK:
                return None, "msg_type is %d not RTM_NEWLINK" % msg_type
            data = data[16:]
            family, _, if_type, index, flags, change = struct.unpack("=BBHiII", data[:16])

            remaining = msg_len - 32
            data = data[16:]
            while remaining:
                rta_len, rta_type = struct.unpack("=HH", data[:4])
                # This check comes from RTA_OK, and terminates a string of routing
                # attributes.
                if rta_len < 4:
                    return None, "data is broken, since rta len %d < 4" % rta_len

                rta_data = data[4:rta_len]

                increment = (rta_len + 4 - 1) & ~(4 - 1)
                data = data[increment:]
                remaining -= increment

                if rta_type == self.IFLA_IFNAME:
                    fmt = "%dsB" % (rta_len - 5)
                    interface, z, = struct.unpack(fmt, rta_data)
                if rta_type == self.IFLA_OPERSTATE:
                    state_index, = struct.unpack("B", rta_data)
                    state = self.state_by_name[state_index]
                if interface and state:
                    return interface, state
            return None, "data is broken, interface %s, state: %s" % (interface, state)

        except Exception as e:
            return None, str(e)

    def process_link_status(self, sock, eventmask):
        """

        Args:
            sock:
            eventmask:

        Returns:

        """
        try:
            if sock is not None:
                if isinstance(sock, int) and eventmask == zmq.POLLIN:
                    if sock != self.linksock.fileno():
                        self.logger.warn(
                            "Got a unexpected socket event, the sock is not expected ")
                        return
                    data = self.linksock.recv(65535)
                    interface, state = self._decode_link_state(data)
                    if interface is None:
                        self.logger.debug("Fail to decode interface state:%s", state)
                        return
                    self.logger.warn("receive msg: %s is %s", interface, state)
                    Mcast.interface_state_change(interface=interface, state=state)

        except Exception as e:
            self.logger.warn("Exception happens when handle link status, error:" + str(e) + ", The Trace back is:\n" +
                              traceback.format_exc())
        return

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="l2tp main process")
    # parse the daemon settings.
    parser.add_argument("-s", "--simulator",
                        action="store_true",
                        help="run the program with simulator mode")
    arg = parser.parse_args()
    setup_logging(("PROVISION", "L2TP"), filename="provision_l2tp.log")
    l2tp_agent = L2tpAgent(simulate_mode=arg.simulator)
    l2tp_agent.start()
