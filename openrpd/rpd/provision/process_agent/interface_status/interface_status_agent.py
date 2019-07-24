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

from time import time
from psutil import net_if_stats
import zmq
import json
from subprocess import check_output

from rpd.common.utils import SysTools
import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass


class InterfaceStatus(agent.ProcessAgent):
    UP = "UP"
    DOWN = "DOWN"
    NA = "NA"

    EVENT_DOWN_TO_UP = 1
    EVENT_UP_TO_DOWN = 2

    CHECK_INTERFACE_STATUS_PERIOD = 1
    INTERFACE_STATUS_DOWN_LASTED = 120
    # to align with I07 6.11 definition
    # CIN_LINK_TIMEOUT 120 second

    SCAN_INTERFACE_PERIOD = 5
    __metaclass__ = AddLoggerToClass

    init_start = True

    def __init__(self, agent_id=agent.ProcessAgent.AGENTTYPE_INTERFACE_STATUS):

        super(InterfaceStatus, self).__init__(agent_id)

        self.interfaces = {}

        self.register_poll_timer(
            self.SCAN_INTERFACE_PERIOD, self.scan_available_interface)
        self.register_poll_timer(
            self.CHECK_INTERFACE_STATUS_PERIOD,
            self._check_interface_status_callback)

    def process_event_action(self, action):
        """Process the request from the client.

        :param action:
        :return:

        """
        ccap_core_id = action.ccap_core_id
        event_action = action.action

        self.logger.debug("Receive an event action:%s", action)

        if ccap_core_id not in self.ccap_cores:
            self.logger.error(
                "Cannot process the event action for id %s, reason: id is not registered" % ccap_core_id)
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                "CCAP core ID is not registered")
            return

        if not action.HasField("parameter"):
            self.logger.error(
                "Cannot process the event action for id %s, reason:Parameter is not set" % ccap_core_id)
            # return error
            self._send_event_notification(
                ccap_core_id,
                protoDef.msg_core_event_notification.FAIL,
                "Parameter is not set")
            return
        parameter = action.parameter

        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            # check if we are in the requester list, if yes, we just send a current status to it
            if parameter in self.interfaces:
                if ccap_core_id not in self.interfaces[parameter]["requester"]:
                    self.interfaces[parameter]["requester"].append(ccap_core_id)
            else:
                # create a interface in self interfaces
                self.interfaces[parameter] = {
                    "status": self.DOWN,
                    "requester": [ccap_core_id,],
                    "flappingTimer": None,
                }
                # check interface status when first time created
                stats = net_if_stats()
                if parameter in stats and stats[parameter].isup:
                    self.interfaces[parameter]['status'] = self.UP

            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.OK,
                "Id has been issue this action, send current status to you",
                result=self.interfaces[parameter]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            if parameter in self.interfaces:
                if ccap_core_id in self.interfaces[parameter]["requester"]:
                    self.interfaces[parameter]["requester"].remove(ccap_core_id)

                if len(self.interfaces[parameter]["requester"]) == 0 and \
                        self.interfaces[parameter]["status"] == self.DOWN:
                    self.interfaces.pop(parameter)
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.OK,
                    reason="Successful stop event.")
            else:
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                    reason="Cannot stop event since can not find it.")
            return

    def interface_flapping_down_handler(self, interface):
        """Process the interface flapping to down case

        :param interface: eth0
        :return:

        """
        if interface not in self.interfaces:
            return

        self.logger.info("Interface[%s] status flapping to Down", interface)

        self.interfaces[interface]["status"] = self.DOWN
        timer = self.interfaces[interface]["flappingTimer"]
        if None is not timer:
            self.dispatcher.timer_unregister(timer)
            self.interfaces[interface]["flappingTimer"] = None

            # notify the ccap core about status
            popup_list = list()
            for ccap_id in self.interfaces[interface]["requester"]:
                if ccap_id not in self.ccap_cores:
                    popup_list.append(ccap_id)
                    continue
                try:
                    self._send_event_notification(
                        ccap_id,
                        protoDef.msg_core_event_notification.OK,
                        "Status changed",
                        result=self.interfaces[interface]["status"])
                except zmq.ZMQError as ex:
                    self.logger.error("failed to send to manager: %s" % str(ex))
            for ccap_id in popup_list:
                self.interfaces[interface]['requester'].remove(ccap_id)

    def _check_interface_status_callback(self, _):
        self.logger.debug("Check the interface status...")
        if len(self.interfaces) == 0:
            return

        stats = net_if_stats()
        for interface in self.interfaces:
            if interface not in stats:
                self.logger.error(
                    "Cannot find the interface[%s] in current system configuration."% interface)
                continue
            stat = stats[interface]
            current_stat = self.UP if stat.isup else self.DOWN
            self.logger.debug("Check the interface[%s] status, original %s now %s ...",
                              interface, self.interfaces[interface]['status'], current_stat)

            status_changed = False
            # CHeck if there is an status change:
            if stat.isup:
                if None is not self.interfaces[interface]["flappingTimer"]:
                    self.dispatcher.timer_unregister(self.interfaces[interface]["flappingTimer"])
                    self.interfaces[interface]["flappingTimer"] = None
                    self.logger.info(
                        "Cancel interface[%s] flappingTimer." % interface)

                if self.interfaces[interface]["status"] != self.UP:
                    self.interfaces[interface]["status"] = self.UP
                    status_changed = True

            elif (not stat.isup) and self.interfaces[interface]["status"] != self.DOWN:
                # interface flapped status need to last 15s, then changed to Down
                if None is self.interfaces[interface]["flappingTimer"]:
                    self.interfaces[interface]["flappingTimer"] = self.dispatcher.timer_register(
                        self.INTERFACE_STATUS_DOWN_LASTED, self.interface_flapping_down_handler,
                        arg=interface)
                    self.logger.info(
                        "Start interface[%s] flappingTimer." % interface)
            else:
                pass

            # send the status change to the requester
            if not status_changed:
                continue

            self.logger.debug("Interface %s status changes to %s",
                              interface, self.interfaces[interface]["status"])

            popup_list = list()
            for ccap_id in self.interfaces[interface]["requester"]:
                if ccap_id not in self.ccap_cores:
                    popup_list.append(ccap_id)
                    continue
                try:
                    self._send_event_notification(
                        ccap_id,
                        protoDef.msg_core_event_notification.OK,
                        "Status changed",
                        result=self.interfaces[interface]["status"])
                except zmq.ZMQError as ex:
                    self.logger.error("failed to send to manager: %s" % str(ex))
            for ccap_id in popup_list:
                self.interfaces[interface]['requester'].remove(ccap_id)

    def filter_proto_interface(self, proto, interface_list):
        """Filter the needed interface with specified proto.

        :param proto: proto needed
        :param interface_list: list of interface

        """
        if not SysTools.is_system_openwrt():
            return interface_list
        uci_interfaces = set()
        try:
            remove_interface = []
            output = check_output(['uci', 'show', 'network'])
            network_list = output.strip().split('\n')
            for config in network_list:
                cfg, option = config.split('=')
                net_prex = cfg.split(".")
                if net_prex[-1] == "proto":
                    ifname = '.'.join(net_prex[:-1]) + '.ifname'
                    interface = check_output(['uci', 'get', ifname]).split('\n')[0]
                    uci_interfaces.add(interface)

                if net_prex[-1] == "proto" and str(option) != proto:
                    ifname = '.'.join(net_prex[:-1]) + '.ifname'
                    interface = check_output(['uci', 'get', ifname]).split('\n')[0]
                    if interface in interface_list:
                        remove_interface.append(interface)

                if net_prex[-1] == "proto" and str(option).find("dhcpv6") >= 0:
                    ifname = '.'.join(net_prex[:-1]) + '.ifname'
                    interface = check_output(['uci', 'get', ifname]).split('\n')[0]
                    if interface in interface_list and interface in remove_interface:
                        remove_interface.remove(interface)

            # remove proto mismatched interface
            # only return the interface which is configured with
            # proto provision or dhcpv6 and status must be up
            for interface in remove_interface:
                if interface in self.interfaces:
                    continue
                interface_list.remove(interface)
        except Exception as error:
            InterfaceStatus.logger.error("Got exception: %s", str(error))

        self.logger.debug("scan interfaces: up interface list %s, uci interface list %s",
                          interface_list, uci_interfaces)
        interface_list = uci_interfaces.intersection(set(interface_list))
        return list(interface_list)

    def scan_available_interface(self, _):
        interface_up = list()
        stats = net_if_stats()
        for interface in stats.keys():
            stat = stats[interface]
            if interface != 'lo':
                if stat.isup:
                    interface_up.append(interface)

        # need to check redefined interface proto is provision or not for RPD
        interface_ret = self.filter_proto_interface("'provision'", interface_up)

        # prepare for startup
        if self.init_start:
            for interface in interface_ret:
                SysTools.set_protocol(interface)
            self.init_start = False

        for idx in self.mgrs:
            event_request_rsp = protoDef.msg_event_notification()
            event_request_rsp.mgr_event.mgr_id = idx
            event_request_rsp.mgr_event.event_id = self.id
            event_request_rsp.mgr_event.data = json.dumps(interface_ret)
            try:
                self.mgrs[idx]['transport'].sock.send(
                    event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
            except zmq.ZMQError as ex:
                self.logger.error("failed to send to manager: %s" % str(ex))

if __name__ == "__main__":
    setup_logging("PROVISION", filename="provision_interface_status.log")
    pagent = InterfaceStatus()
    pagent.start()
