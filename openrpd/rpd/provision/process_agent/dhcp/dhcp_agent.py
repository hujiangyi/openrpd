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
import json
import argparse
import signal
import sys

from psutil import net_if_stats
import zmq
import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.provision.transport.transport import Transport

from rpd.dispatcher.timer import DpTimerManager
from rpd.confdb.rpd_db import RPD_DB
from rpd.gpb.dhcp_pb2 import t_DhcpMessage, t_DhcpData
from rpd.confdb.cfg_db_adapter import CfgDbAdapter
from rpd.common.utils import SysTools, Convert
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common import rpd_event_def


class DhcpAgent(agent.ProcessAgent):
    __metaclass__ = AddLoggerToClass
    DOWN = "DOWN"
    UP = "UP"

    dhcp_data_path = ['oper', 'DhcpData']
    hw_version_path = ['oper', 'HwVersion']
    hw_version = "OPENWRT v1"

    DHCPV6_BACKOFF_TIMEOUT = 40
    DHCPV4_BACKOFF_TIMEOUT = 60

    SOCK_ADDRESS = 'ipc:///tmp/zmq-dhcp.ipc'

    def __init__(self, simulate_mode=False):

        super(DhcpAgent, self).__init__(agent.ProcessAgent.AGENTTYPE_DHCP)
        self.dhcp = {}
        self.processes = {}
        self.simulate_mode = simulate_mode

        self.process_transport = Transport(self.SOCK_ADDRESS, Transport.PULLSOCK)
        self.register_transport(self.process_transport, self.dhcp_msg_cb)

        # init dhcp related info
        self.db = RPD_DB()
        self.db_adapter = CfgDbAdapter(self.db)
        self.dhcp_data = t_DhcpData()
        self.dhcp_args_mapping = {}
        self.option_43 = '0x2b'

    def gen_dhcp_mapping_info(self, interface):
        """Generate dhcp mapping info if not exist.

        :param interface:
        :return:

        """
        rpd_ident = ['cfg', 'RpdCapabilities', 'RpdIdentification']

        self.dhcp_args_mapping = {
            '0x02': rpd_ident + ['DeviceDescription'],
            '0x04': rpd_ident + ['SerialNumber'],
            '0x05': self.hw_version_path,
            '0x06': rpd_ident + ['CurrentSwVersion'],
            '0x07': rpd_ident + ['BootRomVersion'],
            '0x08': "".join(SysTools.get_mac_address(interface).
                            split(':')[0:3]),  # vendor ID
            '0x09': rpd_ident + ['ModelNumber'],
            '0x0A': rpd_ident + ['VendorName']}

        # Fill device information to DB, if not loaded
        mac_addr_str = rpd_ident + ['DeviceMacAddress']
        if self.db_adapter.get_leaf(mac_addr_str) is None:
            self.db_adapter.set_leaf(mac_addr_str,
                                     SysTools.get_mac_address(interface), True)

        hostname_str = rpd_ident + ['DeviceAlias']
        if self.db_adapter.get_leaf(hostname_str) is None:
            self.db_adapter.set_leaf(hostname_str,
                                     SysTools.get_host_name(), True)

        if self.db_adapter.get_leaf(self.hw_version_path) is None:
            self.db_adapter.set_leaf(self.hw_version_path,
                                     self.hw_version.encode('hex'), True)

    def start_dhcpv6(self, interface):
        exec_timer = self.dispatcher.timer_register(
            self.DHCPV6_BACKOFF_TIMEOUT,
            self._dhcp_timeout_cb,
            arg=interface,
            timer_type=DpTimerManager.TIMER_ONESHOT)
        # process = self.start_process(cmd + args)
        SysTools.set_protocol(interface, proto=SysTools.supported_proto[1])
        self.processes[interface] = {
            "name": 'dhcpv6',
            "process": True,
            "timer": exec_timer,
        }

    def start_dhcpv4(self, interface):
        exec_timer = self.dispatcher.timer_register(
            self.DHCPV4_BACKOFF_TIMEOUT,
            self._dhcp_timeout_cb,
            arg=interface,
            timer_type=DpTimerManager.TIMER_ONESHOT)
        SysTools.set_protocol(interface, proto=SysTools.supported_proto[2])
        self.processes[interface] = {
            "name": 'dhcpv4',
            "process": True,
            "timer": exec_timer,
        }

    def process_event_action(self, action):
        """Process the request from the client.

        :param action:
        :return:

        """
        ccap_core_id = action.ccap_core_id
        event_action = action.action

        self.logger.debug("Receive an event action:%s", action)

        if ccap_core_id not in self.ccap_cores:
            self.logger.warn(
                "Cannot process the event action for id %s, reason: id is not registered" % ccap_core_id)
            self.cleanup_db(ccap_core_id)
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                "CCAP core ID is not registered")
            return

        if not action.HasField("parameter"):
            self.logger.warn(
                "Cannot process the event action for id %s, reason:Parameter is not set" % ccap_core_id)
            # return error
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                "Parameter is not set")
            return
        interface = action.parameter

        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            # check if we are in the requester list, if yes, we just send a
            # current status to it
            if interface in self.dhcp:
                if ccap_core_id not in self.dhcp[interface]["requester"]:
                    self.dhcp[interface]["requester"].append(ccap_core_id)
                if None is self.dhcp[interface]['initiated_by']:
                    self.dhcp[interface]['initiated_by'] = ccap_core_id
                if not self.processes[interface]['process']:
                    if self.simulate_mode:
                        self.start_dhcpv4(interface)
                    else:
                        self.start_dhcpv6(interface)
            else:
                if self.simulate_mode:
                    self.start_dhcpv4(interface)
                else:
                    self.start_dhcpv6(interface)

                # create a interface in self interfaces
                self.dhcp[interface] = {
                    "status": self.DOWN,
                    "requester": [ccap_core_id, ],
                    "lastChangeTime": time(),
                    "transport": self.process_transport,
                    "initiated_by": ccap_core_id,
                }

            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.OK,
                "Id has been issue this action, send current status to you",
                result=self.dhcp[interface]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            if interface in self.dhcp:
                if ccap_core_id in self.dhcp[interface]["requester"]:
                    self.dhcp[interface]["requester"].remove(ccap_core_id)

                if len(self.dhcp[interface]["requester"]) == 0 and self.dhcp[interface]["status"] == self.DOWN:
                    self.dhcp.pop(interface)
                    self.processes.pop(interface)
                    SysTools.set_protocol(interface)
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.OK,
                reason="Successful stop event.")
        else:
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                reason="Cannot stop event since can not find it.")
            return

    def dhcp_msg_cb(self, fd, eventmask):
        """Callback function for received zmq msg.

        :param fd: zmq socket instance.
        :param eventmask: events.
        :return: None

        """
        for interface in self.dhcp:
            transport = self.dhcp[interface]["transport"]
            if transport.sock == fd:
                break
        else:
            self.logger.warn(
                "Cannot find the fd in internal interface DB, receive and ignore it.")
            ipc_msg = fd.recv(flags=zmq.NOBLOCK)

            if ipc_msg:
                dhcp_msg = t_DhcpMessage()
                dhcp_msg.ParseFromString(ipc_msg)
                self.logger.warn(
                    "Received DHCP message from unexpected interface:%s", dhcp_msg)
            return

        # Receive the msg from the remote
        if eventmask == 0:
            self.logger.debug("Got a fake process event, ignore it")
            return

        if eventmask & self.dispatcher.EV_FD_ERR:
            self.logger.warn("Got an FD_ERR event.")
            return

        if transport.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.debug("Got a fake event, the receive is not ready!")
            return

        try:
            ipc_msg = transport.sock.recv(flags=zmq.NOBLOCK)

            dhcp_msg = t_DhcpMessage()
            dhcp_msg.ParseFromString(ipc_msg)
            self.logger.debug("DHCP status received %s[%s] from %s", dhcp_msg.InterfaceName,
                              dhcp_msg.t_Status.Name(dhcp_msg.Status),
                              dhcp_msg.t_Client.Name(dhcp_msg.Client))

            status_changed = False
            interface = dhcp_msg.InterfaceName
            src_client = dhcp_msg.Client
            if interface not in self.processes:
                self.logger.debug("Ignore this message, %s process doesn't started.", interface)
                return
            if src_client == dhcp_msg.DHCPV4 and self.processes[interface]['name'] != 'dhcpv4':
                self.logger.debug("Ignore this message, it's unexpected...")
                return
            elif src_client == dhcp_msg.DHCPV6 and self.processes[interface]['name'] != 'dhcpv6':
                self.logger.debug("Ignore this message, it's unexpected...")
                return

            if dhcp_msg.Status == dhcp_msg.UPDATED:
                if not len(dhcp_msg.DHCPData.CCAPCores):
                    self.notify.critical(rpd_event_def.RPD_EVENT_DHCP_CORE_LIST_MISSING[0], interface)
                    return

                self.dhcp_data = dhcp_msg.DHCPData
                if self.dhcp[interface]['status'] != self.UP:
                    status_changed = True
                    self.dhcp[interface]['status'] = self.UP
                self.delete_dhcp_data()
                self.verify_dhcp_data()

                # ignore this message if no core care about it
                if len(self.dhcp[interface]['requester']) == 0:
                    timer = self.processes[interface]["timer"]
                    if timer:
                        self.dispatcher.timer_unregister(timer)
                        self.processes[interface]["timer"] = None
                    self.logger.debug(
                        "No requester care about DHCP update message received: %s",
                        dhcp_msg.t_Status.Name(dhcp_msg.Status))
                    return

                # send mgr message to mgr process
                for idx in self.mgrs:
                    data = self.db_adapter.get_leaf(self.dhcp_data_path)
                    event_request_rsp = protoDef.msg_event_notification()
                    event_request_rsp.mgr_event.mgr_id = idx
                    event_request_rsp.mgr_event.event_id = self.id
                    event_request_rsp.mgr_event.data = \
                        json.dumps(
                            {'CCAPCores': [ccap for ccap in data.CCAPCores],
                             'TimeServers': [ts for ts in data.TimeServers],
                             'TimeOffset': data.TimeOffset,
                             'LogServers': [ls for ls in data.LogServers],
                             'initiated_by': self.dhcp[interface]['initiated_by'],
                             'Interface': interface})
                    self.mgrs[idx]['transport'].sock.send(
                        event_request_rsp.SerializeToString(),
                        flags=zmq.NOBLOCK)
                    self.logger.debug("Send status change to id %s, msg:%s" %
                                      (idx, event_request_rsp))

            elif dhcp_msg.Status == dhcp_msg.FAILED:
                ret = self._dhcp_no_lease(interface)
                if not ret and self.dhcp[interface]['status'] != self.DOWN:
                    status_changed = True
                    self.dhcp[interface]['status'] = self.DOWN
            else:
                self.logger.error("Unexpected status received from DHCP")
                return

            # Find out from which DHCP process is running (who sent it)
            dhcp_proc = self.processes[interface]["process"]
            timer = self.processes[interface]["timer"]
            # dhcpv6 process can be started atomically
            if not dhcp_proc:
                self.logger.debug("DHCP client process is terminated")
                if self.dhcp[interface]['status'] != self.DOWN:
                    status_changed = True
                    self.dhcp[interface]['status'] = self.DOWN
            if timer:
                self.dispatcher.timer_unregister(timer)
                self.processes[interface]["timer"] = None

            # send the status change to the requester
            if not status_changed:
                return

            popup_list = list()
            for ccap_core_id in self.dhcp[interface]["requester"]:
                if ccap_core_id not in self.ccap_cores:
                    popup_list.append(ccap_core_id)
                    continue
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.OK,
                    "Status changed", result=self.dhcp[interface]["status"])
            for idx in popup_list:
                self.dhcp[interface]['requester'].remove(idx)
        except zmq.Again as e:
            pass
        except Exception as e:
            self.logger.error("Cannot process the event, reason:%s" % str(e))

    def verify_dhcp_data(self):
        """Verify data from msg sent by DHCP client, with invalid or ill
        formatted dataremoved."""
        for descr, value in self.dhcp_data.ListFields():
            self.logger.debug("%s = %s", descr.name, str(value))
            if descr.name in ['CCAPCores', 'LogServers', 'TimeServers']:
                # Walk list of IP addresses and check one-by-one
                for ip_addr in value[:]:
                    # Remove all invalid values
                    if not Convert.is_valid_ip_address(ip_addr):
                        self.logger.warn("Unexpected format of value: "
                                 "%s = %s", descr.name, ip_addr)
                        value.remove(ip_addr)

            elif descr.name == 'TimeOffset':
                # Nothing to be checked (int32)
                pass
            else:
                self.logger.warn(
                    "Unknown DHCP option found: %s, ignore it.", descr.name)

        self.store_dhcp_data()
        
    def delete_dhcp_data(self):
        """Delete DHCP data structure from DB and also clear cached copy of it."""
        self.db_adapter.del_leaf(self.dhcp_data_path)

    def store_dhcp_data(self):
        """Save updated cached copy of DHCP data to DB. It must be called
        after each set operation to this cached structure (to keep it
        synchronized)."""
        self.db_adapter.set_leaf(self.dhcp_data_path, self.dhcp_data, True)

    def _dhcp_timeout_cb(self, interface):
        """DHCP process haven't responded in limited time (backoff timer + extra
         time), so there is probably something wrong (DHCP process crashed, was
         killed, stuck in a loop, ...).

        :return:

        """
        self.logger.warn("DHCP timer expired on %s", interface)
        self._dhcp_no_lease(interface)

    def _dhcp_no_lease(self, interface):
        """DHCP client failed to get required information.

        (backoff timer increased to maximum value without success)
         * If DHCPv6 failed -> try DHCPv4
         * If DHCPv4 failed -> reboot

        :return:

        """
        if interface not in self.processes:
            self.logger.warn("Process information about Interface[%s] doesn't exist", interface)
            return False

        stats = net_if_stats()
        if interface in stats and not stats[interface].isup:
            self.logger.info("Ignore this message caused by link down...")
            return True

        name = self.processes[interface]['name']
        if self.processes[interface]['process']:
            if name == "dhcpv6":
                SysTools.set_protocol(interface)
                self.logger.info("Starting DHCPv4 client ...")
                self.start_dhcpv4(interface)
                return True
            elif name == "dhcpv4":
                self.logger.warn("DHCPv4 failure...")
                SysTools.set_protocol(interface)
                self.processes[interface]['process'] = False
                return False
            else:
                raise ValueError("Unexpected process name {}".format(name))

        return False

    def interrupt_handler(self, signum, frame):
        for interface in self.processes.keys():
            SysTools.set_protocol(interface)

        sys.exit(0)

    def cleanup_db(self, ccap_core_id):
        """cleanup the remain requester if exist."""

        # clear the remain requester if exist
        for interface in self.dhcp.keys():
            if ccap_core_id in self.dhcp[interface]["requester"]:
                self.logger.info("cleanup DHCP agent {}".format(ccap_core_id))
                self.dhcp[interface]["requester"].remove(ccap_core_id)

            if len(self.dhcp[interface]["requester"]) == 0:
                self.dhcp.pop(interface)
                SysTools.set_protocol(interface)
                self.processes[interface]["process"] = False
                self.processes.pop(interface)


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description="dhcp agent")
    # parse the daemon settings.
    parser.add_argument("-s", "--simulator",
                        action="store_true",
                        help="run the program with simulator mode")
    arg = parser.parse_args()
    setup_logging("PROVISION", filename="provision_dhcp.log")
    pagent = DhcpAgent(simulate_mode=arg.simulator)
    signal.signal(signal.SIGINT, pagent.interrupt_handler)
    pagent.start()

