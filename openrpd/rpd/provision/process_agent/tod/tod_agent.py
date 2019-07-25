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

import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.provision.transport.transport import Transport
from rpd.common.utils import Convert
from rpd.gpb.tpc_pb2 import t_TpcMessage
from subprocess import call
import zmq
from time import time
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.rpd_rsyslog import RSyslog
from rpd.common import rpd_event_def


class TimeOfDay(agent.ProcessAgent):
    UP = "UP"
    DOWN = "DOWN"

    SOCK_ADDRESS = 'ipc:///tmp/zmq-tpc.ipc'

    __metaclass__ = AddLoggerToClass

    def __init__(self, agent_id=agent.ProcessAgent.AGENTTYPE_TOD):

        super(TimeOfDay, self).__init__(agent_id)
        self.cmd = ["python",
                    "-m", "rpd.tpc", "--ipc-address", self.SOCK_ADDRESS]

        self.process_transport = Transport(self.SOCK_ADDRESS,
                                           Transport.PULLSOCK)
        self.register_transport(self.process_transport, self.ipc_msg_cb)

        self.tod = {}
        self.log_server = ''

        # init process and tod status
        self.processes['tod'] = None
        self.tod_done = False

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
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                "CCAP core ID is not registered")
            return

        if not action.HasField("parameter"):
            self.logger.warn(
                "Cannot process the event action for id %s, "
                "reason:Parameter is not set" % ccap_core_id)
            # return error
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                "Parameter is not set")
            return

        parameter = action.parameter
        try:
            # parameter's format is "time_server1;time_server2/time_offset|log_servers1;log_servers2"
            time_servers, time_offset = parameter.split("/")
            time_servers = time_servers.split(";")
            time_offset, log_servers = time_offset.split("|")
            if len(time_offset):
                time_offset = int(time_offset)
            else:
                time_offset = 0
            if len(log_servers):
                log_servers = log_servers.split(";")
            else:
                log_servers = ''
            self.logger.debug(
                "time servers:{}, log servers:{}, time offset: {}".
                format(time_servers, log_servers, time_offset))
        except ValueError as e:
            self.logger.warn('parameter is {}, {}'.format(parameter, str(e)))
            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                "Parameter {} format error, should be time_server/time_offset|log_servers".
                format(parameter))
            return

        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            # only one tod is valid which is for principal core
            if self.tod_done:
                status = self.UP
            else:
                status = self.DOWN
            # check if we are in the requester list, if yes,
            # we just send a current status to it
            time_server = time_servers[0]
            if time_server in self.tod:
                if ccap_core_id not in self.tod[time_server]["requester"]:
                    self.tod[time_server]["requester"].append(ccap_core_id)
            else:
                # create a time_server in self time_server
                self.tod[time_server] = {
                    "status": status,
                    "requester": [ccap_core_id, ],
                    "lastChangeTime": time(),
                    "time-server": time_servers,
                    "log-server": log_servers,
                    "time-offset": time_offset
                }
                is_ipv6 = Convert.is_valid_ipv6_address(time_server)
                # Prepare TPC runtime arguments
                args = ['--ipv6'] if is_ipv6 else []
                args.extend(['--offset', str(time_offset)])
                args.extend(['--servers'] +
                            [addr.encode('ascii', 'ignore')
                             for addr in time_servers])

                if None is self.processes['tod'] and not self.tod_done:
                    self.processes['tod'] = self.start_process(self.cmd + args)

            # configure logging server for RPD
            if len(log_servers) == 0:
                self.log_server = ''
                self.logger.warning("No log server found")
                self.rsyslog = RSyslog()
                self.rsyslog.config_rsyslog(None)

            elif self.log_server != log_servers[0]:
                self.log_server = log_servers[0]
                self.logger.info("config log server")
                self.rsyslog = RSyslog()
                self.rsyslog.config_rsyslog(self.log_server)

            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.OK,
                "Id has been issue this action, send current status to you",
                result=self.tod[time_server]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            time_server = time_servers[0]
            if time_server in self.tod:
                if ccap_core_id in self.tod[time_server]["requester"]:
                    self.tod[time_server]["requester"].remove(ccap_core_id)

                if len(self.tod[time_server]["requester"]) == 0:
                    self.tod.pop(time_server)
                    if self.check_process_status(self.processes['tod']) == self.PROCESSSTATE_ALIVE:
                        self.terminate_process(self.processes['tod'])
                        self.processes['tod'] = None
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.OK,
                    reason="Successful stop event.")
            else:
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                    reason="Cannot stop event since can not find it.")
            return

    def ipc_msg_cb(self, fd, eventmask):
        # Receive the msg from the remote
        if eventmask == 0 or self.process_transport.sock != fd:
            self.logger.warn("Got a fake process event, ignore it")
            return

        # FixMe: may need more action
        if eventmask & self.dispatcher.EV_FD_ERR:
            self.logger.warn("Got EV_FD_ERR event")
            return

        if self.process_transport.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.debug("Got a fake event, the receive is not ready!")
            return

        try:
            data = self.process_transport.sock.recv(flags=zmq.NOBLOCK)
            tpc_msg = t_TpcMessage()
            tpc_msg.ParseFromString(data)
            self.logger.debug("TPC status: %s",
                              tpc_msg.t_Status.Name(tpc_msg.Status))
            status_changed = False
            valid_timeserver = tpc_msg.Validtimeserver
            if tpc_msg.Status == tpc_msg.SUCCESS:
                self.logger.info("Valid timestamp received from TPC")
                if tpc_msg.HasField('Timestamp'):
                    if not self.tod_done:
                        status_changed = True

                    self.tod_done = True
                    for time_server in self.tod:
                        self.tod[time_server]['status'] = self.UP
                        self.tod[time_server]["lastChangeTime"] = time()
                    self.terminate_process(self.processes['tod'])
                    self.processes['tod'] = None
                    for idx in self.mgrs:
                        event_request_rsp = protoDef.msg_event_notification()
                        event_request_rsp.mgr_event.mgr_id = idx
                        event_request_rsp.mgr_event.event_id = self.id
                        event_request_rsp.mgr_event.data = 'success/' + str(tpc_msg.Timestamp) + \
                                                           '|' + valid_timeserver
                        self.mgrs[idx]['transport'].sock.send(
                            event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                        self.logger.debug(
                            "Send event notification to id %s, msg:%s" %
                            (idx, event_request_rsp))
                else:
                    self.logger.warn(
                        "Mandatory timestamp missing, ignoring message")
                    self.notify.error(rpd_event_def.RPD_EVENT_TOD_INVALID_FMT[0], '')
            elif tpc_msg.Status == tpc_msg.FIRST_ATTEMPT_FAILED:
                self.logger.info("First attempt to get time failed - "
                                 "resetting time to 1.1.1970")
                # notify the mgr about TOD failure
                for idx in self.mgrs:
                    event_request_rsp = protoDef.msg_event_notification()
                    event_request_rsp.mgr_event.mgr_id = idx
                    event_request_rsp.mgr_event.event_id = self.id
                    event_request_rsp.mgr_event.data = 'tod_first_failed/0' + '|' + valid_timeserver
                    self.mgrs[idx]['transport'].sock.send(
                        event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                    self.logger.debug(
                        "Send event notification to id %s, msg:%s" %
                        (idx, event_request_rsp))
            elif tpc_msg.Status == tpc_msg.ALL_ATTEMPTS_FAILED:
                self.logger.info("All attempt to get time failed")
                # Failed to get time of day - rebooting
                if self.tod_done:
                    status_changed = True
                    self.tod_done = False
                    for time_server in self.tod:
                        self.tod[time_server]['status'] = self.DOWN
                        self.tod[time_server]["lastChangeTime"] = time()

                # notify the mgr about TOD failure
                for idx in self.mgrs:
                    event_request_rsp = protoDef.msg_event_notification()
                    event_request_rsp.mgr_event.mgr_id = idx
                    event_request_rsp.mgr_event.event_id = self.id
                    event_request_rsp.mgr_event.data = 'tod_failed/' + '' + '|' + valid_timeserver
                    self.mgrs[idx]['transport'].sock.send(
                        event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                    self.logger.debug(
                        "Send event notification to id %s, msg:%s" %
                        (idx, event_request_rsp))
            else:
                self.notify.error(rpd_event_def.RPD_EVENT_TOD_INVALID_FMT[0], '')
                return

            # send the status change to the requester
            if not status_changed:
                return

            for time_server in self.tod:
                popup_list = list()
                for ccap_core_id in self.tod[time_server]["requester"]:
                    if ccap_core_id not in self.ccap_cores:
                        popup_list.append(ccap_core_id)
                        continue
                    self._send_event_notification(
                        ccap_core_id, protoDef.msg_core_event_notification.OK,
                        "Status changed", result=self.tod[time_server]["status"])
                for idx in popup_list:
                    self.tod[time_server]['requester'].remove(idx)

        except zmq.Again as e:
            pass
        except Exception as e:
            self.logger.error("Cannot process the event, reason:%s" % str(e))

    def configure_remote_logging(self, address):  # pragma: no cover
        """Set address of remote log server,

        - For now only one log-server is supported (UDP is used, so we don't
        have dependable confirmation, whether logging server is really there)

        :param address: Syslog IP address (v4 or v6) or None to disable remote
         logging feature
        :type address: string or None
        :return:

        """
        if not (None is address or Convert.is_valid_ip_address(address)):
            self.logger.warning(
                "Invalid IP address provided for remote logging: %s", address)
            return

        try:
            call(["uci", "set",
                  "system.@system[0].log_ip=" + (address or "")])
            call(["uci", "commit", "system"])
            call(["/etc/init.d/log", "reload"])
        except (OSError, ValueError):
            self.logger.error("Failed remote logging configuration")


if __name__ == "__main__":
    setup_logging("PROVISION", filename="provision_tod.log")
    pagent = TimeOfDay()
    pagent.start()
