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

import copy
import os
import subprocess
from json import JSONEncoder, loads
import time
import psutil
import zmq

from rpd.dispatcher.dispatcher import Dispatcher
from rpd.dispatcher.timer import DpTimerManager
from rpd.provision.proto import process_agent_pb2
from rpd.provision.proto import provision_pb2
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.transport.transport import Transport
from rpd.common.rpd_logging import AddLoggerToClass


class ProcessAgentEncoder(JSONEncoder):
    """Packet encoder will encode the control packet to string using json
    facility. The excludedFields is used to tell the encoder that don't
    encode these fields.

    """
    Excludefields = ("logger", "event_transport", "api_transport", "cli_transport", "dispatcher")

    def __init__(self):
        super(ProcessAgentEncoder, self).__init__(indent=4)

    def default(self, o):
        """Overwrite the original default function."""
        retDict = copy.copy(o.__dict__)

        for field in self.Excludefields:
            if field in retDict:
                retDict.pop(field)

        return retDict


class ProcessAgentError(Exception):
    pass


class ProcessAgent(object):
    __metaclass__ = AddLoggerToClass

    PROCESSSTATE_ALIVE = 0
    PROCESSSTATE_DEAD = -1

    AGENTTYPE_INTERFACE_STATUS = provision_pb2.AGENTTYPE_INTERFACE_STATUS
    AGENTTYPE_8021X = provision_pb2.AGENTTYPE_8021X
    AGENTTYPE_DHCP = provision_pb2.AGENTTYPE_DHCP
    AGENTTYPE_TOD = provision_pb2.AGENTTYPE_TOD
    AGENTTYPE_IPSEC = provision_pb2.AGENTTYPE_IPSEC
    AGENTTYPE_GCP = provision_pb2.AGENTTYPE_GCP
    AGENTTYPE_PTP = provision_pb2.AGENTTYPE_PTP
    AGENTTYPE_L2TP = provision_pb2.AGENTTYPE_L2TP
    AgentName = {
        AGENTTYPE_INTERFACE_STATUS: "AGENTTYPE_INTERFACE_STATUS",
        AGENTTYPE_8021X: "AGENTTYPE_8021X",
        AGENTTYPE_DHCP: "AGENTTYPE_DHCP",
        AGENTTYPE_TOD: "AGENTTYPE_TOD",
        AGENTTYPE_IPSEC: "AGENTTYPE_IPSEC",
        AGENTTYPE_GCP: "AGENTTYPE_GCP",
        AGENTTYPE_PTP: "AGENTTYPE_PTP",
        AGENTTYPE_L2TP: "AGENTTYPE_L2TP",
    }

    SockPathMapping = {
        AGENTTYPE_INTERFACE_STATUS: {
            "api": "ipc:///tmp/rpd_provision_agent_interface_status_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_interface_status_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_interface_status_pull.sock",
            "cli": "ipc:///tmp/zmq-interface.ipc"
        },
        AGENTTYPE_8021X: {
            "api": "ipc:///tmp/rpd_provision_agent_8021x_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_8021x_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_8021x_pull.sock",
            "cli": "ipc:///tmp/zmq-8021x.ipc"
        },

        AGENTTYPE_DHCP: {
            "api": "ipc:///tmp/rpd_provision_agent_dhcp_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_dhcp_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_dhcp_pull.sock",
            "cli": "ipc:///tmp/zmq-dhcp.ipc"

        },

        AGENTTYPE_TOD: {
            "api": "ipc:///tmp/rpd_provision_agent_tod_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_tod_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_tod_pull.sock",
            "cli": "ipc:///tmp/zmq-tod.ipc"

        },

        AGENTTYPE_IPSEC: {
            "api": "ipc:///tmp/rpd_provision_agent_ipsec_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_ipsec_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_ipsec_pull.sock",
            "cli": "ipc:///tmp/zmq-ikev2.ipc"

        },
        AGENTTYPE_GCP: {
            "api": "ipc:///tmp/rpd_provision_agent_gcp_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_gcp_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_gcp_pull.sock",
            "cli": "ipc:///tmp/zmq-gcp.ipc"

        },
        AGENTTYPE_PTP: {
            "api": "ipc:///tmp/rpd_provision_agent_ptp_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_ptp_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_ptp_pull.sock",
            "cli": "ipc:///tmp/zmq-ptp.ipc"

        },
        AGENTTYPE_L2TP: {
            "api": "ipc:///tmp/rpd_provision_agent_l2tp_api.sock",
            "push": "ipc:///tmp/rpd_provision_agent_l2tp_push.sock",
            "pull": "ipc:///tmp/rpd_provision_agent_l2tp_pull.sock",
            "cli": "ipc:///tmp/zmq-l2tp.ipc"
        },

    }

    def __init__(self, agent_type):
        if agent_type not in self.AgentName:
            self.logger.error(
                "Cannot setup the process agent for type:%d" % agent_type)
            raise ProcessAgentError("Unknown Type:%d" % agent_type)

        if self._process_is_running(agent_type):
            self.logger.error(
                "Cannot setup the process agent for %s since a same agent has been up", agent_type)
            raise ProcessAgentError(
                "Cannot setup a duplicated %s" % self.AgentName[agent_type])

        event_path = self.SockPathMapping[agent_type]["pull"]
        api_path = self.SockPathMapping[agent_type]["api"]
        cli_path = self.SockPathMapping[agent_type]["cli"]

        # Create the pull and api sock to handle the request
        self.event_transport = Transport(event_path, Transport.PULLSOCK)
        self.api_transport = Transport(api_path, Transport.REPSOCK)
        self.cli_transport = Transport(cli_path, Transport.REPSOCK)

        # create a dispatcher
        self.dispatcher = Dispatcher()

        # register the event
        self.register_transport(
            self.event_transport, self._process_event_callback, None)
        self.register_transport(
            self.api_transport, self.api_event_callback, None)
        self.register_transport(
            self.cli_transport, self._process_cli_callback, None)

        # the region to hold all the process obj
        self.processes = {}

        # the region to hold all the ccap cores
        self.ccap_cores = {}
        self.mgrs = {}

        # agent information maintain
        self.name = self.AgentName[agent_type]
        self.id = agent_type  # we will generate  uuid

    def __str__(self):
        """Encoding this process agent to a string."""
        return ProcessAgentEncoder().encode(self)

    @staticmethod
    def is_all_agent_started():
        """Check if all agents are started."""
        for agent_type in ProcessAgent.AgentName:
            checked = False
            # will retry 10 times in 1 second
            for i in range(10):
                file_name = "/tmp/ProcessAgent_" + ProcessAgent.AgentName[agent_type]
                try:
                    process_file = open(file_name, "r")
                    # get the pid
                    pidbuff = process_file.read()
                    process_file.close()

                    if pidbuff:
                        pid = int(pidbuff)
                        # check if the pid is alive
                        if psutil.pid_exists(pid):
                            checked = True
                            break
                except IOError:
                    pass
                time.sleep(0.1)
            if not checked:
                return checked

        return True

    @staticmethod
    def _process_is_running(agent_type):
        # Check if we have setup a agent for this type
        file_name = "/tmp/ProcessAgent_" + ProcessAgent.AgentName[agent_type]

        try:
            process_file = open(file_name, "r")

            # get the pid
            pid = int(process_file.read())

            # check if the pid is alive
            if psutil.pid_exists(pid):
                return True
            else:
                process_file.close()
        except IOError:
            pass
        finally:
            process_file = open(file_name, "w")
            process_file.write(str(os.getpid()))

        return False

    def api_event_callback(self, fd, eventmask):
        """Call back functions, the subclass should implement this function.

        :param fd: passed from the register. the arg should contains the
         transport information.
        :param eventmask: passed from the dispatcher, which indicates the
         event type.
        :return: None

        """
        # Receive the msg from the remote
        if eventmask == 0 or self.api_transport.sock != fd:
            self.logger.warn(
                "Got a fake process event[%x], ignore it." % eventmask)
            return

        if eventmask & self.dispatcher.EV_FD_ERR:
            self.logger.error("Got an error event, handle the failure.")
            # FixMe: may need more action to handle the failure
            return

        if self.api_transport.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.debug("Got a fake event, the receive is not ready!")
            return

        try:
            data = self.api_transport.sock.recv(flags=zmq.NOBLOCK)

            msg = process_agent_pb2.api_request()
            msg.ParseFromString(data)

            self.logger.debug(
                "Receive an api message from the FSM:%s" % str(msg))

            # check the fields, we only processing the register fields
            fields = msg.ListFields()

            for field in fields:
                desc, value = field

                if desc.name == "mgr_reg":
                    self._handle_mgr_register(value)

                elif desc.name == "core_reg":
                    self._handle_core_register(value)

                else:
                    self.logger.error(
                        "Cannot handle the request since no handler for this, msg:%s.", msg)
        except zmq.Again:
            pass
        except Exception as e:
            self.logger.error("Cannot process the event, reason:%s" % str(e))
            rsp = process_agent_pb2.msg_register_rsp()
            rsp.id = ""
            rsp.agent_id = self.id
            rsp.status = process_agent_pb2.msg_register_rsp.FAIL
            rsp.reason = "Exception happens"
            api_rsp = process_agent_pb2.api_rsp()
            api_rsp.reg_rsp.CopyFrom(rsp)
            data = api_rsp.SerializeToString()
            self.send_reg_rsp(data)

    def _handle_core_register(self, reg):
        self.logger.info(
            "%s Processing the core register request:%s" % (self.AgentName[self.id], reg))
        id = reg.ccap_core_id
        action = reg.action
        mgr_id = reg.mgr_id

        if action == process_agent_pb2.msg_core_register.REG:

            # check is the client has been registered
            if id in self.ccap_cores:
                self.logger.info(
                    "The ccap core[%s] has been registered, ignore this request." % id)

                rsp = process_agent_pb2.msg_register_rsp()
                rsp.id = id
                rsp.agent_id = self.id
                rsp.status = process_agent_pb2.msg_register_rsp.OK
                rsp.reason = "Core [%s] has been registered, ignore this register request." % id
                api_rsp = process_agent_pb2.api_rsp()
                api_rsp.reg_rsp.CopyFrom(rsp)
                self.send_reg_rsp(api_rsp)
                return

            if mgr_id not in self.mgrs:
                self.logger.info(
                    "Cannot find the mgr[%s],  core id is [%s]" % (mgr_id, id))
                rsp = process_agent_pb2.msg_register_rsp()
                rsp.id = id
                rsp.agent_id = self.id
                rsp.status = process_agent_pb2.msg_register_rsp.FAIL
                rsp.reason = "Cannot find the mgr:%s." % mgr_id
                api_rsp = process_agent_pb2.api_rsp()
                api_rsp.reg_rsp.CopyFrom(rsp)
                self.send_reg_rsp(api_rsp)
                return

            # Add the fsm to our internal database
            self.ccap_cores[id] = {
                "mgr": mgr_id,
            }

            # send the feed back
            self.logger.info("CCap core [%s] registered successfully" % id)
            rsp = process_agent_pb2.msg_register_rsp()
            rsp.id = id
            rsp.agent_id = self.id
            rsp.status = process_agent_pb2.msg_register_rsp.OK
            rsp.reason = "Register successfully"
            api_rsp = process_agent_pb2.api_rsp()
            api_rsp.reg_rsp.CopyFrom(rsp)
            self.send_reg_rsp(api_rsp)
            return

        elif action == process_agent_pb2.msg_manager_register.UNREG:
            # check if the requester has been registered
            if id not in self.ccap_cores:
                self.logger.error(
                    "Cannot process unregister request since we cannot find the id[%s] in local db", id)
                rsp = process_agent_pb2.msg_register_rsp()
                rsp.id = id
                rsp.agent_id = self.id
                rsp.status = process_agent_pb2.msg_register_rsp.FAIL
                rsp.reason = "Cannot process the unregister request since cannot find the id[%s] in local db" % id
                api_rsp = process_agent_pb2.api_rsp()
                api_rsp.reg_rsp.CopyFrom(rsp)
                self.send_reg_rsp(api_rsp)
                return

            # process the requester
            self.ccap_cores.pop(id)

            # send the feed back
            self.logger.info("CCAP core [%s] unregistered successfully" % id)
            rsp = process_agent_pb2.msg_register_rsp()
            rsp.id = id
            rsp.agent_id = self.id
            rsp.status = process_agent_pb2.msg_register_rsp.OK
            rsp.reason = "Unregistered successfully"
            api_rsp = process_agent_pb2.api_rsp()
            api_rsp.reg_rsp.CopyFrom(rsp)
            self.send_reg_rsp(api_rsp)
            return

        else:
            pass

    def _handle_mgr_register(self, reg):
        self.logger.info(
            "%s Processing the mgr register request:%s" % (self.AgentName[self.id], reg))
        id = reg.id
        action = reg.action

        if action == process_agent_pb2.msg_manager_register.REG:
            path = module_name = parameter = None
            if reg.HasField("path_info"):
                path = reg.path_info
            if reg.HasField("module_name"):
                module_name = reg.module_name
            if reg.HasField("parameter"):
                parameter = reg.parameter

            # check is the client has been registered
            if id in self.mgrs:
                self.logger.info(
                    "The mgr[%s] has been registered, ignore this request." % id)
                rsp = process_agent_pb2.msg_register_rsp()
                rsp.id = id
                rsp.agent_id = self.id
                rsp.status = process_agent_pb2.msg_register_rsp.OK
                rsp.reason = "Mgr has been registered, ignore this register request."
                api_rsp = process_agent_pb2.api_rsp()
                api_rsp.reg_rsp.CopyFrom(rsp)
                self.send_reg_rsp(api_rsp)
                return

            if path is None:
                self.logger.error(
                    "Cannot process the register request since the pull sock is none.")
                rsp = process_agent_pb2.msg_register_rsp()
                rsp.id = id
                rsp.agent_id = self.id
                rsp.status = process_agent_pb2.msg_register_rsp.FAIL
                rsp.reason = "Path is not included in request message"
                api_rsp = process_agent_pb2.api_rsp()
                api_rsp.reg_rsp.CopyFrom(rsp)
                self.send_reg_rsp(api_rsp)
                return

            # Create the pull, will not register to dispatcher, since we will
            # use the non-block send
            transport = Transport(
                path, Transport.PUSHSOCK, Transport.TRANSPORT_CLIENT)

            # Add the fsm to our internal database
            self.mgrs[id] = {
                "transport": transport,
                "name": module_name,
                "para": parameter,
                "path": path,
            }

            # send the feed back
            self.logger.info("Mgr[%s] registered successfully" % id)
            rsp = process_agent_pb2.msg_register_rsp()
            rsp.id = id
            rsp.agent_id = self.id
            rsp.status = process_agent_pb2.msg_register_rsp.OK
            rsp.reason = "Register successfully"
            api_rsp = process_agent_pb2.api_rsp()
            api_rsp.reg_rsp.CopyFrom(rsp)
            self.send_reg_rsp(api_rsp)
            return

        elif action == process_agent_pb2.msg_manager_register.UNREG:
            # check if the requester has been registered
            if id not in self.mgrs:
                self.logger.error(
                    "Cannot process the mgr unregister request since cannot find the id[%s] in local db"
                                  % id)
                rsp = process_agent_pb2.msg_register_rsp()
                rsp.id = id
                rsp.agent_id = self.id
                rsp.status = process_agent_pb2.msg_register_rsp.FAIL
                rsp.reason = "Cannot process mgr unregister request since cannot find the id[%s] in local db" % id
                api_rsp = process_agent_pb2.api_rsp()
                api_rsp.reg_rsp.CopyFrom(rsp)
                self.send_reg_rsp(api_rsp)
                return

            # process the requester
            requester = self.mgrs[id]
            transport = requester["transport"]
            if transport and transport.sock:
                transport.sock.close()

            self.mgrs.pop(id)
            # send the feed back
            self.logger.info(
                "Id[%s] unregistered successfully" % id)
            rsp = process_agent_pb2.msg_register_rsp()
            rsp.id = id
            rsp.agent_id = self.id
            rsp.status = process_agent_pb2.msg_register_rsp.OK
            rsp.reason = "Unregistered successfully"
            api_rsp = process_agent_pb2.api_rsp()
            api_rsp.reg_rsp.CopyFrom(rsp)
            self.send_reg_rsp(api_rsp)
            return

        else:
            pass

    def _send_event_notification(self, ccap_id, status, reason, result="DOWN"):
        """This is a private function, used to send the event notification.

        :param ccap_id: ccap core ID
        :param status: FAIL/OK
        :param reason: The fail reason
        :param result: The success result.
        :return: Node

        """
        msg_event_notification = process_agent_pb2.msg_event_notification()
        msg_event_notification.core_event.id = ccap_id
        msg_event_notification.core_event.ccap_core_id = ccap_id
        msg_event_notification.core_event.status = status
        msg_event_notification.core_event.reason = reason
        msg_event_notification.core_event.event_id = self.id
        msg_event_notification.core_event.result = result

        # Get the transport
        if ccap_id in self.ccap_cores:
            ccap_core = self.ccap_cores[ccap_id]
            transport = self.mgrs[ccap_core["mgr"]]['transport']
            transport.sock.send(msg_event_notification.SerializeToString(), flags=zmq.NOBLOCK)
            self.logger.debug(
                "Process an event action for id %s, return:%s" % (ccap_id, msg_event_notification))
        else:
            self.logger.warn(
                "ccap id %s is not in core db of process agent %s " % (ccap_id, self.__class__))
        return

    def _send_ka_notification(self, mgr_id, status, reason):
        """This is a private function, used to send the event notification.
        TODO paramaters dont match

        :param ccap_id: ccap core ID
        :param status: FAIL/OK
        :param reason: The fail reason
        :param result: The success result.
        :return: Node

        """
        msg_event_notification = process_agent_pb2.msg_event_notification()
        msg_ka_rsp = process_agent_pb2.msg_ka_rsp()
        msg_ka_rsp.id = mgr_id
        msg_ka_rsp.status = status
        msg_ka_rsp.reason = reason
        msg_ka_rsp.agent_id = self.id
        msg_event_notification.ka_rsp.CopyFrom(msg_ka_rsp)

        # Get the transport
        if mgr_id in self.mgrs:
            transport = self.mgrs[mgr_id]['transport']
            transport.sock.send(
                msg_event_notification.SerializeToString(), flags=zmq.NOBLOCK)
            self.logger.debug(
                "Process an event action for id %s, return:%s" % (mgr_id, msg_ka_rsp))
        else:
            self.logger.warn(
                "mgr id %s is not in mgr db of process agent %s " % (mgr_id, self.__class__))
        return

    def process_event_action(self, action):
        """The subclass should overwrite this function.

        :param action:
        :return:

        """
        raise NotImplementedError

    def process_ka_action(self, action):
        """Process the request from the client.

        :param action:
        :return:

        """
        mgr_id = action.id
        event_action = action.action

        if event_action == process_agent_pb2.msg_manager_ka.KA:
            self._send_ka_notification(mgr_id, process_agent_pb2.msg_ka_rsp.OK, reason="KA successfully")
        else:
            self._send_ka_notification(mgr_id, process_agent_pb2.msg_ka_rsp.FAIL,
                                       reason="{} not supported".format(event_action))

    def _process_event_callback(self, fd, eventmask):
        """Callback function for API socket.

        :param fd: passed from the dispatcher, the fd should contains the
         transport information
        :param eventmask: passed from the dispatcher, which indicates the
         event type.
        :return: None

        """
        # Receive the msg from the remote
        if eventmask == 0 or self.event_transport.sock != fd:
            self.logger.warn("Got a fake process event, ignore it")
            return

        if eventmask & self.dispatcher.EV_FD_ERR:
            self.logger.error("Got an error event.")
            # FixMe: may need more action
            return

        if self.event_transport.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.debug("Got a fake event, the receive is not ready!")
            return

        try:
            data = self.event_transport.sock.recv(flags=zmq.NOBLOCK)

            msg = process_agent_pb2.msg_event_request()
            msg.ParseFromString(data)

            self.logger.debug(
                "Receive an event message from the FSM:%s" % str(msg))

            # check the fields, we only processing the register fields
            fields = msg.ListFields()

            for field in fields:
                desc, value = field

                if desc.name == "action":
                    self.process_event_action(value)
                elif desc.name == "ka_msg":
                    self.process_ka_action(value)
        except zmq.Again:
            pass
        except Exception as e:
            self.logger.error(
                "%s:Cannot process the event, reason:%s", self.name, str(e))

    def process_cli_action(self, msg):
        """The subclass should overwrite this function.

        :param msg: t_CliMessage
        :return:

        """
        raise NotImplementedError

    def _process_cli_callback(self, fd, eventmask):
        """Callback function for API socket.

        :param fd: passed from the dispatcher, the fd should contains the
         transport information
        :param eventmask: passed from the dispatcher, which indicates the
         event type.
        :return: None

        """
        # Receive the msg from the remote
        if eventmask == 0 or self.cli_transport.sock != fd:
            self.logger.warn("Got a fake cli message, ignore it")
            return
        # FixMe: may need more action
        if eventmask & self.dispatcher.EV_FD_ERR:
            self.logger.error("Got an error when receiving the msg.")
            return

        if self.cli_transport.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.debug(
                "Got a fake cli message, the receive is not ready!")
            return

        try:
            data = self.cli_transport.sock.recv(flags=zmq.NOBLOCK)

            msg = t_CliMessage()
            msg.ParseFromString(data)

            self.logger.debug("Receive an CLI message: %s" % str(msg))
            self.process_cli_action(msg)
        except zmq.Again as e:
            pass
        except Exception as e:
            self.logger.error(
                "Cannot process the CLI message, reason:%s" % str(e))

    def send_reg_rsp(self, ipc_msg):
        """Send register response message via api sock.

        :param ipc_msg: message information

        """
        if not isinstance(ipc_msg, process_agent_pb2.api_rsp) or not ipc_msg.IsInitialized():
            self.logger.error('Invalid IPC message provided.')
            return False

        try:
            self.api_transport.sock.send(ipc_msg.SerializeToString(), flags=zmq.NOBLOCK)
        except Exception as e:
            self.logger.error(
                "Got error when send register response message: {}".format(ipc_msg))

    def send_cli_rsp(self, rsp_msg):
        """Send cli response message via cli sock.

        :param rsp_msg: message information

        """

        try:
            self.cli_transport.sock.send(
                rsp_msg.SerializeToString(), flags=zmq.NOBLOCK)
        except Exception as e:
            self.logger.error(
                "Got error when send CLI response message: {}".format(rsp_msg))

    def start(self):
        """The start function will make the process into a endless loop.

        :return: Never return

        """
        self.dispatcher.loop()

    def register_poll_timer(self, timeout, callback, args=None):
        """Register a timer to dispatcher.

        :param timeout: the timeout value, the unit is second
        :param callback: Call back function, the format is
         {"function": func, "args": args}
        :return:

        """
        self.logger.info(
            "Register a timer into dispatcher, timeout:%d" % timeout)
        return self.dispatcher.timer_register(
            timeout, callback, arg=args,
            timer_type=DpTimerManager.TIMER_REPEATED)

    def unregister_poll_timer(self, timer):
        """Unregister a timer.

        :param timer: a timer returned by register_poll_timer.
        :return:

        """
        self.dispatcher.timer_unregister(timer)

    def register_transport(self, transport, callback, arg=None):
        """Register transport to dispatcher, the dispatcher will call the
        function when some events happens, currently, we will the use the
        PULLIN event.

        :param transport: one transport class, represents a socket, with
         a fileno.
        :param callback: the callback function, which will called when we
         received sth.
        :param arg: the args we passed into callback
        :return: None

        """
        if not isinstance(transport, Transport):
            self.logger.error(
                "Cannot register the transport, parameter transport type is not correct, expect: "
                "Transport, real:%s" % type(transport))
            return False

        self.logger.info(
            "Register a transport into dispatcher, path=%s" % transport.path)
        self.dispatcher.fd_register(
            transport.sock, Dispatcher.EV_FD_IN | Dispatcher.EV_FD_ERR, callback)

    def unregister_transport(self, transport):
        """Remove the transport from the dispatcher.

        :param transport: one transport class, represents a socket, with
         a fileno.
        :return: None

        """
        if not isinstance(transport, Transport):
            self.logger.error(
                "Cannot unregister the transport, parameter transport type is not correct, expect: "
                "Transport, real:%s" % type(transport))
            return False

        self.logger.info(
            "UnRegister a transport into dispatcher, path=%s" % transport.path)
        self.dispatcher.fd_unregister(transport.fileno)

    def start_process(self, args):
        """
        :param args: The args includes the command, and the it should be
         a tuple or a list.
        :return: popen process class

        """
        try:
            popenObj = subprocess.Popen(args, cwd="/tmp/")
            return popenObj
        except Exception as e:
            self.logger.error(str(e))
            return None

    def terminate_process(self, popenObj):
        """Terminate a process.

        :param popenObj: this is a obj returned by the start process
        :return: True for execute cmd successfully, false for arg error

        """
        if not isinstance(popenObj, subprocess.Popen):
            self.logger.warn("Cannot terminate a process since the arg is %s, not Popen object.", type(popenObj))
            return False

        self.logger.info("Terminate process %d", popenObj.pid)
        popenObj.terminate()

        return True

    def kill_process(self, popenObj):
        """kill a process.

        :param popenObj: this is a obj returned by the start process
        :return: True for execute cmd successfully, false for arg error

        """

        if not isinstance(popenObj, subprocess.Popen):
            self.logger.warn("Cannot kill a process since the arg is %s, not Popen object.", type(popenObj))
            return False

        self.logger.info("kill process %d", popenObj.pid)
        popenObj.kill()

        return True


    def check_process_status(self, popenObj):
        """Check the status of the process.

        :param popenObj: this is a obj returned by the start process
        :return: Terminated/Alive

        """
        if not isinstance(popenObj, subprocess.Popen):
            self.logger.warn("Cannot terminate a process since the arg is %s, not Popen object.", type(popenObj))
            return False, -1

        popenObj.poll()
        retcode = popenObj.returncode

        if retcode is None:
            return self.PROCESSSTATE_ALIVE
        return self.PROCESSSTATE_DEAD

    def set_logging_level(self, level):
        """Set module logger level for system logging.

        :param level:

        """
        try:
            self.logger.setLevel(level)
            return True, 'success'
        except (ValueError, TypeError) as e:
            return False, str(e)

    def cleanup_db(self, ccap_core_id):
        """cleanup the remain requester if exist."""
        raise NotImplementedError()
