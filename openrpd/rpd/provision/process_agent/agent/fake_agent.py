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

import os
from time import time
import zmq
import json

from rpd.common.utils import SysTools
from rpd.common.rpd_logging import AddLoggerToClass
import rpd.provision.proto.process_agent_pb2 as protoDef
import rpd.provision.process_agent.agent.agent as agent


class FakeAgent(agent.ProcessAgent):
    __metaclass__ = AddLoggerToClass

    UP = "UP"
    DOWN = "DOWN"
    NA = "NA"

    FAKE_AGENT_PERIOD_STATUS_CHECK = 1
    FakeAgent_Descriptor = {
        agent.ProcessAgent.AGENTTYPE_INTERFACE_STATUS: "fake_interface",
        agent.ProcessAgent.AGENTTYPE_8021X: "fake_8021X",
        agent.ProcessAgent.AGENTTYPE_DHCP: "fake_dhcp",
        agent.ProcessAgent.AGENTTYPE_TOD: "fake_tod",
        agent.ProcessAgent.AGENTTYPE_IPSEC: "fake_ipsec",
        agent.ProcessAgent.AGENTTYPE_GCP: "fake_gcp",
        agent.ProcessAgent.AGENTTYPE_PTP: "fake_ptp",
        agent.ProcessAgent.AGENTTYPE_L2TP: "fake_l2tp",
    }

    default_interface = 'lo'
    CCAP_CORE = '127.0.0.1'
    test_interface = 'eth1'
    TimeServers = ['2.2.2.2']
    LogServers = ['3.3.3.3']
    DHCP_parameter = {'CCAPCores': [CCAP_CORE],
                      'TimeServers': TimeServers,
                      'TimeOffset': 10000,
                      'LogServers': LogServers,
                      'initiated_by': None,
                      'Interface': default_interface}
    caps = {"ccap_core": CCAP_CORE, 'interface': default_interface, "is_active": True, "is_principal": True}
    Fake_Parameter = {
        agent.ProcessAgent.AGENTTYPE_INTERFACE_STATUS: json.dumps([default_interface]),
        agent.ProcessAgent.AGENTTYPE_8021X: None,
        agent.ProcessAgent.AGENTTYPE_DHCP: json.dumps(DHCP_parameter),
        agent.ProcessAgent.AGENTTYPE_TOD: "success/%d" % int(time()),
        agent.ProcessAgent.AGENTTYPE_IPSEC: None,
        agent.ProcessAgent.AGENTTYPE_GCP: json.dumps("role/" + json.dumps(caps)),
        agent.ProcessAgent.AGENTTYPE_PTP: None,
        agent.ProcessAgent.AGENTTYPE_L2TP: None,
    }

    def __init__(self, agent_type):
        """Init fake agent.

        :param agent_type:
        :return:

        """
        self.input_parameter = {}
        self.agent_status = self.DOWN

        super(FakeAgent, self).__init__(agent_type)
        if not os.path.exists(self.FakeAgent_Descriptor[self.id]):
            SysTools.touch(self.FakeAgent_Descriptor[self.id])

        self.register_poll_timer(self.FAKE_AGENT_PERIOD_STATUS_CHECK, self.fake_agent_period_status_check)

    def prepare_agent_parameters(self, ccap_core_id, parameter):
        """Prepare agent's parameter and response data.

        :return:

        """
        interface_para = json.loads(
            self.Fake_Parameter[self.AGENTTYPE_INTERFACE_STATUS])
        if self.id == self.AGENTTYPE_GCP:
            interface, _ = parameter.split(';')
        else:
            interface = parameter
        if interface not in interface_para:
            self.DHCP_parameter['initiated_by'] = ccap_core_id

            # fill interface agent parameter
            interface_para.append(parameter)
            self.Fake_Parameter[self.AGENTTYPE_INTERFACE_STATUS] = json.dumps(interface_para)

            # fill dhcp
            self.DHCP_parameter['Interface'] = parameter
            self.Fake_Parameter[self.AGENTTYPE_DHCP] = json.dumps(self.DHCP_parameter)

            # fill gcp
            self.caps['interface'] = parameter
            self.Fake_Parameter[self.AGENTTYPE_GCP] = json.dumps("role/" + json.dumps(self.caps))
        elif None is self.DHCP_parameter['initiated_by']:
            self.DHCP_parameter['initiated_by'] = ccap_core_id
            self.Fake_Parameter[self.AGENTTYPE_DHCP] = json.dumps(self.DHCP_parameter)

    def process_event_action(self, action):     # pragma: no cover
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
            if parameter in self.input_parameter:
                if ccap_core_id not in self.input_parameter[parameter]["requester"]:
                    self.input_parameter[parameter]["requester"].append(ccap_core_id)
            else:
                self.prepare_agent_parameters(ccap_core_id, parameter)
                # create a interface in self input_parameter
                self.input_parameter[parameter] = {
                    "requester": [ccap_core_id, ],
                    "lastChangeTime": time(),
                }

            # send mgr message to mgr process
            if None is not self.Fake_Parameter[self.id]:
                for idx in self.mgrs:
                    event_request_rsp = protoDef.msg_event_notification()
                    event_request_rsp.mgr_event.mgr_id = idx
                    event_request_rsp.mgr_event.event_id = self.id
                    event_request_rsp.mgr_event.data = self.Fake_Parameter[self.id]
                    self.mgrs[idx]['transport'].sock.send(
                        event_request_rsp.SerializeToString(),
                        flags=zmq.NOBLOCK)
                    self.logger.debug("Send status change to id %s, msg:%s" %
                                      (idx, event_request_rsp))

            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.OK,
                "Id has been issue this action, send current status to you",
                result=self.agent_status)
            return

        if event_action == protoDef.msg_event.STOP:
            if parameter in self.input_parameter:
                if ccap_core_id in self.input_parameter[parameter]["requester"]:
                    self.input_parameter[parameter]["requester"].remove(ccap_core_id)

                if len(self.input_parameter[parameter]["requester"]) == 0:
                    self.input_parameter.pop(parameter)
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.OK,
                    reason="Successful stop event.")
            else:
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                    reason="Cannot stop event since can not find it.")
            return

    def fake_agent_period_status_check(self, _):
        """Period status check, check if fake agent file descriptor exists.

        :param _: no used
        :return:

        """
        self.logger.debug(
            "Period status check for Agent %s.", self.AgentName[self.id])
        if not os.path.exists(self.FakeAgent_Descriptor[self.id]):
            status = self.DOWN
        else:
            status = self.UP

        if self.agent_status == status:
            return

        self.agent_status = status
        popup_list = list()
        for parameter in self.input_parameter:
            for ccap_id in self.input_parameter[parameter]["requester"]:
                if ccap_id not in self.ccap_cores:
                    popup_list.append(ccap_id)
                    continue
                try:
                    self._send_event_notification(
                        ccap_id, protoDef.msg_core_event_notification.OK,
                        "Status changed", result=self.agent_status)
                except zmq.ZMQError as ex:
                    self.logger.error("failed to send to manager: %s" % str(ex))
        for ccap_id in popup_list:
            self.input_parameter[parameter]['requester'].remove(ccap_id)
