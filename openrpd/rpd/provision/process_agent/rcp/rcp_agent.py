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
import zmq
from time import time
import json
from rpd.rcp.rcp_process import RcpHalProcess
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.dispatcher.timer import DpTimerManager
from rpd.gpb.monitor_pb2 import t_LED
from rpd.provision.proto.MonitorMsgType import MsgTypeSetLed
from rpd.provision.manager.src.manager_process import ManagerProcess
from rpd.common.utils import Convert
from rpd.gpb.CcapCoreIdentification_pb2 import t_CcapCoreIdentification

class RcpOverGcp(agent.ProcessAgent):
    UP = "UP"
    DOWN = "DOWN"
    REBOOT = "REBOOT"
    REDIRECT = "REDIRECT"

    __metaclass__ = AddLoggerToClass
    MSG_TIMEOUT = 5
    GCP_FLAP_RECOVERING_TIMEOUT = 20

    def __init__(self):
        super(RcpOverGcp, self).__init__(agent.ProcessAgent.AGENTTYPE_GCP)
        self.process = RcpHalProcess(
            dispatcher=self.dispatcher, notify_mgr_cb=self.rcp_msg_cb)
        self.rcp = {}
        self.rcp_req_group = {}
        self.timer = self.dispatcher.timer_register(
            self.MSG_TIMEOUT,
            self._timeout_check_cb,
            None,
            timer_type=DpTimerManager.TIMER_REPEATED)

        self.gcp_flapping_list = dict()
        # for principal core
        self.principal_core = None
        self.principal_core_interface = None

    def _timeout_check_cb(self, arg):
        """rcp message response timeout from mgr.

        :param arg: paramters

        """
        # we may need some optimize method to check the timeout
        self.logger.debug("timeout to check the record request...")
        current_time = time()

        for seq_num, core_ip in self.rcp_req_group.keys():
            seq, session, transaction_identifier, trans_id, send_time = self.rcp_req_group[(seq_num, core_ip)]
            if current_time - send_time > self.MSG_TIMEOUT:
                self.logger.warn(
                    "Found a rcp request message timeout, fire!!, seq_number: %d, content:%s",
                    seq_num, seq.ipc_msg)
                self.rcp_req_group.pop((seq_num, core_ip))
                self.process.orchestrator.pkt_director.send_eds_response_directly(
                    session, transaction_identifier,
                    trans_id, seq, result=False)

    def mgr_rcp_rsp(self, msg):
        """rcp message response recv from mgr.

        :param msg: msg_event

        """
        ret = True
        try:
            ret_value = json.loads(msg.parameter)
            self.logger.debug("Rcp response message parameters %s", ret_value)
            action, seq_value, value = ret_value.split("/")
            seq_num, core_ip = seq_value.split(',')
            seq_num = int(seq_num)

            if not self.rcp_req_group.has_key((seq_num, core_ip)):
                self.logger.error("Rcp request message sequence number %s error for core %s", seq_num, core_ip)
                return

            seq, session, transaction_identifier, trans_id, _ = self.rcp_req_group[(seq_num, core_ip)]
            config = seq.ipc_msg.RpdDataMessage.RpdData
            if action == 'get_active_principal':
                if 'fail' in value:
                    ret = False
                else:
                    config.ActivePrincipalCore = value

            # send response
            self.rcp_req_group.pop((seq_num, core_ip))
            self.process.orchestrator.pkt_director.send_eds_response_directly(session, transaction_identifier,
                                                                              trans_id, seq, result=ret)
        except Exception as e:
            self.logger.error("Unexpected failure: %s", str(e))

    def mgr_write_request(self, msg):
        """rcp message response recv from mgr.

        :param msg: msg_event

        """
        try:
            ret_value = json.loads(msg.parameter)
            self.logger.debug("MGR write request: %s", ret_value)
            action, value = ret_value.split("/")
            if action == 'light_led':
                led_msg = t_LED()
                led_msg.setLed.ledType = led_msg.LED_TYPE_STATUS
                led_msg.setLed.color = led_msg.LED_COLOR_GREEN
                if value == "True":
                    led_msg.setLed.action = led_msg.LED_ACTION_LIT
                    self.process.orchestrator.set_system_operational(operational=True)
                else:
                    led_msg.setLed.action = led_msg.LED_ACTION_DARK
                    self.process.orchestrator.set_system_operational()

                self.logger.info("Set led request message: %s", led_msg)
                self.process.hal_ipc.send_mgr_cfg_msg(MsgTypeSetLed, led_msg)
            elif action == 'set_active_principal':
                self.principal_core_interface, self.principal_core = value.split(";")
        except Exception as e:
            self.logger.error("Unexpected failure: %s", str(e))

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
            self.cleanup_db(ccap_core_id)
            # return error
            self._send_event_notification(
                ccap_core_id,
                protoDef.msg_core_event_notification.FAIL,
                "Cannot process the event action for id %s, reason: id is not registered"
                % ccap_core_id)
            return

        if not action.HasField("parameter"):
            self.logger.error("Cannot process the event action for id %s, "
                              "reason:Parameter is not set" % ccap_core_id)
            # return error
            self._send_event_notification(
                ccap_core_id,
                protoDef.msg_core_event_notification.FAIL,
                "Parameter is not set")
            return
        parameter = action.parameter

        if event_action == protoDef.msg_event.READ:
            self.mgr_rcp_rsp(action)
            return
        if event_action == protoDef.msg_event.WRITE:
            self.mgr_write_request(action)
            return
        elif event_action == protoDef.msg_event.UNKNOWN:
            self.logger.error("Got an Unknown action:%s", action)
            return

        try:
            interface, ccap_core = parameter.split(";")
        except ValueError as e:
            self.logger.error(
                "Cannot get the interface and ccap core from parameter, reason:%s", str(e))
            return

        redirectCCAPAddresses = []
        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            # check if we are in the requester list, if yes,
            # we just send a current status to it,
            # parameter supposed to be core's ip address
            if (interface, ccap_core) in self.rcp:
                if ccap_core_id not in self.rcp[(interface, ccap_core)]["requester"]:
                    self.rcp[(interface, ccap_core)]["requester"].append(id)
            else:
                self.rcp[(interface, ccap_core)] = {
                    "status": self.DOWN,
                    "requester": [ccap_core_id,],
                    "lastChangeTime": time(),
                }

            if self.rcp[(interface, ccap_core)]['status'] == self.DOWN:
                redirectCCAPAddresses.extend([";".join([interface, ccap_core]), ])
            if len(redirectCCAPAddresses):
                self.process.add_ccap_cores(redirectCCAPAddresses)

            self._send_event_notification(
                ccap_core_id, protoDef.msg_core_event_notification.OK,
                "Id has been issue this action, send current status to you",
                result=self.rcp[(interface, ccap_core)]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            if (interface, ccap_core) in self.rcp:
                for ccap_core_id in self.rcp[(interface, ccap_core)]["requester"]:
                    self.rcp[(interface, ccap_core)]["requester"].remove(ccap_core_id)

                if len(self.rcp[(interface, ccap_core)]["requester"]) == 0:
                    self.rcp.pop((interface, ccap_core))
                    redirectCCAPAddresses.extend([(interface, ccap_core)])
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.OK,
                    reason="Successful stop event of core %s." % ccap_core)
            else:
                self._send_event_notification(
                    ccap_core_id, protoDef.msg_core_event_notification.FAIL,
                    reason="Cannot stop event since can not find it %s." % ccap_core)
            # send remove connection request to RCP
            if len(redirectCCAPAddresses):
                for (interface, ccap_core) in redirectCCAPAddresses:
                    self.process.orchestrator.remove_sessions_by_core(
                        interface, ccap_core)
            return

    def rcp_msg_cb(self, seq, args=None):
        """Send 'RpdCapabilities', 'CcapCoreIdentification' to manager.

        :param seq: data format t_RcpMessage defined in rcp.proto or
         rcp sequence

        """
        status_changed = False
        specific = None
        if None is seq:
            self.logger.error("Parameters error, can not be NoneType")
            return
        elif isinstance(seq, t_RcpMessage):
            rcp_msg = seq
        else:
            rcp_msg = seq.ipc_msg

        interface_local = ''
        if None is not args:
            session, transaction_identifier, trans_id = args
            interface_local = session.get_descriptor().interface_local
        self.logger.info("RCP message type: %s",
                         rcp_msg.t_RcpMessageType.Name(rcp_msg.RcpMessageType))

        if rcp_msg.RcpMessageType == rcp_msg.RPD_REBOOT:
            self.logger.debug("Received RPD Reboot from RCP")
            core_ip = ''
            info = ''
            if rcp_msg.HasField('parameter'):
                core_para = json.loads(rcp_msg.parameter)
                core_ip = core_para['addr_remote'] if None is not core_para['addr_remote'] else ''
                interface_local = core_para['interface_local'] if None is not core_para['interface_local'] else ''
                info = core_para['info'] if None is not core_para['info'] else ''
            # FixMe, may need to send reboot msg to mgr
            for idx in self.mgrs:
                event_request_rsp = protoDef.msg_event_notification()
                event_request_rsp.mgr_event.mgr_id = idx
                event_request_rsp.mgr_event.event_id = self.id
                event_request_rsp.mgr_event.data = json.dumps("reboot/" + interface_local + ';' + core_ip + ';' + info)
                self.mgrs[idx]['transport'].sock.send(
                    event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                self.logger.debug("Send event notification to id %s, msg:%s" %
                                  (idx, event_request_rsp))

        elif rcp_msg.RcpMessageType == rcp_msg.REDIRECT_NOTIFICATION:
            self.logger.debug("Received RPD Redirect message from RCP")
            #  need to send message to manager to handle this
            core_ip = ''
            if rcp_msg.HasField('parameter'):
                core_para = json.loads(rcp_msg.parameter)
                core_ip = core_para['addr_remote'] if None is not core_para['addr_remote'] else ''
                interface_local = core_para['interface_local'] if None is not core_para['interface_local'] else ''
            for idx in self.mgrs:
                event_request_rsp = protoDef.msg_event_notification()
                event_request_rsp.mgr_event.mgr_id = idx
                event_request_rsp.mgr_event.event_id = self.id
                event_request_rsp.mgr_event.data = json.dumps(
                    "redirect/" +
                    ";".join([core for core in rcp_msg.RedirectCCAPAddresses])
                    + '/' + interface_local + ';' + core_ip)
                self.mgrs[idx]['transport'].sock.send(
                    event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                self.logger.debug("Send manager event to id %s, msg:%s" %
                                  (idx, event_request_rsp))

            # changed the status, then send to corresponding requester
            if interface_local != '' and core_ip != '':
                self.logger.info(
                    "The redirected core is: (%s, %s)", interface_local, core_ip)
                if (interface_local, core_ip) in self.rcp:
                    if self.rcp[(interface_local, core_ip)]['status'] != self.DOWN:
                        status_changed = True
                        specific = (interface_local, core_ip)
                        self.rcp[(interface_local, core_ip)]['status'] = self.DOWN

        elif rcp_msg.RcpMessageType == rcp_msg.RPD_CONFIGURATION:
            self.logger.debug(
                "Received RPD Ccap Core configuration message from RCP")
            cfg_data = rcp_msg.RpdDataMessage.RpdData
            if rcp_msg.HasField('parameter'):
                interface_local = rcp_msg.parameter

            for descr, value in cfg_data.ListFields():
                if descr.name == 'CcapCoreIdentification':
                    #  need to send message to manager to handle this
                    for cap_info in value:
                        caps = {
                            "is_active": cap_info.CoreMode is t_CcapCoreIdentification.COREMODEACTIVE if cap_info.HasField(
                                "CoreMode") else True,
                                "ccap_core": Convert.format_ip(cap_info.CoreIpAddress),
                                'interface': interface_local, "is_principal": cap_info.IsPrincipal}
                        for idx in self.mgrs:
                            event_request_rsp = protoDef.msg_event_notification()
                            event_request_rsp.mgr_event.mgr_id = idx
                            event_request_rsp.mgr_event.event_id = self.id
                            event_request_rsp.mgr_event.data = json.dumps("role/" + json.dumps(caps))
                            self.mgrs[idx]['transport'].sock.send(
                                event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                            self.logger.debug(
                                "Send event notification to id %s, msg:%s" %
                                (idx, event_request_rsp))

                        # changed the status, then send to corresponding requester, just for CLI test
                        for interface, core_ip in self.rcp:
                            if interface != interface_local or \
                                    not Convert.is_ip_address_equal(core_ip, cap_info.CoreIpAddress):
                                continue
                            ccap_core = self.rcp[(interface, core_ip)]
                            # send the Core Identification
                            for core_id in ccap_core['requester']:
                                info_update = protoDef.msg_event_notification()
                                info_update.agent_info_update.ccap_core_id = core_id

                                # The ugly code is casued by the proto file is different place
                                if cap_info.HasField("CoreId"):
                                    info_update.agent_info_update.ccap_core_identification.CoreId = cap_info.CoreId
                                if cap_info.HasField("CoreIpAddress"):
                                    info_update.agent_info_update.ccap_core_identification.CoreIpAddress = \
                                                                             Convert.format_ip(cap_info.CoreIpAddress)
                                if cap_info.HasField("IsPrincipal"):
                                    info_update.agent_info_update.ccap_core_identification.IsPrincipal = cap_info.IsPrincipal
                                if cap_info.HasField("CoreName"):
                                    info_update.agent_info_update.ccap_core_identification.CoreName = cap_info.CoreName
                                if cap_info.HasField("VendorId"):
                                    info_update.agent_info_update.ccap_core_identification.VendorId = cap_info.VendorId
                                if cap_info.HasField("CoreMode"):
                                    info_update.agent_info_update.ccap_core_identification.CoreMode = cap_info.CoreMode
                                if cap_info.HasField("CoreFunction"): 
                                    info_update.agent_info_update.ccap_core_identification.CoreFunction = cap_info.CoreFunction
                                if cap_info.HasField("InitialConfigurationComplete"):
                                    info_update.agent_info_update.ccap_core_identification.InitialConfigurationComplete = cap_info.InitialConfigurationComplete
                                    if (cap_info.InitialConfigurationComplete):
                                        status_changed, specific = self.handle_init_conf_completed(args)
                                if cap_info.HasField("MoveToOperational"):
                                    if cap_info.MoveToOperational:
                                        self._send_event_notification(core_id, protoDef.msg_core_event_notification.OK,
                                                                      "Move to Operational", "OPERATIONAL")

                                if cap_info.HasField("ResourceSetIndex"):
                                    info_update.agent_info_update.ccap_core_identification.ResourceSetIndex = cap_info.ResourceSetIndex

                                info_update.agent_info_update.ccap_core_identification.Index = 0
                                ccap_core_instance = self.ccap_cores[core_id]
                                transport = self.mgrs[ccap_core_instance["mgr"]]['transport']
                                transport.sock.send(
                                    info_update.SerializeToString(),
                                    flags=zmq.NOBLOCK)
                                self.logger.debug(
                                    "Send info to id %s, msg:%s" % (core_id, info_update))
                elif descr.name == 'RedundantCoreIpAddress':
                    for ha_info in value:
                        must_field = ['ActiveCoreIpAddress', 'StandbyCoreIpAddress', 'Operation']
                        ret_field = filter(lambda field: ha_info.HasField(field), must_field)
                        if len(must_field) != len(ret_field):
                            self.logger.warn(
                                "Received RPD HA message {} without must fields".format(ha_info))
                            return
                        caps = {"ActiveCoreIpAddress": Convert.format_ip(ha_info.ActiveCoreIpAddress),
                                "StandbyCoreIpAddress": Convert.format_ip(ha_info.StandbyCoreIpAddress),
                                'interface': interface_local, "operation": ha_info.Operation}
                        for idx in self.mgrs:
                            event_request_rsp = protoDef.msg_event_notification()
                            event_request_rsp.mgr_event.mgr_id = idx
                            event_request_rsp.mgr_event.event_id = self.id
                            event_request_rsp.mgr_event.data = json.dumps("Ha/" + json.dumps(caps))
                            self.mgrs[idx]['transport'].sock.send(
                                event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                            self.logger.debug(
                                "Send event notification to id %s, msg:%s" %
                                (idx, event_request_rsp))
                        # update the capabilities
                        if ha_info.Operation == ManagerProcess.OPERATION_CHANGE:
                            for _, s in self.process.orchestrator.sessions_active.items():
                                addr = s.get_descriptor().addr_remote
                                if addr == caps["ActiveCoreIpAddress"]:
                                    if (hasattr(s.ccap_capabilities, "is_active") and
                                            s.ccap_capabilities.is_active):
                                        active_session = s
                                        active_session.ccap_capabilities.is_active = False
                                        self.logger.info("HA CHANGE: set session[%s] to standby" %
                                                         caps["StandbyCoreIpAddress"])
                                elif addr == caps["StandbyCoreIpAddress"]:
                                    if (hasattr(s.ccap_capabilities, "is_active") and
                                            not s.ccap_capabilities.is_active):
                                        standby_session = s
                                        standby_session.ccap_capabilities.is_active = True
                                        self.logger.info("HA CHANGE: set session[%s] to active" %
                                                         caps["StandbyCoreIpAddress"])

                        elif ha_info.Operation == ManagerProcess.OPERATION_ADD:
                            for _, s in self.process.orchestrator.sessions_active.items():
                                addr = s.get_descriptor().addr_remote
                                if addr == caps["ActiveCoreIpAddress"]:
                                    if (hasattr(s.ccap_capabilities, "is_active") and
                                            not s.ccap_capabilities.is_active):
                                        self.logger.warn("HA ADD: session[%s] is not active now" %
                                                         caps["ActiveCoreIpAddress"])
                                elif addr == caps["StandbyCoreIpAddress"]:
                                    if (hasattr(s.ccap_capabilities, "is_active") and
                                            s.ccap_capabilities.is_active):
                                        self.logger.warn("HA ADD: session[%s] is not inactive now" %
                                                         caps["StandbyCoreIpAddress"])

                elif descr.name == 'ConfiguredCoreTable':
                    for cfg_table in value:
                        must_field = ['ConfiguredCoreIp', 'Operation']
                        ret_field = filter(lambda field: cfg_table.HasField(field), must_field)
                        if len(must_field) != len(ret_field):
                            self.logger.warn(
                                "Received RPD ConfiguredCoreTable message {} without must fields".
                                format(cfg_table))
                            return
                        caps = {"ccap_core": Convert.format_ip(cfg_table.ConfiguredCoreIp),
                                'interface': interface_local,
                                "operation": cfg_table.Operation}
                        for idx in self.mgrs:
                            event_request_rsp = protoDef.msg_event_notification()
                            event_request_rsp.mgr_event.mgr_id = idx
                            event_request_rsp.mgr_event.event_id = self.id
                            event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
                            self.mgrs[idx]['transport'].sock.send(
                                event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                            self.logger.debug(
                                "Send event notification to id %s, msg:%s" %
                                (idx, event_request_rsp))
                elif descr.name == 'MultiCore':
                    self.logger.info("Received RPD MultiCore ConfiguredCoreTable message")
                    for configuredCoreTable in value.ConfiguredCoreTable:
                        caps = {"ccap_core": Convert.format_ip(configuredCoreTable.ConfiguredCoreIp),
                                'interface': interface_local,
                                "operation": ManagerProcess.OPERATION_ADD}
                        for idx in self.mgrs:
                            event_request_rsp = protoDef.msg_event_notification()
                            event_request_rsp.mgr_event.mgr_id = idx
                            event_request_rsp.mgr_event.event_id = self.id
                            event_request_rsp.mgr_event.data = json.dumps("config_table/" + json.dumps(caps))
                            self.mgrs[idx]['transport'].sock.send(
                                event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                            self.logger.debug(
                                "Send event multi-core tlv notification to id %s, msg:%s" %
                                (idx, event_request_rsp))
                elif descr.name == "ActivePrincipalCore":
                    # record the request info
                    core_ip = ''
                    if None is not args:
                        descr = session.get_descriptor()
                        core_ip = Convert.format_ip(descr.addr_remote)
                        self.rcp_req_group[(seq.seq_number, core_ip)] = \
                            (seq, session, transaction_identifier, trans_id, time())
                    for idx in self.mgrs:
                        event_request_rsp = protoDef.msg_event_notification()
                        event_request_rsp.mgr_event.mgr_id = idx
                        event_request_rsp.mgr_event.event_id = self.id
                        event_request_rsp.mgr_event.data = json.dumps("get_active_principal/" + str(seq.seq_number) +
                                                                      ',' + core_ip)
                        self.mgrs[idx]['transport'].sock.send(
                            event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                        self.logger.debug(
                            "Send event notification to id %s, msg:%s" %
                            (idx, event_request_rsp))
                else:
                    self.logger.info(
                        "Recv {} message {}".format(descr.name, value))
                    return

        elif rcp_msg.RcpMessageType == rcp_msg.RPD_CONFIGURATION_DONE:
            self.logger.debug("Got configuration done message...")
            # changed the status, then send to corresponding requester
            status_changed, specific = self.handle_init_conf_completed(args)

        elif rcp_msg.RcpMessageType == rcp_msg.CONNECT_CLOSE_NOTIFICATION:
            # changed the status, then send to corresponding requester
            if rcp_msg.HasField('parameter'):
                core_para = json.loads(rcp_msg.parameter)
                ccap_core_ip = core_para['addr_remote'] if None is not core_para['addr_remote'] else ''
                interface_local = core_para['interface_local'] if None is not core_para['interface_local'] else ''
                reconnect = core_para['reconnect']

                # store flap gcp
                if reconnect and (interface_local, ccap_core_ip) not in self.gcp_flapping_list:
                    flap_timer = self.dispatcher.timer_register(
                        self.GCP_FLAP_RECOVERING_TIMEOUT, self.gcp_flap_timeout, arg=(interface_local, ccap_core_ip))
                    self.gcp_flapping_list[(interface_local, ccap_core_ip)] = flap_timer
                    # send recovering to manager.
                    for idx in self.mgrs:
                        event_request_rsp = protoDef.msg_event_notification()
                        event_request_rsp.mgr_event.mgr_id = idx
                        event_request_rsp.mgr_event.event_id = self.id
                        event_request_rsp.mgr_event.data = json.dumps("gcp_flapping/" +
                                                                      interface_local + ";" + ccap_core_ip +
                                                                      "/recovering")
                        self.mgrs[idx]['transport'].sock.send(
                            event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                        self.logger.debug("Send event notification to id %s, msg:%s" %
                                          (idx, event_request_rsp))
                elif not reconnect:
                    if (interface_local, ccap_core_ip) in self.gcp_flapping_list:
                        flap_timer = self.gcp_flapping_list.pop((interface_local, ccap_core_ip))
                        self.dispatcher.timer_unregister(flap_timer)

                    if (interface_local, ccap_core_ip) in self.rcp:
                        if self.rcp[(interface_local, ccap_core_ip)]['status'] != self.DOWN:
                            status_changed = True
                            specific = (interface_local, ccap_core_ip)
                            self.rcp[(interface_local, ccap_core_ip)]['status'] = self.DOWN
                    # notify mgr about connection info, mgr will log this,
                    # and send notify message to CCAP Core finally.
                    for idx in self.mgrs:
                        event_request_rsp = protoDef.msg_event_notification()
                        event_request_rsp.mgr_event.mgr_id = idx
                        event_request_rsp.mgr_event.event_id = self.id
                        event_request_rsp.mgr_event.data = json.dumps("connect_closed/" +
                                                                      interface_local + ";" + ccap_core_ip +
                                                                      ";" + str(reconnect))
                        self.mgrs[idx]['transport'].sock.send(
                            event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                        self.logger.debug("Send event notification to id %s, msg:%s" %
                                          (idx, event_request_rsp))

        else:
            self.logger.error("Unexpected IPC message received from "
                              "RCP: type: %s(%u)",
                              rcp_msg.t_RcpMessageType.Name(
                                  rcp_msg.RcpMessageType),
                              rcp_msg.RcpMessageType)
            return

        # send the status change to the requester
        if not status_changed:
            return

        popup_list = list()
        if None is not specific and specific in self.rcp:
            for id in self.rcp[specific]["requester"]:
                if id not in self.ccap_cores:
                    popup_list.append(id)
                    continue
                event_request_rsp = protoDef.msg_event_notification()
                event_request_rsp.core_event.id = id
                event_request_rsp.core_event.ccap_core_id = id
                event_request_rsp.core_event.status = protoDef.msg_core_event_notification.OK
                event_request_rsp.core_event.reason = "Status changed"
                event_request_rsp.core_event.event_id = self.id
                event_request_rsp.core_event.result = self.rcp[specific]["status"]
                ccap_core = self.ccap_cores[id]
                transport = self.mgrs[ccap_core["mgr"]]['transport']
                transport.sock.send(
                    event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                self.logger.debug("Send status change to id %s, msg:%s" %
                                  (id, event_request_rsp))
            for idx in popup_list:
                self.rcp[specific]['requester'].remove(idx)

    def handle_init_conf_completed(self, args):
        status_changed = False
        specific = None
        if None is not args:
            session, transaction_identifier, trans_id = args
            interface_local = session.get_descriptor().interface_local
            ccap_core_ip = Convert.format_ip(session.get_descriptor().addr_remote)
            if (interface_local, ccap_core_ip) in self.rcp:
                if self.rcp[(interface_local, ccap_core_ip)]['status'] != self.UP:
                    status_changed = True
                    specific = (interface_local, ccap_core_ip)
                    self.rcp[(interface_local, ccap_core_ip)]['status'] = self.UP
                    if interface_local == self.principal_core_interface and ccap_core_ip == self.principal_core:
                        self.process.orchestrator.set_active_principal_core(interface_local, ccap_core_ip)

            # we need to send this flapping to mgr, otherwise will impact ptp status
            if (interface_local, ccap_core_ip) in self.gcp_flapping_list:
                flap_timer = self.gcp_flapping_list.pop((interface_local, ccap_core_ip))
                self.dispatcher.timer_unregister(flap_timer)
                for idx in self.mgrs:
                    event_request_rsp = protoDef.msg_event_notification()
                    event_request_rsp.mgr_event.mgr_id = idx
                    event_request_rsp.mgr_event.event_id = self.id
                    event_request_rsp.mgr_event.data = json.dumps("gcp_flapping/" +
                                                                  interface_local + ";" + ccap_core_ip +
                                                                  "/done")
                    self.mgrs[idx]['transport'].sock.send(
                        event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                    self.logger.info("Send event notification to id %s, msg:%s" %
                                     (idx, event_request_rsp))
        return status_changed, specific

    def gcp_flap_timeout(self, args):
        """handle gcp flapped case."""

        status_changed = False
        specific = None

        interface_local, ccap_core_ip = args
        if (interface_local, ccap_core_ip) in self.rcp:
            if self.rcp[(interface_local, ccap_core_ip)]['status'] != self.DOWN:
                status_changed = True
                specific = (interface_local, ccap_core_ip)
                self.rcp[(interface_local, ccap_core_ip)]['status'] = self.DOWN

        if (interface_local, ccap_core_ip) in self.gcp_flapping_list:
            self.gcp_flapping_list.pop((interface_local, ccap_core_ip))

        # send the status change to the requester
        if not status_changed:
            return

        popup_list = list()
        if None is not specific and specific in self.rcp:
            for id in self.rcp[specific]["requester"]:
                if id not in self.ccap_cores:
                    popup_list.append(id)
                    continue
                event_request_rsp = protoDef.msg_event_notification()
                event_request_rsp.core_event.id = id
                event_request_rsp.core_event.ccap_core_id = id
                event_request_rsp.core_event.status = protoDef.msg_core_event_notification.OK
                event_request_rsp.core_event.reason = "Status changed"
                event_request_rsp.core_event.event_id = self.id
                event_request_rsp.core_event.result = self.rcp[specific]["status"]
                ccap_core = self.ccap_cores[id]
                transport = self.mgrs[ccap_core["mgr"]]['transport']
                transport.sock.send(
                    event_request_rsp.SerializeToString(), flags=zmq.NOBLOCK)
                self.logger.debug("Send status change to id %s, msg:%s" %
                                  (id, event_request_rsp))
            for idx in popup_list:
                self.rcp[specific]['requester'].remove(idx)

    def cleanup_db(self, ccap_core_id):
        """cleanup the remain requester if exist."""

        redirectCCAPAddresses = []
        deleted_info = []
        for info in self.rcp:
            if ccap_core_id in self.rcp[info]["requester"]:
                self.logger.info("cleanup RCP agent {}".format(ccap_core_id))
                self.rcp[info]["requester"].remove(ccap_core_id)

            if len(self.rcp[info]["requester"]) == 0:
                deleted_info.append(info)
        for info in deleted_info:
            self.rcp.pop(info)
            redirectCCAPAddresses.extend([info])

        # send remove connection request to RCP
        if len(redirectCCAPAddresses):
            for (interface, ccap_core) in redirectCCAPAddresses:
                self.process.orchestrator.remove_sessions_by_core(
                    interface, ccap_core)

if __name__ == "__main__":  # pragma: no cover
    setup_logging(("PROVISION", "GCP"), filename="provision_rcp.log")
    pagent = RcpOverGcp()
    pagent.start()
    #import cProfile
    #cProfile.run('pagent.start()', 'rcp.profile')
