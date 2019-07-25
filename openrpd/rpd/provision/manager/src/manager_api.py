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
"""
This file will provide the following features
1. the interface between the manager and other modules, such as CLI, WEB, etc...
2. debug and test API.
"""
import json
import os
from datetime import datetime
from psutil import net_if_addrs
import socket
import zmq
import time
from rpd.common.utils import SysTools, Convert
import rpd.provision.proto.provision_pb2 as provision_pb2
from rpd.provision.manager.src.manager_ccap_core import CCAPCore
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.provision.transport.transport import Transport
from rpd.provision.manager.src.manager_ccap_core import CoreDescription
from rpd.common.rpd_rsyslog import RSyslog
from rpd.common.rpd_event_def import RPD_EVENT_CONNECTIVITY_SYS_REBOOT, RPD_EVENT_CONNECTIVITY_REBOOT
from rpd.provision.manager.src.manager_fsm import CCAPFsm


class ManagerApi(object):
    API_SOCK_PATH = "ipc:///tmp/rpd_provision_manager_api.sock"
    REBOOT_WAITING = 10

    __metaclass__ = AddLoggerToClass

    def __init__(self, mgr, disp):
        """Init handler for external module requests.

        :param mgr: manager API
        :param disp: dispatcher instance

        """
        self.mgr = mgr
        self.dispatcher = disp

        self.process_api_event_handlers = {
            provision_pb2.t_Provision.SHOW_PROVISION_ALL: self.get_provision_all,
            provision_pb2.t_Provision.SHOW_PROVISION_MANAGER_STATE: self.get_provision_manager_state,
            provision_pb2.t_Provision.SHOW_PROVISION_MANAGER_STATE_HISTORY: self.get_provision_manager_state_history,
            provision_pb2.t_Provision.SHOW_PROVISION_CCAP_CORE: self.get_provision_ccap_core_info,
            provision_pb2.t_Provision.SHOW_PROVISION_CCAP_CORE_ALL: self.get_ccapcore_all,
            provision_pb2.t_Provision.SHOW_PROVISION_STATE_HISTORY: self.get_provision_state_history,
            provision_pb2.t_Provision.CLEAR_PROVISION_STATE_HISTORY: self.clear_provision_state_history,
            provision_pb2.t_Provision.SHOW_PROVISION_CORE_STATISTIC: self.get_provision_core_statistics,
            provision_pb2.t_Provision.SET_PROVISION_LOG_LEVEL: self.set_logging_level,
            provision_pb2.t_Provision.SHOW_PC_REBOOT_HOLD: self.show_pc_reboot_hold,
            provision_pb2.t_Provision.SET_PC_REBOOT_HOLD: self.set_pc_reboot_hold,
            provision_pb2.t_Provision.CLEAR_PC_REBOOT_HOLD: self.clear_pc_reboot_hold,
            provision_pb2.t_Provision.REBOOT: self.reboot_system,

            provision_pb2.t_Provision.SHOW_PROVISION_DHCP: self.get_dhcp_info,
            provision_pb2.t_Provision.SHOW_PROVISION_TOD: self.get_tod_info,
            provision_pb2.t_Provision.SHOW_PROVISION_GCP: self.get_gcp_info,
            provision_pb2.t_Provision.SHOW_PROVISION_INTERFACE_STATUS: self.get_interface_info,
            provision_pb2.t_Provision.SSD_START: self.ssd_start,
            provision_pb2.t_Provision.SSD_GET_AF_TYPE: self.ssd_get_aff_type,
            provision_pb2.t_Provision.SSD_END: self.ssd_end,
        }
        self.core_event_trigger = {}
        self._create_and_register_api()

    def _create_and_register_api(self):
        api = Transport(
            self.API_SOCK_PATH, Transport.REPSOCK, Transport.TRANSPORT_SERVER)
        self.manager_api_sock = api
        self.dispatcher.fd_register(
            api.sock, Dispatcher.EV_FD_IN | Dispatcher.EV_FD_ERR,
            self._handle_manager_api)

    def _handle_manager_api(self, fd, eventmask):
        """Handle the external module request.

        :param fd: zmq sock
        :param eventmask: event mask
        :return:

        """
        if self.manager_api_sock is None:
            self.logger.error(
                "Cannot handle manager API request since api is None, fd:%s", fd)
            return

        if self.manager_api_sock.sock != fd:
            self.logger.error(
                "Cannot handle the manager API request since the sock is not in args, fd:%s, manager api sock:%s", fd,
                self.manager_api_sock.sock)
            return

        api = self.manager_api_sock
        # Receive the msg from the remote
        if eventmask == 0:
            self.logger.warn("Got a fake process event, ignore it")
            return

        # FixMe: may need more action
        if eventmask & self.dispatcher.EV_FD_ERR:
            # C3RPHY-104 -- bug fix: change ZMQ object "fd" to a string to print in log 
            self.logger.error(
                "Got error event when handle the manager API request, event:%s, fd:%s", eventmask, str(fd))
            return

        if api.sock.getsockopt(zmq.EVENTS) != zmq.POLLIN:
            self.logger.warn(
                "Got a fake event, the receiver is not ready! fd:%s", fd)
            return

        op = 0
        try:
            data = api.sock.recv(flags=zmq.NOBLOCK)

            msg = provision_pb2.t_Provision()
            msg.ParseFromString(data)

            self.logger.debug(
                "Receive an event message from the external:%s" % str(msg))

            op = msg.MsgType
            handler = self.process_api_event_handlers[op]

            if msg.HasField('parameter'):
                ret, value = handler(msg.parameter)
            else:
                ret, value = handler(None)
            self.logger.debug("Got a result: %s, %s" % (ret, value))

            rsp_msg = provision_pb2.t_Provision()
            rsp_msg.MsgType = op
            if ret:
                rsp_msg.result = rsp_msg.RESULT_OK
            else:
                rsp_msg.result = rsp_msg.RESULT_FAIL
            rsp_msg.parameter = json.dumps(value)
            api.sock.send(rsp_msg.SerializeToString())
        except zmq.Again:
            pass
        except Exception as e:
            self.logger.error(
                "Cannot process handle the api request, reason:%s" % str(e))
            # send error rsp
            rsp_msg = provision_pb2.t_Provision()
            rsp_msg.MsgType = op
            rsp_msg.result = rsp_msg.RESULT_FAIL
            rsp_msg.parameter = json.dumps(str(e))
            api.sock.send(rsp_msg.SerializeToString())

    def get_provision_all(self, args=None):
        """For external calling interface, such as CLI, web, etc...

        :return:

        """
        provision_info = []
        for idx in CCAPCore.ccap_core_db:
            result, value = self.get_provision_ccap_core_info(idx, detail=False)
            if value == "skip":
                continue
            elif not result and isinstance(value, str):
                return result, value
            else:
                provision_info.append(value)

        return True, provision_info

    def get_ccapcore_all(self, args=None):
        """For external calling intreface, such as CLI, web, etc...

        :return:

        """
        provision_info = []
        for idx in CCAPCore.ccap_core_db:
            result, value = self.get_provision_ccap_core_info(idx, detail=True)
            if value == "skip":
                continue
            elif not result and isinstance(value, str):
                return result, value
            else:
                provision_info.append(value)

        return True, provision_info

    def get_provision_ccap_core_info(self, ccap_core_id, detail=True):
        """Get specific ccap core information.

        :param ccap_core_id:

        """
        if ccap_core_id not in CCAPCore.ccap_core_db:
            self.logger.error(
                "Cannot find the ccap core[%s] since the core id is not in internal db." % ccap_core_id)
            return False, 'Cannot find the ccap core[%s]' % ccap_core_id

        try:
            ccap_core = CCAPCore.ccap_core_db[ccap_core_id]
            state = ccap_core.fsm.current
            if not detail:
                if isinstance(ccap_core.fsm, CCAPFsm):
                    if ccap_core.fsm.current in ccap_core.fsm.STATE_GCP_ALL:
                        state = ccap_core.fsm.STATE_GCP
                    if ccap_core.fsm.current in ccap_core.fsm.STATE_ALL_OPERATIONAL:
                        state = ccap_core.fsm.STATE_ONLINE
            is_principal = CoreDescription.role_str(ccap_core.is_principal)
            is_active = CoreDescription.mode_str(ccap_core.is_active)
            initiated_by = ccap_core.initiated_by
            start_time = ccap_core.start_time
            remote_id = ccap_core.core_id_from_core if ccap_core.core_id_from_core else "NA"
            core_name = ccap_core.core_name if ccap_core.core_name else "NA"
            vendor_id = str(ccap_core.core_vendor_id) if ccap_core.core_vendor_id else "NA"
            para = ccap_core.parameters
            if ProcessAgent.AGENTTYPE_GCP not in para:
                self.logger.warn(
                    "Cannot find the core ip for agent %d" % ProcessAgent.AGENTTYPE_GCP)
                return False, "Cannot find the core ip"
            else:
                agent_para = para[ProcessAgent.AGENTTYPE_GCP].split(';')
                if len(agent_para) == 1:
                    return False, "skip"
                core_ip = agent_para[-1]
            agent_status = ccap_core.agent_status

            if not detail:
                return True, {
                    'Core-id': ccap_core_id, 'Core-ip': core_ip, 'Current-State': state,
                    'Core-Role': is_principal, 'HA-Mode': is_active, 'Initiated-By': initiated_by,
                    'Core-StartTime': start_time, 'parameter': para,
                    'remote_id': remote_id,
                    'core_name': core_name,
                    'vendor_id': vendor_id,
                    'Interface': agent_para[0],
                }
            else:
                return True, {
                    'Core-id': ccap_core_id, 'Core-ip': core_ip, 'Current-State': state,
                    'Core-Role': is_principal, 'HA-Mode': is_active, 'Initiated-By': initiated_by,
                    'Core-StartTime': start_time, 'parameter': para,
                    'remote_id': remote_id,
                    'core_name': core_name,
                    'vendor_id': vendor_id,
                    'Interface': agent_para[0],
                    'agent_status': agent_status
                }
        except Exception as e:
            return False, str(e)

    def get_provision_manager_state(self, args=None):
        """get provision manager state
        :return:
        """
        manager_state = []
        mgr_id = self.mgr.mgr_id
        current_state = self.mgr.fsm.current
        last_change_time = next(reversed(self.mgr.manager_statistics.statistics))
        value = {'id': mgr_id, 'state': current_state, 'time': last_change_time}
        manager_state.append(value)
        return True, manager_state

    def get_provision_manager_state_history(self, _):
        """get provision state machine history record.

        :param _:
        """

        try:
            return True, self.mgr.manager_statistics.statistics
        except Exception as e:
            return False, str(e)

    def get_provision_state_history(self, _):
        """get provision state machine history record.

        :param _:

        """

        try:
            return True, CCAPCore.core_statistics.statistics
        except Exception as e:
            return False, str(e)

    def clear_provision_state_history(self, _):
        """get provision state machine history record.

        :param _:

        """

        try:
            CCAPCore.core_statistics.cleanup()
            return True, "success"
        except Exception as e:
            return False, str(e)

    def get_provision_core_statistics(self, ccap_core_id):
        """get ccap core statistics per state.

        :param ccap_core_id: ccap core id

        """

        try:
            return True, CCAPCore.ccap_core_db[ccap_core_id].statistics_per_state
        except Exception as e:
            return False, str(e)

    def set_logging_level(self, level):
        """Set module logger level for system logging.

        :param level:

        """
        try:
            self.rsyslog = RSyslog()
            self.rsyslog.config_rsyslog_loglevel(int(level))
            return True, 'success'
        except (ValueError) as e:
            return False, str(e)
        except (TypeError) as e:
            # C3RPHY-104 -- simple 'str(e)' fails, return string name of type
            return False, e.__class__.__name__

    def show_pc_reboot_hold(self, args=None):
        """Set PC_REBOOT_HOLD, block the system from reboot."""
        self.logger.info("Receive a request to show PC_REBOOT_HOLD")

        for skip_reboot_file in SysTools.REBOOT_SKIP_FILES:
            if os.path.exists(skip_reboot_file):
                return True, 'PC_REBOOT_HOLD is set'
        else:
            return True, 'PC_REBOOT_HOLD is not set'

    def set_pc_reboot_hold(self, args=None):
        """Set PC_REBOOT_HOLD, block the system from reboot."""
        self.logger.info("Receive a request to set PC_REBOOT_HOLD")
        if os.path.exists(SysTools.REBOOT_SKIP_FILES[-1]):
            self.logger.info("PC_REBOOT_HOLD have been set")
        else:
            os.system("touch %s" % SysTools.REBOOT_SKIP_FILES[-1])

        return True, 'success'

    def clear_pc_reboot_hold(self, args=None):
        """Clear PC_REBOOT_HOLD, the system can reboot as wish."""
        self.logger.info("Receive a request to clear PC_REBOOT_HOLD")
        for skip_reboot_file in SysTools.REBOOT_SKIP_FILES:
            if os.path.exists(skip_reboot_file):
                os.system("rm %s" % skip_reboot_file)

        return True, 'success'

    def reboot_system(self, args=None):
        """Reboot system."""
        if None is not args:
            self.clear_pc_reboot_hold()
            SysTools.notify.info(RPD_EVENT_CONNECTIVITY_REBOOT[0], 'cold start', "by " + "RPD CLI Force", "")
            self.dispatcher.timer_register(
                self.REBOOT_WAITING, SysTools.external_reboot, arg=("cold start", 'RPD CLI Force'))
            return True, 'Rebooting in 10 seconds'

        for skip_reboot_file in SysTools.REBOOT_SKIP_FILES:
            if os.path.exists(skip_reboot_file):
                return True, 'Reboot blocked by reboot hold, please clear it'
        else:
            SysTools.notify.info(RPD_EVENT_CONNECTIVITY_REBOOT[0], 'cold start', "by " + "RPD CLI", "")
            self.dispatcher.timer_register(
                self.REBOOT_WAITING, SysTools.external_reboot, arg=('cold start', 'RPD CLI'))
            return True, 'Rebooting in 10 seconds'

    def get_tod_info(self, args=None):
        """
        :return: TOD info
        para = time_server1;time_server2/time_offset|logserver1;logserver2!status

        """
        tod_info = []
        time_local = datetime.utcfromtimestamp(
            time.time()).strftime('%Y %b %d %H:%M:%S')
        try:
            para = self.mgr.tod_parameter
            if para != '':
                time_servers, time_offset = para.split("/")
                time_servers = time_servers.split(";")
                time_offset, log_servers = time_offset.split("|")
                log_servers, status = log_servers.split("!")
                if len(time_offset):
                    time_offset = int(time_offset)
                else:
                    time_offset = 0
                value = {"Server": time_servers, "TimeOffset": time_offset,
                         "Time": time_local, "Status": bool(status)}
                tod_info.append(value)

            return True, tod_info
        except Exception as e:
            return False, str(e)

    def get_dhcp_info(self, args=None):
        """
        :return: dhcp info

        """
        dhcp_info = {'Interface': [], 'Details': []}
        try:
            nic_info = net_if_addrs()
            for intf in self.mgr.dhcp_parameter:
                netmask = '0.0.0.0'
                is_ipv6 = Convert.is_valid_ipv6_address(self.mgr.dhcp_parameter[intf]['CCAPCores'][0])
                family = (socket.AF_INET, socket.AF_INET6)[is_ipv6]
                for item in nic_info[intf]:
                    if item.family == family:
                        netmask = item.netmask
                        break
                local_ip = SysTools.get_ip_address(str(intf), family=family)
                value = {"Interface": intf, 'IP-Address': local_ip, "Subnet-Mask": netmask}
                dhcp_info['Interface'].append(value)
                addr_type = "IPv4"
                if is_ipv6:
                    if self.mgr.dhcp_parameter[intf]['Slaac']:
                        addr_type = "IPv6<Stateless>"
                    else:
                        addr_type = "IPv6<Stateful>"
                intf_dhcp_parameter = self.mgr.dhcp_parameter[intf]
                intf_dhcp_parameter["AddrType"] = addr_type
                dhcp_info['Details'].append((intf, intf_dhcp_parameter))

            return True, dhcp_info
        except Exception as e:
            return False, str(e)

    def get_gcp_info(self, args=None):
        """
        :return: gcp info

        """
        gcp_info = []
        try:
            agent_id = ProcessAgent.AGENTTYPE_GCP
            for ccap_core_id in CCAPCore.ccap_core_db:
                ccap_core = CCAPCore.ccap_core_db[ccap_core_id]
                status = ccap_core.agent_status[agent_id]
                para = ccap_core.parameters
                principal = ccap_core.is_principal
                is_ipv6 = Convert.is_valid_ipv6_address(ccap_core.ccap_core_network_address)
                family = (socket.AF_INET, socket.AF_INET6)[is_ipv6]
                if agent_id in para and ';' in para[agent_id]:
                    intf, core_ip = para[agent_id].split(';')
                    local_ip = SysTools.get_ip_address(str(intf), family=family)
                    value = {
                        "Core-ID": ccap_core_id, "Core-IP": core_ip, "Local-IP": local_ip,
                        "Principal": 'Yes' if principal == CoreDescription.CORE_ROLE_PRINCIPAL else 'No',
                        'Status': status}

                    gcp_info.append(value)
            return True, gcp_info
        except Exception as e:
            return False, str(e)

    def get_interface_info(self, args=None):
        """
        :return: interface info

        """
        ret_info = []
        try:
            agent_id = ProcessAgent.AGENTTYPE_INTERFACE_STATUS
            for ccap_core_id in CCAPCore.ccap_core_db:
                ccap_core = CCAPCore.ccap_core_db[ccap_core_id]
                status = ccap_core.agent_status[agent_id]
                intf = ccap_core.parameters[agent_id]
                is_ipv6 = Convert.is_valid_ipv6_address(ccap_core.ccap_core_network_address)
                family = (socket.AF_INET, socket.AF_INET6)[is_ipv6]
                local_ip = SysTools.get_ip_address(str(intf), family=family)
                value = {"Registered-Cores": ccap_core_id, "Interface": intf, "IP": local_ip, 'Status': status}

                ret_info.append(value)
            return True, ret_info
        except Exception as e:
            return False, str(e)

    def ssd_start(self, args=None):
        self.set_pc_reboot_hold()
        return True, 'success'

    def ssd_get_aff_type(self, args=None):
        return True, 'ipv4'

    def ssd_end(self, args=None):
        self.clear_pc_reboot_hold()
        return True, 'success'
