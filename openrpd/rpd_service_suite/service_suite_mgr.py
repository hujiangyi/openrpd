#!/usr/bin/python
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

#
# Implements management process for Service Suite which includes servers as
# communication counterparts for OpenRPD.
#

import socket
from subprocess import Popen, check_output

from rpd.it_api.it_api import ItApiServerServiceSuite
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import Convert
from rpd.rcp.rcp_orchestrator import (RCPMasterCapabilities,
                                      RCPMasterDescriptor)
from rpd.rcp.rcp_master_orchestrator import RCPMasterOrchestrator
from rpd.rcp.rcp_packet_director import (RCPMasterScenario, CCAPStep,
                                         RCPMasterPacketBuildDirector)
from rpd.gpb.it_api_msgs_pb2 import t_ItApiServiceCcapCoreV4, t_ItApiServiceCcapCoreV6


class ServiceConfigAdapter(object):

    """Implements configuration actions for supported services.

    Methods ``service_enable()`` and ``service_disable()`` are implemented
    exposed and methods ``_enable()``, ``_disable()`` and
    ``_service_configure()`` are called by the exposed methods but aren't
    implemented because they are service specific.

    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, name):
        if None is name:
            raise AttributeError("No any name of service passed")
        self.name = name
        self.enabled = False
        self.parameters = None

    def service_enable(self, gpb_params=None):
        """Enables service and configures it by the parameters passed in GPB
        message as argument.

        This method just wraps the implementation in ``_enable()`` method if
        the service is not already enabled. If the service is already enabled,
        then ``_service_configure()`` method is called.

        :returns: ``True`` for success, ``False`` otherwise.

        """
        if self.enabled:
            self.logger.debug(
                "%s service already enabled, calling service configure",
                self.name)
            return self._service_configure(gpb_params=gpb_params)

        self.logger.debug("%s service enabling", self.name)
        ret = self._enable(gpb_params)
        if ret:
            self.enabled = True
            self.parameters = gpb_params
            self.logger.debug("%s service enabled", self.name)
        else:
            self.logger.error("%s service enable failed", self.name)
        return ret

    def _enable(self, gpb_params):
        """Enables service and configures it by the parameters passed in GPB
        message as argument.

        :returns: ``True`` for success, ``False`` otherwise.

        """
        raise NotImplementedError()

    def service_disable(self):
        """Disables service, this method just wraps the implementation in
        ``_disable()`` method.

        :returns: ``True`` for success, ``False`` otherwise.

        """
        if not self.enabled:
            self.logger.debug("%s: service already disabled", self.name)
            return True

        self.logger.debug("%s: service disabling", self.name)
        ret = self._disable()
        if ret:
            self.enabled = False
            self.parameters = None
            self.logger.debug("%s service disabled", self.name)
        else:
            self.logger.error("%s service disable failed", self.name)
        return ret

    def _disable(self):
        """Disables service.

        :returns: ``True`` for success, ``False`` otherwise.

        """
        raise NotImplementedError()

    def _service_configure(self, gpb_params):
        """Configures already enabled and configured service.

        :returns: ``True`` for success, ``False`` otherwise.

        """
        raise NotImplementedError()


#
# Definitions of specific config adapters for supported services,
# All supported services must have defined it's own config adapter.
#
class DhcpConfig(ServiceConfigAdapter):
    DEFAULT_IP_ADDR = None
    DEFAULT_SUBNET = None
    DEFAULT_RANGE_START = None
    DEFAULT_RANGE_END = None
    CONFIG_FILE = None
    SERVICE_SCRIPT = None

    __metaclass__ = AddLoggerToClass

    def __init__(self, name):
        super(DhcpConfig, self).__init__(name)

    def _enable(self, gpb_params):
        intf_ip_addr = self._get_intf_ip_address()
        self._replace_ip_addr(intf_ip_addr)
        try:
            Popen("{} start".format(self.SERVICE_SCRIPT), shell=True)
        except OSError as exception:
            self.logger.error("Failed to start %s service: %s", self.name,
                              exception.message)
            return False
        # let the process start and initialize
        return True

    def _disable(self):
        try:
            Popen("{} stop".format(self.SERVICE_SCRIPT), shell=True)
        except OSError as exception:
            self.logger.error("Failed to stop %s service: %s", self.name,
                              exception.message)
            return False
        return True

    def _service_configure(self, gpb_params):
        # Restart service - for case, when IP address on interface was changed
        self._disable()
        self._enable(gpb_params)
        return True

    @staticmethod
    def _get_intf_ip_address():
        raise NotImplementedError()

    @staticmethod
    def _replace_string_in_file(filename, from_string, to_string):
        with open(filename, "r") as cfg_file:
            config = cfg_file.read()
        config = config.replace(from_string, to_string)
        with open(filename, "w") as cfg_file:
            cfg_file.write(config)

    def _replace_ip_addr(self, ip_addr):
        # Replace IP address - for DHCP, TP, log-server, CCAP core
        DhcpConfig._replace_string_in_file(self.CONFIG_FILE,
                                           self.DEFAULT_IP_ADDR,
                                           self._expand_ip_addr(ip_addr))
        for addr in [self.DEFAULT_SUBNET,
                     self.DEFAULT_RANGE_START,
                     self.DEFAULT_RANGE_END]:
            new_ip = self._change_last_byte_ipaddr(
                ip_addr, self._get_last_byte_ip_addr(addr))
            DhcpConfig._replace_string_in_file(self.CONFIG_FILE, addr, new_ip)

    @staticmethod
    def _get_last_byte_ip_addr(ip_addr):
        raise NotImplementedError()

    @staticmethod
    def _expand_ip_addr(addr):
        raise NotImplementedError()


class DhcpV4Config(DhcpConfig):

    """Concrete implementation of the ServiceConfigAdapter for DHCPv4
    server."""
    DEFAULT_IP_ADDR = '192.168.5.1'
    DEFAULT_SUBNET = '192.168.5.0'
    DEFAULT_RANGE_START = '192.168.5.30'
    DEFAULT_RANGE_END = '192.168.5.200'
    CONFIG_FILE = '/etc/dhcpd.conf'
    SERVICE_SCRIPT = '/etc/init.d/dhcpd'

    def __init__(self):
        super(DhcpV4Config, self).__init__("DHCPv4")

    @staticmethod
    def _get_intf_ip_address():
        output = check_output(['uci', 'show', 'network.lan.ipaddr'])
        ip_addr = output.strip().split('=')[1].split('\'')[1]
        return ip_addr if Convert.is_valid_ipv4_address(ip_addr) else None

    @staticmethod
    def _change_last_byte_ipaddr(ip_addr, last_byte):
        bytes = ip_addr.split('.')
        bytes[-1] = last_byte
        return '.'.join(bytes)

    @staticmethod
    def _get_last_byte_ip_addr(ip_addr):
        return ip_addr.split('.')[-1]

    @staticmethod
    def _expand_ip_addr(addr):
        # Nothing to do for IPv4 address
        return addr


class DhcpV6Config(DhcpConfig):

    """Concrete implementation of the ServiceConfigAdapter for DHCPv6
    server."""
    DEFAULT_IP_ADDR = 'fd:00:de:ad:00:01:00:00:00:00:00:00:00:00:00:01'
    DEFAULT_SUBNET = 'fd00:dead:1::'
    DEFAULT_RANGE_START = 'fd00:dead:1::0a'
    DEFAULT_RANGE_END = 'fd00:dead:1::ff'
    CONFIG_FILE = '/etc/dhcpd6.conf'
    SERVICE_SCRIPT = '/etc/init.d/dhcpd6'

    def __init__(self):
        super(DhcpV6Config, self).__init__("DHCPv6")

    @staticmethod
    def _get_intf_ip_address():
        output = check_output(['uci', 'show', 'network.lanV6.ip6addr'])
        # Example output: network.lanV6.ip6addr=fd00:dead:1::1/48\n
        ip_addr = output.strip().split('=')[1].split('\'')[1].split('/')[0]
        return ip_addr if Convert.is_valid_ipv6_address(ip_addr) else None

    @staticmethod
    def _change_last_byte_ipaddr(ip_addr, last_byte):
        hextets = ip_addr.split(':')
        # 'fd00:dead:1::0011'[-1] -> '0011' , '0011'[-2] -> 00
        first_byte = hextets[-1][:-2]
        hextets[-1] = first_byte + last_byte
        return ':'.join(hextets)

    @staticmethod
    def _expand_ip_addr(addr):
        # 'fd00:dead:0001:0000:0000:0000:0000:0009'
        expanded = Convert.bytes_to_ipv6_str(
            Convert.ipaddr_to_tuple_of_bytes(addr)).lower()
        # 'fd00::1' -> 'fd:00:00:00:...:00:00:00:09'
        return ':'.join(x[:2] + ':' + x[2:] for x in expanded.split(':'))

    @staticmethod
    def _get_last_byte_ip_addr(ip_addr):
        return ip_addr.split(':')[-1][-2:]


class TpConfig(ServiceConfigAdapter):

    """Concrete implementation of the ServiceConfigAdapter for TimeProtocol
    server."""
    SERVICE_SCRIPT = '/etc/init.d/tps'

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        super(TpConfig, self).__init__("Tp")

    def _enable(self, gpb_params):
        try:
            Popen("{} start".format(self.SERVICE_SCRIPT), shell=True)
        except OSError as exception:
            self.logger.error(
                "Failed to start TPS service: %s", exception.message)
            return False
        return True

    def _disable(self):
        try:
            Popen("{} stop".format(self.SERVICE_SCRIPT), shell=True)
        except OSError as exception:
            self.logger.error(
                "Failed to stop TPS service: %s", exception.message)
            return False
        return True

    def _service_configure(self, gpb_params):
        self.logger.debug("Nothing to do for TP service")
        return True


class CcapConfig(ServiceConfigAdapter):

    """Common implementation of the ServiceConfigAdapter for CcapCore
    services."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, service_name, addr_family, orchestrator):
        super(CcapConfig, self).__init__(service_name)
        self.addr_family = addr_family
        self.orchestrator = orchestrator
        self.caps = None
        self.descr = None

    def _enable(self, gpb_params):
        return self._service_configure(gpb_params)

    def _disable(self):
        if None is not self.descr:
            self.orchestrator.remove_sessions([self.descr])
            self.caps = None
            self.descr = None
        return True

    def _service_configure(self, gpb_params):
        self._disable()

        scenario = None
        if None is not gpb_params:
            msg_class = t_ItApiServiceCcapCoreV4 if \
                self.addr_family == socket.AF_INET else \
                t_ItApiServiceCcapCoreV6
            if not isinstance(gpb_params, msg_class):
                self.logger.error(
                    "Invalid GPB message passed {}".format(gpb_params))
                return False

            pkt_builder = RCPMasterPacketBuildDirector()
            scenario = None
            for gpb_scenario in gpb_params.ClientScenarios:
                if gpb_scenario.ScenarioType == gpb_scenario.SCENARIO_DEFAULT:
                    continue

                if None is scenario:
                    scenario = RCPMasterScenario()

                if gpb_scenario.ScenarioType == gpb_scenario.SCENARIO_REDIRECT:
                    if not hasattr(gpb_scenario, "redirect_ip_addr"):
                        self.logger.error("Redirect scenario GPB message without "
                                          "redirect IP address")
                        continue

                    addr_redir = gpb_scenario.redirect_ip_addr
                    if gpb_scenario.HasField("client_ip"):
                        client = "{}".format(gpb_scenario.client_ip)
                    else:
                        # default scenario
                        client = None
                    self.logger.debug("Adding redirect scenario: client: %s, "
                                      "redir_ip: %s", client, addr_redir)
                    scenario.add_next_step(
                        CCAPStep(
                            pkt_builder.get_redirect_packet,
                            param_tuple=([addr_redir],),
                            description="Redirect to {}".format(addr_redir)),
                        slave_id=client)

        # continue regardless to result of scenario processing
        if self.addr_family == socket.AF_INET:
            if gpb_params.HasField("IPv4Address"):
                core_addr = gpb_params.IPv4Address
            else:
                core_addr = '0.0.0.0'
            self.caps = RCPMasterCapabilities(
                index=4,
                core_name="ServiceSuiteCCAPv4",
                core_ip_addr=core_addr)
        else:
            if gpb_params.HasField("IPv6Address"):
                core_addr = gpb_params.IPv6Address
            else:
                core_addr = '::'
            self.caps = RCPMasterCapabilities(
                index=6,
                core_name="ServiceSuiteCCAPv6",
                core_ip_addr=core_addr)

        self.descr = RCPMasterDescriptor(
            capabilities=self.caps,
            addr=core_addr,
            addr_family=self.addr_family,
            scenario=scenario)

        self.orchestrator.add_sessions([self.descr])

        try:
            session = \
                self.orchestrator.sessions_active[self.descr.get_uniq_id()]
            if not session.is_initiated():
                self.logger.error("CCAP core's RCP session is not initiated")
                return False
        except Exception as ex:
            self.logger.error(
                "Failed to check CCAP core's RCP session: %s", ex)
            return False

        return True


class CcapV4Config(CcapConfig):

    """Concrete implementation of the ServiceConfigAdapter for CcapCoreV4."""

    def __init__(self, orchestrator):
        super(CcapV4Config, self).__init__(service_name="CcapCoreV4",
                                           addr_family=socket.AF_INET,
                                           orchestrator=orchestrator)


class CcapV6Config(CcapConfig):

    """Concrete implementation of the ServiceConfigAdapter for CcapCoreV6."""

    def __init__(self, orchestrator):
        super(CcapV6Config, self).__init__(service_name="CcapCoreV6",
                                           addr_family=socket.AF_INET6,
                                           orchestrator=orchestrator)


#
# Implementation of the Manager process for Service Suite.
#
class ServiceSuiteManager(object):

    """Implements a process managing all services supported in ServiceSuite.

    Opens IT API socket and starts ItApiServerServiceSuite in order to
    support GPB message exchange between ServiceSuite image and client.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.disp = Dispatcher()
        self.it_api_server = ItApiServerServiceSuite(rx_cb=self._ip_api_rx_cb,
                                                     disp=self.disp)

        self.orchestrator = RCPMasterOrchestrator(self.disp)

        self.services = [
            DhcpV4Config(),
            DhcpV6Config(),
            TpConfig(),
            CcapV4Config(self.orchestrator),
            CcapV6Config(self.orchestrator)
        ]

    def start(self):
        """Starts the manager."""
        for service in self.services:
            service._disable()
        self.disp.loop()

    def get_dhcp_assiged_addr_list(self):
        """This API is used to get the IP Address list which is assigned by
        dhcpd."""
        ip = []
        f = file("/tmp/dhcpd.leases")
        for l in f.readlines():
            al = l.split()
            if len(al) == 3 and al[0] == "lease":
                self.logger.debug("Got ip: %s", al[1])
                ip.append(al[1])
        return ip

    def _ip_api_rx_cb(self, gpb_msg):
        """This method is called when GPB message is received on the IT API
        socket.

        Respective actions are performed with services according to the
        GPB message.

        """
        if None is gpb_msg:
            raise AttributeError("No GPB message passed")

        if not gpb_msg.IsInitialized():
            self.logger.error("Non initialized GPB message passed")
            return

        self.logger.info("Received IT API Service Suite message: %s(%u)",
                         gpb_msg.t_ItApiServiceSuiteMessageType.Name(
                             gpb_msg.MessageType),
                         gpb_msg.MessageType)

        if gpb_msg.MessageType == gpb_msg.IT_API_SERVICE_SUITE_CONFIGURE:
            if not gpb_msg.HasField("ServiceConfigureMessage"):
                self.logger.error("Empty Service Configure message received")
                return
            cfg_gpb_msg = gpb_msg.ServiceConfigureMessage
            ret = True
            for serv in self.services:
                if cfg_gpb_msg.HasField(serv.name):
                    cfg = getattr(cfg_gpb_msg, serv.name)
                    if cfg.enable:
                        ret = serv.service_enable(cfg)
                    else:
                        ret = serv.service_disable()
                    if not ret:
                        break

            # Send response
            gpb_msg.MessageResult = gpb_msg.IT_API_SERVICE_SUITE_RESULT_NONE
            if ret:
                gpb_msg.MessageResult = \
                    gpb_msg.IT_API_SERVICE_SUITE_RESULT_OK
            else:
                gpb_msg.MessageResult = \
                    gpb_msg.IT_API_SERVICE_SUITE_RESULT_FAILED
            self.it_api_server.it_api_send_msg(gpb_msg)

        elif gpb_msg.MessageType == gpb_msg.IT_API_SERVICE_SUITE_L2TP:
            ret = False
            for ip in self.get_dhcp_assiged_addr_list():
                self.logger.info("Start L2TP for ip:%s", ip)
                try:
                    ret = True
                    Popen(
                        ["python", "-m", "rpd.l2tp.l2tpv3.simulator.L2tpv3MasterSim", "ipv4", ip], cwd="/tmp")
                except OSError as exception:
                    ret = False
                    self.logger.error(
                        "Failed to start %s service: %s", self.name, exception.message)

            # Send response
            if ret:
                gpb_msg.MessageResult = gpb_msg.IT_API_SERVICE_SUITE_RESULT_OK
            else:
                gpb_msg.MessageResult = gpb_msg.IT_API_SERVICE_SUITE_RESULT_FAILED
            self.it_api_server.it_api_send_msg(gpb_msg)
        else:
            self.logger.error(
                "Received unsupported message type:%d", gpb_msg.MessageType)

    def cleanup(self):
        self.it_api_server.cleanup()

if __name__ == "__main__":
    setup_logging("MasterSim", filename="srv_suite_mgr.log")
    ServiceSuiteManager().start()
