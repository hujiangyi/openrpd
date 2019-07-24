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
# limitations under the License

import time

from rpd.common.rpd_logging import AddLoggerToClass
from rpd_service_suite.topology import Topology, VirtMachine
from rpd.it_api.it_api import (ItApiClient,
                               ItApiClientServiceSuite,
                               ItApiClientOpenRPD)
from rpd.gpb.it_api_msgs_pb2 import (t_ItApiRpdMessage,
                                     t_ItApiServiceSuiteMessage)


class ItApiVm(VirtMachine):

    """Class represents VMs with IT API interface used to send commands and
    receive data from VMs."""

    IT_API_VM_TYPE_OPEN_RPD = "OpenRPD_VM"
    IT_API_VM_TYPE_SERVICE_SUITE = "ServiceSuiteVM"

    __metaclass__ = AddLoggerToClass

    def __init__(self, vm_name, vmdk_path,
                 mac_eth0, mac_eth1,
                 vm_type):
        """Create virtual machine.

        :param vmdk_path: absolute path to VM image
        :param vm_name: VM name (used by virsh)
        :param mac_eth0: MAC address for management interface, in format:
         AA:BB:CC:DD:EE:FF
        :param mac_eth1: MAC address for communication between VMs
        :param vm_type: Type of VM.

        """
        super(ItApiVm, self).__init__(vm_name, vmdk_path, mac_eth0, mac_eth1)
        self.vm_type = vm_type
        self.it_api_client = None

    def connect_to_it_api_server(self):
        """Connects this instance (acting as IT API client) to the IT API
        server listening at booted VM."""
        if None is self.it_api_client:
            raise RuntimeError("Connect called, but IT API client is not"
                               "initialized")

        if not isinstance(self.it_api_client, ItApiClient):
            raise TypeError("Invalid IT API Client type")

        if not self.ip_addresses:
            raise RuntimeError("Connect called, but there's not any VM's IP "
                               "address set")

        self.logger.debug("ItApiVM: %s, %s: Connecting to VM's IT API server, IP "
                          "address: %s", self.name, self.vm_type,
                          self.ip_addresses[0])
        ret = self.it_api_client.connect(self.ip_addresses[0])
        if not ret:
            self.logger.error("ItApiVM: %s, %s: Failed to connect to VM's IT",
                              self.name, self.vm_type)
        return ret

    def vm_command(self, gpb_req):
        """Sends command (GPB message) to the IT API server and received reply
        including requested data. This method is blocking, reply is returned as
        GPB message.

        :param gpb_req: GPB message including request.
        :returns: GPB message with response.

        """
        if not isinstance(gpb_req,
                          (t_ItApiServiceSuiteMessage, t_ItApiRpdMessage)):
            raise AttributeError("Invalid GPB REQ passed")
        return self.it_api_client.it_api_send_msg(gpb_req)

    def cleanup(self):
        """Closes VM and IT API client."""
        super(ItApiVm, self).cleanup()
        if None is not self.it_api_client:
            self.it_api_client.cleanup()


class OpenRpdVm(ItApiVm):

    """Specialized VM for OpenRPD."""

    def __init__(self, vm_name, vmdk_path, mac_eth0, mac_eth1):
        """Create virtual machine.

        :param vmdk_path: absolute path to VM image
        :param vm_name: VM name (used by virsh)
        :param mac_eth0: MAC address for management interface, in format:
         AA:BB:CC:DD:EE:FF
        :param mac_eth1: MAC address for communication between VMs
        :return:

        """
        super(OpenRpdVm, self).__init__(vm_name, vmdk_path,
                                        mac_eth0, mac_eth1,
                                        ItApiVm.IT_API_VM_TYPE_OPEN_RPD)
        self.it_api_client = ItApiClientOpenRPD()


class ServiceSuiteVm(ItApiVm):

    """Specialized VM for ServiceSuite."""

    __metaclass__ = AddLoggerToClass
    ip_v4_pool_eth1 = ["192.168.5.{}".format(num) for num in range(1, 10)]
    ip_v6_pool_eth1 = ["fd00:dead:1::{}".format(num) for num in range(1, 10)]

    def __init__(self, vm_name, vmdk_path, mac_eth0, mac_eth1):
        """Create virtual machine.

        :param vmdk_path: absolute path to VM image
        :param vm_name: VM name (used by virsh)
        :param mac_eth0: MAC address for management interface, in format:
         AA:BB:CC:DD:EE:FF
        :param mac_eth1: MAC address for communication between VMs
        :return:

        """
        super(ServiceSuiteVm, self).__init__(
            vm_name, vmdk_path,
            mac_eth0, mac_eth1,
            ItApiVm.IT_API_VM_TYPE_SERVICE_SUITE)
        self.it_api_client = ItApiClientServiceSuite()

    def start(self, setup=True):
        if not self.ip_v4_pool_eth1 or not self.ip_v6_pool_eth1:
            raise RuntimeError("Not any free IP address for eth1")
        super(ItApiVm, self).start(setup)

    @staticmethod
    def prepare_config_message(dhcpv6=None, dhcpv4=None, tps=None,
                               ccapv6=None, ccapv4=None):
        # True -> enable service, False -> disable, None -> no change
        msg = t_ItApiServiceSuiteMessage()
        msg.MessageType = msg.IT_API_SERVICE_SUITE_CONFIGURE

        mapping = {"DHCPv4": dhcpv4, "DHCPv6": dhcpv6, "Tp": tps,
                   "CcapCoreV6": ccapv6, "CcapCoreV4": ccapv4}
        for gpb_attr, config in mapping.iteritems():
            if config is not None:
                getattr(msg.ServiceConfigureMessage, gpb_attr).enable = config
        return msg

    def change_eth1_ip_addr(self, ip_addr):
        """Checks if the ip_addr is available in the ip_pool_eth1.

        Raises exception if not, otherwise it calls this method of
        parent class.

        """
        if ((ip_addr not in self.ip_v4_pool_eth1) and
                (ip_addr not in self.ip_v6_pool_eth1)):
            raise AttributeError("Passed IP address ({}) is not "
                                 "available".format(ip_addr))

        if ip_addr in self.ip_v4_pool_eth1:
            self.ip_v4_pool_eth1.remove(ip_addr)
            old_ip = self.ip_addresses[1]
            if old_ip and old_ip not in self.ip_v4_pool_eth1:
                self.ip_v4_pool_eth1.append(old_ip)
        else:
            self.ip_v6_pool_eth1.remove(ip_addr)
            old_ip = self.ipv6_addresses[1]
            if old_ip and old_ip not in self.ip_v6_pool_eth1:
                self.ip_v6_pool_eth1.append(old_ip)

        super(ItApiVm, self).change_eth1_ip_addr(ip_addr)
        # Wait some time for network initialization - TODO change to poll
        time.sleep(3)
        self.logger.debug("Changed IP address of eth1 to %s", ip_addr)

    def _post_boot_config(self):
        try:
            super(ItApiVm, self)._post_boot_config()
            ip_addr = self.ip_v4_pool_eth1[0]
            ipv6_addr = self.ip_v6_pool_eth1[0]
            self.change_eth1_ip_addr(ip_addr)
            self.change_eth1_ip_addr(ipv6_addr)
        except Exception as ex:
            self.logger.error("Post boot configuration failed: %s", ex)

    def cleanup(self):
        try:
            ip_addr = self.ip_addresses[1]
        except:
            ip_addr = None
        try:
            ipv6_addr = self.ipv6_addresses[1]
        except:
            ipv6_addr = None

        super(ItApiVm, self).cleanup()

        if ip_addr and ip_addr not in self.ip_v4_pool_eth1:
            self.ip_v4_pool_eth1.append(ip_addr)
        if ipv6_addr and ipv6_addr not in self.ip_v6_pool_eth1:
            self.ip_v6_pool_eth1.append(ipv6_addr)


class ItApiTopology(Topology):

    """Implements some extensions needed for IT API VMs."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, open_rpd_image, service_suite_image):
        """Takes list of VMs supporting IT API and stores them for this
        topology.

        :param open_rpd_image: Path to the image of OpenRPD VM.
        :param service_suite_image: Path to the image of ServiceSuite VM.

        """
        super(ItApiTopology, self).__init__()
        if None is open_rpd_image and None is service_suite_image:
            self.logger.warning("No any VM image set")
        self.image_open_rpd = open_rpd_image
        self.image_service_suite = service_suite_image

    def create_vm_open_rpd(self, name, start=True, image=None):
        """Creates OpenRPD VM and adds it to the topology. VM is started if the
        start attribute is set to True.

        :param name: Name of VM
        :param start: New instance of VM is started (booted) if this parameter
         is set to True.
        :param image: If the desired image for VM is different than the
         default image for topology then it's possible to pass the path to the
         image argument.
        :returns: created VM as instance of OpenRpdVm

        """
        if None is self.image_open_rpd:
            raise RuntimeError("Image for OpenRPD not set")

        if None is image:
            image = self.image_open_rpd
        super(ItApiTopology, self).create_vm(image,
                                             name,
                                             start,
                                             _vm_class=OpenRpdVm)
        return self.nodes[name]

    def create_vm_service_suite(self, name, start=True, image=None):
        """Creates ServiceSuite VM and adds it to the topology. VM is started
        if the start attribute is set to True.

        :param name: Name of VM
        :param start: New instance of VM is started (booted) if this parameter
         is set to True.
        :param image: If the desired image for VM is different than the
         default image for topology then it's possible to pass the path to the
         image argument.
        :returns: created VM as instance of ServiceSuiteVM

        """
        if None is self.image_service_suite:
            raise RuntimeError("Image for ServiceSuite not set")

        if None is image:
            image = self.image_service_suite
        super(ItApiTopology, self).create_vm(image,
                                             name,
                                             start,
                                             _vm_class=ServiceSuiteVm)
        return self.nodes[name]

    def start_vm(self, name, setup=True, wait_for_boot=True,
                 max_boot_time=VirtMachine.MAX_BOOT_TIME):

        super(ItApiTopology, self).start_vm(name, setup, wait_for_boot,
                                            max_boot_time)
        if wait_for_boot:
            machine = self.nodes[name]
            ret = machine.connect_to_it_api_server()
            if not ret:
                self.logger.error(
                    "Failed to connect to IT API socket of VM: %s",
                    machine.name)
                machine.cleanup()

    def start_and_wait_for_all(self, max_boot_time=VirtMachine.MAX_BOOT_TIME):
        super(ItApiTopology, self).start_and_wait_for_all(max_boot_time)
        for machine in self.nodes.values():
            ret = machine.connect_to_it_api_server()
            if not ret:
                self.logger.error(
                    "Failed to connect to IT API socket of VM: %s",
                    machine.name)
                machine.cleanup()
