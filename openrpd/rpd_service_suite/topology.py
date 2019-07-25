# Copyright (c) 2016 Cisco and/or its affiliates, and
#                    Teleste Corporation, and
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
import subprocess
import paramiko
import time
from rpd.common.utils import Convert
from rpd.common.rpd_logging import AddLoggerToClass
from uuid import uuid4
from signal import SIGTERM
from scp import SCPClient

SSH_INFO = ('root', 'lab123', 30)  # (user, password, timeout)


class VMState(object):
    Stopped = 0
    Booting = 1
    Ready = 2


class VMMode(object):
    KVM = 0
    QEMU = 1


class VirtMachine(object):
    VMDK_EXTENSION = ".vmdk"
    QCOW_EXTENSION = ".qcow2"
    MAX_BOOT_TIME = 300

    VM_MODE = VMMode.KVM

    __metaclass__ = AddLoggerToClass

    def __init__(self, vm_name, vmdk_path, mac_eth0, mac_eth1):
        """Create virtual machine.

        :param vmdk_path: absolute path to VM image
        :param vm_name: VM name (used by virsh)
        :param mac_eth0: MAC address for management interface, in format:
         AA:BB:CC:DD:EE:FF
        :param mac_eth1: MAC address for communication between VMs
        :return:

        """
        self.name = vm_name
        self.mac_addresses = (mac_eth0, mac_eth1)
        self.vmdk_path = vmdk_path
        self.ip_addresses = (None, None)  # IP addresses for eth0 and eth1
        self.ipv6_addresses = (None, None)

        self._state = VMState.Stopped
        self._img_path = "{}/{}".format(os.getcwd(), vm_name)
        self._xml_path = "{}/{}.xml".format(os.getcwd(), vm_name)
        self._term_process = None

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, new_state):
        if self._state == new_state:
            return

        self._state = new_state
        if new_state == VMState.Ready:
            # Apply post boot configuration
            try:
                self._post_boot_config()
            except Exception as exception:
                self.logger.error(
                    "Post config actions failed: %s", exception.message)

    def get_new_vmdk_path(self):
        if self._img_path is not None:
            return self._img_path + self.VMDK_EXTENSION
        return None

    def get_gcow_path(self):
        if self._img_path is not None:
            return self._img_path + self.QCOW_EXTENSION
        return None

    def _get_vm_domain_type(self):
        # default to KVM
        domain_type = """kvm"""
        if VirtMachine.VM_MODE == VMMode.QEMU:
            domain_type = """qemu"""
        return domain_type

    def _get_vm_emulator_path(self):
        # default to KVM
        emu_path = """/usr/bin/kvm"""
        if VirtMachine.VM_MODE == VMMode.QEMU:
            emu_path = """/usr/bin/qemu-system-x86_64"""
        return emu_path

    def _generate_xml(self):
        xml_text = """<domain type=\
'{}' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
    <name>{}</name>
    <memory unit='KiB'>594304</memory>
    <currentMemory unit='KiB'>594304</currentMemory>
    <vcpu placement='static'>2</vcpu>
    <os>
        <type arch='i686' machine='pc'>hvm</type>
        <boot dev='hd'/>
    </os>
    <features>
        <acpi/>
    </features>
    <clock offset='utc'/>
    <on_poweroff>destroy</on_poweroff>
    <on_reboot>restart</on_reboot>
    <on_crash>destroy</on_crash>
    <devices>
        <emulator>{}</emulator>
        <disk type='file' device='disk'>
            <driver name='qemu' type='qcow2'/>
            <source file='{}'/>
            <target dev='hda' bus='ide'/>
            <address type='drive' controller='0' bus='0' target='0' unit='0'/>
        </disk>
        <controller type='usb' index='0'>
            <address type='pci' domain='0x0000' bus='0x00' slot='0x01' \
function='0x2'/>
        </controller>
        <controller type='pci' index='0' model='pci-root'/>
        <controller type='ide' index='0'>
            <address type='pci' domain='0x0000' bus='0x00' slot='0x01' \
function='0x1'/>
        </controller>
        <interface type='network'>
            <mac address='{}'/>
            <source network='default'/>
            <model type='e1000'/>
            <address type='pci' domain='0x0000' bus='0x00' slot='0x03' \
function='0x0'/>
        </interface>
        <interface type='network'>
            <mac address='{}'/>
            <source network='virbr1'/>
            <model type='e1000'/>
            <address type='pci' domain='0x0000' bus='0x00' slot='0x05' \
function='0x0'/>
        </interface>
        <serial type='pty'>
            <target port='0'/>
        </serial>
        <console type='pty'>
            <target type='serial' port='0'/>
        </console>
        <input type='mouse' bus='ps2'/>
        <input type='keyboard' bus='ps2'/>
        <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
            <listen type='address' address='0.0.0.0'/>
        </graphics>
        <video>
            <model type='cirrus' vram='9216' heads='1'/>
            <address type='pci' domain='0x0000' bus='0x00' slot='0x02' \
function='0x0'/>
        </video> ")
        <memballoon model='virtio'> ")
            <address type='pci' domain='0x0000' bus='0x00' slot='0x04' \
function='0x0'/>
         </memballoon>
    </devices>
</domain>
""".format(self._get_vm_domain_type(), self.name,
           self._get_vm_emulator_path(), self.get_gcow_path(), *self.mac_addresses)

        with open(self._xml_path, 'w') as xml_file:
            xml_file.write(xml_text)

    def _convert_image(self):
        """Call qemu for image conversion from *.vmdk to *.qcow2 file format.

        :raise subprocess.CalledProcessError: copy or convert commands failed
        :raise OSError: VMDK file not accessible
        :return:

        """
        # Extract image name
        vmdk_new_path = self.get_new_vmdk_path()
        self.logger.debug("vmdk path: '%s'", vmdk_new_path)
        # TODO: Can be optimized: check file hash (md5?) - do not copy & convert
        # if image is already there

        # Copy vmdk image to current directory
        if os.path.isfile(self.vmdk_path):
            cmd = "cp {} {}".format(self.vmdk_path, vmdk_new_path)
            subprocess.check_call(cmd, shell=True)
        else:
            raise OSError("VMDK File not accessible: %s" % self.vmdk_path)

        # Convert image to qcow2 format
        cmd = "qemu-img convert -c -p -O qcow2 {} {}".format(
            vmdk_new_path, self.get_gcow_path())
        subprocess.check_call(cmd, shell=True)

    def _setup(self):
        """Prepare virtual machine image and *.xml files for qemu usage.

        :raise subprocess.CalledProcessError: failed to convert image
        :raise OSError: failed to save XML file
        :return:

        """
        self._convert_image()
        self._generate_xml()

    def start(self, setup=True):
        """Setup virtual machine and start it. Machine state will be changed if
        creation was successful.

        :param setup: Flag whether we need to prepare image & xml for VM or not
        :return:

        """
        try:
            if setup:
                self._setup()
            subprocess.check_call("virsh create " + self._xml_path, shell=True)
        except (subprocess.CalledProcessError, OSError) as exception:
            self.logger.error("Failed to start VM: %s", exception.message)
            return
        self.state = VMState.Booting

    def stop(self):
        """Stop virtual machine specified by name.

        :raise subprocess.CalledProcessError: virsh command failed
        :return:

        """
        if self.state == VMState.Stopped:
            self.logger.debug("VM already stopped")
            return
        if self._term_process is not None:
            self._kill_terminal()
        try:
            subprocess.check_call("virsh destroy " + self.name, shell=True)
        except subprocess.CalledProcessError as exception:
            self.logger.error("Failed to stop VM: %s", exception.message)
            return
        self.state = VMState.Stopped

    def open_terminal(self):
        """Open terminal on VM.

        :return:

        """
        if self._term_process is not None:
            self._kill_terminal()
        try:
            ip_addr = self.ip_addresses[0] or self.get_ip_address()
        except ValueError:
            self.logger.error("Can't get IP address of VM for ssh")
            return
        ps = subprocess.Popen('x-terminal-emulator -e bash -c "sshpass -p {} '
                              'ssh -o UserKnownHostsFile=/dev/null -o'
                              ' StrictHostKeyChecking=no {}@{}"'.format(
                                  SSH_INFO[1], SSH_INFO[0], ip_addr),
                              shell=True, preexec_fn=os.setsid)
        self._term_process = ps

    def _post_boot_config(self):
        # TODO: open test socket
        pass

    def change_eth1_ip_addr(self, ip_addr):
        """Change IP address on eth1 NOTE: Do not forget to restart services if
        already running.

        :param ip_addr: IP address to be assigned to eth1 interface. In format:
         1.2.3.4. This is applicable only for 'external' images.
         RPD image requires DHCP managed eth1 interface. Support for mask and
         gateway change can be added in the future.
        :return:

        """
        if not Convert.is_valid_ip_address(ip_addr):
            raise TypeError("Invalid IP address string provided: %s", ip_addr)
        is_ipv4 = Convert.is_valid_ipv4_address(ip_addr)
        if is_ipv4:
            self.ip_addresses = (self.ip_addresses[0], ip_addr)
            net_name = 'lan'
        else:
            self.ipv6_addresses = (self.ipv6_addresses[0], ip_addr)
            net_name = 'lanV6'
        # Check if protocol on eth1 is set to static (truth only on external)
        try:
            proto = self.run_command(
                "uci show network.{}.proto".format(net_name))
            if proto[0].strip().split('=')[1] != '\'static\'':
                raise TypeError("IP address is not static - not server side?")
            # Configure IP address provided
            if is_ipv4:
                cmd = "uci set network.{net}.ipaddr={ip_addr}; "
            else:
                cmd = "uci set network.{net}.ip6addr={ip_addr}/64; "
            # Commit changes to network configuration
            cmd += "uci commit network; "
            # Apply config to interface
            cmd += "ifup {net}"
            self.run_command(cmd.format(net=net_name, ip_addr=ip_addr))
        except subprocess.CalledProcessError as exception:
            self.logger.error(
                "Failed to set IP address to host: %s", exception.message)
            return

    def _kill_terminal(self):
        os.killpg(self._term_process.pid, SIGTERM)
        self._term_process = None

    def cleanup(self):
        """Remove generated/copied files.

        :return:

        """
        self.stop()
        for file_to_remove in [self._xml_path,
                               self.get_gcow_path(),
                               self.get_new_vmdk_path()]:
            if os.path.exists(file_to_remove):
                os.remove(file_to_remove)

    def is_ready(self):
        """Check if machine is ready to use (ssh connection can be opened)

        :return:

        """
        if self.state == VMState.Ready:
            self.logger.info("VMState.Ready is true")
            return True
        try:
            self.run_command(":")
        except paramiko.SSHException:
            self.logger.info("SSHException error!")
            return False
        return True

    def run_command(self, cmd):
        """Execute command on remote host.

        :param cmd: command to execute on remote
        :raise: ValueError: no VM with specified IP address found
        :raise subprocess.CalledProcessError: command failed on remote host
        :raise paramiko.SSHException: connection failed
        :return: command output

        """
        if self.ip_addresses[0] is None:
            self.ip_addresses = (self.get_ip_address(), self.ip_addresses[1])
        print self.ip_addresses[0], self.ip_addresses[1]
        ip_addr = self.ip_addresses[0]
        if ip_addr is None:
            raise paramiko.SSHException("Failed to IP address for SSH")

        self.logger.info(
            "remote IP '%s' - command for execution: '%s'", ip_addr, cmd)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip_addr, username=SSH_INFO[0], password=SSH_INFO[1],
                           timeout=SSH_INFO[2])
            stdin, stdout, stderr = client.exec_command(cmd)
        except paramiko.SSHException:
            # self.logger.error("Failed to execute remote cmd: %s",
            # exception.message)
            raise
        except paramiko.ssh_exception.NoValidConnectionsError as exception:
            raise paramiko.SSHException("Failed to execute remote cmd: %s",
                                        exception.strerror)

        output_stdout_rc = stdout.channel.recv_exit_status()
        output_stdout = stdout.readlines()
        output_stderr = stderr.readlines()
        self.logger.debug("Stdout rc[%d]:\n%s", output_stdout_rc,
                          ''.join(output_stdout))
        self.logger.debug("Stderr:\n%s", ''.join(output_stderr))
        client.close()

        if 0 != output_stdout_rc:
            raise subprocess.CalledProcessError(
                output_stdout_rc, cmd,
                "Command on remote host failed: %s" % output_stderr)

        self.state = VMState.Ready
        return output_stdout

    def get_ip_address(self, interface='eth0', timeout=MAX_BOOT_TIME):
        """Get IP assigned to VM interface.

        :param interface: VM interface name 'eth0' / 'eth1'
        :param timeout: Time to wait for DHCP server to assign IP for this VM
        :raise ValueError: VM with specified MAC address or interface not found
        :return:

        """
        if interface not in ['eth0', 'eth1']:
            raise ValueError("Invalid interface name")
        if self.state == VMState.Stopped:
            raise ValueError("Trying to get IP addr of not running VM")
        mac_addr = self.mac_addresses[0 if interface == 'eth0' else 1]
        # leases_file = '/var/lib/libvirt/dnsmasq/default.leases'
        arpout = subprocess.check_output("arp", shell=True)
        self.logger.info("arp output: \n%s\n", arpout)
        cmd = "arp | egrep {} | awk ' {{ print $1 }} '".format(
            mac_addr.lower())
        self.logger.info(
            "Wait for VM[%s] interface %s to get IP address",
            self.name, interface)
        for _ in range(timeout):
            try:
                result = subprocess.check_output(cmd, shell=True)
            except (subprocess.CalledProcessError, OSError) as exception:
                raise ValueError("Failed to get VM[%s] ip: %s", self.name,
                                 exception.message)
            if result is None:
                raise ValueError("VM with MAC address does not exist")
            ip_list = result.split()
            if len(ip_list):
                return ip_list[0]
            time.sleep(1)
        raise ValueError("VM with MAC address does not exist")

    def _get_log_dest_dir(self, dest_dir=None):
        """Get the destination directory for storing log files

        :param dest_dir: Optional destination directory/subdirectory
        :return: Destination directory path
        """
        it_subdir = ".%sIT" % os.path.sep
        if dest_dir is None:
            dest_dir = it_subdir
        elif not os.path.isabs(dest_dir):
            dest_dir = os.path.join(it_subdir, dest_dir)

        if self.name is not None:
            dest_dir = os.path.join(dest_dir, self.name)

        # normalize the path
        dest_dir = os.path.normpath(dest_dir)

        return dest_dir

    def get_logs(self, dest_dir=None):
        """Get the log files from this VM instance

        :param dest_dir: Optional destination directory/subdirectory
        :raise paramiko.SSHException: connection failed
        :return:
        """
        dest_dir = self._get_log_dest_dir(dest_dir)

        if os.path.exists(dest_dir):
            self.logger.info("Deleting existing log dir: \"%s\" ...", dest_dir)
            cmd_delete_log_dir = "rm -rf %s" % dest_dir
            os.system(cmd_delete_log_dir)
        self.logger.info("Creating IT log dir: \"%s\" ...", dest_dir)
        os.makedirs(dest_dir)

        # get the list of python processes running on the it_api_topology machine
        cmd_get_processes = "ps w | grep python"
        process_list = self.run_command(cmd_get_processes)
        if process_list is not None:
            self.logger.info("Processes on \"%s\":\n%s", self.name, "".join(process_list))
            ps_file = open(os.path.join(dest_dir, "ps-python.txt"), "w")
            for process in process_list:
                # Note - the items in the process_list already have carriage returns
                ps_file.write("%s" % process)
            ps_file.close()

        # get the rpd log files from the it_api_topology machine

        # there are some logs in /
        cmd_get_log_file_list_root = "ls -1 /*.log"
        log_file_list_root = self.run_command(cmd_get_log_file_list_root)

        # and there are some logs in /tmp
        cmd_get_log_file_list_tmp = "ls -1 /tmp/*.log"
        log_file_list_tmp = self.run_command(cmd_get_log_file_list_tmp)

        # concatenate the two lists into one
        log_file_list = log_file_list_root + log_file_list_tmp

        # If desired, add more files to the list
        # log_file_list.append("/etc/config/network")

        if log_file_list is not None:

            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(self.ip_addresses[0],
                               username=SSH_INFO[0],
                               password=SSH_INFO[1],
                               timeout=SSH_INFO[2])

            # I cannot get the paramiko SFTPClient to work.
            # sftp = client.open_sftp()
            # Attempting to open the sftp client results in:
            # /usr/lib/python2.7/dist-packages/Crypto/Cipher/blockalgo.py:141:
            #   FutureWarning: CTR mode needs counter parameter, not IV
            #   self._cipher = factory.new(key, *args, **kwargs)
            #   SSHException: EOF during negotiation
            # sftp.get("/tmp/*.log", dest_dir)
            # sftp.close()

            scp_client = SCPClient(ssh_client.get_transport())
            for log_file in log_file_list:
                # Note - the items in the log_file_list have carriage returns that
                #  need to be removed
                log_file = log_file.rstrip("\n")
                # Note - the dest_file path should be the log_file path, but relative to dest_path
                dest_file = os.path.join(dest_dir, log_file.lstrip(os.path.sep))
                dest_dirname = os.path.dirname(dest_file)
                # make sure that the directory exists for the dest_file
                if not os.path.exists(dest_dirname):
                    os.makedirs(dest_dirname)
                self.logger.info("Fetching \"%s\" to \"%s\"", log_file, dest_file)
                scp_client.get(log_file, dest_file)

            if scp_client is not None:
                scp_client.close()

            if ssh_client is not None:
                ssh_client.close()

    def __del__(self):
        self.cleanup()


class VirtBridge(object):
    __metaclass__ = AddLoggerToClass

    def __init__(self, net_name, mac_eth1):
        """
        :param net_name: name for network used by wirsh
        :param mac_eth1: network MAC address for VM eth1 (openwrt network)
        :return:
        """
        self.name = 'virbr1'
        self.net_name = net_name
        self.mac_addr = mac_eth1
        self.state = VMState.Stopped
        self._xml_path = "{}/{}.xml".format(os.getcwd(), self.net_name)

    def start(self):
        """Start virtual network.

        :return:

        """
        try:
            self._generate_xml(self._xml_path)
            subprocess.check_call("virsh net-create " + self._xml_path,
                                  shell=True)
        except (subprocess.CalledProcessError, OSError) as exception:
            self.logger.error("Failed to start network: %s", exception.message)
            return
        self.state = VMState.Ready

    def stop(self):
        """Stop virtual network.

        :return:

        """
        if self.state == VMState.Stopped:
            return
        try:
            subprocess.check_call("virsh net-destroy " + self.net_name,
                                  shell=True)
        except subprocess.CalledProcessError as exception:
            self.logger.error("Failed to stop VM: %s", exception.message)
            return
        self.state = VMState.Stopped

    def cleanup(self):
        """Remove generated/copied files.

        :return:

        """
        self.stop()
        if os.path.exists(self._xml_path):
            os.remove(self._xml_path)

    def _generate_xml(self, xml_file_path):
        """Generate network configuration file (.xml) for qemu usage.

        :param xml_file_path: xml file full path
        :raise OSError: Generated file cannot be saved
        :return:

        """
        xml_text = """<network>
    <name>{}</name>"
    <network name='{}' stp='off' delay='0'/>
    <mac address='{}'/>
</network>
""".format(self.net_name, self.name, self.mac_addr)

        with open(xml_file_path, 'w') as xml_file:
            xml_file.write(xml_text)

    def __del__(self):
        self.cleanup()


class Topology(object):

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.nodes = {}  # name : VM
        self.network = None
        self._start_virtual_net()

    def create_vm(self, vmdk_path, name=None, start=True,
                  _vm_class=VirtMachine):
        """Create virtual machine and add it to virtual network.

        :param vmdk_path: absolute path to VM image
        :param name: VM name (used by virsh)
        :param bool start: Whether VM should be also started or not. If this is
         set to False, then it's needed to start it manually.
        :param _vm_class: Class used to instantiated objects representing VMs.
        :return: name of created VM

        """
        if None is _vm_class:
            raise AttributeError("VM class not set")

        name = name or "OpenWrt_" + self._generate_random_name()
        mac_addresses = (self._generate_random_mac(),
                         self._generate_random_mac())
        self.logger.info("Creating VM[%s], path[%s]", name, vmdk_path)
        vm = _vm_class(name, vmdk_path, *mac_addresses)
        self.nodes[name] = vm
        if start:
            self.start_vm(name)
        return name

    def _start_virtual_net(self):
        # Start virtual network
        if self.network is None:
            net_name = 'virbr1'
            self.logger.info("Creating virtual network[%s]", net_name)
            self.network = VirtBridge(net_name, self._generate_random_mac())

    def start_vm(self, name, setup=True, wait_for_boot=True,
                 max_boot_time=VirtMachine.MAX_BOOT_TIME):
        """Start already created VM.

        :param name: Name of VM to start (returned by create_vm)
        :param setup: To create VM some files need to be prepared
         (copy & convert image, generate VM configuration). This needs to be done
         only once for each VM.
        :param wait_for_boot: Block until VM (SSH connection) is ready
        :param max_boot_time: Maximum time in sec to wait until machine is ready
        :return:

        """
        if name not in self.nodes:
            self.logger.error("VM does not exist")
            return
        vm = self.nodes[name]
        if vm.state != VMState.Stopped:
            self.logger.error("VM cannot be started - wrong state")
            return
        if self.network.state == VMState.Stopped:
            self.logger.info("Starting virtual network")
            self.network.start()
        self.logger.info("Starting VM[%s]", name)
        vm.start(setup)
        if wait_for_boot:
            self._wait_for_boot([name], max_boot_time)

    def start_and_wait_for_all(self, max_boot_time=VirtMachine.MAX_BOOT_TIME):
        """Start all nodes in topology.

        :param max_boot_time: Maximum time in seconds to wait until
         topology is ready
        :raise RuntimeError: if some VM cannot be started in specified time
        :return:

        """
        for name in self.nodes:
            self.start_vm(name, wait_for_boot=False)
        self._wait_for_boot(self.nodes.keys(), max_boot_time)

    def stop_vm(self, name):
        """Stop VM.

        :param name: Name of VM to stop
        :return:

        """
        if name not in self.nodes:
            self.logger.error("VM does not exist")
            return
        vm = self.nodes[name]
        if vm.state == VMState.Stopped:
            self.logger.warn("VM already stopped")
            return
        vm.stop()
        if all(node.state == VMState.Stopped for node in self.nodes.values()):
            self.network.stop()

    def stop_all(self):
        """Stop all started VMs + network.

        :return:

        """
        for name in self.nodes:
            self.stop_vm(name)
        if self.network is not None:
            self.network.stop()

    def stop_all_force(self):
        """Stop all VMs and networks found in virsh.

        :return:

        """
        self._kill_everything()
        # Update state for all elements
        if self.network is not None:
            self.network.state = VMState.Stopped
        for node in self.nodes.values():
            node.state = VMState.Stopped

    @staticmethod
    def _kill_everything():
        try:
            vm_names = Topology._get_vm_list_force()
            # Stop all machines
            for name in vm_names:
                subprocess.check_call("virsh destroy {}".format(name),
                                      shell=True)
            # Stop all virtual networks
            net_names = Topology._get_net_list_force()
            for name in net_names:
                subprocess.check_call("virsh net-destroy {}".format(name),
                                      shell=True)
        except (subprocess.CalledProcessError, OSError) as exception:
            Topology.logger.error(
                "Failed to stop element: %s", exception.message)
            return

    def cleanup(self):
        """Stop all VMs and virtual networks and remove all created files.

        :return:

        """
        self.logger.info("Removing files created for VMs")
        for node in self.nodes.values():
            node.cleanup()
        self.nodes.clear()
        if self.network is not None:
            self.network.cleanup()
            self.network = None

    @staticmethod
    def _generate_random_name(length=8):
        return str(uuid4())[:length]

    @staticmethod
    def _generate_random_mac():
        mac_str_length = 12
        while True:
            mac_str = str(uuid4()).translate(None, '-')[:mac_str_length]
            # Check if MAC address is not from reserved range
            if mac_str[:2].lower() == 'fe':
                continue
            # Check if generated MAC address is not multicast
            if not int(mac_str[1], 16) % 2:
                break
        result = ''
        for i in range(0, mac_str_length, 2):
            result += ':' + mac_str[i:i + 2]
        return result[1:]

    @staticmethod
    def _get_vm_list_force():
        try:
            # Skip virsh list header (2 lines)
            vm_names = subprocess.check_output(
                "virsh list | awk 'NR > 2 {print $2}'", shell=True).split()
        except subprocess.CalledProcessError as exception:
            Topology.logger.error(
                "Failed to get list of VMs: %s", exception.message)
            return []
        return vm_names

    @staticmethod
    def _get_net_list_force():
        try:
            # Skip virsh net-list header (2 lines) + default network
            # default should be first - default < OpenWRT_net_*
            net_names = subprocess.check_output(
                "virsh net-list | awk 'NR > 3 {print $1}'", shell=True).split()
        except subprocess.CalledProcessError as exception:
            Topology.logger.error("Failed to get list of virtual networks: %s",
                                  exception.message)
            return []
        return net_names

    def _wait_for_boot(self, vm_names, max_boot_time):
        """Wait for one or more VMs to boot.

        :param vm_names: list of VM names
        :param max_boot_time: maximum time to wait
        :return:

        """
        self.logger.info("Waiting for machines to boot up")
        vm_remaining = vm_names[:]
        print vm_remaining
        for _ in range(max_boot_time):
            for name in vm_remaining[:]:
                if name not in self.nodes:
                    vm_remaining.remove(name)
                    self.logger.warn("VM doest not exist, skipping")
                    continue
                node = self.nodes[name]
                if node.state == VMState.Stopped:
                    self.logger.warn("VM is Stopped")
                    raise RuntimeError("Machine '%s' is not booting" % name)
                elif node.is_ready():
                    vm_remaining.remove(name)
            time.sleep(1)
            if len(vm_remaining) == 0:
                return
        raise RuntimeError("Failed to boot in %d seconds" % max_boot_time)


if __name__ == '__main__':
    # TODO
    pass
