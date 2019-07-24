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

import os
import subprocess
import unittest
import argparse
from rpd_service_suite.topology import VMState, Topology
from rpd.common.utils import Convert
from os import EX_OK


# TODO: change this to find image dynamically or get it from argparse
IMG_PATH = '../../../bin/x86/openwrt-x86-generic-combined-ext4.vmdk'


class TestTopology(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.geteuid() == 0:
            raise RuntimeError("Root required for virsh")
        cls.topology = Topology()

    @classmethod
    def tearDownClass(cls):
        cls.topology.cleanup()

    def tearDown(self):
        self.topology.stop_all()
        self.topology.nodes.clear()
        self.topology.network = None

    def _check_vm_in_virsh(self, name):
        subprocess.check_call("virsh list | grep {}".format(name), shell=True)

    def _check_vm_not_in_virsh(self, name):
        with self.assertRaises(subprocess.CalledProcessError):
            self._check_vm_in_virsh(name)

    def test_start_stop_one_vm(self):
        name = self.topology.create_vm(IMG_PATH)
        self.assertIsInstance(name, basestring)
        self.assertTrue(self.topology.nodes[name].state == VMState.Ready)
        # if VM is not here CalledProcessError will be raised
        self._check_vm_in_virsh(name)
        self.topology.stop_vm(name)
        self._check_vm_not_in_virsh(name)

    def test_start_one_stop_all(self):
        name = self.topology.create_vm(IMG_PATH)
        # if VM is not here CalledProcessError will be raised
        self._check_vm_in_virsh(name)
        self.topology.stop_all()
        self._check_vm_not_in_virsh(name)

    def test_reuse_vm(self):
        name = self.topology.create_vm(IMG_PATH)
        self.topology.stop_vm(name)
        self._check_vm_not_in_virsh(name)
        self.topology.start_vm(name, setup=False)
        self._check_vm_in_virsh(name)
        # will be stopped in common teardown

    def test_more_vms_with_same_image(self):
        machines = ['test', 'test2', 'test3']
        for name in machines:
            self.topology.create_vm(IMG_PATH, name=name)
        for name in machines:
            self._check_vm_in_virsh(name)
        self.topology.stop_vm(machines[1])
        for name in [machines[0], machines[2]]:
            self._check_vm_in_virsh(name)
        self._check_vm_not_in_virsh(machines[1])
        self.topology.stop_all()
        for name in machines:
            self._check_vm_not_in_virsh(name)

    def test_stop_force(self):
        machines = ['test', 'test2', 'test3']
        for name in machines:
            self.topology.create_vm(IMG_PATH, name=name)
        self.topology.stop_all_force()
        for name in machines:
            self._check_vm_not_in_virsh(name)

    def test_create_start_all(self):
        machines = ['test', 'test2', 'test3']
        for name in machines:
            self.topology.create_vm(IMG_PATH, name=name, start=False)
        self.topology.start_and_wait_for_all()
        for name in machines:
            self._check_vm_in_virsh(name)


class TestVirtualMachine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.geteuid() == 0:
            raise RuntimeError("Root required for virsh")
        cls.topology = Topology()
        cls.name = cls.topology.create_vm(IMG_PATH)
        cls.vm = cls.topology.nodes[cls.name]

    @classmethod
    def tearDownClass(cls):
        cls.topology.cleanup()

    def test_remote_cmd(self):
        # One line - stdout
        output = self.vm.run_command('echo "test"')
        self.assertEqual(output[0].strip(), 'test')
        # More lines - stdout
        output = self.vm.run_command('echo -e "test\ntest"')
        self.assertEqual(len(output), 2)
        self.assertEqual(len(output[0].strip()), 4)
        # One line - stderr
        output = self.vm.run_command('echo "test" >&2')
        # Stdout should be empty
        self.assertEqual(len(output), 0)
        # One line - stderr + non-zero rc
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.vm.run_command('file /wrong_file')
            # Check if stderr is part of exception message
            self.assertTrue('not found' in str(error.exception))

    def test_terminal(self):
        self.vm.open_terminal()
        self.assertIsNone(self.vm._term_process.poll(),
                          "Term process not running")
        import pdb
        pdb.set_trace()
        self.topology.stop_vm(self.name)

    def test_ip_change(self):
        ip_addr = "1.1.1.1"
        self.vm.change_eth1_ip_addr(ip_addr)
        ifconfig_output = self.vm.run_command("ifconfig eth1")
        for line in ifconfig_output:
            if 'inet addr:' in line:
                parsed_ip_addr = line.split(':')[1].split()[0]
                if parsed_ip_addr == ip_addr:
                    break
        else:
            self.assertTrue(False, "IP address was not configured")

    def test_get_log_dest_dir(self):
        # relative path cases

        # no dest_dir specified
        it_subdir = ".%sIT" % os.path.sep
        result = self.vm._get_log_dest_dir()
        result = os.path.normpath(result)
        # with no dest_dir specified, expected_result should be:
        # ./IT/<VM_name>
        expected_result = "%s%s%s" % (it_subdir, os.path.sep, self.name)
        expected_result = os.path.normpath(expected_result)
        self.assertEqual(result, expected_result,
                         "When no dest_dir is specified, "
                         "actual result (%s) does not match expected result (%s)" % (result, expected_result))

        # simple dest_dir specified
        subdir = "test01"
        result = self.vm._get_log_dest_dir(subdir)
        result = os.path.normpath(result)
        # with a relative dest_dir specified, expected_result should be:
        # ./IT/<subdir>/<VM_name>
        expected_result = "%s%s%s%s%s" % (it_subdir, os.path.sep, subdir, os.path.sep, self.name)
        expected_result = os.path.normpath(expected_result)
        self.assertEqual(result, expected_result,
                         "When simple dest_dir (%s) is specified, "
                         "actual result (%s) does not match expected result (%s)" % (subdir, result, expected_result))

        # nested dest_dir specified
        subdir = "test01%stest01_subdir" % os.path.sep
        result = self.vm._get_log_dest_dir(subdir)
        result = os.path.normpath(result)
        # with a relative dest_dir specified, expected_result should be:
        # ./IT/<subdir>/<VM_name>
        expected_result = "%s%s%s%s%s" % (it_subdir, os.path.sep, subdir, os.path.sep, self.name)
        expected_result = os.path.normpath(expected_result)
        self.assertEqual(result, expected_result,
                         "When nested dest_dir (%s) is specified, "
                         "actual result (%s) does not match expected result (%s)" % (subdir, result, expected_result))

        # also test an ending slash
        subdir = "%s%s" % (subdir, os.path.sep)
        result = self.vm._get_log_dest_dir(subdir)
        result = os.path.normpath(result)
        # with a relative dest_dir specified, expected_result should be:
        # ./IT/<subdir>/<VM_name>
        expected_result = "%s%s%s%s%s" % (it_subdir, os.path.sep, subdir, os.path.sep, self.name)
        expected_result = os.path.normpath(expected_result)
        self.assertEqual(result, expected_result,
                         "When dest_dir is specified with trailing separator, "
                         "actual result (%s) does not match expected result (%s)" % (result, expected_result))

        # absolute path case
        absdir = "/tmp/rpd_service_suite/test_topology"
        result = self.vm._get_log_dest_dir(absdir)
        result = os.path.normpath(result)
        # with an absolute dest_dir specified, expected_result should be:
        # /<absdir>/<VM_name>
        expected_result = "%s%s%s" % (absdir, os.path.sep, self.name)
        expected_result = os.path.normpath(expected_result)
        self.assertEqual(result, expected_result,
                         "When absolute dest_dir (%s) is specified, "
                         "actual result (%s) does not match expected result (%s)" % (absdir, result, expected_result))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rpd-image', required=True, action='append')
    parser.add_argument('--server-image')
    parser.add_argument('--server-addr', help='IP address to be used for eth1')
    parser.add_argument('--disable-terminal', action='store_true')
    parser.add_argument('--destroy-before', action='store_true',
                        help='Destroy all VMs and networks at the beginning')
    args = parser.parse_args()
    # Check arguments
    for image_path in args.rpd_image:
        if not os.path.exists(image_path):
            parser.error("RPD image file not found: {}".format(image_path))
    if args.server_image is not None:
        if not os.path.exists(args.server_image):
            parser.error("Server image file not found: {}".format(
                args.server_image))
    if args.server_addr is not None and \
            not Convert.is_valid_ip_address(args.server_addr):
        parser.error("Server IP address is not valid: {}".format(
            args.server_addr))
    # Create topology and start VMs
    topology = Topology()
    if args.destroy_before:
        topology.stop_all_force()
    if args.server_image is not None:
        topology.create_vm(args.server_image, name='server', start=False)
    for idx, image_path in enumerate(args.rpd_image):
        topology.create_vm(image_path, name='RPD' + str(idx + 1), start=False)
    topology.start_and_wait_for_all()
    # Assign server address
    if None not in (args.server_addr, args.server_image):
        topology.nodes['server'].change_eth1_ip_addr(args.server_addr)
    # Open terminals or print IP addresses
    for node in topology.nodes.values():
        if not args.disable_terminal:
            node.open_terminal()
        else:
            print "VM: '{}': '{}'".format(node.name, node.ip_addresses[0])
    print "Topology should be ready, press anything to kill it"
    raw_input()
    # Destroy topology and delete created files
    topology.cleanup()
    exit(EX_OK)


if __name__ == "__main__":
    main()
