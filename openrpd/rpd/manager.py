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

import time
import os
import zmq
# Duplicate glibc import added to fix issues with old libc (signalfd)
import glibc
from signal import SIGTERM, SIGINT, SIGQUIT
from subprocess import call, Popen, check_output, CalledProcessError
from datetime import datetime
from fysom import Fysom
from glibc import (
    SIG_BLOCK, SIG_UNBLOCK, sigset_t, signalfd_siginfo, sigemptyset, sigaddset,
    sigprocmask)
from google.protobuf.message import DecodeError
from collections import Iterable

from rpd.dispatcher.dispatcher import Dispatcher
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.confdb.rpd_db import RPD_DB
from rpd.confdb.cfg_db_adapter import CfgDbAdapter
from rpd.gpb.dhcp_pb2 import t_DhcpMessage, t_DhcpData
from rpd.gpb.tpc_pb2 import t_TpcMessage
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.gpb.example_pb2 import t_ExampleMessage
from rpd.common.utils import Convert, SysTools
from rpd.gpb.cfg_pb2 import config


class ProcessInfo(object):
    # Lifetime processes are periodically checked and respawned
    # in case of failure
    PERIODIC_CHECK_TIMEOUT = 5  # seconds
    # Dispatcher instance. Used for managing events on sockets and timers.
    # Must be set before starting first process.
    dispatcher = None

    __metaclass__ = AddLoggerToClass

    def __init__(self, command_with_args, ipc_addr, exec_timeout=0,
                 timeout_cb=None):
        """Store process info, process must be explicitly started using
        provided method.

        :param command_with_args: Command and args as a list of strings.
         For example: ["ls", "-l"] to run ls command with argument "-l".
        :type command_with_args: list(string)
        :param string ipc_addr: Combination of protocol and address in format
         used by ZeroMQ. Tested only with "ipc://" protocol (Unix domain socket).
         For example:
           * "ipc:///tmp/dhcp"           -> absolute path
           * "ipc://test"                -> relative path
           * "tcp://*:9999"              -> tcp with wildcard
         More info: http://api.zeromq.org/2-1:zmq-bind
        :param int exec_timeout: Maximum number of seconds that a process is
         allowed to run before being automatically terminated. Zero to do not
         start execution timer - useful for lifetime processes. It's just safety
         catch for cases, when process "forgets" to inform manager about its
         termination - like process crash, stuck in a loop, ... .
        :param timeout_cb: Callback to be called if process does not respond
         in specified time (exec_timeout). Not applicable for lifetime
         processes. Process cleanup should be called from this callback at least
         to kill still running process.
        :type timeout_cb: callable
        :return:

        """
        if None in [command_with_args, ipc_addr]:
            raise TypeError("Invalid arguments provided")
        if not isinstance(command_with_args, Iterable):
            raise TypeError("Command must be specified as cmd + list of args")
        if 0 != exec_timeout and timeout_cb is None:
            raise AttributeError("Timeout callback must be specified")

        self.command_with_args = command_with_args
        self.ipc_sock_addr = ipc_addr
        self.ipc_sock = None
        self.ipc_msg_cb = None
        self.process = None
        self.exec_timer = None
        self.exec_timeout = exec_timeout
        self.timeout_cb = timeout_cb

    def _setup_zeromq_ipc(self, ipc_cb, ipc_sock=None, sock_type=zmq.PULL):
        if ipc_sock is None:
            ctx = zmq.Context.instance()
            self.ipc_sock = ctx.socket(sock_type)
            self.ipc_sock.bind(self.ipc_sock_addr)
            self.dispatcher.fd_register(self.ipc_sock.getsockopt(zmq.FD),
                                        self.dispatcher.EV_FD_IN,
                                        self._ipc_msg_cb)
            self.ipc_msg_cb = ipc_cb
        else:
            self.ipc_sock = ipc_sock
            # Assuming that socket is already register in dispatcher
        if self.exec_timeout != 0:
            self.exec_timer = self.dispatcher.timer_register(self.exec_timeout,
                                                             self._timeout_cb)

    def start(self, ipc_cb, args_to_append=None, ipc_sock=None,
              sock_type=zmq.PULL):
        """Start process specified by command, arguments from constructor and
        "runtime" arguments specified as args_to_append.

        :param ipc_cb: Callback to be called, when any message is received
         on IPC socket
        :type ipc_cb: callable
        :param args_to_append: List of arguments to be appended to command
         arguments specified in constructor. This is useful if command arguments
         are not known in time, when process class is created.
        :type args_to_append: list(string)
        :param ipc_sock: Socket for IPC communication if already exist.
         If None is provided, then new socket is created.
        :type ipc_sock: ZeroMQ socket or None
        :param sock_type: Type of socket, like zmq.PULL, ZMQ.PAIR, ZMQ.REP,...
         More info: http://zeromq.github.io/rbzmq/classes/ZMQ/Socket.html
        :return:

        """
        # if self.dispatcher is None:
        #    raise ValueError("Dispatcher instance not provided")

        if ipc_cb is not None:
            self._setup_zeromq_ipc(ipc_cb=ipc_cb,
                                   ipc_sock=ipc_sock,
                                   sock_type=sock_type)

        cmd = self.command_with_args
        if args_to_append is not None:
            cmd += args_to_append
        try:
            self.process = Popen(cmd)
        except OSError as exception:
            self.logger.error(
                "Process execution failed: %s", exception.message)

    def cleanup(self, close_ipc_sock=True):
        """Terminate process if it was started, close & unregister socket,..
        Send SIGTERM and wait for termination. In the future this can be
        optimized by moving waiting part outside of this class, so we can send
        SIGTERM to more processes and wait until all of them are terminated.

        :param bool close_ipc_sock: Close IPC socket or leave it opened
         to reuse it in other processes
        :return:

        """
        if self.ipc_sock and not self.ipc_sock.closed and close_ipc_sock:
            self.dispatcher.fd_unregister(self.ipc_sock.getsockopt(zmq.FD))
            self.ipc_sock.close()
            self.ipc_sock = None
        if self.exec_timer is not None:
            self.dispatcher.timer_unregister(self.exec_timer)
            self.exec_timer = None
        if self.process is not None:
            self.process.terminate()
            while self.process.poll() is None:
                time.sleep(.5)
            self.process = None

    def is_running(self):
        """Check if process is running.

        :return:
        :rtype: bool

        """
        if self.process is None:
            return False
        return self.process.poll() is None

    def _timeout_cb(self, _):
        self.logger.warn(
            "%s - execution timer expired", self.command_with_args[0])
        if self.timeout_cb is not None:
            self.timeout_cb()
        self.exec_timer = None

    def _ipc_msg_cb(self, fd, eventmask):
        del eventmask
        if self.ipc_sock is None:
            self.logger.warn("Message received on closed socket")
            return
        try:
            # socket can be closed in callback, must check if it is still valid
            while self.ipc_sock and not self.ipc_sock.closed and \
                    (self.ipc_sock.getsockopt(zmq.EVENTS) and zmq.POLLIN):
                msg = self.ipc_sock.recv(flags=zmq.NOBLOCK)
                self.logger.debug("IPC message from fd [%d] received, len[%d]",
                                  fd, len(msg))
                if len(msg) > 0:
                    self.ipc_msg_cb(msg)
        except zmq.Again:
            # Ignore ... retry handled by dispatcher
            return
            # All other exceptions are considered as fatal, handled in main


class Manager(object):
    INTF = "cmc_eth0"
    DHCP_SOCK_ADDRESS = 'ipc:///tmp/zmq-dhcp.ipc'
    TPC_SOCK_ADDRESS = 'ipc:///tmp/zmq-tpc.ipc'
    RCP_SOCK_ADDRESS = 'ipc:///tmp/zmq-rcp.ipc'
    HAL_SOCK_ADDRESS = 'ipc:///tmp/zmq-hal.ipc'
    EXAMPLE_PROC_SOCK_ADDRESS = 'ipc:///tmp/zmq-example.ipc'
    IF_UP_TIMEOUT = 60
    # If process should respond in exponential backoff timer, this is safety
    # catch for cases, when something goes wrong
    BACKOFF_TIMEOUT = 600

    dhcp_data_path = ['oper', 'DhcpData']
    hw_version_path = ['oper', 'HwVersion']
    hw_version = "OPENWRT v1"

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.dhcpv4_process = None
        self.dhcpv6_process = None
        self.sfd_stream = None
        self.db = RPD_DB()
        self.db_adapter = CfgDbAdapter(self.db)
        self.dhcp_data = t_DhcpData()
        self.disp = Dispatcher()
        self.signal_mask = self.create_signal_mask()
        self.dhcp_sock = None
        self.dhcp_timer = None
        self.processes = {}

        ProcessInfo.dispatcher = self.disp
        self.processes['dhcpv6'] = ProcessInfo(
            ["odhcp6c",                         # Args - start
             "-s", "/lib/netifd/dhcpv6.script",
             "-P", "0",
             # Request IPv6 Prefix = auto
             "-t", "256",
             # Random backoff <1, 256>
             "-v",  # Verbose
             "-I", self.DHCP_SOCK_ADDRESS],     # Args - end
            self.DHCP_SOCK_ADDRESS,             # IPC address
            self.BACKOFF_TIMEOUT,               # Timeout in seconds
            self._dhcp_no_lease                 # Timeout callback
        )
        self.processes['dhcpv4'] = ProcessInfo(
            ["udhcpc",                          # Args - start
                "-p",  # Create PID file
                "/var/run/udhcpc-" + self.INTF + ".pid",
                "-f",
                "-t", "8",  # Random backoff <1, 256>
                "-i", self.INTF,
                "-C",  # Don't send MAC address as client-id
                "-B",  # Enable broadcast
                "-S",  # Enable logging to syslog
                "-n",  # Exit if lease is not obtained
                "-I", self.DHCP_SOCK_ADDRESS],     # Args - end
            self.DHCP_SOCK_ADDRESS,             # IPC address
            self.BACKOFF_TIMEOUT,               # Timeout in seconds
            self._dhcp_no_lease                 # Timeout callback
        )
        self.processes['rcp'] = ProcessInfo(
            ["python",  # Args - start
             "-m", "rpd.rcp.rcp_process",
             "--ipc-address",
             self.RCP_SOCK_ADDRESS],  # Args - end
            self.RCP_SOCK_ADDRESS  # IPC address
        )

        confFile = '/etc/config/hal.conf'
        self.processes['hal'] = ProcessInfo(
            ("python -m rpd.hal.src.HalMain --conf=" + confFile).split(
                " "),
            ""
        )
        self.processes['tpc'] = ProcessInfo(
            ["python",  # Args - start
             "-m", "rpd.tpc",
             "--ipc-address",
             self.TPC_SOCK_ADDRESS],  # Args - end
            self.TPC_SOCK_ADDRESS,  # IPC address
            self.BACKOFF_TIMEOUT,  # Timeout in seconds
            self.reboot  # Timeout callback
        )
        self.processes['example'] = ProcessInfo(
            ["python",                          # Args - start
                "-m", "rpd.example",
                "--ipc-address",
                self.EXAMPLE_PROC_SOCK_ADDRESS],   # Args - end
            self.EXAMPLE_PROC_SOCK_ADDRESS,     # IPC address
            60,                                 # Timeout in seconds
            self.reboot                         # Timeout callback
        )
        self.processes['example'].start(self.example_msg_cb)
        # Source of subTLV codes - section 6.4.1 of
        # http://www.cablelabs.com/wp-content/uploads/specdocs/CM-SP-R-PHY-I01_150615.pdf
        rpd_ident = ['cfg', 'RpdCapabilities', 'RpdIdentification']

        self.dhcp_args_mapping = {
            '0x02': rpd_ident + ['DeviceDescription'],
            '0x04': rpd_ident + ['SerialNumber'],
            '0x05': Manager.hw_version_path,
            '0x06': rpd_ident + ['CurrentSwVersion'],
            '0x07': rpd_ident + ['BootRomVersion'],
            '0x08': "".join(SysTools.get_mac_address(self.INTF).
                            split(':')[0:3]),  # vendor ID
            '0x09': rpd_ident + ['ModelNumber'],
            '0x0A': rpd_ident + ['VendorName']}

        # Fill device information to DB, if not loaded
        mac_addr_str = rpd_ident + ['DeviceMacAddress']
        if self.db_adapter.get_leaf(mac_addr_str) is None:
            # TODO negative case handling
            self.db_adapter.set_leaf(mac_addr_str,
                                     SysTools.get_mac_address(self.INTF), True)

        hostname_str = rpd_ident + ['DeviceAlias']
        if self.db_adapter.get_leaf(hostname_str) is None:
            # TODO negative case handling
            self.db_adapter.set_leaf(hostname_str,
                                     SysTools.get_host_name(), True)

        # TODO get from HW
        if self.db_adapter.get_leaf(Manager.hw_version_path) is None:
            # TODO negative case handling
            self.db_adapter.set_leaf(Manager.hw_version_path,
                                     Manager.hw_version, True)

        self.fsm = Fysom({
            'initial': {'state': 'init'},
            'events': [
                {'name': 'init_done',
                 'src': 'init',
                 'dst': 'if_up_waiting'},
                {'name': 'if_is_up',
                 'src': 'if_up_waiting',
                 'dst': 'dhcpv6_waiting'},
                {'name': 'dhcpv6_failed',
                 'src': 'dhcpv6_waiting',
                 'dst': 'dhcpv4_waiting'},
                {'name': 'dhcp_ack',
                 'src': ['dhcpv6_waiting', 'dhcpv4_waiting', 'time_waiting',
                         'log_waiting', 'gcp_started'],
                 'dst': 'time_waiting'},
                {'name': 'time_cfged',
                 'src': 'time_waiting',
                 'dst': 'log_waiting'},
                {'name': 'log_done',
                 'src': 'log_waiting',
                 'dst': 'gcp_started'},
                {'name': 'fatal_failure',
                 'src': ['if_up_waiting', 'dhcpv6_waiting', 'dhcpv4_waiting',
                         'time_waiting', 'gcp_started'],
                 'dst': 'reboot'}
            ],
            'callbacks': {
                'onchangestate': self._onchangestate,
                'onif_is_up': self._on_iface_is_up,
                'ondhcp_ack': self._ondhcp_ack,
                'ontime_cfged': self._ontime_cfged,
                'onlog_done': self._onlog_done,
                'onfatal_failure': self.reboot,
            }
        })

    def delete_dhcp_data(self):
        """Delete DHCP data structure from DB and also clear cached copy of it.

        :return:

        """
        # TODO negative case handling
        self.db_adapter.del_leaf(Manager.dhcp_data_path)

    def store_dhcp_data(self):
        """Save updated cached copy of DHCP data to DB. This must be called
        after each set operation to this cached structure (to keep it
        synchronized).

        :return:

        """
        # TODO negative case handling - clear self.DhcpData
        self.db_adapter.set_leaf(Manager.dhcp_data_path, self.dhcp_data, True)

    def _dhcp_timeout_cb(self, _):
        """DHCP process haven't responded in limited time (backoff timer +
        extra time), so probably something wrong happened (DHCP process
        crashed, was killed, stuck in a loop, ...)

        :return:

        """
        self.logger.warn("DHCP timer expired")
        self._dhcp_no_lease()

    def _dhcp_data_ready(self):
        """Received new DHCP data, do necessary cleanup if needed
        (start/update) (old GCP sessions must be closed). Keep remote logging
        enabled, so we don't loose syslog messages in case of DHCP update.

        :return:

        """
        if not self.fsm.can('dhcp_ack'):
            raise ValueError("Wrong state '%s' for dhcp_ack event",
                             self.fsm.current)

        self.fsm.dhcp_ack()

    def _dhcp_no_lease(self):
        """DHCP client failed to get required information (backoff timer
        increased to maximum value without success)

        - If DHCPv6 failed -> try DHCPv4
        - If DHCPv4 failed -> reboot

        :return:

        """
        dhcpv6_proc = self.processes['dhcpv6']
        dhcpv4_proc = self.processes['dhcpv4']

        if dhcpv6_proc.process is not None:
            # Kill DHCPv6 process if it still running, cleanup all related
            # stuff, but keep ipc_sock - it will be reused for dhcpv4
            dhcpv6_proc.cleanup(close_ipc_sock=False)
            dhcpv6_proc.process = None

            if not self.fsm.can('dhcpv6_failed'):
                raise ValueError("Wrong state '%s' for dhcpv6_failed event",
                                 self.fsm.current)
            self.fsm.dhcpv6_failed()
            # Prepare "runtime" args
            args = []
            for code, attr in self.dhcp_args_mapping.iteritems():
                if isinstance(attr, basestring):
                    attr_val = attr
                else:
                    attr_val = self.db_adapter.get_leaf(attr)
                if attr_val is None or not isinstance(attr_val, basestring):
                    self.logger.warning(
                        "Attribute: %s not set in DB, ignoring ", attr)
                    continue
                # append args in format: -x 0x0A:value
                args.extend(['-c', '{}:{}'.format(code, attr_val)])
            self.logger.info("Starting DHCPv4 client ...")
            dhcpv4_proc.start(self.dhcp_msg_cb, args, dhcpv6_proc.ipc_sock)
        elif dhcpv4_proc.process is not None:
            dhcpv4_proc.cleanup()
            dhcpv4_proc.process = None
            self.logger.error("Both DHCPv6 & DHCPv4 failed - exiting ...")
            self.fsm.fatal_failure()
        else:
            raise ValueError("Received unexpected DHCP failed message")

    def _cleanup(self):
        """Cleanup method, this should be used only in scenario, when Manager
        is killed directly.

        :return:

        """
        for process in self.processes.values():
            process.cleanup()

        if self.sfd_stream is not None:
            self.sfd_stream.close()

        self.configure_remote_logging(None)
        exit(0)

    def testing_cleanup(self):
        """Cleanup method for testing purposes."""
        for process in self.processes.values():
            process.cleanup()

        if self.sfd_stream is not None:
            self.sfd_stream.close()
        # let the cleanup finish
        time.sleep(2)

    def fd_event_handler(self, signal_fd, eventmask):
        """Callback called by dispatcher when any signal is received on
        signalfd Reads signal info from fd and calls applicable signal handler.

        :return:

        """
        del eventmask
        siginfo = signalfd_siginfo()
        if self.sfd_stream is None:
            try:
                self.sfd_stream = os.fdopen(signal_fd, 'rb', 0)
            except IOError, ex:
                self.logger.error("Failed to open signal fd - %s",
                                  os.strerror(ex.errno))
                self._cleanup()
                return
        self.sfd_stream.readinto(siginfo)
        self._signal_handler(siginfo.ssi_signo, None)

    def _signal_handler(self, signum, frame):
        """Handles signals send from child processes or user.

        SIGTERM, SIGQUIT, SIGINT - cleanup & exit
        :return:

        """
        del frame
        if signum in [SIGQUIT, SIGTERM, SIGINT]:
            self.logger.debug("Exit signal received")
            self._cleanup()
        else:
            self.logger.error("Unexpected signal received [%d]", signum)

    def dhcp_msg_cb(self, ipc_msg):
        try:
            # Find out from which DHCP process is running (who sent it)
            for proc_name in ['dhcpv6', 'dhcpv4']:
                dhcp_proc = self.processes.get(proc_name)
                if dhcp_proc and dhcp_proc.is_running():
                    break
            else:
                self.logger.error(
                    "Received DHCP message, but no DHCP is running")
                return
            # Response from DHCP received, we can stop execution timer and
            # change process to lifetime. If it is DHCP update, then timer was
            # already stopped
            if dhcp_proc.exec_timer:
                self.disp.timer_unregister(dhcp_proc.exec_timer)
                dhcp_proc.exec_timer = None
                dhcp_proc.exec_timeout = 0  # 0 = lifetime

            dhcp_msg = t_DhcpMessage()
            dhcp_msg.ParseFromString(ipc_msg)
            self.logger.debug("DHCP status received: %s",
                              dhcp_msg.t_Status.Name(dhcp_msg.Status))
            if dhcp_msg.Status == dhcp_msg.UPDATED:
                self.dhcp_data = dhcp_msg.DHCPData
                self._dhcp_data_ready()
            elif dhcp_msg.Status == dhcp_msg.FAILED:
                self._dhcp_no_lease()
            else:
                self.logger.error("Unexpected status received from DHCP")
                return
        except DecodeError, ex:
            self.logger.error("Failed to decode IPC message: %s", ex.message)
            return

    def send_msg_to_rcp(self, ipc_msg):
        """Send IPC message to RCP process.

        :param ipc_msg: GPB message to be sent
        :type ipc_msg: t_RcpMessage
        :return:

        """
        if not isinstance(ipc_msg, t_RcpMessage) or \
                not ipc_msg.IsInitialized():
            self.logger.error('Invalid IPC message provided')
            return
        msg_str = ipc_msg.SerializeToString()
        if 0 == len(msg_str):
            self.logger.warn('Empty IPC msg, dropping ...')
            return
        sock = self.processes['rcp'].ipc_sock
        if sock is None or sock.closed:
            self.logger.warn("Trying to send message to closed socket")
            return
        sock.send(msg_str)
        self.logger.info("Data sent to RCP, length[%d]", len(msg_str))

    def rcp_msg_cb(self, ipc_msg):
        try:
            # Get values encoded in GPB message
            rcp_msg = t_RcpMessage()
            rcp_msg.ParseFromString(ipc_msg)
            self.logger.info("RCP message type: %s",
                             rcp_msg.t_RcpMessageType.Name(rcp_msg.RcpMessageType))

            if rcp_msg.RcpMessageType == rcp_msg.RPD_CONFIGURATION:
                if not rcp_msg.HasField("RpdDataMessage") or \
                        not rcp_msg.RpdDataMessage.IsInitialized():
                    self.logger.error(
                        "Non initialized RpdData message received")
                    rcp_msg.RcpDataResult =\
                        t_RcpMessage.RCP_RESULT_GENERAL_ERROR
                    self.send_msg_to_rcp(rcp_msg)
                    return

                operation = rcp_msg.RpdDataMessage.RpdDataOperation
                if operation == t_RpdDataMessage.RPD_CFG_READ:
                    # read data from DB and respond directly
                    self.logger.debug("Handling config operation READ")
                    self.db_adapter.prepare_data(
                        cfg_data=rcp_msg.RpdDataMessage)
                    result = self.db_adapter.process_all()
                    if None is not result:
                        if not isinstance(result, config):
                            raise TypeError("Invalid data provided by DB"
                                            "adapter")
                        rcp_msg.RpdDataMessage.RpdData.CopyFrom(result)
                    else:
                        self.logger.debug("Read result with no data")
                    rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
                    self.send_msg_to_rcp(rcp_msg)
                elif operation == t_RpdDataMessage.RPD_CFG_WRITE or \
                        operation == t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE or \
                        operation == t_RpdDataMessage.RPD_CFG_DELETE:
                    self.logger.debug("Handling config operation %s op=%d",
                                      ("WR or AW" if
                                       operation in [t_RpdDataMessage.RPD_CFG_WRITE,
                                                     t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE]
                                       else "DEL"), operation)
                    # send to DB
                    self.db_adapter.prepare_data(
                        cfg_data=rcp_msg.RpdDataMessage)
                    result = self.db_adapter.process_all()
                    if True is not result:
                        if operation == t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE:
                            self.logger.error(
                                "Failed to process config operation AW ")
                        else:
                            self.logger.error(
                                "Failed to process config operation %s",
                                ("WR" if
                                 operation == t_RpdDataMessage.RPD_CFG_WRITE
                                 else "DEL"))
                        rcp_msg.RcpDataResult =\
                            t_RcpMessage.RCP_RESULT_GENERAL_ERROR
                        self.send_msg_to_rcp(rcp_msg)
                        return

                    # if there is not HAL process registered, then reply to
                    # the RCP process right now
                    if not self.processes['hal'].is_running():
                        self.logger.warning("No HAL process running, sending RSP IPC"
                                            "message to RCP with OK result.")
                        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
                        self.send_msg_to_rcp(rcp_msg)
                        return

                else:
                    self.logger.error(
                        "Invalid config operation passed from RCP")
                    rcp_msg.RcpDataResult =\
                        t_RcpMessage.RCP_RESULT_GENERAL_ERROR
                    self.send_msg_to_rcp(rcp_msg)
                    return

            elif rcp_msg.RcpMessageType == rcp_msg.RPD_REBOOT:
                self.logger.debug("Received RPD Reboot from RCP")
                self.reboot()

            elif rcp_msg.RcpMessageType == rcp_msg.REDIRECT_NOTIFIFACTION:
                ret = self.db_adapter.set_leaf(
                    ["oper", "RedirectCCAPAddresses"],
                    rcp_msg.RedirectCCAPAddresses)
                if ret:
                    rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
                    self.send_msg_to_rcp(rcp_msg)
                else:
                    self.logger.error("Failed to write redirect IP addresses into DB, "
                                      "addresses: %s", rcp_msg.RedirectCCAPAddresses)
                    rcp_msg.RcpDataResult =\
                        t_RcpMessage.RCP_RESULT_GENERAL_ERROR
                    self.send_msg_to_rcp(rcp_msg)

            else:
                self.logger.error("Unexpected IPC message received from RCP: type: "
                                  "%s(%u)",
                                  rcp_msg.t_RcpMessageType.Name(
                                      rcp_msg.RcpMessageType),
                                  rcp_msg.RcpMessageType)

        except DecodeError as ex:
            self.logger.error(
                "Failed to decode RCP IPC message: %s", ex.message)
            return

    def tpc_msg_cb(self, ipc_msg):
        try:
            tpc_msg = t_TpcMessage()
            tpc_msg.ParseFromString(ipc_msg)
            self.logger.debug(
                "TPC status: %s", tpc_msg.t_Status.Name(tpc_msg.Status))
            if tpc_msg.Status == tpc_msg.SUCCESS:
                self.logger.info("Valid timestamp received from TPC")
                if tpc_msg.HasField('Timestamp'):
                    self.set_system_time(tpc_msg.Timestamp)
                    self.fsm.time_cfged()
                    self.processes['tpc'].cleanup()
                else:
                    self.logger.error(
                        "Mandatory timestamp missing, ignoring message")
            elif tpc_msg.Status == tpc_msg.FIRST_ATTEMPT_FAILED:
                self.logger.info("First attempt to get time failed - "
                                 "resetting time to 1.1.1970")
                self.set_system_time(0)
            elif tpc_msg.Status == tpc_msg.ALL_ATTEMPTS_FAILED:
                # don't have correct time -> restart device
                self.logger.error("Failed to get time of day - rebooting")
                self.reboot()
            else:
                self.logger.error("Unexpected status received from TPC")
                return
        except DecodeError, ex:
            self.logger.error("Failed to decode IPC message: %s", ex.message)
            return

    def example_msg_cb(self, ipc_msg):
        # Valid response received, we can cleanup all related stuff
        # (stop execution timer, close IPC socket, ...)
        self.processes['example'].cleanup()
        try:
            # Get values encoded in GPB message
            example_msg = t_ExampleMessage()
            example_msg.ParseFromString(ipc_msg)
            self.logger.debug("Message received: %s", example_msg.Message)
        except DecodeError as ex:
            self.logger.error("Failed to decode IPC message: %s", ex.message)
            return

    def start(self):
        """Start RPD initialization process (Section 6.1 or R-PHY
        specification) Whole process is described by state machine (constructor
        of this class)

        :return:

        """
        # Get fd for terminate signals
        sfd = glibc.signalfd(-1, self.signal_mask, 0)

        # Always reset after boot
        os.environ['PC_REBOOT_HOLD'] = "FALSE"

        # Register manager's signalfd to dispatcher
        self.disp.fd_register(sfd, self.disp.EV_FD_IN, self.fd_event_handler)

        # Init RCP
        self.processes['rcp'].start(ipc_cb=self.rcp_msg_cb, sock_type=zmq.PAIR)
        call(["ifconfig", self.INTF, "up"])
        self.fsm.init_done()
        # FIXME:  delete below codes to skip dhcp procedure
        # Wait up to IF_UP_TIMEOUT for network interface to go up
        # if not self.wait_for_eth_up(Manager.IF_UP_TIMEOUT):
        #    self.fsm.fatal_failure()
        # self.fsm.if_is_up()
        self._onlog_done('')

    @staticmethod
    def configure_remote_logging(address):
        """Set address of remote log server,

        - For now only one log-server is supported (UDP is used, so we don't
          have dependable confirmation, whether logging server is really there)

        :param address: Syslog IP address (v4 or v6) or None to disable remote
                        logging feature
        :type address: string or None
        :return:

        """
        if not (None is address or Convert.is_valid_ip_address(address)):
            Manager.logger.warning(
                "Invalid IP address provided for remote logging: %s",
                address)
            return

        try:
            call(["uci", "set",
                  "system.@system[0].log_ip=" + (address or "")])
            call(["uci", "commit", "system"])
            call(["/etc/init.d/log", "reload"])
        except (OSError, ValueError):
            Manager.logger.error("Failed remote logging configuration")

    @staticmethod
    def create_signal_mask():
        """Create signal mask for blocking/unblocking signals.

        :return:

        """
        mask = sigset_t()
        sigemptyset(mask)
        for sig in [SIGINT, SIGQUIT, SIGTERM]:
            sigaddset(mask, sig)
        return mask

    @staticmethod
    def wait_for_eth_up(timeout_secs):
        """Wait until interface goes up, documentation:
        https://www.kernel.org/doc/Documentation/networking/operstates.txt.

        :param timeout_secs: Maximum time to wait for interface to go up
        :return: True if interface goes up until timer expires
        :rtype: bool

        """
        Manager.logger.info("Waiting for interface to go up")
        for _ in xrange(timeout_secs):
            try:
                # Expected content is one of these values:
                # - "up" -> interface is up, we are done
                # - "down", "dormant", "lowerlayerdown" -> not ready,
                #                                          retry after 1 sec
                # - "unknown",... -> neither driver nor userspace has set
                #                    operational state, check carrier state
                result = check_output(["cat", "/sys/class/net/" + Manager.INTF +
                                       "/operstate"]).strip()
                if "up" == result:
                    return True
                elif result not in ["down", "dormant", "lowerlayerdown"]:
                    result = check_output(["cat", "/sys/class/net/" +
                                           Manager.INTF + "/carrier"]).strip()
                    if "1" == result:
                        return True
            except (CalledProcessError, OSError):
                pass
            time.sleep(1)
        return False

    def set_system_time(self, timestamp):
        """Set system time to provided timestamp.

        :param timestamp: POSIX timestamp
        :type timestamp: float
        :return:

        """
        self.disp.update_all_timers(timestamp - time.time())
        with open(os.devnull, "w") as dev_null:
            self.logger.info("Setting system time to %s",
                             datetime.utcfromtimestamp(timestamp).strftime(
                                 '%Y %b %d %H:%M:%S'))
            try:
                call(["date", "+%s", "-s", "@" + str(timestamp)],
                     stdout=dev_null)
            except OSError:
                self.logger.exception("Failed to set system time")

    def _verify_dhcp_data(self):
        """Verify data from msg sent by DHCP client. Invalid or bad formatted
        data are removed.

        :return:

        """
        for descr, value in self.dhcp_data.ListFields():
            self.logger.info("%s = %s", descr.name, str(value))
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
                self.logger.error("Unknown value found: %s", descr.name)

        self.store_dhcp_data()

    #
    # FSM Callbacks #
    #

    def _on_iface_is_up(self, event):
        """Network should be ready now, start DHCPv6 with subTLVs loaded from
        DB init file and from the system configuration files.

        :param event: unused
        :return:

        """
        del event

        # Prepare "runtime" args - read suboption values from DB and append it
        # in expected format
        args = []

        for code, attr in self.dhcp_args_mapping.iteritems():
            if isinstance(attr, basestring):
                attr_val = attr
            else:
                attr_val = self.db_adapter.get_leaf(attr)
            if attr_val is None or type(attr_val) not in [str,
                                                          basestring, unicode]:
                self.logger.debug(
                    "Attribute: %s not set in DB, ignoring ", attr)
                continue
            # append args in format: -x 0x0A:value
            args.extend(['-x', '{}:{}'.format(code, attr_val)])
        args.append(self.INTF)
        self.processes['dhcpv6'].start(self.dhcp_msg_cb, args)
        # Re-enable signal blocking, which was disabled before forking
        sigprocmask(SIG_BLOCK, self.signal_mask, None)

        self.disp.loop()

    def _ondhcp_ack(self, event):
        """DHCP data are ready, parse msg with info from DCHP client.

        (without checking if mandatory data are here - these are checked during
        initialization process) and start with next step - get & set system time

        :param event: unused
        :return:

        """
        del event

        # DHCP data updated - remove old CCAP Cores and close connections
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.REMOVE_ALL_CCAP_CORES
        self.send_msg_to_rcp(rcp_msg)
        # Clear DHCP data from DB, if there are any from previous DHCP Ack
        self.delete_dhcp_data()

        self._verify_dhcp_data()

        if len(self.dhcp_data.TimeServers) == 0:
            self.logger.error("No time servers found")
            self.fsm.fatal_failure()
            return

        is_ipv6 = Convert.is_valid_ipv6_address(self.dhcp_data.TimeServers[0])
        # Prepare TPC runtime arguments
        args = ['--ipv6'] if is_ipv6 else []
        args.extend(['--offset', str(self.dhcp_data.TimeOffset)])
        args.extend(['--servers'] +
                    [addr.encode('ascii', 'ignore')
                     for addr in self.dhcp_data.TimeServers])
        # Start TPC
        # (continue in tpc_msg_cb or timeout_cb specified in process info)
        self.processes['tpc'].start(self.tpc_msg_cb, args)

    def _ontime_cfged(self, event):
        """System time is configured, we are ready to enable remote logging. If
        no log-server was provided, just skip this step.

        :param event: unused
        :return:

        """
        del event
        if len(self.dhcp_data.LogServers) == 0:
            self.logger.warning("No log server found")
            # TODO Is log-server mandatory? Ignoring for now ...
            self.configure_remote_logging(None)
        else:
            self.configure_remote_logging(self.dhcp_data.LogServers[0])
        self.fsm.log_done()

    def _onlog_done(self, event):
        """Remote logging is enabled, let's open connections to CCAP cores and
        do all GCP/RCP related work, we cannot continue without any CCAP core
        address -> reboot.

        :param event: unused
        :return:

        """
        del event
        # FIXME: add a ccap core for cmc temperary debug
        self.dhcp_data.CCAPCores.append("127.0.0.1")
        if len(self.dhcp_data.CCAPCores) == 0:
            self.logger.error("No CCAP cores found")
            self.fsm.fatal_failure()
            return

        # Notify RCP process about new CCAP cores
        rcp_msg = t_RcpMessage()
        rcp_msg.RcpMessageType = rcp_msg.ADD_CCAP_CORES
        rcp_msg.RedirectCCAPAddresses.extend(self.dhcp_data.CCAPCores)
        self.send_msg_to_rcp(rcp_msg)

        # For now we are done, orchestrator is taking control,
        # manager will handle only DHCP updates

    @staticmethod
    def _onchangestate(event):
        """Special callback - called on every state change

        :param event: event.{fsm, src, dst, event}
        :return:
        """
        Manager.logger.info('Changing state: %s -> %s', event.src, event.dst)

    @staticmethod
    def reboot(event=None):
        """Some fatal event occurred, like:

        * no DHCP server responded
        * no Time from Time servers
        * ...

        -> we need to retry from beginning (reboot or manager restart)

        :param event: unused
        :return:

        """
        del event
        Manager.logger.critical("Rebooting in 10 seconds ...")
        time.sleep(10)
        if os.getenv("PC_REBOOT_HOLD", "false").lower() in ['true', '1']:
            # TODO: cleanup (kill running processes,..)
            Manager.logger.info("Reboot blocked by env. variable")
        else:
            if 1 == 1:
                return
            call(["reboot"])



if __name__ == "__main__":
    setup_logging("Manager", filename="manager.log")
    try:
        Manager().start()
    except Exception as ex:
        Manager.exception("Unexpected failure: %s", ex.message)
        Manager.reboot()
