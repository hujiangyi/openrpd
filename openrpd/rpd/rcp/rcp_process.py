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

import argparse
import logging
import signal
import sys
from os import EX_OSERR, EX_DATAERR
from socket import AF_INET, AF_INET6

import zmq
from google.protobuf.message import DecodeError

from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import Convert, SysTools
from rpd.dispatcher.dispatcher import Dispatcher, DispatcherTimeoutError
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.hal.src.HalConfigMsg import *
from rpd.provision.proto import GcpMsgType
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor, GCPSessionDescriptor
from rpd.rcp.rcp_hal import RcpHalIpc
from rpd.rcp.rcp_orchestrator import RCPSlaveOrchestrator
from rpd.common.rpd_logging import AddLoggerToClass


__all__ = ['RcpProcess']


gcp_module_map = {
    GcpMsgType.GcpTLV:
        ["ValueFormatStorage",
         "ValueFormatFlat",
         "ValueFormatGPB",
         "GCPObject",
         "MessageFields",
         "TLVData", "Message",
         "GCPPacket",
         "UCDBurstProfile",
         "DocsisMsgMacMessage",
         "RCP_TLVData",
         "RCPMessage",
         "RCPSequence",
         "RCPPacket"],

    GcpMsgType.GcpSession:
        ["GCPSession",
         "GCP_IO_CTX",
         "GCPSlaveSession",
         "GCPSessionDescriptor",
         "GCPSlaveDescriptor",
         "GCPSessionOrchestrator",
         "RCPSlaveSession",
         "gcp_sessions"],

    GcpMsgType.GcpPacketHandling:
        ["RCPPacketBuilder",
         "RCPPacketHandler",
         "RCPSlavePacketHandler",
         "RCPSlavePacketHandlerCallbackSet",
         "RCPOrchestrator",
         "RCPSlaveOrchestrator",
         "RCPSlavePacketBuildDirector",
         "RcpProcess",
         "RcpHalProcess",
         "RcpConfigFilter",
         "RcpMessageRecord",
         "RcpHalIpc",
         "RcpOverGcp",
         "rcp_orchestrator",
         "rcp_hal",
         "main"],

    GcpMsgType.GcpGDM: ["GdmMsgHandler"],

    GcpMsgType.GcpOther:
        ["Dispatcher",
         "DpTimerManager",
         "HalTransport"],

}
gcp_module_map.update({
    GcpMsgType.GcpAll: gcp_module_map[GcpMsgType.GcpOther] +
                       gcp_module_map[GcpMsgType.GcpPacketHandling] +
                       gcp_module_map[GcpMsgType.GcpSession] +
                       gcp_module_map[GcpMsgType.GcpGDM] +
                       gcp_module_map[GcpMsgType.GcpTLV]
})


class RcpProcess(object):
    __metaclass__ = AddLoggerToClass

    def __init__(self, ipc_sock_addr, dispatcher=None):
        """Prepare RCP Process object - initiate all required components, open
        socket for IPC communication, register for events on this socket.

        :param string ipc_sock_addr: Socket address for IPC communication
         to manager process
        :return:

        """
        self.dispatcher = dispatcher \
            if dispatcher is not None else Dispatcher()

        # the ipc_rsp_callback must be initialized to None before the
        # RCPSlaveOrchestrator is instantiated, because in the orchestrator's
        # constructor, there is register_ipc_msg_rx_callback() called.
        self.ipc_rsp_callback = None
        self.orchestrator = RCPSlaveOrchestrator(disp=self.dispatcher,
                                                 cfg_ipc_channel=self,
                                                 # TODO we need reboot IPC msg
                                                 reboot_cb=None)
        # reboot_cb=Manager.reboot)
        self.ipc_sock = None
        try:
            if None is not ipc_sock_addr:
                context = zmq.Context.instance()
                self.ipc_sock = context.socket(zmq.PAIR)
                self.ipc_sock.connect(ipc_sock_addr)
                self.dispatcher.fd_register(self.ipc_sock.getsockopt(zmq.FD),
                                            self.dispatcher.EV_FD_IN,
                                            self._ipc_msg_cb)
        except zmq.ZMQError:
            raise RuntimeError("Failed to open IPC socket")

        self.CliMsgsHandler = {
            GcpMsgType.ShowGcpSession: self.show_gcp_session,
            GcpMsgType.ShowGcpSessionDetail: self.show_gcp_session_detail,
            GcpMsgType.ChangeGcpLoggingLevel: self.change_gcp_logging_level,
        }

        self.cli_sock = None
        try:
            context = zmq.Context.instance()
            self.cli_sock = context.socket(zmq.REP)
            self.cli_sock.bind("ipc:///tmp/zmq-gcp.ipc")
            self.dispatcher.fd_register(self.cli_sock.getsockopt(zmq.FD),
                                        self.dispatcher.EV_FD_IN,
                                        self._cli_msg_cb)
            self.logger.info("Start Gcp Cli server")
        except zmq.ZMQError:
            raise RuntimeError("Failed to open CLI socket")

    def cleanup(self):
        if None is not self.ipc_sock:
            self.dispatcher.fd_unregister(self.ipc_sock.getsockopt(zmq.FD))
            self.ipc_sock.close()

    def send_ipc_msg(self, ipc_msg):  # pragma: no cover
        """Notify manager about progress.

        :param ipc_msg: GPB message to be sent
        :type ipc_msg: t_ExampleMessage
        :return:

        """
        if not isinstance(ipc_msg, t_RcpMessage) or \
                not ipc_msg.IsInitialized():
            self.logger.error('Invalid IPC message provided')
            exit(EX_DATAERR)
        msg_str = ipc_msg.SerializeToString()
        if 0 == len(msg_str):
            self.logger.warn('Empty IPC msg, dropping ...')
            return
        self.ipc_sock.send(msg_str)
        self.logger.info("Data sent to manager, length[%d]", len(msg_str))

    def register_ipc_msg_rx_callback(self, callback):
        """Implements method from RpcIpcContext.

        Registers a callback for results of config operations. Callback
        takes one argument which is an IPC response message.

        """
        if None is callback or not callable(callback):
            self.logger.error("Invalid callback passed")

        self.ipc_rsp_callback = callback

    def _cli_msg_cb(self, fd, eventmask):  # pragma: no cover
        del eventmask
        try:
            while self.cli_sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
                zmq_msg = self.cli_sock.recv(flags=zmq.NOBLOCK)
                self.logger.debug("GCP CLI message received, len[%d]",
                                  len(zmq_msg))
                if len(zmq_msg) > 0:
                    msg = t_CliMessage()
                    msg.ParseFromString(zmq_msg)
                    self.logger.debug("Receive an GCP CLI message:%s", msg)
                    rsp_msg = t_CliMessage()
                    rsp_msg.CliMsgType = msg.CliMsgType
                    rsp_msg.CliDataOperation = msg.CliDataOperation
                    if msg.CliMsgType in self.CliMsgsHandler:
                        handler = self.CliMsgsHandler[msg.CliMsgType]
                        ret = handler(msg, rsp_msg)

                        if ret:
                            rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_OK
                        else:
                            rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_FAIL
                    else:
                        self.logger.debug(
                            "Receive a fake CLI message:%s" % str(msg))
                        rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_NONE

                    self.cli_sock.send(rsp_msg.SerializeToString(), flags=zmq.NOBLOCK)
        except zmq.Again:
            # Ignore ... retry handled by dispatcher
            return
        except DecodeError as exception:
            self.logger.error("Malformed CLI message, dropping ...: %s",
                              exception.message)
            return

    def _ipc_msg_cb(self, fd, eventmask):  # pragma: no cover
        del eventmask
        try:
            while self.ipc_sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
                zmq_msg = self.ipc_sock.recv(flags=zmq.NOBLOCK)
                self.logger.debug("IPC message from manager received, len[%d]",
                                  len(zmq_msg))
                if len(zmq_msg) > 0:
                    msg = t_RcpMessage()
                    msg.ParseFromString(zmq_msg)
                    self.logger.info("RCP message type: %s",
                                     msg.t_RcpMessageType.Name(
                                         msg.RcpMessageType))
                    if msg.RcpMessageType == msg.ADD_CCAP_CORES:
                        self.add_ccap_cores(msg.RedirectCCAPAddresses)
                    elif msg.RcpMessageType == msg.REMOVE_ALL_CCAP_CORES:
                        self.orchestrator.remove_sessions_all()
                    elif msg.RcpMessageType == msg.RPD_CONFIGURATION:
                        # call the registered response callback
                        try:
                            self.ipc_rsp_callback(msg)
                        except Exception as ex:
                            self.logger.error(
                                "IPC RCP callback call failed: %s", ex)
                    else:
                        raise DecodeError("Unexpected message type received")
        except zmq.Again:
            # Ignore ... retry handled by dispatcher
            return
        except DecodeError as exception:
            self.logger.error("Malformed IPC message, dropping ...: %s",
                              exception.message)
            return
            # All other exceptions are considered as fatal, handled in main

    def start(self):  # pragma: no cover
        self.dispatcher.loop()

    def add_ccap_cores(self, ccap_cores, port_master=GCPSessionDescriptor.DEFAULT_PORT_MASTER):
        """Create GCP descriptors based on addresses of CCAP cores received
        from DHCP server to orchestrator.

        :param ccap_cores: list of "interface;core ip"
        :type ccap_cores: list(string)
        :return:

        """
        descriptors = []

        for core_addr in ccap_cores:
            interface, core = core_addr.split(';')
            if not Convert.is_valid_ip_address(core):
                self.logger.warn("Malformed IP address received: %s", core)
                continue

            is_ipv6 = Convert.is_valid_ipv6_address(core)
            family = (AF_INET, AF_INET6)[is_ipv6]
            addr_local = SysTools.get_ip_address(str(interface), family)
            # TODO pass also local address to use specific interface
            descriptors.append(
                GCPSlaveDescriptor(
                    core, port_master=port_master, addr_local=addr_local,
                    interface_local=interface,
                    addr_family=family))
        self.orchestrator.add_sessions(descriptors)

    def show_gcp_session(self, cmd_msg, rsp_msg):

        active_sessions = rsp_msg.CliGcp.ShowGcpSession.ActiveSessions
        for session in self.orchestrator.sessions_active_fd.itervalues():
            ss = active_sessions.add()
            ss.session = session.descr.__str__()

        principal_sessions = rsp_msg.CliGcp.ShowGcpSession.PrincipalSessions
        for session in self.orchestrator.principal:
            ss = principal_sessions.add()
            ss.session = session.descr.__str__()

        nonprincipal_sessions = rsp_msg.CliGcp.ShowGcpSession.NonPrincipalSessions
        for session in self.orchestrator.non_principals:
            ss = nonprincipal_sessions.add()
            ss.session = session.descr.__str__()

        principal_candidate_session = rsp_msg.CliGcp.ShowGcpSession.PrincipalCandidateSession
        principal_candidate_session.session = \
            'None' if self.orchestrator.principal_candidate is None else self.orchestrator.principal_candidate.descr.__str__()

        failed_sessions = rsp_msg.CliGcp.ShowGcpSession.FailedSessions
        for session in self.orchestrator.sessions_failed.itervalues():
            ss = failed_sessions.add()
            ss.session = session.descr.__str__()

        return True

    def show_gcp_session_detail(self, cmd_msg, rsp_msg):
        i = 1
        gs = rsp_msg.CliGcp.ShowGcpStats
        for active_session in self.orchestrator.sessions_active_fd.itervalues():
            ss = gs.add()
            ss.sessions.session = "Session{}: ".format(i) + active_session.descr.__str__()
            i += 1

            stats = active_session.stats
            ss.Rx = stats.Rx
            ss.RxRunt = stats.RxRunt
            ss.RxFrag = stats.RxFrag
            ss.RxInvalidLen = stats.RxInvalidLen
            ss.RxDecodeFail = stats.RxDecodeFail
            ss.RxDecodeFrag = stats.RxDecodeFrag
            ss.RxSessionErr = stats.RxSessionErr
            ss.RxSessionClose = stats.RxSessionClose
            ss.RxNoData = stats.RxNoData
            ss.RxSockErr = stats.RxSockErr
            ss.RxQEmpty = stats.RxQEmpty

            ss.Tx = stats.Tx
            ss.TxQEmpty = stats.TxQEmpty
            ss.TxQFull = stats.TxQFull
            ss.TxFrag = stats.TxFrag
            ss.TxEncodeErr = stats.TxEncodeErr
            ss.TxEncodeFail = stats.TxEncodeFail
            ss.TxSessionErr = stats.TxSessionErr
            ss.TxSockErr = stats.TxSockErr

        return True

    def change_gcp_logging_level(self, cmd_msg, rsp_msg):
        try:
            module = cmd_msg.CliGcp.GcpLogging.module
            level = cmd_msg.CliGcp.GcpLogging.level

            all_classes = AddLoggerToClass.moduleMapping
            sub_classes = gcp_module_map[module]

            level_mapping = {
                'debug': logging.DEBUG,
                'info': logging.INFO,
                'warn': logging.WARN,
                'error': logging.ERROR,
            }

            if level not in level_mapping:
                self.logger.warn("invalid logging level %s", level)
                return False

            for name in sub_classes:
                logger = all_classes[name]
                logger.setLevel(level_mapping[level])
        except Exception as e:
            self.logger.warn("Got exception when handling logging level: %s", str(e))
            return False

        return True


class RcpHalProcess(RcpProcess):

    __metaclass__ = AddLoggerToClass

    def __init__(self, ipc_sock_addr=None, dispatcher=None, notify_mgr_cb=None):
        super(RcpHalProcess, self).__init__(
            ipc_sock_addr, dispatcher=dispatcher)
        self.notify_mgr_cb = notify_mgr_cb
        self.hal_ipc = RcpHalIpc("HalClient", "This is a RcpHal application",
                                 "1.0.0", (MsgTypeRoutePtpStatus, MsgTypeFaultManagement,
                                           MsgTypeRpdIpv6Info, MsgTypeRpdGroupInfo,
                                           MsgTypeGeneralNtf, MsgTypeStaticPwStatus,
                                           MsgTypeRpdCapabilities),
                                 self, "/etc/config/ClientLogging.conf")
        self.hal_ipc.start(
            self.orchestrator.config_operation_rsp_cb,
            self.orchestrator.notification_process_cb)

    def cleanup(self):
        super(RcpHalProcess, self).cleanup()
        if None is not self.hal_ipc:
            self.hal_ipc.connection_cleanup(self.dispatcher)

    def rcp_msg_dispatcher(self, ipc_msg):
        """Dispatch ipc msg to manager or Hal.

        :param ipc_msg: {"session": session, "req_pkt": None, "req_data": data}

        """
        data = ipc_msg['req_data']
        session = ipc_msg['session']
        desc = session.get_descriptor()
        interface_local = desc.interface_local
        addr_remote = desc.addr_remote
        if isinstance(data, t_RcpMessage) and data.IsInitialized():
            if self.notify_mgr_cb:
                self.notify_mgr_cb(data)
        elif isinstance(data, list):
            remove_list = []
            for seq in data:
                if isinstance(seq.ipc_msg, t_RcpMessage):
                    msg_name = [desc.name for desc, value in seq.ipc_msg.RpdDataMessage.RpdData.ListFields()]
                    rcp_field = filter(lambda x: x in ['RpdCapabilities', 'RedundantCoreIpAddress'], msg_name)
                    if len(rcp_field):
                        self.logger.info("Data sent to rcp agent")
                        if None is not interface_local:
                            if 'RpdConfigurationDone' in rcp_field:
                                seq.ipc_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION_DONE
                                seq.ipc_msg.parameter = ';'.join([interface_local, addr_remote])
                            else:
                                seq.ipc_msg.parameter = interface_local
                        if self.notify_mgr_cb:
                            self.notify_mgr_cb(seq)
                else:
                    remove_list.append(seq)
                    self.logger.error('Invalid IPC message provided')
                    continue
            for remove_msg in remove_list:
                data.remove(remove_msg)

            # send real configuration to hal
            if len(data):
                self.hal_ipc.rcp_cfg_req(ipc_msg)
        else:
            self.logger.error("Unknown message found: {}".format(data))
            return

    def send_ipc_msg(self, ipc_msg):
        """Notify manager about progress.

        :param ipc_msg: configuration message to be sent
        :type ipc_msg: {"session": session, "req_pkt": None, "req_data": data}
        :return: or not ipc_msg.IsInitialized()

        """
        if not isinstance(ipc_msg, dict):
            self.logger.error('Invalid IPC message provided')
            exit(EX_DATAERR)
        self.rcp_msg_dispatcher(ipc_msg)

    def _ipc_msg_cb(self, fd, eventmask):  # pragma: no cover
        try:
            while self.ipc_sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
                zmq_msg = self.ipc_sock.recv(flags=zmq.NOBLOCK)
                self.logger.debug("IPC message from manager received, len[%d]",
                                  len(zmq_msg))
                if len(zmq_msg) > 0:
                    msg = t_RcpMessage()
                    msg.ParseFromString(zmq_msg)
                    self.logger.info("RCP message type: %s",
                                     msg.t_RcpMessageType.Name(
                                         msg.RcpMessageType))
                    if msg.RcpMessageType == msg.ADD_CCAP_CORES:
                        self.add_ccap_cores(msg.RedirectCCAPAddresses)
                    elif msg.RcpMessageType == msg.REMOVE_ALL_CCAP_CORES:
                        if not msg.HasField('RedirectCCAPAddresses'):
                            self.orchestrator.remove_sessions_all()
                        else:
                            for (interface, core) in msg.RedirectCCAPAddresses:
                                self.orchestrator.remove_sessions_by_core(
                                    interface, core)
                    elif msg.RcpMessageType == msg.RPD_CONFIGURATION:
                        # call the registered response callback
                        try:
                            self.ipc_rsp_callback(msg)
                        except Exception as ex:
                            self.logger.error("IPC RCP callback call failed: %s", ex)
                    else:
                        raise DecodeError("Unexpected message type received")
        except zmq.Again:
            # Ignore ... retry handled by dispatcher
            return
        except DecodeError as exception:
            self.logger.error("Malformed IPC message, dropping ...: %s",
                              exception.message)
            return
            # All other exceptions are considered as fatal, handled in main

    def add_ccap_cores(self, ccap_cores):
        super(RcpHalProcess, self).add_ccap_cores(ccap_cores)


def notification_mgr_cb(msg):  # pragma: no cover
    pass


def main():  # pragma: no cover
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipc-address', required=True,
                        help='Address for IPC communication')
    args = parser.parse_args()

    rcp = RcpHalProcess(args.ipc_address, notify_mgr_cb=notification_mgr_cb)
    logger = logging.getLogger("main")
    while True:
        try:
            rcp.start()
        except DispatcherTimeoutError:
            logger.debug("Dispatcher timeout error, "
                         "seems that time has been changed")
            rcp.dispatcher.end_loop()
            ret = rcp.orchestrator.orchestration_restart()
            if not ret:
                logger.error("Failed to handle dispatcher timeout error")
                exit(EX_OSERR)
            logger.info("Recovered from time change")

        except Exception as exception:
            logger.error(
                "Unexpected failure (%s): %s", type(exception), exception)
            exit(EX_OSERR)


def handle_interrrupt_signal(signum, frame):  # pragma: no cover
    sys.exit(0)


# register the ctrl C to handle this signal
if __name__ == "__main__":  # pragma: no cover
    signal.signal(signal.SIGINT, handle_interrrupt_signal)

    # setup logging, will search the config files
    setup_logging("GCP", filename="rcp.log")

    main()
