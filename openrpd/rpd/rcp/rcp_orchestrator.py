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
import json
import errno
import socket

from rpd.rcp.rcp_msg_handling import RCPSlavePacketHandler as \
    RCPSlavePacketHandler
from rpd.rcp.rcp_sessions import RCPSlaveSession
from rpd.dispatcher import dispatcher
from rpd.rcp.rcp_packet_director import RCPSlavePacketBuildDirector
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.rcp.rcp_hal import RcpHalIpc
from rpd.hal.src.HalConfigMsg import MsgTypeRoutePtpStatus, MsgTypeFaultManagement, MsgTypeRpdIpv6Info, \
    MsgTypeRpdGroupInfo, MsgTypeGeneralNtf, MsgTypeStaticPwStatus, MsgTypeUcdRefreshNtf
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_lib.gcp_packet import GCPPacket
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPDecodeError
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.dispatcher.timer import DpTimerManager
from rpd.common import rpd_event_def
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification
from rpd.gpb.RfChannel_pb2 import t_RfChannel
import rpd.provision.proto.process_agent_pb2 as protoDef
import rpd.rcp.rcp_lib.rcp_tlv_def as rcp_tlv_def
import rpd.rcp.gcp.gcp_sessions as gcp_sessions
import rpd.rcp.rcp_lib.rcp as rcp


def create_testing_notify_rsp(packet, caps):    # pragma: no cover
    # create packet with NotifyResp
    msg = rcp.Message(gcp_msg_def.NotifyRSP)
    msg.msg_fields.TransactionID.set_val(
        packet.msgs[0].msg_fields.TransactionID.get_val())
    msg.msg_fields.Mode.set_val(0)
    msg.msg_fields.EventCode.set_val(
        packet.msgs[0].msg_fields.EventCode.get_val())

    rcp_msg = rcp.RCPMessage(msg.message_id, rcp_tlv_def.RCP_MSG_TYPE_NTF)
    seq = rcp.RCPSequence(msg.message_id, rcp_tlv_def.RCP_MSG_TYPE_NTF, 0,
                          rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)

    ccap_id = seq.CcapCoreIdentification.add_new_repeated()
    ccap_id.Index.set_val(123)
    ccap_id.CoreId.set_val("pukino")
    ccap_id.IsPrincipal.set_val(caps.is_principal)

    msg.tlv_data.rcp_msgs.append(rcp_msg)
    rcp_msg.sequences.append(seq)

    pkt = rcp.RCPPacket()
    pkt.transaction_identifier = packet.transaction_identifier
    pkt.protocol_identifier = packet.protocol_identifier
    pkt.unit_id = 3
    pkt.msgs.append(msg)
    return pkt


def log_measured_values(master_orch):   # pragma: no cover
    # print measured delays
    for fd, transactions in master_orch.data_to_measure.items():
        RCPOrchestrator.logger.debug("Measured data for FD: %s", fd)

        t = 0.0
        trans_count = 0
        for t_id, data_list in transactions.items():
            master_orch.log_measured_data(data_list)

            try:
                if None is not t:
                    for data in data_list:
                        t += (data.end_time - data.start_time)
                    trans_count += 1
            except Exception as ex:
                RCPOrchestrator.logger.error(
                    "Measuring failed, failed to compute average time: %s", ex)
                t = None

        if None is not t:
            t_sec = t / trans_count
            t_msec = (t_sec % 1) * 1000
            t_usec = (t_msec % 1) * 1000
            t_nsec = (t_usec % 1) * 1000
            RCPOrchestrator.logger.debug(
                "Measured average transaction time for %u transactions: "
                "%uS %umS %uuS %unS (%.6f)",
                trans_count, t_sec, t_msec, t_usec, t_nsec, t_sec)


class GdmMsgHandler(object):
    """Handle gcp device management request.

    1. such as keep alive message, cold reset, warm reset, power up/down

    """
    __metaclass__ = AddLoggerToClass

    @staticmethod
    def send_gdm_command_to_mgr(slave, rcp_process_channel, cmd, info):
        """Keep alive message.

        :param slave: The RCP slave session on which the packet has been
         received
        :param rcp_process_channel: rcp process instance
        :param cmd: gdm command
        :param info: command information

        """
        reboot_msg = t_RcpMessage()
        reboot_msg.RcpMessageType = cmd

        desc = slave.get_descriptor()
        ccap_core_para = {'addr_remote': None, 'interface_local': None}
        if None is not desc.addr_remote:
            ccap_core_para['addr_remote'] = desc.addr_remote
        if None is not desc.interface_local:
            ccap_core_para['interface_local'] = desc.interface_local
        ccap_core_para['info'] = info
        reboot_msg.parameter = json.dumps(ccap_core_para)

        # send reboot message to agent
        rcp_process_channel.notify_mgr_cb(reboot_msg)

    @staticmethod
    def ka_msg_hanlder(slave, _):
        """Keep alive message handler.

        :param slave: The RCP slave session on which the packet has been
         received
        :return: success

        """
        GdmMsgHandler.logger.debug(
            "GDM keep alive message handling from %s", slave.get_descriptor())
        return gcp_msg_def.GCP_RC_SUCCESS.rc

    @staticmethod
    def cold_reset(slave, rcp_process_channel):
        """Cold reset via GCP gdm message.

        :param slave: The RCP slave session on which the packet has been
         received
        :param rcp_process_channel: rcp process instance

        """
        GdmMsgHandler.logger.debug(
            "GDM cold reset message handling from %s", slave.get_descriptor())
        GdmMsgHandler.send_gdm_command_to_mgr(
            slave, rcp_process_channel, t_RcpMessage.RPD_REBOOT,
            "cold start")
        return gcp_msg_def.GCP_RC_SUCCESS.rc

    @staticmethod
    def warm_reset(slave, rcp_process_channel):
        """Warm reset via GCP gdm message.

        :param slave: The RCP slave session on which the packet has been
         received
        :param rcp_process_channel: rcp process instance

        """
        GdmMsgHandler.logger.debug(
            "GDM warm reset message handling from %s", slave.get_descriptor())
        GdmMsgHandler.send_gdm_command_to_mgr(
            slave, rcp_process_channel, t_RcpMessage.RPD_REBOOT,
            "Warm start")
        return gcp_msg_def.GCP_RC_SUCCESS.rc

    @staticmethod
    def standby_cb(slave, _):
        """Standby via GCP gdm message.

        :param slave: The RCP slave session on which the packet has been
         received

        """
        GdmMsgHandler.logger.debug(
            "GDM standby message handling from %s", slave.get_descriptor())
        return gcp_msg_def.GCP_RC_SUCCESS.rc

    @staticmethod
    def wake_up(slave, _):
        """Wake up command via GCP gdm message.

        :param slave: The RCP slave session on which the packet has been
         received

        """
        GdmMsgHandler.logger.debug("GDM wake up message handling from %s", slave.get_descriptor())
        return gcp_msg_def.GCP_RC_SUCCESS.rc

    @staticmethod
    def power_up(slave, _):
        """Power up via GCP gdm message.

        :param slave: The RCP slave session on which the packet has been
         received

        """
        GdmMsgHandler.logger.debug("GDM power up message handling from %s", slave.get_descriptor())
        return gcp_msg_def.GCP_RC_SUCCESS.rc

    @staticmethod
    def power_down(slave, _):
        """Power down command via GCP gdm message.

        :param slave: The RCP slave session on which the packet has been
        received

        """
        GdmMsgHandler.logger.debug(
            "GDM power down message handling from %s", slave.get_descriptor())
        return gcp_msg_def.GCP_RC_SUCCESS.rc


class RCPOrchestrator(gcp_sessions.GCPSessionOrchestrator):

    """Describes interface for the implementation of RCP session orchestrator.

    Is intended to be used as a superclass.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self, disp):
        """Adds dispatcher object and dictionary for active sessions (which
        have FDs or timers registered in dispatcher) where file descriptors
        are used as keys.

        :param disp: The instance of dispatcher

        """
        super(RCPOrchestrator, self).__init__()
        self.dispatcher = disp
        self.sessions_active_fd = {}

    def session_is_active_fd(self, fd):
        """Checks the session identified by the file descriptor if it's an
        active session of this orchestrator."""
        if fd in self.sessions_active_fd:
            return True
        return False

    def session_ev_cb(self, fd, event_mask):
        """Dispatcher callback for FD events handling.

        Calls rd_cb(), wr_cb() and ex_cb() according to the event which has
        occurred.

        """
        # event_mask = fd.values()[0]
        # fd = fd.keys()[0]
        if not event_mask:
            self.logger.error("Session event callback called without any event")
            return

        if not self.session_is_active_fd(fd):
            self.logger.error(
                "Session event callback called for inactive session, fd:%s", fd)
            return

        try:
            # handle exception and drop all other events
            if event_mask & self.dispatcher.EV_FD_ERR:
                self.logger.debug("Handling error event.")
                self.ex_cb(fd)
                return

            # send message
            if event_mask & self.dispatcher.EV_FD_OUT:
                self.logger.debug("Handling write event.")
                self.wr_cb(fd)

            # receive message
            if event_mask & self.dispatcher.EV_FD_IN:
                self.logger.debug("Handling receive event.")
                self.rd_cb(fd)
        except KeyError:
            self.logger.error(
                "Session event callback called for unknown session, fd:%s", fd)

    def rd_cb(self, fd):    # pragma: no cover
        """This function is called, when some data are received on some
        session's socket.

        File descriptor related to the session is passed as argument.

        """
        raise NotImplementedError()

    def wr_cb(self, fd):    # pragma: no cover
        """This function is called, when some session's socket is prepared for
        sending a data.

        File descriptor related to the session is passed as argument.

        """
        raise NotImplementedError()

    def ex_cb(self, fd):    # pragma: no cover
        """This function is called, when some session raised an exception.
        File descriptor related to the session is passed as argument."""
        raise NotImplementedError()


class RCPSlaveOrchestrator(
        RCPOrchestrator,
        RCPSlavePacketHandler.RCPSlavePacketHandlerCallbackSet):
    """Implements an orchestrating class for exactly one RCP slave, which
    initiates and maintains GCP sessions with GCP masters according to the
    RPD specification.

    Uses object of the class dispatcher.Dispatcher to register for certain
    events.

    Uses object of the class rpd_db.RPD_DB to store current state of the
    RCP slave.

    """
    __metaclass__ = AddLoggerToClass
    # If a CCAP-Core has not responded after CORE_CONNECT_TIMEOUT,
    # then the RPD MUST retry the connection CONFIG_RETRY_COUNT.
    # TODO update and use this to implement timeouts and retries
    _CORE_CONNECT_TIMEOUT = 5  # seconds
    _CONFIG_RETRY_COUNT = 3
    # TODO need to store session context with the timer and retry count
    # TODO we need to start the timer before we call the session initiation
    # TODO and stop the timer when we receive configration (check with spec)
    # TODO and handle timeouts (continue with next ccap core, or just
    # TODO close the session)
    # Start the timer
    # initiate_timer = self.dispatcher.timer_register(_CORE_CONNECT_TIMEOUT,
    #                                                 self.timeout_cb)
    # if not initiate_timer:
    #     self.logger.debug("Failed to start the intiation timer")
    #     return
    #
    # initiate_retries += 1
    # self.logger.debug("Initiating RCP session (%s), number of retries: %u",
    #           descr, initiate_retries)

    # The per msg timeout is 15s at rcp_hal side, so use 60s here for each pkt.
    PKT_HANDLE_TIMEOUT = 60
    RCP_ORCH_STATE_INIT = 0
    RCP_ORCH_STATE_NO_SESSIONS = 1
    RCP_ORCH_STATE_LOOKING_FOR_PRINCIPAL = 2
    RCP_ORCH_STATE_PRINCIPAL_CONNECTED = 3
    RCP_ORCH_STATE_NO_PRINCIPAL = 4
    RCP_ORCH_STATE_PRINCIPAL_FAILED = 5
    RCP_ORCH_STATE_REDIRECT_RECEIVED = 6
    RCP_ORCH_STATE_REDIRECT_RESPONDED = 7

    __state_str = {
        RCP_ORCH_STATE_INIT: "RCP_SLAVE_ORCH_INIT",
        RCP_ORCH_STATE_LOOKING_FOR_PRINCIPAL:
            "RCP_SLAVE_ORCH_LOOKING_FOR_PRINCIPAL",
        RCP_ORCH_STATE_PRINCIPAL_CONNECTED:
            "RCP_SLAVE_ORCH_PRINCIPAL_CONNECTED",
        RCP_ORCH_STATE_NO_SESSIONS: "RCP_SLAVE_ORCH_NO_SESSIONS",
        RCP_ORCH_STATE_NO_PRINCIPAL: "RCP_SLAVE_ORCH_NO_PRINCIPAL",
        RCP_ORCH_STATE_PRINCIPAL_FAILED: "RCP_ORCH_STATE_PRINCIPAL_FAILED",
        RCP_ORCH_STATE_REDIRECT_RECEIVED: "RCP_ORCH_STATE_REDIRECT_RECEIVED",
        RCP_ORCH_STATE_REDIRECT_RESPONDED: "RCP_ORCH_STATE_REDIRECT_RESPONDED"
    }

    @classmethod
    def _state_to_str(cls, state):
        """Convert state name to string."""
        return cls.__state_str[state]

    __ORCHESTRATION_TIME = 1  # second
    __BG_PROCESSING_PKT_TIME = 0.010  # 10ms
    __TIME_TO_KA = 0.8  # keep alive time minus 0.2 seconds, leave 0.2 to do KA.

    def __orchestration_start(self):
        # register timer for periodical call of the orchestrate_cb
        self.orchestrate_timer = \
            self.dispatcher.timer_register(self.__ORCHESTRATION_TIME,
                                           self.orchestrate_cb)

    def orchestration_restart(self):    # pragma: no cover
        try:
            if None is not self.orchestrate_timer:
                try:
                    self.dispatcher.timer_unregister(self.orchestrate_timer)
                except Exception:
                    pass

            self.__orchestration_start()
        except Exception as e:
            self.logger.error("Failed to restart orchestration, reason:%s", e)
            return False
        return True

    #
    # Implementation of the CallbackSet interface
    #
    def ccap_identification_update(self, session):    # pragma: no cover
        """This callback is called by the PacketHandler when an update of
        the CCAP's capabilities has been received.

        State of the sessoin must not be changed here. (so also orchestration
        methods must not be called here)

        :param session: The session where capabilities are updated.
        :type session: RCPSlaveSession

        """
        # If the principal active's state has been changed,
        # then set principal to none and change the state
        if session in self.principal and not session.ccap_identification.is_principal:
            self.principal.remove(session)
            if not len(self.principal):
                self._set_orch_state(
                    self.RCP_ORCH_STATE_LOOKING_FOR_PRINCIPAL,
                    "Principal active CCAP Core's capabilities changed.")

    def redirect_received(self, session, ccap_core_addres_list):
        """This callback is called by PacketHandler when a redirect to the
        list of CCAP core IP addresses was received.

        State of the session must not be changed here. (so also orchestration
        methods must not be called here)

        :param session: The session where capabilities are updated.
        :type session: RCPSlaveSession
        :param ccap_core_addres_list: List of tuples of ip addresses and
         address families.

        """
        self.logger.info("Redirect received at %s, addresses: %s" %
                         (session.get_descriptor(), ccap_core_addres_list))

        self._redir_resp_session = session
        self._redir_addr_list = ccap_core_addres_list
        self._set_orch_state(self.RCP_ORCH_STATE_REDIRECT_RECEIVED,
                             "Redirect received at session: {}".format(
                                 session.get_descriptor()))

        # TODO add writing into DB, need to remove FDs from session_activ_fd

        # unregister all sessions except to the current one from dispatcher
        for fd in self.sessions_active_fd.iterkeys():
            if fd == session.get_socket_fd():
                continue
            self.dispatcher.fd_unregister(fd)

    def device_management_handler(self, slave, cmd):
        """This callback is called by PacketHandler when a device management
        operation needs to be performed on RPD system. Operations are
        described as command list.

        :param slave: The RCP slave sessions on which the message has been
         received.
        :param cmd: the device management command send via gcp
        :type cmd: enum 0-6
         device management operation request.

        """
        if cmd in self.device_management_cb:
            handler = self.device_management_cb[cmd]
            ret = handler(slave, self.rcp_process_channel)
        else:
            ret = gcp_msg_def.GCP_RC_UNSUPPORTED.rc

        return ret

    def configuration_to_rcp_wrapper(self, session, seq, transaction_identifier,
                                     trans_id, msg_type=t_RcpMessage.RPD_CONFIGURATION):
        """This callback is called by PacketHandler when a GCP
        operation needs to be send to manager_process.

        :param session: The session where capabilities are updated.
        :param seq: sequences info
        :param transaction_identifier: pkt transaction_id.
        :param trans_id: gcp message transaction_id.
        :param msg_type: config or Done.

        """
        seq.ipc_msg.RcpMessageType = msg_type
        self.rcp_process_channel.notify_mgr_cb(seq, args=(session, transaction_identifier, trans_id))

    def configuration_operation(self, session, rcp_sequence_list,
                                pkt_req, gcp_msg):
        """This callback is called by PacketHandler when a configuration
        operation needs to be performed on RPD system. Operations are
        described as list of RCPSequences.

        :param session: The session where capabilities are updated.
        :type session: RCPSlaveSession
        :param rcp_sequence_list: List of RCPSequence objects.
        :param pkt_req: A RCPPacket object including a packet with the
         configuration operation request.
        :param gcp_msg: The Gcp msg

        """
        if None in (session, rcp_sequence_list, pkt_req):
            raise AttributeError("Mandatory attribute not passed")

        if not rcp_sequence_list:
            raise AttributeError("Empty sequence list passed")

        for seq in rcp_sequence_list:
            if not isinstance(seq, rcp.RCPSequence):
                raise TypeError(
                    "RCPSequences are expected in tuple of RCP data")

            try:
                operation = RcpHalIpc.RCP_OPER_TO_RPD_DATA_OPER[seq.operation]
            except:
                raise AttributeError(
                    "Invalid RCP operation set in sequence: %u" %
                    seq.operation)
            ipc_oper = RcpHalIpc.RPD_DATA_OPER_TO_IPC_OPER[operation]
            seq.ipc_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            seq.ipc_msg.RpdDataMessage.RpdDataOperation = ipc_oper

        if pkt_req not in self.req_msg_db:
            timer = self.dispatcher.timer_register(self.PKT_HANDLE_TIMEOUT,
                                                   self.config_op_timeout_cb, arg=pkt_req)
            self.req_msg_db[pkt_req] = {"session": session,
                                        "cfg_timeout": timer,
                                        "sent_msg": []}

        self.req_msg_db[pkt_req]["sent_msg"].append(gcp_msg)

        # send configuration to other module directly, skip original prepare and process procedure
        self.rcp_process_channel.send_ipc_msg({"session": session,
                                               "req_packet": pkt_req,
                                               "gcp_msg": gcp_msg,
                                               "req_data": rcp_sequence_list,
                                               })

    def __init__(self, disp, cfg_ipc_channel, reboot_cb):
        """Implements the method from the RCPOrchestrator interface.

        :param disp: The instance of dispatcher.
        :param cfg_ipc_channel:  The instance of RPD IPC channel for
         configuration operations.
        :param reboot_cb: The callback which is called when the handling of
         some error case needs to reboot the device.

        """
        if None is dispatcher:
            raise TypeError("None dispatcher object is not supported.")

        super(RCPSlaveOrchestrator, self).__init__(disp)

        if cfg_ipc_channel is None:
            raise TypeError("None cfg ipc channel is not supported")

        self.rcp_process_channel = cfg_ipc_channel

        self.orchestrate_timer = None
        self.orch_state = self.RCP_ORCH_STATE_INIT
        self.reboot_cb = reboot_cb
        self._set_orch_state(self.RCP_ORCH_STATE_NO_SESSIONS)

        # used to find Principal active CCAP core
        self.non_principals = []
        self.principal_candidate = None  # current candidate for principal
        self.principal = []

        # get the RCPPacketBuildDirector instance
        self.pkt_director = RCPSlavePacketBuildDirector()

        # create RCPSlaveMessageHandler
        self.pkt_handler = RCPSlavePacketHandler(
            callback_set=self,
            packet_director=self.pkt_director)

        # redirect data
        self._redir_resp_session = None
        # list of tuples of format: (ip_addr_str, addr_family)
        self._redir_addr_list = None

        # The following section is for the collect all the req, rsp message
        self.rsp_msg_db = dict()
        self.req_msg_db = dict()

        self.device_management_cb = {
            gcp_msg_def.GDM_NULL.cmd: GdmMsgHandler.ka_msg_hanlder,
            gcp_msg_def.GDM_COLD_RESET.cmd: GdmMsgHandler.cold_reset,
            gcp_msg_def.GDM_WARM_RESET.cmd: GdmMsgHandler.warm_reset,
            gcp_msg_def.GDM_STANDBY.cmd: GdmMsgHandler.standby_cb,
            gcp_msg_def.GDM_WAKE_UP.cmd: GdmMsgHandler.wake_up,
            gcp_msg_def.GDM_POWER_DOWN.cmd: GdmMsgHandler.power_down,
            gcp_msg_def.GDM_POWER_UP.cmd: GdmMsgHandler.power_up,
        }

        self.node_notification_cb = {
            MsgTypeRpdIpv6Info: self.notification_ipv6_status,
            MsgTypeRoutePtpStatus: self.notification_ptp_status,
            MsgTypeFaultManagement: self.notification_fault_management_cb,
            MsgTypeRpdGroupInfo: self.notification_group_info,
            MsgTypeGeneralNtf: self.notification_general_info,
            MsgTypeStaticPwStatus: self.notification_static_pw_status,
            MsgTypeUcdRefreshNtf: self.notification_ucdrefresh_info,
        }
        self.fault_level = None
        self.fault_text_limit = 255
        self.index_id = 1

        self.__orchestration_start()

    def set_active_principal_core(self, interface, core_ip):
        """Notification entrance.

        :param interface: should be the port connected to active principal core's
        :param core_ip: should be the actie principal core's ip
        :return:

        """
        self.logger.info("Got active principal core[%s, %s] information from manager", interface, core_ip)

        for uid, session in self.sessions_active.items():
            desc = session.get_descriptor()
            if None is session.ccap_identification:
                continue
            if desc.addr_remote == core_ip and desc.interface_local == interface:
                if not session.ccap_identification.is_active:
                    session.ccap_identification.is_active = True
                    self.logger.info("set active principal core[%s] information success", core_ip)
            else:
                if session.ccap_identification is not None:
                    session.ccap_identification.is_active = False

    def notification_process_cb(self, notification_type, msg):
        """Notification entrance.

        :param notification_type: notification type need to send
        :param msg: message payload
        :return:

        """
        if notification_type in self.node_notification_cb:
            handler = self.node_notification_cb[notification_type]
            handler(msg)
        else:
            self.logger.warning("Unsupported notification message type %s", notification_type)

    def notification_ptp_status(self, msg):
        """Send ptp route status to CCAP cores.

        :param msg: ptp status message
        :return:

        """
        for fd, session in self.sessions_active_fd.items():
            ntf_req = self.pkt_director.get_ptp_notify_packet(session, msg)
            session.io_ctx.add_tx_packet(ntf_req)

            if session.io_ctx.is_tx_empty():
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)
            else:
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_ALL)

    def notification_general_info(self, msg):
        """Send general notify status to CCAP cores.

        :param msg: like ptp status message
        :return:

        """
        gen_ntf_msg = t_GeneralNotification()
        gen_ntf_msg.ParseFromString(msg)
        msg_type = gen_ntf_msg.NotificationType
        for fd, session in self.sessions_active_fd.items():
            ntf_req = self.pkt_director.get_general_notify_packet(session, msg_type, gen_ntf_msg)
            session.io_ctx.add_tx_packet(ntf_req)

            if session.io_ctx.is_tx_empty():
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)
            else:
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_ALL)

        # notify the ccap core via fault management
        if msg_type == t_GeneralNotification.PTPRESULTNOTIFICATION:
            if gen_ntf_msg.PtpResult == t_GeneralNotification.PTPSYNCHRONIZED:
                self.notify.info(rpd_event_def.RPD_EVENT_CONNECTIVITY_SYNC[0], "")
            else:
                self.notify.error(rpd_event_def.RPD_EVENT_CONNECTIVITY_LOSS_SYNC[0], "")

    def notification_ucdrefresh_info(self, msg):
        """Send general notify ucdrefresh to CCAP cores.

        :param msg: RfChannel message
        :return:

        """
        gen_ntf_msg = t_RfChannel()
        gen_ntf_msg.ParseFromString(msg)
        for fd, session in self.sessions_active_fd.items():
            ntf_req = self.pkt_director.get_ucdrefresh_notify_packet(session, gen_ntf_msg)
            session.io_ctx.add_tx_packet(ntf_req)

            if session.io_ctx.is_tx_empty():
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)
            else:
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_ALL)

        # notify the ccap core via fault management
        self.notify.error(rpd_event_def.RPD_EVENT_CONNECTIVITY_LOSS_SYNC[0], "")

    def notification_ipv6_status(self, msg):
        """Send ipv6 info to CCAP cores.

        :param msg: RpdIpv6Info message
        :return:

        """
        for fd, session in self.sessions_active_fd.items():
            ntf_req = self.pkt_director.get_ipv6_notify_packet(session, msg)
            session.io_ctx.add_tx_packet(ntf_req)

            if session.io_ctx.is_tx_empty():
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)
            else:
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_ALL)

    def notification_group_info(self, msg):
        """Send group info to CCAP cores.

        :param msg: RpdGroupInfo message
        :return:

        """
        for fd, session in self.sessions_active_fd.items():
            ntf_req = self.pkt_director.get_group_notify_packet(session, msg)
            session.io_ctx.add_tx_packet(ntf_req)

            if session.io_ctx.is_tx_empty():
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)
            else:
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_ALL)

    def send_fault_management_message(self, session, event, text, info):
        """Send the fault management message to notify CBR8 about the event.

        :param session: gcp connection to send message
        :param event: event id
        :param text: event text string
        :param info: event information
        :return:

        """
        event = int(event)

        # fault message text is limited to 255, so drop the rest
        ntf_req = self.pkt_director.get_fault_management_notify_packet(
            session, event, text, info)
        session.io_ctx.add_tx_packet(ntf_req)

    def notification_static_pw_status(self, msg):
        """
        send static pseudowires report status information
        :param msg: t_StaticPwStatus
        :return:

        """
        try:
            for fd, session in self.sessions_active.items():
                if not session.ccap_identification or \
                        not (session.ccap_identification.is_active and session.ccap_identification.is_principal):
                    continue
                ntf_req = self.pkt_director.get_pw_status_notify_packet(session, msg)
                session.io_ctx.add_tx_packet(ntf_req)
                if session.io_ctx.is_tx_empty():
                    self.dispatcher.fd_modify(session.get_socket_fd(), self.dispatcher.MASK_RD_ERR)
                else:
                    self.dispatcher.fd_modify(session.get_socket_fd(), self.dispatcher.MASK_ALL)
        except ValueError:
            pass

    def notification_fault_management_cb(self, msg):
        """
        send fault management information to principal CCAP core
        :param msg: fault management information
        :return:

        """
        try:
            event, text, value = json.loads(msg)
            for _, session in self.sessions_active.items():
                if not session.ccap_identification or \
                        not (session.ccap_identification.is_active and session.ccap_identification.is_principal):
                    continue
                self.send_fault_management_message(session, event, text, value)
                if session.io_ctx.is_tx_empty():
                    self.dispatcher.fd_modify(session.get_socket_fd(), self.dispatcher.MASK_RD_ERR)
                else:
                    self.dispatcher.fd_modify(session.get_socket_fd(), self.dispatcher.MASK_ALL)
        except ValueError:
            pass

    def config_op_timeout_cb(self, pkt_req):
        """Callback is called when waiting responses for all msgs times out."""
        if pkt_req not in self.req_msg_db:
            self.logger.debug("Packet {} have been handled".format(pkt_req))
            return
        self.logger.warning(
            "Configuration timeout for Packet {}".format(pkt_req))
        try:
            if pkt_req not in self.rsp_msg_db:
                session = self.req_msg_db[pkt_req]["session"]
                # Create response
                tx_pkt = self.pkt_director.get_resulting_rsp_packets(
                    session,
                    pkt_req,
                    [])
                tx_pkt = tx_pkt[0]
                if session.is_initiated():
                    session.io_ctx.add_tx_packet(tx_pkt)
            else:
                rcp_list = list()
                for msg in self.rsp_msg_db[pkt_req]:
                    rcp_list.extend(msg["req_data"])

                msg = self.rsp_msg_db[pkt_req][0]
                session = msg["session"]
                pkt_req = msg["req_packet"]
                tx_pkt = self.pkt_director.get_resulting_rsp_packets(
                    session,
                    pkt_req,
                    rcp_list)
                tx_pkt = tx_pkt[0]
                if session.is_initiated():
                    session.io_ctx.add_tx_packet(tx_pkt)
                self.rsp_msg_db.pop(pkt_req)

            # clear db
            self.logger.debug("clear request message db")
            self.req_msg_db.pop(pkt_req)

            self.dispatcher.fd_modify(session.get_socket_fd(),
                                      self.dispatcher.MASK_ALL)
        except Exception as e:
            self.logger.error(
                "Got exception when handling config rsp, reason %s", str(e))

    def config_operation_rsp_cb(self, rsp_data_list):
        """Callback is called when responses for all requests of one
        configuration operations bulk are collected.

        Expects list of response data passed as parameter.

        """
        if not isinstance(rsp_data_list, dict):
            self.logger.error(
                "Expect dict type, got {}".format(type(rsp_data_list)))
            return

        try:
            pkt_req = rsp_data_list["req_packet"]

            # maybe timeout if pkt not in request db
            if pkt_req not in self.req_msg_db:
                return

            # Currently, we only judge the rsp msg count
            if pkt_req not in self.rsp_msg_db:
                self.rsp_msg_db[pkt_req] = list()
                if rsp_data_list not in self.rsp_msg_db[pkt_req]:  # filter the duplicated
                    self.rsp_msg_db[pkt_req].append(rsp_data_list)
            else:
                self.rsp_msg_db[pkt_req].append(rsp_data_list)

            if len(self.rsp_msg_db[pkt_req]) < len(self.req_msg_db[pkt_req]["sent_msg"]):
                return

            rcp_list = list()
            for msg in self.rsp_msg_db[pkt_req]:
                rcp_list.extend(msg["req_data"])

            msg = self.rsp_msg_db[pkt_req][0]
            # pop the pkt_req from rsp_msg_db to avoid memory exhaustion
            self.rsp_msg_db.pop(pkt_req)
            if pkt_req in self.req_msg_db:
                self.logger.debug("Unregister timer as normal message responded")
                self.dispatcher.timer_unregister(
                    self.req_msg_db[pkt_req]['cfg_timeout'])
                self.req_msg_db.pop(pkt_req)

            session = msg["session"]
            pkt_req = msg["req_packet"]
            # gcp_msg = msg["gcp_msg"], currently, this field is useless, in future, we should improve the packet builder

            # Create response
            tx_pkt = self.pkt_director.get_resulting_rsp_packets(
                session,
                pkt_req,
                rcp_list)
            tx_pkt = tx_pkt[0]
            session.io_ctx.add_tx_packet(tx_pkt)
            self.dispatcher.fd_modify(session.get_socket_fd(),
                                      self.dispatcher.MASK_ALL)

            self.logger.debug("RSP added to TX queue")

            if None is self._redir_resp_session:
                # register back all active FDs
                for fd, session in self.sessions_active_fd.iteritems():
                    if fd == session.get_socket_fd():
                        continue

                    if session.io_ctx.is_tx_empty():
                        self.dispatcher.fd_modify(
                            fd, self.dispatcher.MASK_RD_ERR)
                    else:
                        self.dispatcher.fd_modify(fd, self.dispatcher.MASK_ALL)
        except Exception as e:
            self.logger.error(
                "Got exception when handling config rsp, reason %s", str(e))

    def rd_cb(self, fd):
        """Implements the method from the rd_cb() RCPOrchestrator interface and
        is called when there are some data for read from socket identified by
        it's file descriptor."""
        try:
            session = self.sessions_active_fd[fd]
            ctx = session.get_fd_io_ctx(fd)
        except KeyError:
            self.logger.error(
                "Cannot handle the fd since the session is not active or unknown session, fd:%s", fd)
            return

        try:
            i = j = 0
            while True:
                pkt = session.read_pkt(fd)
                if pkt is None:
                    break

                try:
                    msg_id = pkt.fast_decode_msg_type()
                    if GCPPacket.is_gdm_msg(msg_id):
                        i = i + 1
                        ctx.add_rx_packet(pkt, high_priority=True)
                    else:
                        ctx.add_rx_packet(pkt, high_priority=False)
                        j = j + 1
                except gcp_sessions.GCPSessionFull:
                    # stop enqueue more packets, this can back pressure core side
                    self.logger.info(
                        "GCP RX Low Queue Full, stop queuing incoming packets")
                    break

            self.logger.debug(
                "rd cb enqueue hi%d, low%d, remaining hi%d, low%d"
                % (i, j, ctx.packet_rx_high_pri_queue.qsize(),
                   ctx.packet_rx_low_pri_queue.qsize()))

            i = j = 0
            while True:
                pkt = ctx.get_rx_high_pri_packet()
                if pkt is None:
                    break
                try:
                    result = pkt.decode()
                    i = i + 1
                except GCPDecodeError:
                    self.logger.error("Packet decoding failed")
                    session.RxDecodeFail += 1
                    continue
                if result != GCPObject.DECODE_DONE:
                    self.logger.error(
                        "Decoding of received GCP packet failed, result: %s",
                        result)
                    session.stats.RxDecodeFail += 1
                    continue

                session.stats.Rx += 1
                self.pkt_handler.handle_pkt(pkt, session)
                self.wr_cb(fd)

            # Send packet only for 0.8 seconds each time, since keep-alive is 1s on cmts side.
            old_time = time.time()
            while True:
                pkt = ctx.get_rx_low_pri_packet()
                if pkt is None:
                    break
                try:
                    result = pkt.decode()
                    j = j + 1
                except GCPDecodeError:
                    self.logger.error("Packet decoding failed")
                    session.RxDecodeFail += 1
                    continue
                if result != GCPObject.DECODE_DONE:
                    self.logger.error(
                        "Decoding of received GCP packet failed, result: %s",
                        result)
                    session.stats.RxDecodeFail += 1
                    continue

                session.stats.Rx += 1
                self.pkt_handler.handle_pkt(pkt, session)

                # for more packets, use timer to process, this can give time to send packet in wr_cb.
                current_time = time.time()
                if (current_time - old_time) >= self.__TIME_TO_KA and not ctx.is_rx_empty():
                    self.dispatcher.timer_register(
                        self.__BG_PROCESSING_PKT_TIME,
                        self.rd_cb,
                        arg=fd,
                        timer_type=DpTimerManager.TIMER_ONESHOT)
                    self.logger.debug(
                        "rd cb decode hi%d, low%d, remaining hi%d, low%d"
                        % (i, j, ctx.packet_rx_high_pri_queue.qsize(),
                           ctx.packet_rx_low_pri_queue.qsize()))

                    return
            self.logger.debug(
                "rd cb decode hi%d, low%d, remaining hi%d, low%d"
                % (i, j, ctx.packet_rx_high_pri_queue.qsize(),
                   ctx.packet_rx_low_pri_queue.qsize()))
        except gcp_sessions.GCPSessionClosed:
            self.logger.error(
                "The GCP session with FD: %u is closed, removing session"
                "(%s) from orchestrator", fd, session.get_descriptor())
            self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                              "closed by core side", session.get_descriptor())
            self.__handle_failure(session)
        except gcp_sessions.GCPSessionError as ex:
            self.logger.error(
                "The GCP session %s failed @RX: %s, removing session from"
                "orchestrator", session.get_descriptor(), ex)
            self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                              "GCPSessionError @RX:" + str(ex), session.get_descriptor())
            self.__handle_failure(session)

        except Exception as ex:
            self.logger.error(
                "Failed to handle packet received at: %s: %s",
                session.get_descriptor(), ex)

    def wr_cb(self, fd):
        """Implements the method from the wr_cb() RCPOrchestrator interface and
        is called when the socket identified by it's file descriptor is ready
        for write prepared data."""
        i = j = 0
        try:
            session = self.sessions_active_fd[fd]
            ctx = session.get_fd_io_ctx(fd)
            self.logger.debug(
                "Sending message to the: %s",
                gcp_sessions.GCPSession.get_sock_string(ctx.socket))
        except KeyError:
            self.logger.error("wr_cb() called for non existing FD")
            return

        while not ctx.packet_tx_high_pri_queue.empty():
            try:
                res = session.send_pkt(fd)
                i = i + 1
            except gcp_sessions.GCPSessionError as ex:
                self.logger.error(
                    "The GCP session %s failed @TX: %s, removing session from"
                    "orchestrator", session.get_descriptor(), ex)
                self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                                  "GCPSessionError @TX:" + str(ex), session.get_descriptor())

                self.__handle_failure(session)
                return

            if res[0] == gcp_sessions.GCPSession.PKT_SEND_FAILED:
                self.logger.error("Failed to send packet")
                return
            elif res[0] == gcp_sessions.GCPSession.PKT_SEND_FRAGMENTED:
                # the packet couldn't be sent completely, we will wait till
                # the socket will be ready for write again
                self.logger.debug("Packet fragmented during send")
                return
            elif res[0] == gcp_sessions.GCPSession.PKT_SEND_DONE:
                continue

        old_time = time.time()
        while not ctx.packet_tx_low_pri_queue.empty():
            try:
                res = session.send_pkt(fd)
                j = j + 1
            except gcp_sessions.GCPSessionError as ex:
                self.logger.error(
                    "The GCP session %s failed: %s, removing session from"
                    "orchestrator", session.get_descriptor(), ex)
                self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                                  "GCPSessionError @TX:" + str(ex), session.get_descriptor())
                self.__handle_failure(session)
                return

            if res[0] == gcp_sessions.GCPSession.PKT_SEND_FAILED:
                self.logger.error("Failed to send packet")
                return
            elif res[0] == gcp_sessions.GCPSession.PKT_SEND_FRAGMENTED:
                # the packet couldn't be sent completely, we will wait till
                # the socket will be ready for write again
                self.logger.debug("Packet fragmented during send")
                return
            elif res[0] == gcp_sessions.GCPSession.PKT_SEND_DONE:
                current_time = time.time()
                # not expect TOD big change in GCP stage.
                if (current_time - old_time) >= self.__TIME_TO_KA and not ctx.is_tx_empty():
                    # for more packets, use timer to process, this can give time to send packet in rd_cb.
                    self.dispatcher.timer_register(
                        self.__BG_PROCESSING_PKT_TIME,
                        self.wr_cb,
                        arg=fd,
                        timer_type=DpTimerManager.TIMER_ONESHOT)
                    self.logger.debug(
                        "wr_cb hi%d, low%d, remaining hi%d, low%d"
                        % (i, j, ctx.packet_tx_low_pri_queue.qsize(),
                           ctx.packet_tx_high_pri_queue.qsize()))

                    return
                else:
                    continue

        self.logger.debug(
            "wr_cb hi%d, low%d, remaining hi%d, low%d"
            % (i, j, ctx.packet_tx_low_pri_queue.qsize(),
               ctx.packet_tx_high_pri_queue.qsize()))

        if ctx.is_tx_empty():
            if self.orch_state == self.RCP_ORCH_STATE_REDIRECT_RECEIVED:
                # we can proceed with the redirect procedure
                self.dispatcher.fd_unregister(fd)
                self._set_orch_state(
                    self.RCP_ORCH_STATE_REDIRECT_RESPONDED,
                    "TX queue of the session is empty")
            else:
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)

    def ex_cb(self, fd):
        """Implements the method from the ex_cb() RCPOrchestrator interface and
        is called when exception occurred at the socket identified by it's
        file descriptor."""
        self.logger.info("ex_cb() Slave orchestrator got exception")
        try:
            self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                              "Slave session got exception", self.sessions_active_fd[fd].get_descriptor())
            self.__handle_failure(self.sessions_active_fd[fd])
        except KeyError:
            self.logger.error("ex_cb() called for non active FD")

    def session_connecting_timeout_cb(self, session):
        """Called when the session is timeout connecting to the core."""

        session.connecting_timer = None
        if None is not session:
            if session.is_initiated():
                session.connecting_retry = 0
                return
            else:
                session.connecting_retry += 1
                if session.connecting_retry <= session.CORE_CONNECT_RETRY_COUNT:
                    self.logger.info("Session: %s retry %d times",
                                     session.get_descriptor(), session.connecting_retry)

                    # reconnect
                    session.update_reconnect_cnt()
                    session.close()
                    session.reinit()
                    session.initiate()
                else:
                    self.logger.warning("Session connecting finally failed: %s",
                                        session.get_descriptor())
                    self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                                      "connecting timeout", session.get_descriptor())
                    self.__handle_failure(session)

    def session_timeout_cb(self, session):   # pragma: no cover
        """Called when the session is timeout due to lost GDM Messages."""
        # fixme by zhicwang, remove it when CSCva40098 is resolved
        return

        if session.get_descriptor().get_uniq_id() not in self.sessions_active:
            self.logger.info("Session timeout failed: %s",
                             session.get_descriptor())
            return

        if session.RCP_RCV_SYNC is session.keep_alive:
            session.keep_alive = session.RCP_WAIT_FOR_SYNC
        elif session.RCP_WAIT_FOR_SYNC is session.keep_alive:
            self.logger.info("Session timeout callback: %s",
                             session.get_descriptor())
            self.notify.error(rpd_event_def.RPD_EVENT_GCP_FAILED_EVENT[0],
                              "session timeout!!!", session.get_descriptor())
            self.__handle_failure(session)

    def session_initiate_cb(self, session):
        """Is passed as an argument when the initiation of the session is
        started and is called when the initiation of the session is done."""
        self.logger.info("Session initiated callback: %s",
                         session.get_descriptor())
        if session.get_descriptor().get_uniq_id() not in self.sessions_active:
            self.logger.info("Session initiation failed: %s",
                             session.get_descriptor())
            return

        try:
            session.timeout_timer = session.dispatcher.timer_register(
                session.TIMEOUT_TIME, session.timeout_cb, arg=session,
                timer_type=DpTimerManager.TIMER_REPEATED)
        except Exception as e:
            self.logger.error("start the GDM KA timer fail: %s" % str(e))

        self.logger.debug("RCP Slave session has been initiated")
        session.session_state = RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED

        # Send NotifyREQ to the master
        if self.rcp_process_channel and \
                hasattr(self.rcp_process_channel, "hal_ipc") and self.rcp_process_channel.hal_ipc\
                and hasattr(self.rcp_process_channel.hal_ipc, "rpd_cap") and self.rcp_process_channel.hal_ipc.rpd_cap:
            ntf_req = self.pkt_director.get_notify_request_packet(session, cap=self.rcp_process_channel.hal_ipc.rpd_cap)
        else:
            ntf_req = self.pkt_director.get_notify_request_packet(session)
        session.io_ctx.add_tx_packet(ntf_req)
        fd = session.get_socket_fd()
        self.dispatcher.fd_register(
            fd, self.dispatcher.MASK_ALL, self.session_ev_cb)
        # add it into the sessions_active_fd
        self.sessions_active_fd[fd] = session

        self.__send_mgr_session_initiated(session)

        session.clear_reconnect_cnt()
        self.logger.info("Session initiated: %s", session.get_descriptor())

    def _set_orch_state(self, new_state, debug_str=None):
        """Change orchestration state."""
        self.logger.debug("Changing orchestration state: FROM: %s TO: %s%s",
                          self._state_to_str(self.orch_state),
                          self._state_to_str(new_state),
                          "" if None is debug_str else " %s" % debug_str)
        self.orch_state = new_state

    def __handle_connect(self, session):
        """Handle a connecting session."""
        if session.get_descriptor().get_uniq_id() not in self.sessions_active:
            self.logger.info("Session connect handle failed: %s",
                             session.get_descriptor())
            return
        self.logger.debug("Session is in connecting: %s", session.get_descriptor())

        try:
            ret = session.start_and_check_connect()
            if ret in [0, errno.EINPROGRESS, errno.EALREADY]:
                session.session_state = session.SESSION_STATE_INPROCESS
            elif ret == errno.EISCONN:
                session.session_state = session.SESSION_STATE_GCP_SLAVE_INITIATED
                session.initiated_cb(session)
            else:
                session.session_state = session.SESSION_STATE_FAILED
                self.logger.error(
                    "GCP slave session %s initiation failed: %s",
                    session.get_descriptor(), errno.errorcode[ret])
        except socket.error as ex:
            self.logger.error("GCP slave session initiation failed: %s", ex)
            session.session_state = session.SESSION_STATE_FAILED

    def __send_mgr_session_initiated(self, session):
        msg = t_RcpMessage()
        msg.RcpMessageType = msg.SESSION_INITIATED
        desc = session.get_descriptor()
        ccap_core_para = {'addr_remote': None, 'interface_local': None}
        if None is not desc.addr_remote:
            ccap_core_para['addr_remote'] = desc.addr_remote
        if None is not desc.interface_local:
            ccap_core_para['interface_local'] = desc.interface_local
        msg.parameter = json.dumps(ccap_core_para)
        self.logger.info("GCP send notification session_initiated to Rcp agent for %s", desc)
        self.rcp_process_channel.send_ipc_msg({"session": session,
                                               "req_packet": None,
                                               "req_data": msg})

    def __handle_failure(self, session):
        """Handle a failed session."""
        self.logger.info("Session failed: %s", session.get_descriptor())

        # fault management notify
        self.notify.error(rpd_event_def.RPD_EVENT_CONNECTIVITY_GCP_FAILURE[0],
                          rpd_event_def.RpdEventTag.ccap_ip(session.get_descriptor().addr_remote))
        for fd, s in self.sessions_active_fd.items():
            if session == s:
                # delete the FD from the list
                del self.sessions_active_fd[fd]

        # reconnect
        reconnect = False
        if session.connecting_retry <= session.CORE_CONNECT_RETRY_COUNT:
            reconnect = True

        if session.is_reconnect_timeout():
            session.clear_reconnect_cnt()
            timeout_msg = t_RcpMessage()
            timeout_msg.RcpMessageType = timeout_msg.CONNECT_CLOSE_NOTIFICATION
            desc = session.get_descriptor()
            ccap_core_para = {'addr_remote': None, 'interface_local': None, "reconnect": reconnect}
            if None is not desc.addr_remote:
                ccap_core_para['addr_remote'] = desc.addr_remote
            if None is not desc.interface_local:
                ccap_core_para['interface_local'] = desc.interface_local
            timeout_msg.parameter = json.dumps(ccap_core_para)
            self.logger.info("send timeout notification to Rcp agent for %s, reconnect %s", desc, reconnect)
            self.rcp_process_channel.send_ipc_msg({"session": session,
                                                   "req_packet": None,
                                                   "req_data": timeout_msg})

        if reconnect:
            self.logger.warn("Reconnect session: %s", session.get_descriptor())
            session.connecting_retry += 1
            session.update_reconnect_cnt()
            session.close()
            session.reinit()
            session.initiate()
            return

        # delete from active sessions
        sid = session.get_descriptor().get_uniq_id()
        del self.sessions_active[sid]
        # close session
        session.close()

    def __next_principal_candidate(self):   # pragma: no cover
        """Closes the session with current principal candidate if it's not
        principal CCAP core and initiates session with new principal candidate.
        """
        if None is not self.principal_candidate:
            fd = self.principal_candidate.get_socket_fd()
            self.principal_candidate.close()
            if fd in self.sessions_active_fd:
                del self.sessions_active_fd[fd]
            self.non_principals.append(self.principal_candidate)
            # reinit the session to for further usage when the principal
            # core will be known
            self.principal_candidate.reinit()
            self.principal_candidate = None

        if not self.sessions_active:
            self.logger.debug("No any active session")
            return

        if len(self.non_principals) == len(self.sessions_active):
            # all active sessions walked and no any principal core has
            # been found
            # Set all active sessions as failed
            self.logger.error("Principal active CCAP core not found")
            for uid, session in self.sessions_active.items():
                session.close()
                self.sessions_failed[uid] = session
            self.sessions_active.clear()
            return

        # find a session which was not a principal candidate and try
        for uid, session in self.sessions_active.items():
            if session not in self.non_principals:
                if session.is_initiated():
                    # TODO how to handle this case ?
                    self.logger.debug("Session %s already initiated, "
                                      "reinitiating the session",
                                      session.get_descriptor())
                    session.close()
                    session.reinit()

                self.principal_candidate = session

                self.principal_candidate.initiate()
                self.logger.debug("Next candidate for Principal active: %s",
                                  self.principal_candidate.get_descriptor())
                return

        # can't find next candidate for principal active
        self.logger.error("Unexpected state")

    def _orchestrate(self):
        """Orchestrates slave sessions according to the orchestrator's
        state.

        Called for these events:
         * failed to get CCAP core capabilities
         * when some session was removed
         * periodically

        """

        if self.orch_state == self.RCP_ORCH_STATE_REDIRECT_RECEIVED:
            # we have just received the redirect, we are waiting till
            # we respond to the request
            if len(self.sessions_active_fd) == 0:
                self._set_orch_state(self.RCP_ORCH_STATE_REDIRECT_RESPONDED,
                                     "No any active session")
                # FixMe: delay this action until message responded
                # self._redir_resp_session = None
            return
        if self.orch_state == self.RCP_ORCH_STATE_REDIRECT_RESPONDED:
            # remove all sessions
            if self._redir_resp_session in self.principal:
                self.principal.remove(self._redir_resp_session)
            self.principal_candidate = None
            self._set_orch_state(self.RCP_ORCH_STATE_LOOKING_FOR_PRINCIPAL,
                                 "Starting to use redirection list")

            redirect_msg = t_RcpMessage()
            redirect_msg.RcpMessageType = redirect_msg.REDIRECT_NOTIFICATION

            # set the redirected core as the first ip in the list, others are the cores redirect to
            desc = self._redir_resp_session.get_descriptor()
            # self.remove_sessions([desc, ])

            ccap_core_para = {'addr_remote': None, 'interface_local': None}
            if None is not desc.addr_remote:
                ccap_core_para['addr_remote'] = desc.addr_remote
            if None is not desc.interface_local:
                ccap_core_para['interface_local'] = desc.interface_local
            redirect_msg.parameter = json.dumps(ccap_core_para)

            for addr in self._redir_addr_list:
                redirect_msg.RedirectCCAPAddresses.append("{}".format(addr[0]))
            # send redirect message to agent
            self.rcp_process_channel.send_ipc_msg(
                {"session": self._redir_resp_session,
                 "req_packet": None,
                 "req_data": redirect_msg
                 })

            self._redir_addr_list = None
            self._redir_resp_session = None

        else:
            if not self.sessions_active:
                self.logger.debug("No any active session")
                return

            for uid, session in self.sessions_active.items():
                if not session.is_initiated():
                    self.__handle_connect(session)
                else:
                    caps = session.ccap_identification
                    if None is caps:
                        self.logger.debug(
                            "Session %s is initiated, but waiting for CCAP core capabilities.",
                            session.get_descriptor())
                    else:
                        self.logger.debug("Session(%s) initiated: Principal: %s",
                                          session.get_descriptor(), caps.is_principal)

    def orchestrate_cb(self, arg):
        """Implements the method from the GCPSessionOrchestrator interface."""
        try:
            self._orchestrate()
        except Exception as ex:
            self.logger.debug("Orchestration failed, exception: %s", ex)
        # continue with orchestration
        self.__orchestration_start()

    def add_sessions(self, session_descriptors):
        """Implements the method from the GCPSessionOrchestrator interface.

        :param session_descriptors: List of instances of the GCPSlaveDescriptor

        """
        for desc in session_descriptors:
            if not isinstance(desc, gcp_sessions.GCPSlaveDescriptor):
                raise TypeError("Invalid session descriptor passed. "
                                "Only instances of the GCPSlaveDescpriptors "
                                "are supported.")

            if desc.get_uniq_id() in self.sessions_active:
                self.logger.info("RCP session: %s is already active, don't "
                                 "need to proceed.", desc)
                continue

            if desc.get_uniq_id() in self.sessions_failed:
                self.logger.info(
                    "RCP session: %s is already failed, moving to the "
                    "list of active sessions.", desc)
                del self.sessions_failed[desc.get_uniq_id()]
            else:
                self.logger.info("Adding new session: %s", desc)

            # just create the instance and store
            # initiation will be started in the orchestrate_cb()
            session = RCPSlaveSession(desc, self.dispatcher,
                                      self.session_initiate_cb,
                                      self.session_timeout_cb,
                                      self.session_connecting_timeout_cb)
            self.sessions_active[desc.get_uniq_id()] = session

            # session operation
            session.initiate()
            self.logger.debug("Candidate for Principal active: %s",
                              session.get_descriptor())
            # orchestrate the current state
            # We can't call orchestration here, because it will try to
            # connect to CCAP core before the dispatcher.loop()
            # self._orchestrate()

    def remove_sessions(self, session_descriptors):
        """Implements the method from the GCPSessionOrchestrator interface.

        :param session_descriptors: List of instances of the
         GCPSlaveSessionDescriptor.

        """
        for desc in session_descriptors:
            if not isinstance(desc, gcp_sessions.GCPSlaveDescriptor):
                raise TypeError("Invalid session descriptor passed. "
                                "Only instances of the GCPSlaveDescpriptors "
                                "are supported.")

            # remove from the list of active sessions if exists
            try:
                if desc.get_uniq_id() in self.sessions_active:
                    self.logger.info(
                        "RCP session: %s removing from the list of "
                        "active sessions.", desc)

                    ses = self.sessions_active[desc.get_uniq_id()]

                    try:
                        del self.sessions_active_fd[ses.get_socket_fd()]
                    except Exception:
                        self.logger.debug(
                            "GCP sessions: %s is not part of active "
                            "sessions FDs list.", desc)

                    ses.close()
                    del self.sessions_active[desc.get_uniq_id()]
                    continue

                # remove from the list of failed sessions if exists
                if desc.get_uniq_id() in self.sessions_failed:  # pragma: no cover
                    self.logger.info(
                        "RCP session: %s removing from the list of "
                        "failed sessions.", desc)
                    del self.sessions_failed[desc.get_uniq_id()]
            except Exception as ex:
                self.logger.error(
                    "Session (%s) remove failed: %s",
                    desc.get_uniq_id(), ex)

        # orchestrate the current state
        self._orchestrate()

    def remove_sessions_all(self):
        """Removes all sessions which are orchestrated by this instance.
        Walks all active and failed sessions and creates list of their
        descriptors, which is then passed into the remove_sessions() method.
        """
        d_list = []
        for session in self.sessions_active.values():
            d_list.append(session.get_descriptor())
        for session in self.sessions_failed.values():   # pragma: no cover
            d_list.append(session.get_descriptor())

        # remove all
        self.remove_sessions(d_list)
        self.logger.info("All RCP sessions removed")

    def remove_sessions_by_core(self, interface, ccap_core):
        """Removes all sessions which are orchestrated by this instance.

        Walks all active and failed sessions and creates list of their
        descriptors, which is then passed into the remove_sessions()
        method.

        """
        d_list = []
        for session in self.sessions_active.values():
            desc = session.get_descriptor()
            if desc.addr_remote == ccap_core and desc.interface_local == interface:
                d_list.append(desc)
        for session in self.sessions_failed.values():   # pragma: no cover
            desc = session.get_descriptor()
            if desc.addr_remote == ccap_core and desc.interface_local == interface:
                d_list.append(desc)

        # remove by core
        self.remove_sessions(d_list)
        self.logger.info("RCP sessions (%s, %s) removed", interface, ccap_core)
