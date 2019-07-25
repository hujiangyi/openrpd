#!/usr/bin/python
#
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
#

import time
import Queue
from google.protobuf.message import Message as GPBMessage

from rpd.rcp.rcp_sessions import *
from rpd.rcp.rcp_packet_director import *
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPDecodeError
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.rcp.rcp_orchestrator import RCPOrchestrator, log_measured_values
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification


class RCPMasterOrchestrator(RCPOrchestrator):

    """Implements orchestrating class for RCPMasters. More than one RCPMaster
    can be orchestrated by one instance of this class.

    Uses object of the class dispatcher.Dispatcher to register for
    certain events.

    """
    __metaclass__ = AddLoggerToClass
    _PKT_DIRECTOR = RCPMasterPacketBuildDirector()

    _DEFAULT_SCENARIO = RCPMasterScenario()
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.get_rpd_capabilities_read_packet,
                 description="DEFAULT: Read RPD Capabilities"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.get_ccap_core_ident_write_packet,
                 description="DEFAULT: Write CCAP Capabilities"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.get_gdm_packet,
                 description="DEFAULT: GDM Request Message"))

    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.send_initial_complete_packet,
                 description="DEFAULT: Write Initial Configuration Complete Message"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.send_ptp_config_packet,
                 description="DEFAULT: Send PTP Configuration Message"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.send_config_done_packet,
                 description="DEFAULT: Send Configuration Done Message"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.send_ds_static_l2tp_packet,
                 description="DEFAULT: Send DS Static L2TP Message"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.send_us_static_l2tp_packet,
                 description="DEFAULT: Send US Static L2TP Message"))
    _DEFAULT_SCENARIO.add_next_step(
        CCAPStep(_PKT_DIRECTOR.send_multiple_core_add_packet,
                 description="DEFAULT: Send Multiple Core Add Message"))

    _DEFAULT_SCENARIO.add_trigger_step(
        CCAPStep(_PKT_DIRECTOR.move_to_operational_write_packet,
                 description="DEFAULT: Send Move To Operational Message"),
        "ptp_notify")

    class RCPDataForSlave(object):
        """Class is used to store configuration in GPB format and store also
        GCP message ID, RCP message ID and RCP operation type which will be
        used to encapsulate the configuration which will be sent to the
        slave identified by slave descriptor."""

        def __init__(self, slave_descriptor, gpb_data,
                     gcp_message_id=gcp_msg_def.DataStructREQ,
                     rcp_message_id=rcp_tlv_def.RCP_MSG_TYPE_REX,
                     rcp_operation=rcp_tlv_def.RCP_OPERATION_TYPE_WRITE):
            """

            :param slave_descriptor: The session descriptor of the slave, where
             the remote IP:port identifies Master which sends the data and
             local IP:port identifies destination slave.
            :type slave_descriptor: GCPSlaveDescriptor
            :param gpb_data: GPB message including configuration to be sent
            :type gpb_data: GCPMessage
            :param gcp_message_id: ID of the GCP message used to encapsulate
             RCP message and configuration
            :param rcp_message_id: ID of the RCP message used to encapsulate
             the RCP sequence with the configuration.
            :param rcp_operation: The operation type which should be performed
             with the configuration.

            """
            if (None is not slave_descriptor and
                    not isinstance(slave_descriptor,
                                   gcp_sessions.GCPSlaveDescriptor)):
                raise TypeError()
            if not isinstance(gpb_data, GPBMessage):
                raise TypeError()

            if gcp_message_id not in gcp_msg_def.GCP_MSG_SET.child_dict_by_id:
                raise AttributeError("Invalid GCP message ID: {}".format(
                    gcp_message_id))
            if rcp_message_id not in rcp_tlv_def.RCP_MSG_TYPES:
                raise AttributeError("Invalid RCP message ID: {}".format(
                    rcp_message_id))
            if rcp_operation not in rcp_tlv_def.RCP_OPERATION_TYPES:
                raise AttributeError("Invalid RCP operation: {}".format(
                    rcp_operation))

            self.slave_descriptor = slave_descriptor
            self.gpb_data = gpb_data
            self.gcp_message_id = gcp_message_id
            self.gcp_message_name = \
                gcp_msg_def.GCP_MSG_SET.child_dict_by_id[gcp_message_id].name
            self.rcp_message_id = rcp_message_id
            self.rcp_message_name = rcp_tlv_def.RCP_MSG_DICT[rcp_message_id]
            self.rcp_operation = rcp_operation

    class RPDMeasuringData(object):
        """Stores data used for internal measurement of RTT of the REQ/RSP
        pair."""

        def __init__(self, gcp_packet):
            # measurement
            self.transaction_id = gcp_packet.transaction_identifier
            self.gcp_messages = []
            for msg in gcp_packet.msgs:
                self.gcp_messages.append((msg.message_id, msg.message_name))

            self.start_time = None
            self.end_time = None

    __ORCHESTRATION_TIME = 1  # second

    def __init__(self, disp):
        """Implements the method from the RCPOrchestrator interface.
        Initializes also queue for data which will be sent to connected slaves
        and initializes also dictionary of measured data and starts the
        orchestration.

        :param disp: The instance of dispatcher

        """
        super(RCPMasterOrchestrator, self).__init__(disp)

        # Data to send queues
        self.data_to_send = Queue.Queue()
        self.data_to_send_no_wait = Queue.Queue()

        self.data_to_measure = {}
        self.__orchestration_start()

    def add_data_to_send(self, data):
        """Inserts data for slaves into the queue and only one piece of data
        (one instance) is sent at the same time.

        :param data: Configuration and encapsulation parameters.
        :type data: RCPDataForSlave
        :return:

        """
        if not isinstance(data, self.RCPDataForSlave):
            raise TypeError()
        self.data_to_send.put_nowait(data)
        self.logger.info("Added data to be sent to the slave: %s",
                         data.slave_descriptor)

    def _get_data_to_send(self):
        """Removes data from queue and returns them."""
        if self.data_to_send.empty():
            return None
        return self.data_to_send.get_nowait()

    def add_data_to_send_no_wait(self, data):
        """Inserts data for slaves into the queue and all data are sent at the
        same time when the destination slave has been connected.

        :param data: Configuration and encapsulation parameters.
        :type data: RCPDataForSlave
        :return:

        """
        if not isinstance(data, self.RCPDataForSlave):
            raise TypeError()
        self.data_to_send_no_wait.put_nowait(data)
        self.logger.info("Added data to be sent to the slave in bulk: %s",
                         data.slave_descriptor)

    def _get_data_to_send_no_wait(self):
        """Removes data from queue and returns them."""
        if self.data_to_send_no_wait.empty():
            return None
        return self.data_to_send_no_wait.get_nowait()

    def add_data_to_measure(self, data, fd):
        """Stores data in the dict of format:

         * file_descriptor: transaction_id: list_of_data

        Also sets time when the data were stored.

        """
        if not isinstance(data, self.RPDMeasuringData):
            raise TypeError()

        self.logger.debug("Add measurement data, fd: %s" % fd)

        if fd in self.data_to_measure:
            master_data_dict = self.data_to_measure[fd]
        else:
            self.data_to_measure[fd] = dict()
            master_data_dict = self.data_to_measure[fd]

        if data.transaction_id in master_data_dict:
            data_list = master_data_dict[data.transaction_id]
        else:
            data_list = []
            master_data_dict[data.transaction_id] = data_list

        data.start_time = time.time()
        data_list.append(data)

    def measure_time(self, transaction_id, fd):
        """Saves current time for the transaction_id and file descriptor passed
        as arguments."""
        try:
            master_data = self.data_to_measure[fd]
            if not master_data:
                return None

            data_list = master_data[transaction_id]
            if not data_list:
                return None
        except KeyError:
            return None

        for data in data_list:
            data.end_time = time.time()

    def get_measured_data(self, transaction_id, fd):
        """Returns measured data with the end_time set to the time when
        this method was called last time."""
        self.logger.debug("Get measurement data, fd: %s" % fd)

        try:
            master_data = self.data_to_measure[fd]
            if not master_data:
                return None

            data_list = master_data[transaction_id]
            if not data_list:
                return None
        except KeyError:
            return None

        return data_list

    def log_measured_data(self, data_list):
        """Prints measured data into the self.logger.debug."""
        if not data_list:
            self.logger.debug("No any measured data")
        else:
            for data in data_list:
                if (None is data.start_time or
                        None is data.end_time):
                    self.logger.debug("Measured delay MSGs: %s, transaction "
                                      "%u: start: %s, end: %s" %
                                      (data.gcp_messages, data.transaction_id,
                                       data.start_time, data.end_time))
                    return

                t = data.end_time - data.start_time
                t_sec = t
                t_msec = (t % 1) * 1000
                t_usec = (t_msec % 1) * 1000
                t_nsec = (t_usec % 1) * 1000

                self.logger.debug("Measured delay MSGs: %s, transaction "
                                  "%u: %uS %umS %uuS %unS (%.6f)" %
                                  (data.gcp_messages, data.transaction_id,
                                   t_sec, t_msec, t_usec, t_nsec, t_sec))

    def execute_scenario_step(self, master, slave_ctx, slave_fd,
                              scenario_step):
        # TODO move this into the rcp_msg_handling.py
        """Runs the master_dir_method from scenario_step and passes to it all
        mandatory parameters and also optional parameters if exists.
        The resulting packet(s) are inserted into the TX-queue of the
        slave's connection and file descriptor is registered also for write.

        :param master: RCPMasster session.
        :param slave_ctx: Context of the slave's connection.
        :type slave_ctx: RCPMaster.RCPMasterConnectionContext
        :param slave_fd: File descriptor of the slave's connection.
        :param scenario_step: One ste from the slave's scenario.
        :type scenario_step: CCAPStep

        """
        if None is scenario_step:
            self.logger.debug("No any scenario step")
            return

        self.logger.info("Processing scenario step for master: %s, slave: %s, "
                         "slave_fd: %s, description: %s",
                         master.get_descriptor(),
                         gcp_sessions.GCPSession.get_sock_string(slave_ctx.socket),
                         slave_fd, scenario_step.description)
        if scenario_step.param_tuple:
            result = scenario_step.master_dir_method(
                master,
                slave_fd,
                *scenario_step.param_tuple)
        else:
            result = scenario_step.master_dir_method(master, slave_fd)

        if not isinstance(result, list):
            result = [result, ]

        for tx_packet in result:
            slave_ctx.add_tx_packet(tx_packet)

        # register for all
        self.dispatcher.fd_modify(slave_fd, self.dispatcher.MASK_ALL)

    def _packet_decode(self, session, ctx, packet):
        """Decodes data in packet and returns the decoded packet"""
        try:
            result = packet.decode()
        except GCPDecodeError:
            self.logger.error("Packet decoding failed")
            session.RxDecodeFail += 1
            return None

        # if the GCP packet is fragmented, store the fragment and
        # return None
        if result == GCPObject.DECODE_FRAGMENTED:
            self.logger.info("GCP packet is fragmented, store the fragment")
            session.RxDecodeFrag += 1
            ctx.packet_fragment = packet
            return None

        # if the decoding is not done, handle it as failure
        if result != GCPObject.DECODE_DONE:
            self.logger.error("Decoding of received GCP packet failed, result: %s",
                              result)
            session.RxDecodeFail += 1
            return None

        return packet

    def rd_cb(self, fd):
        """Implements the method from the RCPOrchestrator interface.

        This method is called when some data have been received at the
        socket identified by file descriptor. The data are read and
        related processing methods are called. Method is also called
        when new slave is connecting to the master, the connection is
        accepted in this case a the new connection is inserted into the
        self.sessions_active_fd dictionary.

        """
        try:
            master = self.sessions_active_fd[fd]
        except KeyError:
            self.logger.error("rd_cb() called for non existing FD")
            return

        if master.get_socket_fd() == fd:
            # accept new connection
            slave_fd = master.accept_connection()
            if None is slave_fd:
                self.logger.error("Connection acceptance failed")
                return

            # save the FD for the master session and register FD for read
            self.sessions_active_fd[slave_fd] = master
            self.dispatcher.fd_register(slave_fd,
                                        self.dispatcher.MASK_RD_ERR,
                                        self.session_ev_cb)
        else:
            # read message from the slave
            slave_ctx = master.get_fd_io_ctx(fd)
            self.logger.debug("Received message from: %s",
                              gcp_sessions.GCPSession.get_sock_string(
                                  slave_ctx.socket))

            try:
                pkt = master.read_pkt(fd)
                if None is not pkt:
                    pkt = self._packet_decode(master, slave_ctx, pkt)

                while None is not pkt:

                    if not pkt.msgs:
                        self.logger.error("Received empty packet")
                        pkt = master.read_pkt(fd)
                        if None is not pkt:
                            pkt = self._packet_decode(master, slave_ctx, pkt)
                        continue

                    # Store received response for testing purposes
                    master.add_response(pkt, fd)

                    for msg in pkt.msgs:
                        self.logger.debug("Processing message: %s (%u)",
                                          msg.message_name, msg.message_id)

                        self.measure_time(pkt.transaction_identifier, fd)
                        m_data = \
                            self.get_measured_data(pkt.transaction_identifier,
                                                   fd)
                        self.log_measured_data(m_data)

                        if msg.message_id == gcp_msg_def.NotifyREQ:
                            # send redirect or RPD capabilities
                            self.logger.info("Received NotifyREQ")

                            # Run the scenario step if exists
                            ptp_ok = False
                            for rcp_msg in msg.tlv_data.rcp_msgs:
                                for sequence in rcp_msg.sequences:
                                    val = getattr(sequence.parent_gpb, "GeneralNotification")
                                    if val.NotificationType is t_GeneralNotification.PTPRESULTNOTIFICATION \
                                            and val.PtpResult is t_GeneralNotification.PTPSYNCHRONIZED:
                                        ptp_ok = True

                            if not ptp_ok:
                                scenario_step = master.slave_cons[fd]. \
                                    scenario_steps.get_step_next()
                            else:
                                scenario_step = master.slave_cons[fd]. \
                                    scenario_steps.get_ntf_event_step("ptp_notify")
                            self.execute_scenario_step(master, slave_ctx,
                                                       fd, scenario_step)

                        elif (msg.message_id == gcp_msg_def.DataStructRSP):
                            self.logger.info("Received DataStructRSP")

                            # Run the scenario step if exists
                            scenario_step = master.slave_cons[fd]. \
                                scenario_steps.get_step_next()
                            self.execute_scenario_step(master, slave_ctx,
                                                       fd, scenario_step)

                            # also send a gdm msg here
                            # scenario_step = master.slave_cons[fd]. \
                            #     scenario_steps.get_step_next()
                            # self.execute_scenario_step(master, slave_ctx,
                            #                            fd, scenario_step)

                        elif (msg.message_id == gcp_msg_def.ManagementRSP):
                            self.logger.info("Received RPD device management response")

                            # Run the scenario step if exists
                            scenario_step = master.slave_cons[fd]. \
                                scenario_steps.get_step_next()
                            self.execute_scenario_step(master, slave_ctx,
                                                       fd, scenario_step)
                        else:
                            self.logger.warning("# TODO !!!")
                            self.logger.warning(
                                "# Handling of the message not implemented")
                            self.logger.warning("# TODO !!!")

                    pkt = master.read_pkt(fd)
                    if None is not pkt:
                        pkt = self._packet_decode(master, slave_ctx, pkt)
                    # TODO add handling of the GCP messages

            except gcp_sessions.GCPSessionClosed:
                self.logger.debug("Connection with FD: %u closed, "
                                  "removing from master", fd)
                log_measured_values(self)

                try:
                    master.remove_connection(fd)
                except:
                    self.logger.error("Failed to remove connection from master, "
                                      "closing the master %s",
                                      master.get_descriptor())
                    self.__handle_failure(master)
            except gcp_sessions.GCPSessionError as ex:
                self.logger.error(
                    "Session %s failed: %s", master.get_descriptor(), ex)
                self.__handle_failure(master)

    def wr_cb(self, fd):
        """Implements the method from the RCPOrchestrator interface.
        Is called when the socket identified by file descriptor is prepared
        for write and the prepared packet is sent."""
        try:
            master = self.sessions_active_fd[fd]
            ctx = master.get_fd_io_ctx(fd)
            self.logger.debug(
                "Sending message to the: %s" %
                gcp_sessions.GCPSession.get_sock_string(ctx.socket))
        except KeyError:
            self.logger.error("wr_cb() called for non existing FD")
            return

        try:
            res = master.send_pkt(fd)
        except gcp_sessions.GCPSessionError as ex:
            self.logger.error(
                "Session %s failed: %s", master.get_descriptor(), ex)
            self.__handle_failure(master)

        if res[0] == gcp_sessions.GCPSession.PKT_SEND_FAILED:
            self.logger.error("Failed to send packet")
        elif res[0] == gcp_sessions.GCPSession.PKT_SEND_DONE:
            # Get data to be measured and set the start to now and end to
            # None so we will measure the RoundTripTime of REQ and RSP
            if None is not res[1]:
                m_data_list = \
                    self.get_measured_data(res[1].transaction_identifier, fd)
                if m_data_list:
                    for m_data in m_data_list:
                        m_data.start_time = time.time()
                        m_data.end_time = None

            # if the TX queue is empty, then unregister for write
            # it it's not empty, then call this method recursively
            if ctx.is_tx_empty():
                self.dispatcher.fd_modify(fd, self.dispatcher.MASK_RD_ERR)
            else:
                self.wr_cb(fd)
        elif res[0] == gcp_sessions.GCPSession.PKT_SEND_FRAGMENTED:
            # the packet couldn't be sent completely, we will wait till
            # the socket will be ready for write again
            self.logger.debug("Packet fragmented during send")

    def ex_cb(self, fd):
        """Implements the method from the RCPOrchestrator interface.
        This method is called when some exception occurred on the socket
        identified by the file descriptor."""
        try:
            master = self.sessions_active_fd[fd]
            if master.get_socket_fd() == fd:
                # master session has failed
                self.logger.error("Master session %s has failed" %
                                  (master.get_descriptor()))
                self.__handle_failure(master)
            else:
                # master's slave connection has failed
                ctx = master.get_fd_io_ctx(fd)
                self.logger.error("Master's (%s) connection to slave (%s) has failed",
                                  master.get_descriptor(),
                                  (None if None is ctx else
                                   gcp_sessions.GCPSession.get_sock_string(
                                       ctx.socket)))
                master.remove_connection(fd)

        except KeyError:
            self.logger.error("ex_cb() called for non existing FD")

    def __handle_failure(self, session):
        session.close()
        # delete all items from the sessions_active_fd
        for fd, master in self.sessions_active_fd.items():
            if master == session:
                del self.sessions_active_fd[fd]

        sid = session.get_descriptor().get_uniq_id()
        del self.sessions_active[sid]
        self.sessions_failed[sid] = session

    def __orchestration_start(self):
        # register timer for periodical call of the orchestrate_cb
        self.orchestrate_timer = \
            self.dispatcher.timer_register(self.__ORCHESTRATION_TIME,
                                           self.orchestrate_cb)

    def _orchestrate(self):
        # walk all sessions and initiate new sessions or move failed sessions
        # from active to failed list
        for sid, session in self.sessions_active.items():
            if not session.is_started():
                session.initiate()
                if session.is_initiated():
                    self.sessions_active_fd[session.get_socket_fd()] = session
                    self.dispatcher.fd_register(session.get_socket_fd(),
                                                self.dispatcher.MASK_RD_ERR,
                                                self.session_ev_cb)

            if session.is_session_failed():
                self.__handle_failure(session)

    def _get_master(self, addr, port):
        for master in self.sessions_active.values():
            try:
                addr_port = master.io_ctx.socket.getsockname()
                if addr_port[0] == addr and addr_port[1] == port:
                    return master
            except:
                self.logger.debug("Failed to get IP and port of the: %s",
                                  master.descr)
        return None

    @staticmethod
    def _get_slave_fd(master, addr, port):
        for fd, ctx in master.slave_cons.items():
            try:
                addr_port = ctx.socket.getpeername()
                if addr_port[0] == addr:  # and addr_port[1] == port:
                    return fd
            except:
                RCPOrchestrator.logger.debug(
                    "Failed to get IP and port of the slave with FD: %s", fd)
        return None

    def _send_data_from_master_to_slave(self, master, slave_fd, data):
        # TODO we assume root config GPB here
        seq = rcp.RCPSequence(data.gcp_message_id, data.rcp_message_id,
                              master.slave_cons[slave_fd].get_next_seq_id(),
                              data.rcp_operation, data.gpb_data)

        rcp_msg = rcp.RCPMessage(data.gcp_message_id, data.rcp_message_id)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(data.gcp_message_id)
        # TODO implement correct setting of message fields
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)
        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        # Add packet into the tx queue and register for write
        master.slave_cons[slave_fd].add_tx_packet(pkt)
        self.dispatcher.fd_modify(slave_fd, self.dispatcher.MASK_ALL)

        # store data for measuring
        m_data = self.RPDMeasuringData(pkt)
        self.add_data_to_measure(m_data, slave_fd)

    def _prepare_data_to_be_sent(self, data):
        if None is not data.slave_descriptor:
            # use the remote address of the slave as ID of master
            master_ip = data.slave_descriptor.addr_remote
            master_port = data.slave_descriptor.port_remote
            slave_ip = data.slave_descriptor.addr_local
            slave_port = data.slave_descriptor.port_local

            master = self._get_master(master_ip, master_port)
            if None is master:
                self.logger.error("Failed to find Master: %s:%u",
                                  master_ip, master_port)
                return

            slave_fd = self._get_slave_fd(master, slave_ip, slave_port)
            if None is slave_fd:
                self.logger.error("Failed to find Master's ({}:{}) "
                                  "slave: {}:{}".format(master_ip, master_port,
                                                        slave_ip, slave_port))
                return

            self._send_data_from_master_to_slave(master, slave_fd, data)

            self.logger.debug("Data prepared to send from "
                              "Master (%s:%u) to Slave (%s:%u)",
                              master_ip, master_port,
                              slave_ip, slave_port)
        else:
            self.logger.debug(
                "Data without slave descriptor, will be sent to all")
            for m_id, master in self.sessions_active.items():
                self.logger.debug(
                    "Sendig data to slaves of the master %s" % m_id)
                for slave_fd, ctx in master.slave_cons.items():
                    self._send_data_from_master_to_slave(master,
                                                         slave_fd, data)
                    self.logger.debug(
                        "Data prepared to be sent to slave %s",
                        gcp_sessions.GCPSession.get_sock_string(
                            ctx.socket))

    def _send_data_to_slave(self):
        data = self._get_data_to_send()
        if None is data:
            return

        self._prepare_data_to_be_sent(data)
        self.logger.info("Data for slave %s inserted into the TX queue",
                         data.slave_descriptor)

    def _send_data_to_slave_no_wait(self):
        data = self._get_data_to_send_no_wait()
        if None is data:
            return

        packets = 0
        while None is not data:
            self._prepare_data_to_be_sent(data)
            data = self._get_data_to_send_no_wait()
            packets += 1
        self.logger.info("Data for slaves in %u packets are inserted into the "
                         "TX queue", packets)

    def orchestrate_cb(self, arg):
        """Implements the method from the GCPSessionOrchestrator interface.

        Removes data from queues and sends them to the slaves.

        """
        self._orchestrate()

        # send some data to slaves if any
        if len(self.sessions_active_fd) > len(self.sessions_active):
            self._send_data_to_slave()
            self._send_data_to_slave_no_wait()

        self.__orchestration_start()

    def add_sessions(self, session_descriptors):
        """Implements the method from the GCPSessionOrchestrator interface.

        Instantiates new RCPMaster sessions and inserts them into the
        sessions_active dictionary and calls orchestration method.

        """
        for desc in session_descriptors:
            if not isinstance(desc, RCPMasterDescriptor):
                raise TypeError("Invalid session descriptor passed. "
                                "Only instances of the GCPMasterDescpriptors "
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
                self.logger.info("Adding new RCP session: %s", desc)

            # Get scenario or use default one
            if None is not desc.scenario:
                scenario = desc.scenario
            else:
                scenario = self._DEFAULT_SCENARIO

            # just create the instance and store
            # initiation will be started in the orchestrate_cb()
            new_master = RCPMaster(desc, self.dispatcher,
                                   scenario=scenario)
            self.sessions_active[desc.get_uniq_id()] = new_master

        # orchestrate the new state
        self._orchestrate()

    def get_master(self, desc):
        """Returns the master session object identified by descriptor."""
        return self.sessions_active[desc.get_uniq_id()]

    def remove_sessions(self, session_descriptors):
        """Implements the method from the GCPSessionOrchestrator interface.

        Removes RCPMaster sessions identified by descriptors in the
        list.

        """
        for desc in session_descriptors:
            if not isinstance(desc, gcp_sessions.GCPMasterDescriptor):
                raise TypeError("Invalid session descriptor passed. "
                                "Only instances of the GCPMasterDescpriptors "
                                "are supported.")

            # remove from the list of active sessions if exists
            if desc.get_uniq_id() in self.sessions_active:
                self.logger.info(
                    "RCP session: %s, removing from the list of "
                    "active sessions.", desc)

                # remove slave connections from the list of active FDs
                s = self.sessions_active[desc.get_uniq_id()]
                slaves = s.slave_cons
                for fd, ctx in slaves.items():
                    try:
                        del self.sessions_active_fd[fd]
                        self.logger.debug("Slave connection: %s of master: %s "
                                          "has been deleted from the list of active "
                                          "sessions FDs list.",
                                          gcp_sessions.GCPSession
                                          .get_sock_string(ctx.socket),
                                          desc)
                    except KeyError:
                        self.logger.warning(
                            "Slave connection: %s of master: %s is "
                            "not part of the active sessions FDs "
                            "list.",
                            gcp_sessions.GCPSession
                            .get_sock_string(ctx.socket),
                            desc)

                try:
                    del self.sessions_active_fd[s.get_socket_fd()]
                except KeyError:
                    self.logger.debug("GCP sessions: %s is not part of active "
                                      "sessions FDs list.", desc)

                s.close()
                del self.sessions_active[desc.get_uniq_id()]
                continue

            # remove from the list of failed sessions if exists
            if desc.get_uniq_id() in self.sessions_failed:
                self.logger.info("RCP session: %s, removing from the list of "
                                 "failed sessions.", desc)
                del self.sessions_failed[desc.get_uniq_id()]

        # orchestrate the new state
        self._orchestrate()
