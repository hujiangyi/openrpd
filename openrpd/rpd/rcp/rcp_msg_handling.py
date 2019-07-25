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

import socket
from rpd.common import utils
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib import rcp
from rpd.rcp.rcp_sessions import RCPSlaveSession, RCPMaster, \
    CcapCoreIdentification
from rpd.common.utils import Convert
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.rcp.gcp.gcp_sessions import GCPSessionFull
from rpd.gpb.CcapCoreIdentification_pb2 import t_CcapCoreIdentification
from rpd.rcp.rcp_lib import rcp_tlv_def


class RCPMSGHandlingError(rcp.RCPException):
    pass


#
# RCP Packet handlers
#
class RCPPacketHandler(object):  # pragma: no cover
    """Implements handling of RCP messages.

    Should be used as superclass.

    """

    __metaclass__ = AddLoggerToClass

    def handle_pkt(self, pkt):
        """Processes packet and returns its messages.

        :param pkt: The RCP packet
        :type pkt: RCPPacket
        :return: List of GCP messages of the packet

        """
        if not isinstance(pkt, rcp.RCPPacket):
            raise AttributeError("Invalid packet passed")

        # TODO process packet header

        if not pkt.msgs:
            self.logger.warning("Handling empty GCP packet")

        return pkt.msgs


class RCPSlavePacketHandler(RCPPacketHandler):
    """Implements handling of RCP messages specific for Slave side of the RCP
    session."""

    __metaclass__ = AddLoggerToClass

    class RCPSlavePacketHandlerCallbackSet(object):  # pragma: no cover
        """Defines interface which have to be implemented by the class which
        want to use the RCPSlavePacketHandler.

        State of the session must not be changed in the callback. '

        """
        __metaclass__ = AddLoggerToClass

        def ccap_identification_update(self, session):  # pragma: no cover
            """This callback is called by the PacketHandler when an update of
            the CCAP's capabilities has been received.

            :param session: The session where capabilities are updated.
            :type session: RCPSlaveSession

            """
            raise NotImplementedError()

        def redirect_received(self, session, ccap_core_addres_list):  # pragma: no cover
            """This callback is called by PacketHandler when a redirect to the
            list of CCAP core IP addresses was received.

            :param session: The session where capabilities are updated.
            :type session: RCPSlaveSession
            :param ccap_core_addres_list: List of tuples of ip addresses and
             address families.

            """
            raise NotImplementedError()

        def configuration_operation(self, session, rcp_sequence_list,
                                    pkt_req, gcp_msg):  # pragma: no cover
            """This callback is called by PacketHandler when a configuration
            operation needs to be performed on RPD system. Operations are
            described as list of RCPSequences.

            :param session: The session where capabilities are updated.
            :type session: RCPSlaveSession
            :param rcp_sequence_list: List of RCPSequence objects.
            :param pkt_req: A RCPPacket object including a packet with the
             configuration operation request.

            """
            raise NotImplementedError()

        def device_management_handler(self, slave, cmd):  # pragma: no cover
            """This callback is called by PacketHandler when a device management
            operation needs to be performed on RPD system. Operations are
            described as command list.

            :param slave: The RCP slave sessions on which the message has
             been received.
            :param cmd: the device management command send via gcp
            :type cmd: enum 0-6
             device management operation request.

            """
            raise NotImplementedError()

        def configuration_to_rcp_wrapper(self, session, seq, transaction_identifier, trans_id,
                                         msg_type=t_RcpMessage.RPD_CONFIGURATION):  # pragma: no cover
            """This callback is called by PacketHandler when a GCP
            operation needs to be send to manager_process.

            :param session: The session where capabilities are updated.
            :param seq: sequences info
            :param transaction_identifier: pkt transaction_id.
            :param trans_id: gcp message transaction_id.
            :param msg_type: config or Done.

            """
            raise NotImplementedError()

    def __init__(self, callback_set, packet_director):
        """Creates internal mappings of message IDs to handling callbacks.

        :param callback_set: Set of callbacks for handling of concrete events.
        :type callback_set: RCPSlavePacketHandlerCallbackSet
        :raises AttributeError: If mandatory parameter is missing.
        :raises TypeError: If some parameter of unexpected type was passed.

        """
        if None is callback_set:
            raise AttributeError("No callback_set passed")

        if not isinstance(
                callback_set,
                RCPSlavePacketHandler.RCPSlavePacketHandlerCallbackSet):
            raise TypeError("Invalid callback_set passed")

        RCPPacketHandler.__init__(self)

        self.callback_set = callback_set
        self.pkt_director = packet_director

        # mapping of message IDs to methods which handles it
        self.msg_id_cb = {
            gcp_msg_def.NotifyRSP: self.handle_msg_notify_rsp,
            gcp_msg_def.ManagementREQ: self.handle_msg_gdm_req,
            gcp_msg_def.DataStructREQ: self.handle_msg_eds_req,
        }

        # mapping of message IDs to methods which fill message fields
        self.fill_msg_cb = {
            gcp_msg_def.DataStructRSP: self._fill_msg_eds_rsp,
        }

    def handle_pkt(self, pkt, slave):
        """Process packet and its messages from the slave's perspective.

        :param pkt: The RCP packet
        :type pkt: RCPPacket
        :param slave: The RCP slave session on which the packet has
         been received
        :type slave: RCPSlaveSession
        :return:

        """
        if not isinstance(slave, RCPSlaveSession):
            raise AttributeError("Invalid RCP Slave sessions passed")

        if slave.is_session_failed():
            raise RCPMSGHandlingError("Handling message for the slave "
                                      "session which is failed")

        msgs = RCPPacketHandler.handle_pkt(self, pkt)

        for msg in msgs:
            self.logger.debug("Handling message: %s (%u) for slave: %s",
                              msg.message_name, msg.message_id,
                              slave.get_sock_string(slave.get_socket()))

            try:
                cb = self.msg_id_cb[msg.message_id]
            except KeyError:
                raise RCPMSGHandlingError(
                    "Unexpected message id ({}) for RCP "
                    "slave".format(msg.message_id))

            try:
                cb(msg, slave, pkt)
                slave.keep_alive = slave.RCP_RCV_SYNC
            except RCPMSGHandlingError as ex:
                self.logger.warning(
                    "Message handling failed: %s, msg:%s", ex, msg.message_id)
            except Exception as ex:
                self.logger.warning(
                    "Message handling met exception: %s, msg:%s", ex, msg.message_id)
                raise

    #
    # Internal methods
    #
    def _new_packet_req(self, slave):   # pragma: no cover
        """Creates new RCP packet with header set according to slave's
        state."""

        pkt = rcp.RCPPacket()
        slave.io_ctx.transaction_id += 1
        pkt.transaction_identifier = slave.io_ctx.transaction_id
        pkt.protocol_identifier = slave.protocol_id
        pkt.unit_id = 0
        return pkt

    def _new_packet_rsp(self, pkt_rcvd):    # pragma: no cover
        """Creates new RCP packet with header set according to received
        packet's header."""
        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = pkt_rcvd.transaction_identifier
        pkt.protocol_identifier = pkt_rcvd.transaction_identifier
        pkt.unit_id = 0
        return pkt

    def _new_gcp_msg(self, slave, msg_id, transaction_id=0):    # pragma: no cover
        """Creates new GCP message and calls methods which fill GCP message
        headers."""
        gcp_msg = rcp.Message(msg_id)

        try:
            cb = self.fill_msg_cb[msg_id]
        except KeyError:
            raise NotImplementedError("The _new_msg method not implemented for"
                                      " %s (%u) message" %
                                      (gcp_msg.message_name,
                                       gcp_msg.message_id))
        cb(gcp_msg, slave, transaction_id)
        return gcp_msg

    def _fill_msg_eds_rsp(self, gcp_msg, slave, transaction_id):    # pragma: no cover
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(0)
        gcp_msg.msg_fields.Channel.set_val(0)
        gcp_msg.msg_fields.VendorID.set_val(0)
        gcp_msg.msg_fields.VendorIndex.set_val(0)

    #
    # Message handlers for RCPSlave
    #
    def handle_msg_eds_req(self, msg, slave, pkt):
        """Handles GCP EDS REQ message.

        :param msg: The GCP EDS REQ message
        :type msg: Message
        :param slave: The RCP slave sessions on which the message has been
         received.
        :type slave: RCPSlaveSession
        :param pkt: The RCP packet where the message was encapsulated
        :type pkt: RCPPacket
        :return:

        """
        seq_list = []
        for rcp_msg in msg.tlv_data.rcp_msgs:
            for seq in rcp_msg.sequences:

                # Handle special messages including redirect
                # and CCAP Capabilities and ssd
                if rcp_msg.rcp_message_id == rcp_tlv_def.RCP_MSG_TYPE_IRA:
                    if slave.is_ira_recv == False:
                        slave.is_ira_recv = True
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave, seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val(),
                            msg_type=t_RcpMessage.IRA_RECEIVED)
                if rcp_msg.rcp_message_id == rcp_tlv_def.RCP_MSG_TYPE_REX:
                    if slave.is_rex_recv == False:
                        slave.is_rex_recv = True
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave, seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val(),
                            msg_type=t_RcpMessage.REX_RECEIVED)
                if seq.parent_gpb.HasField("Ssd"):
                    self.logger.info("Handling Ssd received at %s" %
                                     slave.get_descriptor())
                    if (not slave.ccap_identification.is_active) \
                            or (not slave.ccap_identification.is_principal):
                        self.logger.debug("Ssd received from non active %d or non principal %d ",
                                          slave.ccap_identification.is_active, slave.ccap_identification.is_principal)
                        try:
                            resp = self.pkt_director.get_positive_rsp_packets(slave, pkt)
                        except Exception as ex:
                            self.logger.warning("Got exception when constructing ssd rsp packet: %s", str(ex))
                            raise
                        if 1 != len(resp):
                            raise RCPMSGHandlingError(
                                "Invalid packet response returned by director")
                        resp = resp[0]
                        try:
                            slave.io_ctx.add_tx_packet(resp)
                            self.logger.debug("send ssd response")
                        except GCPSessionFull:
                            self.logger.error("GCP session tx full, failed to send SSD response msg")
                            raise
                        continue

                if len(seq.parent_gpb.RpdRedirect) > 0:
                    self.logger.info(
                        "Handling redirect received at %s"
                        % slave.get_descriptor())
                    # handle redirect and drop all next data
                    addr_list = []
                    for redir_item in seq.parent_gpb.RpdRedirect:
                        ip_addr = redir_item.RedirectIpAddress
                        addr_family = (socket.AF_INET if Convert.is_valid_ipv4_address(ip_addr) else socket.AF_INET6)
                        addr_list.append((ip_addr, addr_family))

                    # send redirect response
                    try:
                        resp = self.pkt_director.get_positive_rsp_packets(slave, pkt)
                    except Exception as ex:
                        self.logger.warning("Got exception when constructing  redirect rsp packet: %s", str(ex))
                        raise

                    if 1 != len(resp):
                        raise RCPMSGHandlingError(
                            "Invalid packet response returned by director")
                    resp = resp[0]

                    try:
                        slave.io_ctx.add_tx_packet(resp)
                    except GCPSessionFull:
                        self.logger.error("GCP session tx full, failed to send redirect response msg")
                        raise

                    slave.dispatcher.fd_modify(
                        slave.get_socket_fd(), slave.dispatcher.MASK_WR_ERR)
                    self.logger.debug("Response to redirect added to TX queue")
                    try:
                        self.callback_set.redirect_received(slave, addr_list)
                    except Exception as ex:
                        self.logger.warning("Got exception when handling redirect msg: %s", str(ex))
                        raise
                    continue

                if len(seq.parent_gpb.CcapCoreIdentification) > 0:
                    index = -1
                    identRecord = CcapCoreIdentification()
                    self.logger.info("Handling CcapCoreIdentification update")
                    ccap_caps = seq.parent_gpb.CcapCoreIdentification[0]
                    self.logger.debug("msg is: %s", ccap_caps)
                    op = seq.operation
                    if len(seq.parent_gpb.CcapCoreIdentification) > 1:
                        self.logger.warning(
                            "Only one instance of CCAP caps is expected, but received: %u",
                            len(seq.parent_gpb.CcapCoreIdentification))

                    core_ip = slave.get_descriptor().addr_remote

                    if ccap_caps.HasField("CoreIpAddress"):
                        core_ip = Convert.format_ip(ccap_caps.CoreIpAddress)
                        ip = Convert.format_ip(ccap_caps.CoreIpAddress)

                    if op == rcp_tlv_def.RCP_OPERATION_TYPE_WRITE:
                        if ccap_caps.HasField("Index"):
                            index = ccap_caps.Index
                            identRecord.index = index
                            identRecord.read()
                        else:
                            self.logger.warning("RCP write type %d should include index", op)
                            self.pkt_director.send_eds_response_directly(slave, pkt.transaction_identifier,
                                                                         msg.msg_fields.TransactionID.get_val(), seq, False)
                            continue
                    elif op == rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE:
                        identRecord.allocateIndex(core_ip)
                        ccap_caps.Index = identRecord.index
                    elif op == rcp_tlv_def.RCP_OPERATION_TYPE_READ:
                        seq_list.append(seq)
                        continue

                    identRecord.core_ip_addr = core_ip
                    if ccap_caps.HasField("IsPrincipal"):
                        self.logger.info("Received NotifyRSP from CCAP core is_principal[%s]",
                                         ccap_caps.IsPrincipal)
                        identRecord.is_principal = True if ccap_caps.IsPrincipal else False

                    self.logger.debug("CcapCoreIdentification operation=%d index=%d", op, ccap_caps.Index)

                    if ccap_caps.HasField("CoreId"):
                        identRecord.core_id = ccap_caps.CoreId

                    if ccap_caps.HasField("CoreName"):
                        identRecord.core_name = ccap_caps.CoreName

                    if ccap_caps.HasField("VendorId"):
                        identRecord.vendor_id = ccap_caps.VendorId

                    if ccap_caps.HasField("CoreMode"):
                        identRecord.core_mode = ccap_caps.CoreMode
                        identRecord.is_active = ccap_caps.CoreMode is t_CcapCoreIdentification.COREMODEACTIVE

                    if ccap_caps.HasField("InitialConfigurationComplete"):
                        identRecord.initial_configuration_complete = ccap_caps.InitialConfigurationComplete

                    if ccap_caps.HasField("MoveToOperational"):
                        identRecord.move_to_operational = ccap_caps.MoveToOperational

                    if ccap_caps.HasField("CoreFunction"):
                        identRecord.core_function = ccap_caps.CoreFunction

                    if ccap_caps.HasField("ResourceSetIndex"):
                        identRecord.resource_set_index = ccap_caps.ResourceSetIndex

                    if op in [rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                              rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE]:
                        identRecord.write()
                        self.logger.debug("Core ident DB save index =%d core_ip_addr=%s op=%d",
                                          identRecord.index, identRecord.core_ip_addr, op)
                    # Set the ccap core Identification into the slave session
                    slave.ccap_identification = identRecord

                    # call CCAP caps update callback
                    self.callback_set.ccap_identification_update(slave)

                    try:
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave, seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val())
                    except Exception as ex:
                        self.logger.warning("Got exception when handling core identification msg: %s", str(ex))
                        raise

                if seq.parent_gpb.HasField('RpdConfigurationDone'):
                    self.logger.info(
                        "Handling configuration done message to MGR")
                    self.pkt_director.send_eds_response_directly(
                        slave, pkt.transaction_identifier,
                        msg.msg_fields.TransactionID.get_val(), seq)
                    try:
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave, seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val(),
                            msg_type=t_RcpMessage.RPD_CONFIGURATION_DONE)
                    except Exception as ex:
                        self.logger.warning("Got exception when handling cfg_done msg: %s", str(ex))
                        raise

                    continue

                if seq.parent_gpb.HasField('RpdGlobal'):
                    if slave.ccap_identification.is_principal and slave.ccap_identification.is_active:
                        self.logger.info("Receive RpdGlobal message from active principal core via session %s",
                                         slave.get_descriptor())
                    else:
                        self.logger.info("Receive RpdGlobal message from non active principal core via session %s",
                                         slave.get_descriptor())
                        self.pkt_director.send_eds_response_directly(slave, pkt.transaction_identifier,
                                                                     msg.msg_fields.TransactionID.get_val(), seq)
                        continue

                if len(seq.parent_gpb.ConfiguredCoreTable) > 0:
                    self.logger.info(
                        "Handling configuration core table message to MGR")
                    self.pkt_director.send_eds_response_directly(
                        slave, pkt.transaction_identifier,
                        msg.msg_fields.TransactionID.get_val(), seq)
                    try:
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave, seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val())
                    except Exception as ex:
                        self.logger.warning("Got exception when handling core_table msg: %s", str(ex))
                        raise

                    continue

                if seq.parent_gpb.HasField('MultiCore'):
                    self.logger.info(
                        "Handling MultiCore configuration msg is_principal=%d is_active=%d",
                        slave.ccap_identification.is_principal,
                        slave.ccap_identification.is_active)
#                   ****** temporary 4 line hack follows to work around 
#                   ****** the issue described in C3RPHY-122
                    resource_set_index = 0
                    for resource_set in seq.parent_gpb.MulitCore.ResourceSet:
                        resource_set.ResourceSetIndex = resource_set_index
                        resource_set_index = resource_set_index + 1
#                   ****** end of 4 line hack to get around C3RPHY-122
                    self.pkt_director.send_eds_response_directly(
                        slave, pkt.transaction_identifier,
                        msg.msg_fields.TransactionID.get_val(), seq)
                    try:
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave, seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val())
                    except Exception as ex:
                        self.logger.warning("Got exception when handling  MultiCore msg: %s", str(ex))
                        raise

                    continue

                if seq.parent_gpb.HasField('ActivePrincipalCore'):
                    self.logger.info(
                        "Handling get active principal request on session %s",
                        slave.get_descriptor())
                    try:
                        self.callback_set.configuration_to_rcp_wrapper(
                            slave,
                            seq, pkt.transaction_identifier,
                            msg.msg_fields.TransactionID.get_val())
                    except Exception as ex:
                        self.logger.warning("Got exception when handling Active Principal core msg: %s", str(ex))
                        raise

                    continue
                seq_list.append(seq)

        if not seq_list:
            self.logger.info("EDS message without any RCPSequence received")
            return

        try:
            self.callback_set.configuration_operation(
                session=slave,
                rcp_sequence_list=seq_list,
                pkt_req=pkt, gcp_msg=msg)
        except Exception as ex:
            # TODO we need to handle failures with a granularity
            self.logger.error("Failed to process configuration: %s", ex)
            import traceback
            self.logger.error(traceback.format_stack())
            raise RCPMSGHandlingError()

    def handle_msg_notify_rsp(self, msg, slave, pkt):
        """Handles GCP Notify RSP message.

        :param msg: The GCP NTF RSP message
        :type msg: Message
        :param slave: The RCP slave sessions on which the message has been
         received.
        :type slave: RCPSlaveSession
        :param pkt: The RCP packet where the message was encapsulated
        :type pkt: RCPPacket
        :return:

        """
        self.logger.debug(
            "Received NotifyRSP, this message is unexpected, skipping.")

    def handle_msg_gdm_req(self, msg, slave, pkt):
        """Handles GCP Notify RSP message.

        :param msg: The GCP GDM RSP message
        :type msg: Message
        :param slave: The RCP slave sessions on which the message has been
         received.
        :type slave: RCPSlaveSession
        :param pkt: The RCP packet where the message was encapsulated
        :type pkt: RCPPacket
        :return:

        """
        self.logger.debug(
            "GDM message:trans_p:%d, trans_m:%d, port:%d, channel:%d, "
            "comm:%d", pkt.transaction_identifier,
            msg.msg_fields.TransactionID.get_val(),
            msg.msg_fields.Port.get_val(),
            msg.msg_fields.Channel.get_val(),
            msg.msg_fields.Command.get_val())
        builder = self.pkt_director.builder
        builder.add_packet(transaction_id=pkt.transaction_identifier)
        builder.add_gcp_msg(gcp_msg_def.ManagementRSP,
                            msg.msg_fields.TransactionID.get_val())
        # Fill GCP message fields
        builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        ret = self.callback_set.device_management_handler(
            slave, msg.msg_fields.Command.get_val())
        builder.last_gcp_msg.msg_fields.ReturnCode.set_val(ret)
        pkts = builder.get_packets()
        if len(pkts) != 1:
            raise RCPMSGHandlingError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))

        tx_pkt = pkts[0]
        try:
            slave.io_ctx.add_tx_packet(tx_pkt, high_priority=True)
        except GCPSessionFull:
            self.logger.error("GCP session tx full, failed to send gdm response msg")
            raise

        slave.dispatcher.fd_modify(slave.get_socket_fd(),
                                   slave.dispatcher.MASK_WR_ERR)
        self.logger.debug("Sent GDM RSP")


class RCPMasterPacketHandler(RCPPacketHandler):  # pragma: no cover
    """Implements handling of RCP messages specific for Master side of the
    RCP session."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, packet_director):
        RCPPacketHandler.__init__(self)
        self.packet_director = packet_director

    def handle_pkt(self, pkt, master, slave_fd):
        """Process packet and its messages from the master's perspective.

        :param pkt: The RCP packet
        :type pkt: RCPPacket
        :param master: The RCP master session on which the packet has
         been received
        :type master: RCPMaster
        :return:

        """
        if not isinstance(master, RCPMaster):
            raise AttributeError("Invalid RCP master passed")

        msgs = RCPPacketHandler.handle_pkt(self, pkt)

        # for msg in msgs:
        #     pass
        raise NotImplementedError()
