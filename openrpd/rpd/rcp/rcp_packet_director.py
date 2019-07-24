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

import os
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib.rcp import RCPPacketBuilder
from rpd.rcp.rcp_lib.rcp import RCPPacketBuildError
from rpd.rcp.rcp_lib.rcp import RCPSequence
from rpd.rcp.rcp_lib import rcp
from rpd.rcp.gcp.gcp_sessions import GCPSessionFull
from rpd.common import utils
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.gpb.VendorSpecificExtension_pb2 import t_VendorSpecificExtension
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification
from rpd.gpb.StaticPwStatus_pb2 import t_StaticPwStatus
import random
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities


class RCPSlavePacketBuildDirector(object):
    """Defines functions which helps to build GCP packets for specific
    operations for RCP Slave.

    Uses RCPPacketBuilder for this purpose.

    """
    __metaclass__ = AddLoggerToClass
    PTP_SYNC = 1
    PTP_LOS = 2
    PTP_STATUS_TO_GCP_VAL = {
        "ALIGNED":          PTP_SYNC,
        "LOSS OF SYNC":     PTP_LOS,
    }

    CISCO_VENDOR_ID = 9
    CABLELABS_VENDOR_ID = 4491
    CABLELABS_VENDOR_INDEX = 1

    def __init__(self):
        self.builder = RCPPacketBuilder()

    def _set_ipv6_info(self, seq, msg):
        """set VendorSpecificExtension Ipv6Address from msg."""

        self.logger.debug("send a RpdIpv6Info notification message to Hal %s",msg)
        ipv6_msg = t_VendorSpecificExtension()
        ipv6_msg.ParseFromString(msg)
        seq.VendorSpecificExtension.VendorId.set_val(self.CISCO_VENDOR_ID)
        for ipaddr in ipv6_msg.Ipv6Address:
            sub_tlv_ipv6_addr = seq.VendorSpecificExtension.Ipv6Address.add_new_repeated()
            sub_tlv_ipv6_addr.EnetPortIndex.set_val(ipaddr.EnetPortIndex)
            sub_tlv_ipv6_addr.AddrType.set_val(ipaddr.AddrType)
            sub_tlv_ipv6_addr.IpAddress.set_val(utils.Convert.ipaddr_to_tuple_of_bytes(ipaddr.IpAddress))
            sub_tlv_ipv6_addr.PrefixLen.set_val(ipaddr.PrefixLen)

    def _set_group_info(self, seq, msg):
        """set VendorSpecificExtension RpdGroupInfo from msg."""

        self.logger.debug("send a RpdGroupInfo notification message to Hal %s", msg)
        group_msg = t_VendorSpecificExtension()
        group_msg.ParseFromString(msg)
        seq.VendorSpecificExtension.VendorId.set_val(self.CISCO_VENDOR_ID)
        if group_msg.HasField("RpdGroupInfo"):
            sub_tlv = seq.VendorSpecificExtension.RpdGroupInfo
            if group_msg.RpdGroupInfo.HasField("ShelfId"):
                sub_tlv.ShelfId.set_val(utils.Convert.mac_to_tuple_of_bytes(group_msg.RpdGroupInfo.ShelfId))
            if group_msg.RpdGroupInfo.HasField("Master"):
                sub_tlv.Master.set_val(group_msg.RpdGroupInfo.Master)
            if group_msg.RpdGroupInfo.HasField("ShelfSn"):
                sub_tlv.ShelfSn.set_val(group_msg.RpdGroupInfo.ShelfSn)
            if group_msg.RpdGroupInfo.HasField("CpuId"):
                sub_tlv.CpuId.set_val(group_msg.RpdGroupInfo.CpuId)

    def _set_ptp_clock_status(self, seq, msg):
        val = self.PTP_STATUS_TO_GCP_VAL[msg]
        seq.RpdPTPClockStatus.set_val(val)

    def _set_notify_static_pw_status(self, seq, msg):
        staticPwStatus = t_StaticPwStatus()
        staticPwStatus.ParseFromString(msg)
        sub_tlv = seq.StaticPwStatus
        commonStaticPwStatus = sub_tlv.CommonStaticPwStatus
        commonStaticPwStatus.Direction.set_val(staticPwStatus.CommonStaticPwStatus.Direction)
        commonStaticPwStatus.Index.set_val(staticPwStatus.CommonStaticPwStatus.Index)
        commonStaticPwStatus.RpdCircuitStatus.set_val(staticPwStatus.CommonStaticPwStatus.RpdCircuitStatus)
        self.logger.debug("Send a commonStaticPwStatus Index=%d",
                          staticPwStatus.CommonStaticPwStatus.Index)

    def _set_general_ntf_info(self, seq, msg_type, gen_ntf_msg=None):
        sub_tlv = seq.GeneralNotification
        sub_tlv.NotificationType.set_val(msg_type)
        if msg_type == t_GeneralNotification.PTPRESULTNOTIFICATION:
            sub_tlv.PtpEnetPortIndex.set_val(1)
            sub_tlv.PtpResult.set_val(gen_ntf_msg.PtpResult)
            sub_tlv.PtpRpdPtpPortIndex.set_val(1)
            sub_tlv.PtpClockSource.set_val(0)
            self.logger.debug("Send a ptp notify message NotificationType=%d PtpResult=%d",
                              gen_ntf_msg.NotificationType, gen_ntf_msg.PtpResult)
        else:
            self.logger.debug("Send general notification message Type=%d", msg_type)

    def _set_rpd_identification(self, seq, interface_local=None, cap=None):
        if isinstance(cap, t_RpdCapabilities):
            seq.parent_gpb.RpdCapabilities.RpdIdentification.CopyFrom(cap.RpdIdentification)
            return

        seq.RpdCapabilities.RpdIdentification.VendorName.set_val("Cisco")
        seq.RpdCapabilities.RpdIdentification.VendorId.set_val(self.CISCO_VENDOR_ID)
        seq.RpdCapabilities.RpdIdentification.ModelNumber.set_val("123456")
        mac = utils.SysTools.get_sys_mac_address()

        #for vRPD we can get the mac from interface in case the system mac is not set
        if mac == "00:00:00:00:00:00" and utils.SysTools.is_vrpd():
            try:
                if None is not interface_local:
                    mac = utils.SysTools.get_mac_address(interface_local)
            except IOError as e:
                self.logger.warn(str(e))
        seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_val(
            utils.Convert.mac_to_tuple_of_bytes(mac))
        seq.RpdCapabilities.RpdIdentification.CurrentSwVersion.\
            set_val("Prototype")
        seq.RpdCapabilities.RpdIdentification.DeviceDescription.\
            set_val('vRPD')
        seq.RpdCapabilities.RpdIdentification.DeviceAlias.\
            set_val("TP")
        # the value must be '123456' in sdn side, changed it from 777
        seq.RpdCapabilities.RpdIdentification.SerialNumber.\
            set_val("123456")
        seq.RpdCapabilities.RpdIdentification.RpdRcpProtocolVersion.\
            set_val("1.0")
        seq.RpdCapabilities.RpdIdentification.RpdRcpSchemaVersion.\
            set_val("1.0.0")

    def _set_devicelocation(self, seq, cap=None):
        if isinstance(cap, t_RpdCapabilities):
            seq.parent_gpb.RpdCapabilities.DeviceLocation.CopyFrom(cap.DeviceLocation)
            return
        seq.RpdCapabilities.DeviceLocation.DeviceLocationDescription.set_val("NA")
        seq.RpdCapabilities.DeviceLocation.GeoLocationLatitude.set_val("+000000.0")
        seq.RpdCapabilities.DeviceLocation.GeoLocationLongitude.set_val("+0000000.0")
        self.logger.debug("Set DeviceLocation to default NA")

    def get_fault_management_notify_packet(self, slave, event, text, msg):
        if None is slave or None is msg:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(0)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        # Fill some hardcoded data now
        seq = self.builder.last_rcp_sequence

        # seq.EventNotification.Index.set_val(index)
        seq.EventNotification.PendingOrLocalLog.set_val(msg['PENDING_LOCAL'])
        seq.EventNotification.EvFirstTime.set_val(utils.Convert.pack_timestamp_to_string(int(msg['FirstTime'])))
        seq.EventNotification.EvLastTime.set_val(utils.Convert.pack_timestamp_to_string(int(msg['LastTime'])))
        seq.EventNotification.EvCounts.set_val(msg['Counts'])
        seq.EventNotification.EvLevel.set_val(msg['Level'])
        seq.EventNotification.EvId.set_val(event)
        seq.EventNotification.EvString.set_val(text.strip())

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_ipv6_notify_packet(self, slave, msg):
        """get NTF for VendorSpecificExtension Ipv6Address."""

        if None is slave or None is msg:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)  

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(0)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        seq = self.builder.last_rcp_sequence
        self._set_ipv6_info(seq, msg)

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        self.logger.debug("Send IPv6 info packets to ccap core:%s", pkts[0])
        return pkts[0]

    def get_group_notify_packet(self, slave, msg):
        """get NTF for VendorSpecificExtension Ipv6Address."""

        if None is slave or None is msg:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(0)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        seq = self.builder.last_rcp_sequence
        self._set_group_info(seq, msg)

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        self.logger.debug("Send Group info packets to ccap core:%s", pkts[0])
        return pkts[0]

    def get_ptp_notify_packet(self, slave, msg):
        if None is slave or None is msg:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)  # TODO get the GPB from DB

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0xc0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(0)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        # TODO get the GPB from DB and use it in the add_rcp_seq() above
        # Fill some hardcoded data now
        seq = self.builder.last_rcp_sequence
        self._set_ptp_clock_status(seq, msg)

        # can we guarantee the first packet is the one we just created?
        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        self.logger.info("Send PTP packets to ccap core:%s", pkts[0])
        return pkts[0]

    def get_pw_status_notify_packet(self, slave, pw_status_msg):
        if None is slave or None is pw_status_msg:
            raise AttributeError()
        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)  # TODO get the GPB from DB

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0x0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(0)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        # TODO get the GPB from DB and use it in the add_rcp_seq() above
        # Fill some hardcoded data now
        seq = self.builder.last_rcp_sequence
        self._set_notify_static_pw_status(seq, pw_status_msg)

        # can we guarantee the first packet is the one we just created?
        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected GeneralNtf resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        self.logger.info("Send GeneralNtf packets to ccap core:%s", pkts[0])
        return pkts[0]

    def get_general_notify_packet(self, slave, msg_type, gen_ntf_msg):
        if None is slave or None is gen_ntf_msg:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)  # TODO get the GPB from DB

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0x0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(0)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        # TODO get the GPB from DB and use it in the add_rcp_seq() above
        # Fill some hardcoded data now
        seq = self.builder.last_rcp_sequence
        self._set_general_ntf_info(seq, msg_type, gen_ntf_msg)

        # can we guarantee the first packet is the one we just created?
        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected GeneralNtf resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        self.logger.info("Send GeneralNtf packets to ccap core:%s", pkts[0])
        return pkts[0]

    def get_notify_up_request_packet(self, slave):

        """Builds and returns GCP packet including GCP NTFUPReq message with NTF UP
        RCP message

        :param slave: The RCP Slave session.
        :returns RCP packet with all data set.
        :raises AttributeError: If the slave session is not passed.
        :raises RCPPacketBuildError : If some error occurred during the build
        of the packet.

        """
        if None is slave:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)  # TODO get the GPB from DB

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0xc0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(1)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        # TODO get the GPB from DB and use it in the add_rcp_seq() above
        # Fill some hardcoded data now
        seq = self.builder.last_rcp_sequence
        self._set_general_ntf_info(seq, t_GeneralNotification.STARTUPNOTIFICATION)
        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_notify_request_packet(self, slave, cap=None):

        """Builds and returns GCP packet including GCP NTFReq message with NTF
        RCP message and RCPSequence with RPD Identification data.

        :param slave: The RCP Slave session.
        :returns RCP packet with all data set.
        :raises AttributeError: If the slave session is not passed.
        :raises RCPPacketBuildError : If some error occurred during the build
        of the packet.

        """
        if None is slave:
            raise AttributeError()

        self.builder.clear()
        transaction_id = slave.get_next_trans_id()
        rcp_sequence_id = slave.get_next_seq_id()

        self.builder.add_packet()
        self.builder.add_gcp_msg(gcp_msg_def.NotifyREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_NTF)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None)  # TODO get the GPB from DB

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0xc0)
        self.builder.last_gcp_msg.msg_fields.Status.set_val(1)
        self.builder.last_gcp_msg.msg_fields.EventCode.set_val(1)

        # TODO get the GPB from DB and use it in the add_rcp_seq() above
        # Fill some hardcoded data now
        seq = self.builder.last_rcp_sequence
        self._set_rpd_identification(seq, slave.get_descriptor().interface_local, cap=cap)
        self._set_devicelocation(seq, cap=cap)
        self._set_general_ntf_info(seq, t_GeneralNotification.STARTUPNOTIFICATION)
        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_gcp_err_rsp_packet(self, slave, req):
        # TODO
        pass

    def _prepare_gcp_msg_rsp(self, gcp_msg):
        gcp_msg.reinit()
        gcp_msg.tlv_data.reinit()
        gcp_msg.msg_fields.reinit()
        # Change the message ID from req to rsp
        if gcp_msg.message_id == gcp_msg_def.M_DataStructREQ.message_id:
            gcp_msg.message_id = gcp_msg_def.M_DataStructRSP.message_id
            gcp_msg.message_name = gcp_msg_def.M_DataStructRSP.name
        elif gcp_msg.message_id == gcp_msg_def.M_NotifyREQ.message_id:
            gcp_msg.message_id = gcp_msg_def.M_NotifyRSP.message_id
            gcp_msg.message_name = gcp_msg_def.M_NotifyRSP.name
        elif gcp_msg.message_id == gcp_msg_def.M_ManagementREQ.message_id:
            gcp_msg.message_id = gcp_msg_def.M_ManagementRSP.message_id
            gcp_msg.message_name = gcp_msg_def.M_ManagementRSP.name
        else:
            raise RCPPacketBuildError(
                "Invalid GCP message id in processed "
                "packet: {}".format(gcp_msg.message_id))

    def _prepare_rcp_msg_rsp(self, rcp_msg, gcp_msg):
        rcp_msg.gcp_message_id = gcp_msg.message_id
        rcp_msg.reinit()

    def _prepare_rcp_seq_rsp(self, seq, gcp_msg):
        # TODO remove these doubled data
        seq.gcp_message_id = gcp_msg.message_id
        seq.gcp_message_name = gcp_msg.message_name
        seq.msg_id = gcp_msg.message_id
        seq.msg_name = gcp_msg.message_name
        seq.reinit()
        #seq.clear_read()
        if seq.operation == rcp_tlv_def.RCP_OPERATION_TYPE_READ:
            seq.operation =\
                rcp_tlv_def.RCP_OPERATION_TYPE_READ_RESPONSE
        elif seq.operation == rcp_tlv_def.RCP_OPERATION_TYPE_WRITE:
            seq.operation =\
                rcp_tlv_def.RCP_OPERATION_TYPE_WRITE_RESPONSE
        elif seq.operation ==\
                rcp_tlv_def.RCP_OPERATION_TYPE_DELETE:
            seq.operation =\
                rcp_tlv_def.RCP_OPERATION_TYPE_DELETE_RESPONSE
        elif seq.operation ==\
                rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE:
            seq.operation =\
                rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE_RESPONSE
        else:
            raise RCPPacketBuildError(
                "Invalid RCP Operation type ({}) during processing"
                " of processed packet".format(seq.operation))

    def _set_seq_failed(self, seq):
        # seq.ResponseCode.set_val(rcp.RCP_RESPONSE_CODE_FAILED)
        seq.rcp_seq_ret_code = rcp.RCP_RESPONSE_CODE_FAILED

    def _set_seq_ok(self, seq):
        # seq.ResponseCode.set_val(rcp.RCP_RESPONSE_CODE_OK)
        seq.rcp_seq_ret_code = rcp.RCP_RESPONSE_CODE_OK

    def send_eds_response_directly(self, slave, transaction_id, trans_id, seq, result=True):
        """Creates response packets according to the list of results.

        :param slave: The slave session.
        :param transaction_id: the pkt transaction_id.
        :param trans_id: the gcp message transaction_id.
        :param seq: sequence.
        :param result: rcp response code.
        :raise AttributeError: if some of attributes is None
        :return list of instances of the RCPPacket

        """
        try:
            if None is slave:
                raise AttributeError()

            self.builder.clear()

            self.builder.add_packet(transaction_id=transaction_id)
            self.builder.add_gcp_msg(gcp_msg_def.DataStructRSP, transaction_id)
            self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)

            # Fill GCP message fields
            self.builder.last_gcp_msg.msg_fields.TransactionID.set_val(trans_id)
            self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
            self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
            self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
            """
            In RPHY spec, section B.2.1 RCP over GCP EDS Message,
            it is defined that in GCP EDS message, the VendorID is Cablelabs(4491),
            and the vendor index is CABLELABS_VENDOR_INDEX(1) as defined.
            """
            self.builder.last_gcp_msg.msg_fields.VendorID.set_val(self.CABLELABS_VENDOR_ID)
            self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(self.CABLELABS_VENDOR_INDEX)

            if seq.operation == rcp_tlv_def.RCP_OPERATION_TYPE_READ:
                operation = rcp_tlv_def.RCP_OPERATION_TYPE_READ_RESPONSE
            elif seq.operation == rcp_tlv_def.RCP_OPERATION_TYPE_WRITE:
                operation = rcp_tlv_def.RCP_OPERATION_TYPE_WRITE_RESPONSE
            elif seq.operation == rcp_tlv_def.RCP_OPERATION_TYPE_DELETE:
                operation = rcp_tlv_def.RCP_OPERATION_TYPE_DELETE_RESPONSE
            elif seq.operation == rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE:
                operation = rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE_RESPONSE
            else:
                raise RCPPacketBuildError(
                    "Invalid RCP Operation type ({}) during processing"
                    " of processed packet".format(seq.operation))
            ret_seq = RCPSequence(
                gcp_message_id=seq.gcp_message_id,
                rcp_message_id=seq.rcp_message_id,
                seq_number=seq.seq_number,
                operation=operation,
                parent_gpb=seq.ipc_msg.RpdDataMessage.RpdData,
                skip_create_tlv_data=True
            )
            if result:
                self._set_seq_ok(ret_seq)
            else:
                self._set_seq_failed(ret_seq)
            self.logger.info("Session[%s] send message %s response %s",
                             slave.get_descriptor(), 'success' if result else 'fail',
                             seq.ipc_msg.RpdDataMessage.RpdData)
            self.builder.last_rcp_msg.sequences.append(ret_seq)
        except Exception as ex:
            self.logger.error("Failed to re-init RCP SEQ with result data: %s", ex)
            return

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))

        tx_pkt = pkts[0]

        try:
            slave.io_ctx.add_tx_packet(tx_pkt, high_priority=False)
        except GCPSessionFull:
            self.logger.error("GCP session tx full, failed to send eds direct response msg")
            raise
        slave.dispatcher.fd_modify(slave.get_socket_fd(),
                                   slave.dispatcher.MASK_ALL)
        self.logger.debug("Sent EDS RSP")

    def get_resulting_rsp_packets(self, slave, pkt_req, rsp_data_list):
        """Creates response packets according to the list of results.

        :param slave: The slave session.
        :param pkt_req: The packet including the request.
        :raise AttributeError: if some of attributes is None
        :return list of instances of the RCPPacket

        """
        # TODO need to add fragmentation for large configurations

        if None is slave or None is pkt_req:
            raise AttributeError()

        pkt_req.reinit()
        for gcp_msg in pkt_req.msgs:
            self._prepare_gcp_msg_rsp(gcp_msg)

            # walk all sequences and change operation types from req to rsp
            for rcp_msg in gcp_msg.tlv_data.rcp_msgs:
                self._prepare_rcp_msg_rsp(rcp_msg, gcp_msg)
                tmp = rcp_msg.sequences
                rcp_msg.sequences = []
                for seq in tmp:
                    self._prepare_rcp_seq_rsp(seq, gcp_msg)

                    # get rsp_data
                    rsp_data = None
                    for data in rsp_data_list:
                        self.logger.debug("the rsp date operation_id: %d, seq number: %d",
                                          data.operation_id, seq.seq_number)
                        if data.operation_id == seq.seq_number:
                            rsp_data = data
                            rsp_data_list.remove(rsp_data)
                            break

                    try:
                        ret_seq = RCPSequence(
                            gcp_message_id=seq.gcp_message_id,
                            rcp_message_id=seq.rcp_message_id,
                            seq_number=seq.seq_number,
                            operation=seq.operation,
                            parent_gpb=rsp_data.rsp_data if rsp_data is not None else None,
                            skip_create_tlv_data=True
                        )
                        self._set_seq_ok(ret_seq)
                        rcp_msg.sequences.append(ret_seq)
                    except Exception as ex:
                        self.logger.error("Failed to re-init RCP SEQ with result data: %s", ex)

                    if None is rsp_data:
                        self.logger.error("Results for RCP sequence number %s are missing", ret_seq.seq_number)
                        self._set_seq_failed(ret_seq)
                        continue
        return [pkt_req]

    def get_positive_rsp_packets(self, slave, req_packet):
        """Gets packet including a request and all requested data filled. This
        method walks all messages and sequences from the packet and modifies it
        to the response packet and returns as result.

        :param slave: The slave session.
        :param req_packet: The packet including the request.
        :raise AttributeError: if some of attributes is None
        :return list of instances of the RCPPacket

        """
        # TODO need to add fragmentation for large configurations

        if None is slave or None is req_packet:
            raise AttributeError()

        req_packet.reinit()
        for gcp_msg in req_packet.msgs:
            self._prepare_gcp_msg_rsp(gcp_msg)

            # walk all sequences and change operation types from req to rsp
            for rcp_msg in gcp_msg.tlv_data.rcp_msgs:
                self._prepare_rcp_msg_rsp(rcp_msg, gcp_msg)

                for seq in rcp_msg.sequences:
                    self._prepare_rcp_seq_rsp(seq, gcp_msg)
                    self._set_seq_ok(seq)

        return [req_packet]


class RCPMasterPacketBuildDirector(object):  # pragma: no cover
    """Defines functions which helps to build GCP packets for specific
    operations for RCP Master.

    Uses RCPPacketBuilder for this purpose. All methods defined here
    must have a master parameter (even if it's not used) because the
    methods are used to build scenario  steps.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.builder = RCPPacketBuilder()

    def get_rpd_capabilities_read_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with IRA message with the
        sequence including read operation for RPD Capabilities.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_IRA)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        self.builder.last_rcp_sequence.RpdCapabilities.set_is_used()

        seq = self.builder.last_rcp_sequence
        seq.RpdCapabilities.NumBdirPorts.set_is_used()
        seq.RpdCapabilities.NumDsRfPorts.set_is_used()
        seq.RpdCapabilities.NumUsRfPorts.set_is_used()
        seq.RpdCapabilities.NumTenGeNsPorts.set_is_used()
        seq.RpdCapabilities.NumOneGeNsPorts.set_is_used()
        seq.RpdCapabilities.NumDsScQamChannels.set_is_used()
        seq.RpdCapabilities.NumDsOfdmChannels.set_is_used()
        seq.RpdCapabilities.NumUsScQamChannels.set_is_used()
        seq.RpdCapabilities.NumUsOfdmaChannels.set_is_used()
        seq.RpdCapabilities.NumDsOob55d1Channels.set_is_used()
        seq.RpdCapabilities.NumUsOob55d1Channels.set_is_used()
        seq.RpdCapabilities.NumOob55d2Modules.set_is_used()
        seq.RpdCapabilities.NumUsOob55d2Demodulators.set_is_used()
        seq.RpdCapabilities.NumNdfChannels.set_is_used()
        seq.RpdCapabilities.NumNdrChannels.set_is_used()
        seq.RpdCapabilities.SupportsUdpEncap.set_is_used()
        seq.RpdCapabilities.NumDsPspFlows.set_is_used()
        seq.RpdCapabilities.NumUsPspFlows.set_is_used()

        # for rcp rpd capabilities 50.19
        seq.RpdCapabilities.RpdIdentification.set_is_used()
        seq.RpdCapabilities.RpdIdentification.VendorName.set_is_used()
        seq.RpdCapabilities.RpdIdentification.VendorId.set_is_used()
        seq.RpdCapabilities.RpdIdentification.ModelNumber.set_is_used()
        seq.RpdCapabilities.RpdIdentification.DeviceMacAddress.set_is_used()
        seq.RpdCapabilities.RpdIdentification.CurrentSwVersion.set_is_used()
        seq.RpdCapabilities.RpdIdentification.BootRomVersion.set_is_used()
        seq.RpdCapabilities.RpdIdentification.DeviceDescription.set_is_used()
        seq.RpdCapabilities.RpdIdentification.DeviceAlias.set_is_used()
        seq.RpdCapabilities.RpdIdentification.SerialNumber.set_is_used()
        seq.RpdCapabilities.RpdIdentification.UsBurstReceiverVendorId.set_is_used()
        seq.RpdCapabilities.RpdIdentification.UsBurstReceiverModelNumber.set_is_used()
        seq.RpdCapabilities.RpdIdentification.UsBurstReceiverDriverVersion.set_is_used()
        seq.RpdCapabilities.RpdIdentification.UsBurstReceiverSerialNumber.set_is_used()
        seq.RpdCapabilities.RpdIdentification.RpdRcpProtocolVersion.set_is_used()
        seq.RpdCapabilities.RpdIdentification.RpdRcpSchemaVersion.set_is_used()
        seq.RpdCapabilities.RpdIdentification.HwRevision.set_is_used()

        # for rcp rpd capabilities 50.20
        sub_tlv = \
            seq.RpdCapabilities.LcceChannelReachability.add_new_repeated()
        sub_tlv.EnetPortIndex.set_val(1)
        sub_tlv.ChannelType.set_val(
            rcp_tlv_def.CHANNEL_TYPE_1_DsScQa_downstream_QAM[0])
        sub_tlv.RfPortIndex.set_val(1)
        sub_tlv.StartChannelIndex.set_val(1)
        sub_tlv.EndChannelIndex.set_val(1)

        # for rcp rpd capabilities 50.21
        seq.RpdCapabilities.PilotToneCapabilities.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.NumCwToneGens.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.LowestCwToneFreq.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.HighestCwToneFreq.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.MaxPowerDedCwTone.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.QamAsPilot.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.MinPowerDedCwTone.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.MaxPowerQamCwTone.set_is_used()
        seq.RpdCapabilities.PilotToneCapabilities.MinPowerQamCwTone.set_is_used()

        # for rcp rpd capabilities 50.22
        sub_tlv = seq.RpdCapabilities.AllocDsChanResources.add_new_repeated()
        sub_tlv.DsPortIndex.set_val(1)
        sub_tlv.AllocatedDsOfdmChannels.set_is_used()
        sub_tlv.AllocatedDsScQamChannels.set_is_used()
        sub_tlv.AllocatedDsOob55d1Channels.set_is_used()
        sub_tlv.Deprecated.set_is_used()
        sub_tlv.AllocatedNdfChannels.set_is_used()


        # for rcp rpd capabilities 50.23
        sub_tlv = seq.RpdCapabilities.AllocUsChanResources.add_new_repeated()
        sub_tlv.UsPortIndex.set_val(1)
        sub_tlv.AllocatedUsOfdmaChannels.set_is_used()
        sub_tlv.AllocatedUsScQamChannels.set_is_used()
        sub_tlv.AllocatedUsOob55d1Channels.set_is_used()
        sub_tlv.Deprecated.set_is_used()
        sub_tlv.AllocatedNdrChannels.set_is_used()


        # for rcp rpd capabilities 50.24
        sub_tlv = seq.RpdCapabilities.DeviceLocation
        sub_tlv.set_is_used()
        sub_tlv.DeviceLocationDescription.set_is_used()
        sub_tlv.GeoLocationLatitude.set_is_used()
        sub_tlv.GeoLocationLongitude.set_is_used()

        # for rcp rpd capabilities 50.(25,26,27,28)
        seq.RpdCapabilities.NumAsyncVideoChannels.set_is_used()
        seq.RpdCapabilities.SupportsFlowTags.set_is_used()
        seq.RpdCapabilities.SupportsFrequencyTilt.set_is_used()
        seq.RpdCapabilities.TiltRange.set_is_used()

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_ccap_capabilities_write_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for CCAP Capabilities.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence

        caps = master.get_descriptor().capabilities
        master_addr = master.get_socket().getsockname()

        ccap_ident = seq.CcapCoreIdentification.add_new_repeated()
        ccap_ident.Index.set_val(caps.index)
        ccap_ident.CoreId.set_val("{}".format(master_addr[1]))
        ccap_ident.CoreIpAddress.set_val(
            utils.Convert.ipaddr_to_tuple_of_bytes(master.descr.addr_local))
        ccap_ident.IsPrincipal.set_val(1 if caps.is_principal else 0)
        if None is caps.core_name:
            ccap_ident.CoreName.set_val(
                "Testing_core_{}".format(master_addr[0]))
        else:
            ccap_ident.CoreName.set_val(caps.core_name)
        ccap_ident.VendorId.set_val(0)

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_gdm_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for CCAP Capabilities.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.ManagementREQ, transaction_id)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Command.set_val(0)

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def test_config_done_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence
        seq.RpdConfigurationDone.set_val(1)

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def test_rpd_ha_add_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence
        ha_info = seq.RedundantCoreIpAddress.add_new_repeated()
        # (utils.Convert.ipaddr_to_tuple_of_bytes(master.descr.addr_local))
        ha_info.ActiveCoreIpAddress.set_val(
            utils.Convert.ipaddr_to_tuple_of_bytes(master.descr.addr_local))
        ha_info.StandbyCoreIpAddress.set_val(
            utils.Convert.ipaddr_to_tuple_of_bytes("10.0.2.15"))
        #ha_info.CoreHaRole.set_val(1)  # 0: active, 1: standby
        ha_info.Operation.set_val(0)  # 0: add, 1: del, 2: change

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def test_rpd_ha_change_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence
        ha_info = seq.RedundantCoreIpAddress.add_new_repeated()
        # (utils.Convert.ipaddr_to_tuple_of_bytes(master.descr.addr_local))
        ha_info.ActiveCoreIpAddress.set_val(
            utils.Convert.ipaddr_to_tuple_of_bytes(master.descr.addr_local))
        ha_info.StandbyCoreIpAddress.set_val(utils.Convert.ipaddr_to_tuple_of_bytes("10.0.2.15"))
        #ha_info.CoreHaRole.set_val(0)  # 0: active, 1: standby
        ha_info.Operation.set_val(2)  # 0: add, 1: del, 2: change

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def test_rpd_ha_delete_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_DELETE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence
        ha_info = seq.RedundantCoreIpAddress.add_new_repeated()
        ha_info.ActiveCoreIpAddress.set_val(
            utils.Convert.ipaddr_to_tuple_of_bytes(master.descr.addr_local))
        ha_info.StandbyCoreIpAddress.set_val(utils.Convert.ipaddr_to_tuple_of_bytes("10.0.2.15"))
        #ha_info.CoreHaRole.set_val(1)  # 0: active, 1: standby
        ha_info.Operation.set_val(1)  # 0: add, 1: del, 2: change

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def test_multiple_core_add_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence
        ha_info = seq.ConfiguredCoreTable.add_new_repeated()
        ha_info.ConfiguredCoreIp.set_val(utils.Convert.ipaddr_to_tuple_of_bytes("10.0.2.15"))
        ha_info.Operation.set_val(0)  # 0: add, 1: del, 2: change

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_active_principal_acore_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_READ,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence

        self.builder.last_rcp_sequence.ActivePrincipalCore.set_is_used()
        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def test_multiple_core_del_packet(self, master, slave_fd):
        """Creates a packet including EDSReq message with REX message with the
        sequence including write operation for HA feature.

        :param master: The master session.
        :return RCPPacket
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_DELETE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        seq = self.builder.last_rcp_sequence
        ha_info = seq.ConfiguredCoreTable.add_new_repeated()
        ha_info.ConfiguredCoreIp.set_val(
            utils.Convert.ipaddr_to_tuple_of_bytes("10.0.2.15"))
        ha_info.Operation.set_val(1)  # 0: add, 1: del, 2: change

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_redirect_packet(self, master, slave_fd, addr_list):
        """Creates packet including EDSReq message with IRA message and
        redirect.

        :param master: The master session.
        :param addr_list: The list of IP addresses.
        :param slave_fd: The file descriptor of the slave's connection.

        """
        if None is master:
            raise AttributeError()

        if not addr_list:
            raise AttributeError()

        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_IRA)
        self.builder.add_rcp_seq(rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        for addr in addr_list:
            redir = self.builder.last_rcp_sequence.RpdRedirect.\
                add_new_repeated()
            redir.RedirectIpAddress.set_val(
                utils.Convert.ipaddr_to_tuple_of_bytes(addr))

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    def get_cfg_pkt_eds_rex(self, master, slave_fd, operation, configuration):
        """Creates a request packet including the passed configuration.
        The configuration is passed as instance of RCPSequence and will be
        encapsulated into EDSReq / REX messages. SequenceNumber and
        TransactionID from the master session are used and set and resulting
        packet is returned.

        :param master: The master session.
        :param slave_fd: The file descriptor of the slave's connection.
        :param operation: The RCP operation which will be set into the
         RCPSequence.
        :type operation: Operation type defined in rcp_tlv_def.py
        :param configuration: The configuration which will be sent.
        :type configuration: RCPSequence
        :return list of instances of RCPPacket

        """
        if None in (master, slave_fd, operation, configuration):
            raise AttributeError()

        if operation not in rcp_tlv_def.RCP_OPERATION_TYPES:
            raise AttributeError(
                "Invalid operation passed {}".format(operation))

        if not isinstance(configuration, RCPSequence):
            raise TypeError()

        # TODO need to add fragmentation for large configurations
        self.builder.clear()
        transaction_id = master.slave_cons[slave_fd].get_next_trans_id()
        rcp_sequence_id = master.slave_cons[slave_fd].get_next_seq_id()

        self.builder.add_packet(transaction_id=transaction_id)
        self.builder.add_gcp_msg(gcp_msg_def.DataStructREQ, transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)

        configuration.seq_number = rcp_sequence_id
        configuration.operation = operation
        self.builder.append_rcp_seq(configuration)

        # Fill GCP message fields
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]


class CCAPStep(object):  # pragma: no cover
    """Class stores data forming one step in a scenario."""
    __NO_DESCRIPTION = "No description"

    __metaclass__ = AddLoggerToClass

    def __init__(self, master_dir_method, param_tuple=None,
                 description=__NO_DESCRIPTION):
        """

        :param master_dir_method: Method of the RCPMasterPacketBuildDirector,
        which takes at least two parameters. The first parameter is
        master session and the second one is slave's file descriptor.
        Next parameters are optional.
        :param param_tuple: Tuple of next parameters (except to master and
        slave_fd parameter) of the master_dir_method.
        Can be None in case that the  method has only the two mandatory
        parameters.
        :type param_tuple: Tuple
        :param description: Description of the step.
        :type description: String

        """
        if not callable(master_dir_method):
            raise AttributeError("Parameter master_dir_method is not method")

        if master_dir_method.im_class is not RCPMasterPacketBuildDirector:
            raise AttributeError("Parameter master_dir_method is not method "
                                 "of the RCPMasterPacketBuildDirector class")

        if None is not param_tuple and not isinstance(param_tuple, tuple):
            raise TypeError("Invalid param_tuple type")

        self.master_dir_method = master_dir_method
        self.param_tuple = param_tuple
        self.description = description


class CCAPStepSet(object):  # pragma: no cover

    """Class stores steps of the scenario in order in which they will be sent
    to a slave.

    Class stores also an index pointing to the current step which will
    be processed.

    """

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.index = 0
        self.steps = []

    def reset(self):
        """Sets index pointing to the current step at the first step."""
        self.index = 0

    def get_step_next(self):
        """Returns current step and moves index.

        None is returned if there is not next step.

        """
        try:
            step = self.steps[self.index]
        except IndexError:
            return None
        self.index += 1
        return step

    def clear_steps(self):
        """Clears steps and sets index to zero."""
        self.steps = []
        self.index = 0

    def add_step(self, step):
        """Adds new step at the end of list of steps.

        :param step: Object describing one step in scenario.
        :type step: CCAPStep

        """
        if not isinstance(step, CCAPStep):
            raise TypeError("Invalid step type")
        self.steps.append(step)

    def remove_step(self, index):
        """Removes a step identified by index."""
        try:
            self.steps.remove(index)
        except KeyError:
            return

        # set correct index if we have removed some previous step
        if self.index < index:
            self.index -= 1

    def clone_steps(self):
        """Creates a copy of steps and returns new instance of steps."""
        copy = self.__class__()
        # make a shallow copy of steps
        copy.steps = list(self.steps)
        copy.index = self.index
        return copy


class RCPMasterScenario(object):  # pragma: no cover
    """Class is used to store steps creating scenario for one concrete slave.

    These steps are processed by orchestrator. Scenario may contain a
    default scenario (with slave_id 0) and this default scenario is used
    for slave_ids without scenario specified. This class implements
    methods to create the scenario from particular steps.

    """

    __metaclass__ = AddLoggerToClass
    _DEFAULT_SLAVE_ID = 0

    def __init__(self):
        self.slave_step_set = {}

    def add_next_step(self, step, slave_id=None):
        """Creates new list of steps if it doesn't already exist and adds
        new step at the end of the list.

        If the slave_id is None, then the step is added into the default
        scenario, which is used for slave_ids without scenario specified.

        :param step: Object describing the next step.
        :type step: CCAPStep
        :param slave_id: The unique ID of slave, string in format address:port
         or just address. Can be None.
         The step is added into the default set of steps if the
         slave_id is None.
        :type slave_id: String

        """
        if not isinstance(step, CCAPStep):
            raise TypeError("Invalid step type")

        if None is slave_id:
            slave_id = self._DEFAULT_SLAVE_ID

        if slave_id not in self.slave_step_set:
            self.slave_step_set[slave_id] = CCAPStepSet()

        self.slave_step_set[slave_id].add_step(step)

    def get_steps(self, slave_id):
        """Returns all steps for the slave identified by the slave_id.

        :param slave_id: The unique ID of slave, string in format address:port
        :type slave_id: String

        """
        if None is slave_id or slave_id not in self.slave_step_set:
            default_steps = self.slave_step_set.get(self._DEFAULT_SLAVE_ID)
            if None is not default_steps:
                return default_steps.clone_steps()
            return None
        return self.slave_step_set[slave_id]

    def clear_steps(self, slave_id):
        """Clears steps of the slave identified by slave_id parameter.

        :param slave_id: The unique ID of slave, string in format address:port
        :type slave_id: String

        """
        self.slave_step_set[slave_id].clear_steps()

    def clear_steps_all(self):
        """Clears steps of all slaves."""
        for steps in self.slave_step_set.itervalues():
            steps.clear_steps()

    def remove_slave(self, slave_id):
        """Removes slave.

        :param slave_id: The unique ID of slave, string in format address:port
        :type slave_id: String

        """
        if None is slave_id:
            return

        if slave_id not in self.slave_step_set:
            return
        del self.slave_step_set[slave_id]

    def clone_scenario(self):
        """Creates copy of this instance of the scenario and returns it."""
        copy = RCPMasterScenario()
        for slave_id, steps in self.slave_step_set.iteritems():
            copy.slave_step_set[slave_id] = steps.clone_steps()
        return copy
