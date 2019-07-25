#
# Copyright (c) 2016 Cisco and/or its affiliates, and
# Cable Television Laboratories, Inc. ("CableLabs")
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

# Add the path to system
import re
import time
import zmq

from zmq.utils.monitor import recv_monitor_message

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.dispatcher.timer import DpTimerManager
from rpd.gpb.cfg_pb2 import config
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_sessions import GCPSessionQHigh, GCPSessionFull
from rpd.rcp.rcp_lib import rcp
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.rcp_lib import docsis_message
from rpd.common.utils import SysTools
from rpd.rcp.vendorTLVs.src.RcpVspTlv import RcpVendorTlv, DEFAULT_VENDOR_ID


class DataObj(object):

    """Stores the data prepared for cfg operations and results of the
    operations."""

    CFG_OPER_RESULT_NONE = None
    CFG_OPER_RESULT_OK = "OK"
    CFG_OPER_RESULT_GENERAL_ERROR = "GeneralError"
    CFG_OPER_RESULT_TIMEOUTED = "Timeouted"
    CFG_OPER_RESULT_INTERNAL = "InternalError"

    def __init__(self, data, operation, operation_id, path=None):
        if None is operation:
            raise AttributeError("No any operation specified")
        if (None is data) and (operation in RcpHalIpc.RPD_DATA_OPER_WR_OR_AW):
            raise AttributeError("No any data passed")

        self.data = data
        self.operation = operation
        self.operation_id = operation_id
        self.path = path
        self.ipc_req_msg = None

        # Data set in response
        self.response_data = None  # is set in response to read operation
        self.result = None

    def __str__(self):
        ret_str = "The content of " + self.__class__.__name__ + " instance is:\n"
        ret_str += "data:" + str(self.data) + "\n"
        ret_str += "operation:" + str(self.operation) + "\n"
        ret_str += "operation_id:" + str(self.operation_id) + "\n"
        ret_str += "path:" + str(self.path) + "\n"
        ret_str += "ipc_req_msg:" + str(self.ipc_req_msg) + "\n"
        ret_str += "response_data:" + str(self.response_data) + "\n"
        ret_str += "result:" + str(self.result) + "\n"
        return ret_str


class RcpHalClientError(Exception):

    def __init__(self, msg, expr=None):
        super(RcpHalClientError, self).__init__(msg)
        self.msg = msg
        self.expr = expr


class RcpMessageRecordElem(object):

    def __init__(self, req_msg, pkt=None):
        self.ref_count = 0
        self.msg_req = req_msg  # the type for msg req os dataObj
        # When the msg is returned, we should  put the message into this dict, the reason is that, we have to compose
        # the packet for the read.
        self.msg_fragments = dict()
        self.seq_nums = list()
        self.send_out_time = time.time()
        self.pkt = pkt
        self.rsp_list = list()

    def set_pkt(self, pkt):
        self.pkt = pkt

    def __str__(self):
        ret_str = "The content of " + self.__class__.__name__ + " instance is:\n"
        ret_str += "ref_count:" + str(self.ref_count) + "\n"
        ret_str += "send_out_time:" + str(self.send_out_time) + "\n"
        ret_str += "packet:" + str(self.pkt) + "\n"
        ret_str += "rsp list:" + str(self.rsp_list) + "\n"
        return ret_str


class RcpMessageRecord(object):

    """This class is used to record the msg which has been send to HAL.

    The reason that we need this class is we want to Async the message
    processing. When we send out a message, we will do this following steps:

    1. Record the message into internal DB when sending out a msg.
    2. If the message is fragmented, we need to also record the SeqNum and increase the reference counter.
    3. When receiving a msg, if the message result is successful, we would remove the seqNUm and decrease the reference
       counter. When the counter is decreased to zero, we need send out the rsp to GCP orchestrator.
    4. If the message is fail, we need immediately send an error message to orchestrator.
    5. If we cannot find the message, we will ignore this message.
    6. For the timeout, we will use a centralized repeated timer to check the record to see if it has been timeout.

    """
    __metaclass__ = AddLoggerToClass
    MSG_TIMEOUT = 15

    def __init__(self, disp, event_fire_cb=None, unittest=None):
        """
        :param event_fire_cb: this call back function will be called if
         we want to send a successful or fail rsp

        The callback format is::
        {
            "rsp_seq_list":,
            "rsp_session":,
            "rsp_pkt":
        }

        The pkt_list format is as following::
        {
            "last_pkt": last_pkt,
            "last_session": last_session,
            "req_list":req_list,
        }
        """
        self.pkt_db = dict()

        self.dispatcher = disp
        # The timer is to check the rsp_list to find  if there is some rsp is timed out
        self.timer = self.dispatcher.timer_register(
            self.MSG_TIMEOUT,
            self._timeout_check_cb,
            None,
            timer_type=DpTimerManager.TIMER_REPEATED)
        self.seq_num_mapping = dict()
        self.recv_rsp_cb = event_fire_cb
        self.unittest = unittest

    def _generate_error_rsp(self, record_req_elem):
        data_obj = record_req_elem.msg_req
        cfg_rsp = data_obj.ipc_req_msg
        cfg_rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR
        data_obj.result = DataObj.CFG_OPER_RESULT_GENERAL_ERROR
        data_obj.rsp_data = cfg_rsp.RpdDataMessage.RpdData
        record_req_elem.pkt["msg_rsp"].append(data_obj)

    def _timeout_check_cb(self, arg):

        # we may need some optimize method to check the timeout
        self.logger.debug("timeout to check the record req elem...")
        current_time = time.time()

        for seq_num in self.seq_num_mapping.keys():
            record_req_elem = self.seq_num_mapping[seq_num]
            if current_time - record_req_elem.send_out_time > self.MSG_TIMEOUT and record_req_elem.ref_count > 0:
                self.logger.warning(
                    "Found a message timeout, fire!!, seq_number: %d, content:%s",
                    seq_num, record_req_elem)
                self.seq_num_mapping.pop(seq_num)
                record_req_elem.ref_count = -3  # negative value for error
                self._generate_error_rsp(record_req_elem)
                try:
                    self._check_and_fire(record_req_elem)
                except GCPSessionQHigh as e:
                    self.logger.info("%s return to re-timeout" % str(e))
                    return

        if self.unittest and self.unittest['enable']:  # pragma: no cover
            if self.unittest['runtimes'] > 0:
                self.unittest['runtimes'] -= 1
            if self.unittest['runtimes'] <= 0:
                self.dispatcher.end_loop()

    def add_pkt_to_internal_db(self, last_session, last_pkt, gcp_msg, req_list):
        self.logger.debug(
            "Add a pkt into internal DB: %s, %s, %s"
            % (last_session, last_pkt, gcp_msg))

        if (last_session, last_pkt, gcp_msg) not in self.pkt_db:
            self.pkt_db[(last_session, last_pkt, gcp_msg)] = {
                "last_session": last_session,
                "last_pkt": last_pkt,
                "gcp_msg": gcp_msg,
                "req_list": req_list,
                "send_done": False,
                "recv_done": False,
                "msg_rsp": list(),
            }

        return self.pkt_db[(last_session, last_pkt, gcp_msg)]

    def remove_pkt_from_internal_db(self, last_session, last_pkt, gcp_msg):
        self.logger.debug(
            "Remove the pkt from internal DB: %s, %s, %s"
            % (last_session, last_pkt, gcp_msg))

        if (last_session, last_pkt, gcp_msg) in self.pkt_db:
            self.pkt_db.pop((last_session, last_pkt, gcp_msg))

    def add_req_to_internal_db(self, last_session, last_pkt, gcp_msg, seq_num, record_req_elem):
        if (last_session, last_pkt, gcp_msg) not in self.pkt_db:
            self.logger.warning(
                "Cannot find the instance in pkt db, for req_elem:%s"
                % record_req_elem)
            return

        pkt_req = self.pkt_db[(last_session, last_pkt, gcp_msg)]

        self.logger.debug(
            "Add the seq num %d into dict, currently, you have %d brothers has been out, wait the rsp back!"
            % (seq_num, record_req_elem.ref_count))

        if seq_num in self.seq_num_mapping:
            self.logger.warning(
                "Seq num [%d]has been in seq mapping, ignore it~" % seq_num)
            return

        record_req_elem.ref_count += 1
        if seq_num not in record_req_elem.seq_nums:
            record_req_elem.seq_nums.append(seq_num)

        if not record_req_elem.pkt:
            record_req_elem.set_pkt(pkt_req)

        self.seq_num_mapping[seq_num] = record_req_elem
        return

    def remove_req_from_internal_db(self, seq_num, record_req_elem):
        self.logger.debug("Remove seq[%d] from internal db :%s" % (seq_num, record_req_elem))
        if seq_num in self.seq_num_mapping:
            self.seq_num_mapping.pop(seq_num)
            record_req_elem.ref_count -= 1
            if seq_num in record_req_elem.seq_nums:
                record_req_elem.seq_nums.remove(seq_num)
        return

    def set_send_procedure_done(self, last_session, last_pkt, gcp_msg):
        pkt_req = self.pkt_db[(last_session, last_pkt, gcp_msg)]
        pkt_req['send_done'] = True

    def recv_fragment_msg(self, hal_recv_msg):

        self.logger.debug("Receive a HAL rsp message content:%s" % (hal_recv_msg.msg))

        seq_num = hal_recv_msg.msg.SeqNum
        if seq_num not in self.seq_num_mapping:
            self.logger.warning(
                "Got a message with seq number:%d, not in seq_num_mapping.",
                seq_num)
            return

        record_req_elem = self.seq_num_mapping[seq_num]
        self.seq_num_mapping.pop(seq_num)
        if record_req_elem.ref_count < 0:
            self.logger.warning(
                "We received HAL error message, ignore the succeeded msg, seq_num:%d" % seq_num)
            return

        # Check the status
        if hal_recv_msg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            # yes, we recv a error message from HAL
            self.logger.warning(
                "Receive a hal fail message:%s" % hal_recv_msg.msg)
            # here -1 means there are some errors, the succeed msg should ignore this message
            record_req_elem.ref_count = -1
            self._generate_error_rsp(record_req_elem)
            self._check_and_fire(record_req_elem)
            return

        cfg_rsp = t_RcpMessage()
        cfg_rsp.ParseFromString(hal_recv_msg.msg.CfgMsgPayload)
        if cfg_rsp.RcpDataResult != t_RcpMessage.RCP_RESULT_OK:
            # yes we recv a error msg from driver
            self.logger.warning("Recv a driver fail message:%s" % str(cfg_rsp))
            record_req_elem.ref_count = -2
            self._generate_error_rsp(record_req_elem)
            self._check_and_fire(record_req_elem)
            return

        # we are win here!!
        self.logger.debug("We receive a perfect result:%s" % hal_recv_msg.msg)
        record_req_elem.ref_count -= 1
        record_req_elem.rsp_list.append(cfg_rsp)  # we don't care the seq

        self.check_if_all_done(record_req_elem)

        return

    def recv_bypass_msg(self, record_req_elem, cfg):
        """This function may be called when shadowlayer enabled.

        :param record_req_elem:
        :param cfg:
        :return:

        """
        record_req_elem.rsp_list.append(cfg)

    def check_if_all_done(self, record_req_elem):
        if record_req_elem.ref_count == 0:
            self.logger.debug(
                "We have received all the messages, compose it to a rsp.")
            cfg_rsp = self._compose_message(
                record_req_elem.msg_req, record_req_elem.rsp_list,
                t_RcpMessage.RCP_RESULT_OK)
            data_obj = record_req_elem.msg_req
            data_obj.result = DataObj.CFG_OPER_RESULT_OK
            data_obj.rsp_data = cfg_rsp.RpdDataMessage.RpdData
            record_req_elem.pkt["msg_rsp"].append(data_obj)
            self._check_and_fire(record_req_elem)
            return

    def check_recv_done(self, record_req_elem):
        pkt = record_req_elem.pkt
        if (len(pkt["msg_rsp"]) == len(pkt["req_list"])) and (record_req_elem.ref_count <= 0):
            pkt["recv_done"] = True
        else:
            self.logger.debug(
                "Wait some pkt rsp in the messages,rsp: %d < req: %d or "
                " record_req_elem.ref_count is %s "
                % (len(pkt["msg_rsp"]), len(pkt["req_list"]), str(record_req_elem.ref_count)))

    def check_and_fire_pkt(self, pkt):
        if pkt["recv_done"] and pkt["send_done"]:
            self.logger.debug(
                "We have collect all the messages, fire!!! %s"
                % pkt)

            session = pkt['last_session']

            # pop from the packet db
            key = (pkt['last_session'], pkt['last_pkt'], pkt['gcp_msg'])
            if key in self.pkt_db:
                self.pkt_db.pop(key)

            # Call the callback:
            if self.recv_rsp_cb:
                self.recv_rsp_cb({
                    "session": pkt['last_session'],
                    "req_packet": pkt['last_pkt'],
                    "gcp_msg": pkt['gcp_msg'],
                    "req_data": pkt['msg_rsp'],
                })
            else:
                self.logger.warning(
                    "Cannot send the pkt [%s] since the callback is not ready!"
                    % pkt)
            try:
                if session.io_ctx and session.io_ctx.socket and session.io_ctx.is_tx_low_pri_queue_at_high_watermark():
                    raise GCPSessionQHigh(
                        "TX low priority queue reach high watermark, stop sending")
            except AttributeError as e:
                self.logger.warning("AttributeExcpetion happened: %s", str(e))

    def _check_and_fire(self, record_req_elem):
        pkt = record_req_elem.pkt
        self.check_recv_done(record_req_elem)
        self.check_and_fire_pkt(pkt)

    def _compose_message(self, data_obj, rsp_list, result):
        req = data_obj.ipc_req_msg
        cfg_rsp = t_RcpMessage()
        cfg_rsp.RcpMessageType = req.RcpMessageType
        cfg_rsp.RpdDataMessage.RpdDataOperation = req.RpdDataMessage.RpdDataOperation
        cfg_rsp.RcpDataResult = result

        for rsp in rsp_list:
            rsp_data = rsp.RpdDataMessage.RpdData
            for desc, value in rsp_data.ListFields():
                if desc.name in ['RfChannel']:
                    for rf_channel in rsp_data.RfChannel:
                        rfch = cfg_rsp.RpdDataMessage.RpdData.RfChannel.add()
                        rfch.CopyFrom(rf_channel)
                elif desc.name in ['RfPort']:
                    for rf_port in rsp_data.RfPort:
                        rf_port_rsp = cfg_rsp.RpdDataMessage.RpdData.RfPort.add()
                        rf_port_rsp.CopyFrom(rf_port)
                elif desc.name in ['RpdCapabilities']:
                    rpd_cap = cfg_rsp.RpdDataMessage.RpdData.RpdCapabilities
                    rpd_cap.CopyFrom(value)
                elif desc.name == "CcapCoreIdentification":
                    for ccap_cfg in rsp_data.CcapCoreIdentification:
                        ccap_cfg_rsp = cfg_rsp.RpdDataMessage.RpdData.CcapCoreIdentification.add()
                        ccap_cfg_rsp.CopyFrom(ccap_cfg)
                else:
                    if desc.type == desc.TYPE_MESSAGE:
                        if desc.label == desc.LABEL_REPEATED:
                            for sub_field in value:
                                field = getattr(cfg_rsp.RpdDataMessage.RpdData, desc.name).add()
                                field.CopyFrom(sub_field)
                        else:
                            getattr(cfg_rsp.RpdDataMessage.RpdData, desc.name).CopyFrom(value)
                    else:
                        if desc.label == desc.LABEL_REPEATED:
                            field = getattr(cfg_rsp.RpdDataMessage.RpdData, desc.name)
                            field.extend(value)
                        else:
                            setattr(cfg_rsp.RpdDataMessage.RpdData, desc.name, value)

        return cfg_rsp

    def set_fire_cb(self, fire_cb):
        self.recv_rsp_cb = fire_cb


class RcpHalIpc(object):
    """The Client for Hal."""
    __metaclass__ = AddLoggerToClass
    REG_PERIOD = 5
    REG_TRYCNT = 3
    DEFAULT_RETRRY_NR = 10
    SYNC = "ALIGNED"
    LOS = "LOSS OF SYNC"
    RCP_HAL_THROTTLING_SIZE = 64

    RPD_DATA_OPER_RD = 'RD'
    RPD_DATA_OPER_WR = 'WR'
    RPD_DATA_OPER_DEL = 'DEL'
    RPD_DATA_OPER_AW = 'AW'
    RPD_DATA_OPER = (RPD_DATA_OPER_RD,
                     RPD_DATA_OPER_WR,
                     RPD_DATA_OPER_DEL,
                     RPD_DATA_OPER_AW)
    RPD_DATA_OPER_WR_OR_AW = (RPD_DATA_OPER_WR,
                              RPD_DATA_OPER_AW)

    RCP_OPER_TO_RPD_DATA_OPER = {
        rcp_tlv_def.RCP_OPERATION_TYPE_READ: RPD_DATA_OPER_RD,
        rcp_tlv_def.RCP_OPERATION_TYPE_WRITE: RPD_DATA_OPER_WR,
        rcp_tlv_def.RCP_OPERATION_TYPE_DELETE: RPD_DATA_OPER_DEL,
        rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE: RPD_DATA_OPER_AW,
    }

    RPD_DATA_OPER_TO_IPC_OPER = {
        RPD_DATA_OPER_RD: t_RpdDataMessage.RPD_CFG_READ,
        RPD_DATA_OPER_WR: t_RpdDataMessage.RPD_CFG_WRITE,
        RPD_DATA_OPER_DEL: t_RpdDataMessage.RPD_CFG_DELETE,
        RPD_DATA_OPER_AW: t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE,
    }

    CTRL_RPD_INIT_PROV_INFO_PATH = '/rpd/config/ctrl_rpd_init_prov_info'

    def __init__(self, appName, appDesc, appVer, interestedNotification,
                 channel, logConfigurePath=None, shadowLayerConf=None):
        """ TODO missing params

        :param appName: The application name, such as RPD CLI
        :param appDesc: A brief description about this application, such as
                        the functionality description
        :param appVer: Driver specific version, such as 1.0.1
        :param interestedNotification: a tuple or list for the application
                        interested msg types, the form will be (1, 2, 456, 10)
        :return: HalClient object

        """
        # sanity check the input args
        if not isinstance(appName, str) or not isinstance(appDesc, str) or not \
                isinstance(appVer, str):
            raise RcpHalClientError("Driver name/desc/version "
                                    "should be a str type")

        if not isinstance(interestedNotification, tuple) and not \
                isinstance(interestedNotification, list):
            raise RcpHalClientError("supportedMsgType should be "
                                    "a tuple or list")

        self.appName = appName
        self.appDesc = appDesc
        self.appVer = appVer
        self.interestedNotification = list(interestedNotification)
        self.channel = channel
        self.rcp_cfg_rsp_cb = None
        self.rcp_notification_cb = None
        self.pollTimeout = 2000

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            # "HalSetLoggingLevelRsp":self.recvHalSetLoggingLevelRspCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfigRsp": self.recvCfgMsgRspCb,
            "HalClientInterestNotificationCfgRsp":
                self.recvInterestedNotificationsRspCb,
            "HalNotification": self.recvNotificationCb,
        }

        self.HalConfigMsgHandlers = {
            HalConfigMsg.MsgTypeRpdCapabilities: self.recMsgTypeRpdCapabilitiesCb,
        }

        self.HalConfigMsgRspHandlers = {
            HalConfigMsg.MsgTypeRpdCapabilities: self.recMsgTypeRpdCapabilitiesRspCb,
        }

        self.clientID = None

        self.mgrConnection = None
        self.pushSock = None
        self.pullSock = None

        self.regTry = self.REG_TRYCNT
        self.regDone = False
        self.regDoneTimer = None

        self.disconnected = True
        self.retryNr = self.DEFAULT_RETRRY_NR
        self.poller = None

        self.seqNum = 1
        self.index = -1

        # rpd capability
        self.rpd_cap = None

        self.msg_record = RcpMessageRecord(
            self.channel.dispatcher,
            self.channel.orchestrator.config_operation_rsp_cb)

    def start(self, cfg_cb, notify_cb):
        """Start poll the transport socket."""
        self.logger.debug("Start the client poll...")
        self.connection_setup(self.channel.dispatcher)
        self.rcp_cfg_rsp_cb = cfg_cb
        self.rcp_notification_cb = notify_cb
        self.register(self.clientID)

        # set the config callback
        self.msg_record.set_fire_cb(self.rcp_cfg_rsp_cb)

    def rcp_hal_cb(self, sock, mask):  # pragma: no cover
        if self.pushSock is not None and sock == self.pushSock.monitor:
            self.pushSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.pullSock is not None and sock == self.pullSock.monitor:
            self.pullSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.mgrConnection is not None and \
                sock == self.mgrConnection.monitor:
            self.mgrConnection.monitorHandler(recv_monitor_message(sock))
            return
        while sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
            try:
                bin = sock.recv(flags=zmq.NOBLOCK)
                msg = HalMessage.DeSerialize(bin)
                #self.logger.debug("Got a zmq msg:%s" % msg.msg)
                if msg.type in self.HalMsgsHandler:
                    handler = self.HalMsgsHandler[msg.type]
                    handler(msg)
            except zmq.ZMQError as e:
                self.logger.debug(
                    "Got an error when trying with non-block read:" + str(e))
                break
            except (GCPSessionQHigh, GCPSessionFull) as e:
                self.logger.warning("%s return to re-schedule" % str(e))
                return
            except Exception as e:
                self.logger.warning(
                    "Error happens when receiving the zmq msg, reason:%s" % str(e))
                break

    def connection_setup(self, disp):
        """Create the connection to the mgr and setup the poller."""
        self.logger.info("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr,
                                          HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)

        self.HalMsgsHandler[self.mgrConnection.socket] = self.recvRegisterMsgCb
        # create the poller
        if self.poller is None:
            self.poller = disp.get_poll()

        # register the mgr socket
        disp.fd_register(self.mgrConnection.socket,
                         zmq.POLLIN, self.rcp_hal_cb)
        disp.fd_register(self.mgrConnection.monitor,
                         zmq.POLLIN, self.rcp_hal_cb)

    def connection_cleanup(self, disp):     # pragma: no cover
        """Close the connection to the mgr."""
        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return

        if self.mgrConnection is not None:
            disp.fd_unregister(self.mgrConnection.socket)
            disp.fd_unregister(self.mgrConnection.monitor)
            self.mgrConnection.socket.disable_monitor()
            self.mgrConnection.monitor.close()
            self.mgrConnection.socket.close()

        if self.pullSock is not None:
            disp.fd_unregister(self.pullSock.socket)
            disp.fd_unregister(self.pullSock.monitor)
            self.pullSock.socket.disable_monitor()
            self.pullSock.monitor.close()
            self.pullSock.socket.close()

        if self.pushSock is not None:
            disp.fd_unregister(self.pushSock.monitor)
            self.pushSock.socket.disable_monitor()
            self.pushSock.monitor.close()
            self.pushSock.socket.close()

        self.disconnected = True

    def register(self, clientID):
        """Send a register message to Hal and get the client ID from the Hal."""
        if clientID is None:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.appName,
                                     ClientDescription=self.appDesc,
                                     ClientVersion=self.appVer)
        else:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.appName,
                                     ClientDescription=self.appDesc,
                                     ClientVersion=self.appVer,
                                     ClientID=clientID)

        if self.mgrConnection is None:
            errMsg = "Cannot send the register since " \
                     "the mgr connection is not setup"
            self.logger.warning(errMsg)
            raise RcpHalClientError(errMsg)
        self.logger.info("Send the register msg to Hal:" + str(registerMsg.msg))
        self.regDone = False
        self.regTry = self.REG_TRYCNT
        self.mgrConnection.send(registerMsg.Serialize())

    def send(self, msg):
        if self.pushSock:
            self.pushSock.send(msg)
        else:
            # this use of unicode() removes 75 tracebacks in unit test results
            self.logger.warning("Cannot send the msg since the push socket is none, "
                                "msg: '{}'".format(unicode(msg, errors='ignore')))

    def sayHelloToHal(self):
        """Send a hello message to verify the agent path is correct."""
        self.logger.info(" ".join([str(self.appName), str(self.clientID), ":Send a Hello message to Hal"]))
        try:
            helloMsg = HalMessage("HalClientHello", ClientID=self.clientID)
            self.send(helloMsg.Serialize())
            self.sendRpdCapReq()
        except Exception as e:
            self.logger.warning("Got exception, %s" % str(e))

    def sendInterestedNotifications(self, notifications):
        """Send the notifications to the HAL.

        :param notifications:
        :return:

        """
        if notifications is not None and not \
                isinstance(notifications, tuple) and not \
                isinstance(notifications, list):
            self.logger.warning("Cannot set an notification with wrong type, "
                                "you can pass a tuple or list to it ")
            return
        configMsg = HalMessage("HalClientInterestNotificationCfg",
                               ClientID=self.clientID,
                               ClientNotificationMessages=notifications)
        self.logger.info("Send a Interested notification configuration msg to HAL:" + str(configMsg.msg))
        self.mgrConnection.send(configMsg.Serialize())

    def recvInterestedNotificationsRspCb(self, rsp):
        """Receive a response message from the HAL for the notification rsp
        callback.

        :param rsp:
        :return:

        """
        self.logger.info(
            "Receive a interest notification response message:" +
            str(rsp.msg))

        self.regDone = True
        if None is not self.regDoneTimer:
            self.channel.dispatcher.timer_unregister(self.regDoneTimer)
            self.regDoneTimer = None

    def recvHelloRspMsgCb(self, hello):
        """Call back for Hello Message.

        :param hello:
        :return:

        """
        self.logger.info("Recv a hello message:" + str(hello.msg))

    def sendRpdCapReq(self):
        try:
            if self.rpd_cap:
                self.logger.debug("Already has Rpd cap in store, need to send req")
                return True
            rcp_msg = t_RcpMessage()
            rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
            rpd_data_msg = t_RpdDataMessage()
            rpd_data_msg.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
            rcp_cfg = config()
            sub_tlv = rcp_cfg.RpdCapabilities
            GCPObject.default_gpb(gpb=sub_tlv)
            rpd_data_msg.RpdData.CopyFrom(rcp_cfg)
            rcp_msg.RpdDataMessage.CopyFrom(rpd_data_msg)

            cfgMsgContent = rcp_msg.SerializeToString()
            msg = HalMessage("HalConfig", SrcClientID=self.clientID,
                             SeqNum=self.seqNum,
                             CfgMsgType=HalConfigMsg.MsgTypeRpdCapabilities,
                             CfgMsgPayload=cfgMsgContent)
            self.send(msg.Serialize())
            self.seqNum += 1
            self.logger.debug("send RPD capabilities req to hal driver")
            return True
        except Exception as e:
            self.logger.warning("send RPD cap req failed :%s", str(e))
            return False

    def recvCfgMsgRspCb(self, cfg):
        """Receive a configuration response message from the Hal, process it.

        :param cfg: HalMessage type
        :return:

        """
        #self.logger.debug("Recv a configuration response message:" + str(cfg.msg))
        self.logger.debug("The response SeqNum:" + str(cfg.msg.SeqNum))
        if cfg.msg.CfgMsgType in self.HalConfigMsgRspHandlers:
            cb = self.HalConfigMsgRspHandlers[cfg.msg.CfgMsgType]
            cb(cfg)
        else:
            self.msg_record.recv_fragment_msg(cfg)

    @staticmethod
    def _set_rpd_identification(identification):
        identification.VendorName = "Cisco"
        identification.VendorId = 9
        identification.ModelNumber = "123456"
        identification.DeviceMacAddress = "00:00:00:00:00:00"
        identification.CurrentSwVersion = "Prototype"
        identification.DeviceDescription = 'TestingPrototypeWithHardcodedValues'
        identification.DeviceAlias = "TP"
        # the value must be '123456' in sdn side, changed it from 777
        identification.SerialNumber = "123456"
        identification.RpdRcpProtocolVersion = "1.0"
        identification.RpdRcpSchemaVersion = "1.0.8"

    def _setRpdCapabilities(self, cfgMsg):
        """
        set AssetId, DeviceAlias, DeviceLocationDescription, GeoLocationLatitude and GeoLocationLongitude.
        """
        recv_rcp_msg = cfgMsg.RpdDataMessage.RpdData
        if recv_rcp_msg.RpdCapabilities.HasField("RpdIdentification"):
            identification = recv_rcp_msg.RpdCapabilities.RpdIdentification
            self.rpd_cap.RpdIdentification.AssetId = identification.AssetId
            self.rpd_cap.RpdIdentification.DeviceAlias = identification.DeviceAlias
            with open(self.CTRL_RPD_INIT_PROV_INFO_PATH, 'w') as f:
                f.write("Asset Id=" + identification.AssetId + '\n')
                f.write("Device Alias=" + identification.DeviceAlias + '\n')
        if recv_rcp_msg.RpdCapabilities.HasField("DeviceLocation"):
            location = recv_rcp_msg.RpdCapabilities.DeviceLocation
            self.rpd_cap.DeviceLocation.DeviceLocationDescription = location.DeviceLocationDescription
            self.rpd_cap.DeviceLocation.GeoLocationLatitude = location.GeoLocationLatitude
            self.rpd_cap.DeviceLocation.GeoLocationLongitude = location.GeoLocationLongitude
            with open(self.CTRL_RPD_INIT_PROV_INFO_PATH, 'a') as f:
                f.write("RPD Location Description=" + location.DeviceLocationDescription + '\n')
                f.write("RPD Location Geo Latitude=" + location.GeoLocationLatitude + '\n')
                f.write("RPD Location Geo Longitude=" + location.GeoLocationLongitude + '\n')

    def recMsgTypeRpdCapabilitiesCb(self, halcfgmsg):
        """

        :param halcfgmsg:
        :return:
        """

        try:
            cfgMsg = halcfgmsg.msg
            rcp_msg = t_RcpMessage()
            rcp_msg.ParseFromString(cfgMsg.CfgMsgPayload)
            rcp_rpd_cap = rcp_msg.RpdDataMessage.RpdData.RpdCapabilities
            if self.rpd_cap:
                if rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_READ:
                    self.fill_requested_data(self.rpd_cap, rcp_rpd_cap)
                elif rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_WRITE:
                    self._setRpdCapabilities(rcp_msg)
                else:
                    self.logger.warning("Status:%s "
                                        "ErrorDescription: Operation %d for RpdCapabilities is not supported", HalCommon_pb2.FAILED, rcp_msg.RpdDataMessage.RpdDataOperation)
                    return False
            else:
                self._set_rpd_identification(rcp_rpd_cap.RpdIdentification)

            rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            cfgMsg.CfgMsgPayload = rcp_msg.SerializeToString()

            rsp_msg = {"Status": HalCommon_pb2.SUCCESS,
                       "ErrorDescription": "Receive RpdCapabilities success"}

            msg = HalMessage("HalConfigRsp", SrcClientID=cfgMsg.SrcClientID,
                             SeqNum=cfgMsg.SeqNum, Rsp=rsp_msg,
                             CfgMsgType=cfgMsg.CfgMsgType,
                             CfgMsgPayload=cfgMsg.CfgMsgPayload)
            self.msg_record.recv_fragment_msg(msg)
            self.logger.debug("Receive RpdCapabilities request from core")
            return True
        except Exception as e:
            self.logger.warning("Cannot process the msg[%d], reason:%s", halcfgmsg.msg.CfgMsgType, e)
            return False

    def recMsgTypeRpdCapabilitiesRspCb(self, halrspmsg):
        try:
            # Check the status
            if halrspmsg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
                # yes, we recv a error message from HAL
                self.logger.warning(
                    "Receive a hal fail message:%s" % halrspmsg.msg)
                return False

            cfg_rsp = t_RcpMessage()
            cfg_rsp.ParseFromString(halrspmsg.msg.CfgMsgPayload)
            if cfg_rsp.RcpDataResult != t_RcpMessage.RCP_RESULT_OK:
                # yes we recv a error msg from driver
                self.logger.warning("Recv a driver fail message:%s" % str(cfg_rsp))
                return False
            rcp_rpd_cap = cfg_rsp.RpdDataMessage.RpdData.RpdCapabilities
            if not self.valid_rpd_cap(rcp_rpd_cap):
                self.logger.debug("Receive invalid RpdCapabilities rsp from driver")
                return False
            if not self.rpd_cap:
                self.rpd_cap = t_RpdCapabilities()
            self.rpd_cap.CopyFrom(rcp_rpd_cap)
            self.logger.debug("Receive RpdCapabilities rsp from driver")
            return True
        except Exception as e:
            self.logger.warning("cap fail %s", str(e))
            return False

    def valid_rpd_cap(self, rcp_rpd_cap):
        # check the instance
        if not isinstance(rcp_rpd_cap, t_RpdCapabilities):
            return False
        # check it is not the default value
        default_cap = t_RpdCapabilities()
        GCPObject.default_gpb(default_cap)
        if rcp_rpd_cap == default_cap:
            return False

        return True

    def connectionDisconnectCb(self, msg):
        """The connection has been detected as disconnected, register it again
        We have reconenct, we have to assure the regiter message is received
        by the HAL.

        :param msg:
        :return:

        """

        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return
        self.logger.info("Detected disconnected, register again")
        # clean up the push and pull socket
        if 0:
            self.pushSock.close()
            self.pullSock.close()

            self.channel.dispatcher.fd_unregister(self.pullSock.socket)
            self.channel.dispatcher.fd_unregister(self.pullSock.monitor)
            self.channel.dispatcher.fd_unregister(self.pullSock.monitor)

            self.pushSock = None
            self.pullSock = None
            self.mgrConnection = None
            # self.clientID = None #will not set it to none since

            self.connection_setup(self.channel.dispatcher)

        if self.retryNr:  # pragma: no cover
            self.retryNr -= 1
            self.channel.dispatcher.fd_unregister(self.mgrConnection.socket)
            self.channel.dispatcher.fd_unregister(self.mgrConnection.monitor)
            self.mgrConnection.socket.disable_monitor()
            self.mgrConnection.monitor.close()
            self.mgrConnection.close()

            # create the connection again
            self.connection_setup(self.channel.dispatcher)
            self.register(self.clientID)
        else:
            self.connection_cleanup(self.channel.dispatcher)

        self.disconnected = True

    def sendNotificationMsg(self, notificationType, notificationPayload):
        """Send a notification to Hal.

        :param notificationType: The notification type, the client must
         declare the notification type to Hal first
        :param notificationPayload: the string payload, Hal will not touch
         this part
        :return:

        """
        self.logger.debug("send a a notification message to Hal")
        if self.disconnected:
            self.logger.warning(
                "The client is on disconnected state,"
                " skip to send the message, notification type:%s",
                notificationType)
            return

        if notificationType is None or not isinstance(notificationPayload, str):
            self.logger.warning("Cannot send a None or incorrect type to HAL, "
                                "str is required for msg.")
            return

        notification = HalMessage("HalNotification",
                                  ClientID=self.clientID,
                                  HalNotificationType=notificationType,
                                  HalNotificationPayLoad=notificationPayload)
        self.send(notification.Serialize())

    def sendCfgMsg(self, cfgMsgType, cfgMsgContent):
        """The configutaion response routine, the driver implementor should
        fill sth into this function."""
        # self.logger.debug("Send a config message to HAL:" + str(cfgMsgContent))

        if self.disconnected:
            self.logger.warning("The client is on disconnected state,"
                                " skip to send the message, msg type:%s", cfgMsgType)
            return

        if cfgMsgContent is None or not isinstance(cfgMsgContent, str):
            self.logger.warning("Cannot send a None or incorrect type to HAL, "
                                "str is required for msg.")
            return

        msg = HalMessage("HalConfig", SrcClientID=self.clientID,
                         SeqNum=self.seqNum,
                         CfgMsgType=cfgMsgType,
                         CfgMsgPayload=cfgMsgContent)

        # for the cfgMsgType can be handled by RCP module, no need send to hal
        if cfgMsgType in self.HalConfigMsgHandlers:
            cb = self.HalConfigMsgHandlers[cfgMsgType]
            cb(msg)
        else:
            self.send(msg.Serialize())

        seq = self.seqNum
        self.seqNum += 1
        return seq

    def send_mgr_cfg_msg(self, msg_type, msg):
        """Send msg to Hal driver.

        :param msg: payload
        :param msg_type: Hal msg type
        :param msg: msg need to send

        """
        payload = msg.SerializeToString()
        self.sendNotificationMsg(msg_type, payload)

    def send_rcp_cfg_msg(self, msg, msg_type, cfg_type, op):
        """Send msg to Hal driver.

        :param msg: payload
        :param msg_type: Hal msg type
        :param op: RD, WR

        """
        try:
            rcp_msg = t_RcpMessage()
            rcp_msg.RpdDataMessage.RpdDataOperation = op
            rcp_msg.RcpMessageType = cfg_type
            rcp_msg.RpdDataMessage.RpdData.CopyFrom(msg)
            payload = rcp_msg.SerializeToString()
            seq_num = self.sendCfgMsg(msg_type, payload)
            if seq_num is None:
                raise RcpHalClientError("sendCfgMsg fail, please check "
                                        "the client status or input payload")
            return seq_num
        except Exception as e:
            raise RcpHalClientError("RpdDataMessage message error: %s" % str(e))

    def rcp_cfg_req(self, ipc_msg):
        """Construct HalMessage to HalMain, do configuration.

        :param ipc_msg: {"session": session, "req_pkt": None, "req_data": data}

        """
        last_session = ipc_msg['session']
        last_pkt = ipc_msg['req_packet']
        gcp_msg = ipc_msg['gcp_msg']
        req_data = ipc_msg['req_data']

        # self.logger.debug("Receive a rcp config request:" + str(ipc_msg))

        if not isinstance(req_data, list):
            raise TypeError("The rcp_data operation must be a list")

        req_list = list()
        docsisMsgType_list = list()
        for seq in req_data:
            if not isinstance(seq, rcp.RCPSequence):
                raise TypeError(
                    "RCPSequences are expected in tuple of RCP data")

            try:
                operation = self.RCP_OPER_TO_RPD_DATA_OPER[seq.operation]
            except:
                raise AttributeError(
                    "Invalid RCP operation set in sequence: %u" % seq.operation)

            data = DataObj(seq, operation, seq.seq_number)
            data.ipc_req_msg = seq.ipc_msg
            RfData = seq.ipc_msg.RpdDataMessage.RpdData
            for RfCh in RfData.RfChannel:
                # Parsing Docsis msg here, convert into RfChannel or RfPort proto structure.
                # If cannot parse to RfChannel or RfPort structure, store the msg type in
                # docsisMsgType_list and send the raw msg to hal phy driver in the
                # following send procedure.
                if RfCh.HasField("DocsisMsg"):
                    docsis_buf = RfCh.DocsisMsg
                    docsis_msg = docsis_message.DocsisMsgMacMessage()
                    docsis_msg.decode(docsis_buf, 0, len(docsis_buf))
                    RfChMsg = docsis_msg.convert_to_RCPSequence(
                        gcp_msg_def.NotifyREQ,
                        rcp_tlv_def.RCP_MSG_TYPE_IRA,
                        RfCh,
                        rcp_tlv_def.RCP_OPERATION_TYPE_WRITE)

                    if RfChMsg is None:
                        docsisMsgType_list.append(
                            {'rfch': RfCh, 'type': docsis_msg.msgtype})
            req_list.append(data)

        if len(req_list) == 0:
            raise Exception("The packet contains nothing, fire !!!")
        req_pkt = self.msg_record.add_pkt_to_internal_db(last_session, last_pkt, gcp_msg, req_list)

        for data_obj in req_list:
            req_msg = data_obj.ipc_req_msg
            op = req_msg.RpdDataMessage.RpdDataOperation
            cfg_data = req_msg.RpdDataMessage.RpdData
            record_req_elem = RcpMessageRecordElem(data_obj)
            try:
                for desc, value in cfg_data.ListFields():
                    if desc.name == 'ReadCount':
                        continue
                    if desc.name == 'RfChannel':
                        for rf_channel in cfg_data.RfChannel:
                            for rf_desc, rf_value in rf_channel.ListFields():
                                if rf_desc.name in HalConfigMsg.RCP_TO_HAL_MSG_TYPE:
                                    mst_type = HalConfigMsg.RCP_TO_HAL_MSG_TYPE[rf_desc.name]
                                elif rf_desc.name == 'DocsisMsg':
                                    mst_type = None
                                    for dmsg in docsisMsgType_list:
                                        # send raw Docsis msg to hal driver.
                                        if dmsg['rfch'] == rf_channel:
                                            mst_type = dmsg['type']
                                            break
                                    if mst_type is None:
                                        continue
                                elif rf_desc.name == 'RfChannelSelector':
                                    continue
                                else:
                                    self.logger.warning("Unsupported hal rf channel cfg msg type: %s",
                                                        rf_desc.name)
                                    mst_type = HalConfigMsg.MsgTypeInvalid

                                data = config()
                                if cfg_data.HasField("ReadCount"):
                                    data.ReadCount = cfg_data.ReadCount
                                msg = data.RfChannel.add()
                                msg.CopyFrom(rf_channel)
                                nexSeqNum = self.seqNum
                                self.msg_record.add_req_to_internal_db(
                                    last_session, last_pkt, gcp_msg, nexSeqNum,
                                    record_req_elem)
                                self.send_rcp_cfg_msg(
                                    data, mst_type,
                                    req_msg.RcpMessageType, op)

                    elif desc.name == 'RfPort':
                        for rf_port in cfg_data.RfPort:
                            for rf_desc, rf_value in rf_port.ListFields():
                                if rf_desc.name in HalConfigMsg.RCP_TO_HAL_MSG_TYPE:
                                    mst_type = HalConfigMsg.RCP_TO_HAL_MSG_TYPE[rf_desc.name]
                                elif rf_desc.name == 'RfPortSelector':
                                    continue
                                else:
                                    self.logger.warning("Unsupported hal rf port cfg msg type: %s",
                                                        rf_desc.name)
                                    mst_type = HalConfigMsg.MsgTypeInvalid

                                data = config()
                                if cfg_data.HasField("ReadCount"):
                                    data.ReadCount = cfg_data.ReadCount
                                msg = data.RfPort.add()
                                msg.CopyFrom(rf_port)
                                nexSeqNum = self.seqNum
                                self.msg_record.add_req_to_internal_db(
                                    last_session, last_pkt, gcp_msg, nexSeqNum,
                                    record_req_elem)
                                self.send_rcp_cfg_msg(
                                    data, mst_type,
                                    req_msg.RcpMessageType, op)

                    elif desc.name == "CcapCoreIdentification":
                        mst_type = HalConfigMsg.RCP_TO_HAL_MSG_TYPE[desc.name]
                        for ccap_cfg in cfg_data.CcapCoreIdentification:
                            data = config()
                            if cfg_data.HasField("ReadCount"):
                                data.ReadCount = cfg_data.ReadCount
                            ccap = data.CcapCoreIdentification.add()
                            ccap.CopyFrom(ccap_cfg)
                            nexSeqNum = self.seqNum
                            self.msg_record.add_req_to_internal_db(
                                last_session, last_pkt, gcp_msg, nexSeqNum,
                                record_req_elem)
                            self.send_rcp_cfg_msg(
                                data, mst_type,
                                req_msg.RcpMessageType, op)

                    elif desc.name == "RpdCapabilities":
                        data = config()
                        if cfg_data.HasField("ReadCount"):
                            data.ReadCount = cfg_data.ReadCount
                        data.RpdCapabilities.CopyFrom(value)
                        mst_type = HalConfigMsg.RCP_TO_HAL_MSG_TYPE[desc.name]
                        nexSeqNum = self.seqNum
                        self.msg_record.add_req_to_internal_db(
                            last_session, last_pkt, gcp_msg, nexSeqNum,
                            record_req_elem)
                        self.send_rcp_cfg_msg(data, mst_type,
                                              req_msg.RcpMessageType, op)

                    elif desc.name == "VendorSpecificExtension":
                        for vend_desc, vend_value in cfg_data.VendorSpecificExtension.ListFields():
                            if vend_desc.name in HalConfigMsg.RCP_TO_HAL_MSG_TYPE:
                                mst_type = HalConfigMsg.RCP_TO_HAL_MSG_TYPE[vend_desc.name]
                            elif vend_desc.name == "VendorId":
                                vendorTlv = RcpVendorTlv(vendorID=DEFAULT_VENDOR_ID)
                                status, mst_type = vendorTlv.setDriverMsgCode(vend_value, value)
                                if (status == 1):
                                    vsp_tlv = config()
                                    if cfg_data.HasField("ReadCount"):
                                        data.ReadCount = cfg_data.ReadCount
                                    vsp_tlv.VendorSpecificExtension.CopyFrom(value)
                                    nexSeqNum = self.seqNum
                                    self.msg_record.add_req_to_internal_db(
                                        last_session, last_pkt, gcp_msg, nexSeqNum,
                                        record_req_elem)
                                    self.send_rcp_cfg_msg(vsp_tlv, mst_type,
                                                          req_msg.RcpMessageType, op)
                                    # entire VendorSpecificExtension TLV copied and sent to driver so break
                                    break
                                else:
                                    continue
                            else:
                                self.logger.warning("Unsupported hal vendorSpecificExtension msg type: %s",
                                                    vend_desc.name)
                                mst_type = HalConfigMsg.MsgTypeInvalid
                            data = config()
                            if cfg_data.HasField("ReadCount"):
                                data.ReadCount = cfg_data.ReadCount
                            msg = data.VendorSpecificExtension
                            msg.CopyFrom(cfg_data.VendorSpecificExtension)
                            nexSeqNum = self.seqNum
                            self.msg_record.add_req_to_internal_db(
                                last_session, last_pkt, gcp_msg, nexSeqNum,
                                record_req_elem)
                            self.send_rcp_cfg_msg(
                                data, mst_type,
                                req_msg.RcpMessageType, op)

                    elif desc.name == "ReadCount":
                        continue

                    else:
                        if desc.name in HalConfigMsg.RCP_TO_HAL_MSG_TYPE:
                            mst_type = HalConfigMsg.RCP_TO_HAL_MSG_TYPE[desc.name]
                        else:
                            self.logger.warning("Unsupported hal cfg msg type %s" % (desc.name))
                            mst_type = HalConfigMsg.MsgTypeInvalid

                        if desc.type == desc.TYPE_MESSAGE:
                            if desc.label == desc.LABEL_REPEATED:
                                for sub_info in value:
                                    data = config()
                                    if cfg_data.HasField("ReadCount"):
                                        data.ReadCount = cfg_data.ReadCount
                                    field = getattr(data, desc.name).add()
                                    field.CopyFrom(sub_info)
                                    nexSeqNum = self.seqNum
                                    self.msg_record.add_req_to_internal_db(
                                        last_session, last_pkt, gcp_msg, nexSeqNum,
                                        record_req_elem)
                                    self.send_rcp_cfg_msg(
                                        data, mst_type, req_msg.RcpMessageType, op)
                            else:
                                data = config()
                                if cfg_data.HasField("ReadCount"):
                                    data.ReadCount = cfg_data.ReadCount
                                getattr(data, desc.name).CopyFrom(value)
                                nexSeqNum = self.seqNum
                                self.msg_record.add_req_to_internal_db(
                                    last_session, last_pkt, gcp_msg, nexSeqNum,
                                    record_req_elem)
                                self.send_rcp_cfg_msg(
                                    data, mst_type, req_msg.RcpMessageType, op)
                        else:
                            if desc.label == desc.LABEL_REPEATED:
                                for sub_info in value:
                                    data = config()
                                    if cfg_data.HasField("ReadCount"):
                                        data.ReadCount = cfg_data.ReadCount
                                    field = getattr(data, desc.name)
                                    field.extend([sub_info, ])
                                    nexSeqNum = self.seqNum
                                    self.msg_record.add_req_to_internal_db(
                                        last_session, last_pkt, gcp_msg, nexSeqNum,
                                        record_req_elem)
                                    self.send_rcp_cfg_msg(
                                        data, mst_type, req_msg.RcpMessageType, op)
                            else:
                                data = config()
                                if cfg_data.HasField("ReadCount"):
                                    data.ReadCount = cfg_data.ReadCount
                                setattr(data, desc.name, value)
                                nexSeqNum = self.seqNum
                                self.msg_record.add_req_to_internal_db(
                                    last_session, last_pkt, gcp_msg, nexSeqNum,
                                    record_req_elem)
                                self.send_rcp_cfg_msg(
                                    data, mst_type, req_msg.RcpMessageType, op)
            except RcpHalClientError:
                self.msg_record.remove_req_from_internal_db(self.seqNum, record_req_elem)
                self.msg_record.remove_pkt_from_internal_db(last_session, last_pkt, gcp_msg)
                raise

            if not record_req_elem.pkt:
                self.logger.warning(
                    'The hal record element is not associated with any packet, attach an error rsp')
                record_req_elem.set_pkt(req_pkt)
                self.msg_record._generate_error_rsp(record_req_elem)
            self.msg_record.check_recv_done(record_req_elem)
        self.msg_record.set_send_procedure_done(
            last_session, last_pkt, gcp_msg)  # Done the message
        self.msg_record.check_and_fire_pkt(req_pkt)

    def recvRegisterMsgCb(self, cfg):
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
        :return:

        """
        # self.logger.debug("Recv a Message from the Hal:" % str(cfg.msg))

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.warning(
                "Cannot register to Hal, reason[%s]",
                cfg.msg.Rsp.ErrorDescription)
            return

        self.clientID = cfg.msg.ClientID

        # Setup the push and pull connection
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

        # get the index of the path
        index = self._getIndexFromPath()
        if index == -1:
            self.logger.warning(
                "Cannot get index from the path [%s]" % self.pushPath)
            return
        if self.index == -1:
            self.index = index
            self.pushSock = HalTransport(
                HalTransport.HalTransportClientAgentPull,
                HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPushMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            self.pullSock = HalTransport(
                HalTransport.HalTransportClientAgentPush,
                HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPullMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            # register to the poller
            self.channel.dispatcher.fd_register(self.pullSock.socket,
                                                zmq.POLLIN, self.rcp_hal_cb)
            self.channel.dispatcher.fd_register(self.pushSock.monitor,
                                                zmq.POLLIN, self.rcp_hal_cb)
            self.channel.dispatcher.fd_register(self.pullSock.monitor,
                                                zmq.POLLIN, self.rcp_hal_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        if len(self.interestedNotification):
            self.regDoneTimer = self.channel.dispatcher.timer_register(self.REG_PERIOD, self._check_register_done)
            self.sendInterestedNotifications(self.interestedNotification)
        else:
            self.regDone = True
        self.disconnected = False
        self.retryNr = self.DEFAULT_RETRRY_NR

        return

    def _check_register_done(self):  # pragma: no cover
        if self.regTry > 0:
            self.regTry -= 1
            if not self.regDone:
                self.regDoneTimer = self.channel.dispatcher.timer_register(self.REG_PERIOD, self._check_register_done)
                self.sendInterestedNotifications(self.interestedNotification)
        else:
            # we can not register the client to Hal successfully, reboot the node
            # TODO: may we restart the rcp process instead of reboot?
            SysTools.sys_failure_reboot('rcp client register fail')
            SysTools.diagnostic_self_test_fail('Processing error', "rcp client register fail", 'Severity level=error')

    def recvNotificationCb(self, msg):
        """Receive the notification from hal driver.

        :param msg:
        :return:

        """
        self.logger.debug("recv the notification from driver")
        if None is self.rcp_notification_cb:
            self.logger.warning("rcp_notification_cb not registered yet")
            return

        if msg.msg.HalNotificationType == HalConfigMsg.MsgTypeRoutePtpStatus and msg.msg.HalNotificationPayLoad in [self.LOS, self.SYNC]:
            self.logger.debug(
                "send %s notification to provision",
                msg.msg.HalNotificationPayLoad)
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeRoutePtpStatus, msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeGeneralNtf:
            self.logger.debug(
                "send  MsgTypeGeneralNtf %s GeneralNotification to provision",
                msg.msg.HalNotificationPayLoad)
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeGeneralNtf, msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeFaultManagement:
            self.logger.debug(
                "send %s notification to core", msg.msg.HalNotificationPayLoad)
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeFaultManagement, msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeRpdIpv6Info:
            self.logger.debug(
                "send %s notification to core", msg.msg.HalNotificationPayLoad)
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeRpdIpv6Info, msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeRpdGroupInfo:
            self.logger.debug(
                "send %s notification to core", msg.msg.HalNotificationPayLoad)
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeRpdGroupInfo, msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeStaticPwStatus:
            self.logger.debug(
                "send  MsgTypeStaticPwStatus %s to GCPP core",
                msg.msg.HalNotificationPayLoad)
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeStaticPwStatus, msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeRpdCapabilities:
            self.notification_rpd_cap(msg.msg.HalNotificationPayLoad)
        elif msg.msg.HalNotificationType == HalConfigMsg.MsgTypeUcdRefreshNtf:
            self.logger.debug(
                "send  MsgTypeUcdReFreshNtf to GCCP core")
            self.rcp_notification_cb(
                HalConfigMsg.MsgTypeUcdRefreshNtf, msg.msg.HalNotificationPayLoad)
        else:
            self.logger.warning(
                "recv notification unrecognized: %s",
                msg.msg.HalNotificationType)

    def notification_rpd_cap(self, msg):
        """receive rpd capabilities notification.

        :param msg: t_RpdCapabilities message
        :return:

        """
        rpd_cap = t_RpdCapabilities()
        rpd_cap.ParseFromString(msg)
        if not self.valid_rpd_cap(rpd_cap):
            self.logger.warning("RCP receive invalid rpdCapabilities notification from driver")
            return
        self.rpd_cap = rpd_cap
        self.logger.debug("Receive rpdCapabilities notification:  %s", str(self.rpd_cap))
        return

    def _getIndexFromPath(self):
        rePattern = r"/(\d+)/"
        ret = re.search(rePattern, self.pushPath)

        if ret is not None:
            digitStr = ret.group(1)
            return int(digitStr)

        return -1

    @staticmethod
    def fill_requested_data(src_gpb, tar_gpb):
        request_field_list = []
        for desc, value in tar_gpb.ListFields():
            request_field_list.append(desc.name)
        tar_gpb.CopyFrom(src_gpb)
        for desc, value in tar_gpb.ListFields():
            if desc.name not in request_field_list:
                tar_gpb.ClearField(desc.name)
