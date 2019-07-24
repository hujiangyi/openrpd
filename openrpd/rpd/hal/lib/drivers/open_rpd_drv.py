#
# Copyright (c) 2017 MaxLinear, Inc. ("MaxLinear") and
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
import logging
import re
import zmq
import signal
#import time
import time
import threading
import socket
import sys
import psutil
import rpd.python_path_resolver
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.dispatcher.dispatcher import Dispatcher
from zmq.utils.monitor import recv_monitor_message
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.gpb.cfg_pb2 import config
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
##import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient, HalDriverClientError
from zmq.utils.monitor import recv_monitor_message
from open_rpd_drv_msg_handlers import *
import rpd.l2tp.l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
import l2tpv3.src.L2tpv3VspAvp_pb2 as L2tpv3VspAvp_pb2
import string
import random
import struct
    
class OpenRpdDriverError(HalDriverClientError):

    def __init__(self, msg, expr=None):
        super(OpenRpdDriverError, self).__init__(msg)
        self.msg = msg
        self.expr = expr


class OpenRpdDriver(HalDriverClient):
    """The OpenRPD base driver
    
    """

##    __metaclass__ = AddLoggerToClass

    def __init__(self, drvName, drvDesc, drvVer, supportedMsgType,
                 supportedNotificationMsgs,
                 interestedNotification=None):
        """
        
        :param drvName: The driver name, such as Generic Driver
        :param drvDesc: driver for full Cable Labs RPHY support
        :param drvVer: driver version
        :param supportedMsgType: will support all RPHY OpenRPD message types
        :param supportedNotificationMsgs: the supported notification msg types
        :return: OpenRPD Driver object

        NOTES: The 'supportedNotificationMsgs' parameter passed to HalDriverClient
        and then forwarded to HalManager.py, but it seems HalManager.py does NOT
        do anything with this parameter.  Consider remove it from ClientProvision.proto?
        As of now, we don't need to have this parameter.  It just adds confusion!
        """

        if supportedMsgType is None:
            supportedMsgType = default_supported_msg_types
        super(OpenRpdDriver, self).__init__(drvName, drvDesc, drvVer,
                                               supportedMsgType,
                                               supportedNotificationMsgs,
                                               interestedNotification)

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recv_register_msg_cb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfig": self.recv_cfg_msg_cb,
            "HalConfigRsp": self.recv_cfg_msg_rsp_cb,
            "HalNotification": self.recvNotificationCb,
        }

        # Handlers for different configuration messages
        self.hal_config_msg_handlers = {
            HalConfigMsg.MsgTypeRpdCapabilities:             capabilities_get,
            HalConfigMsg.MsgTypeDsRfPort:                    config_ds_port,
            HalConfigMsg.MsgTypeDsScQamChannelConfig:        config_dsqam_channel,
            HalConfigMsg.MsgTypeDsOfdmChannelConfig:         config_dsofdm_channel,
            HalConfigMsg.MsgTypeDsOfdmProfile:               config_dsofdm_profile,
            HalConfigMsg.MsgTypeDsRfPortPerf:                req_dummy,
            HalConfigMsg.MsgTypeDsScQamChannelPerf:          req_dsqam_channel_status,
            HalConfigMsg.MsgTypeDsOfdmChannelPerf:           req_dsofdm_channel_status,
            HalConfigMsg.MsgTypeDsOob551IPerf:               req_oob551_mod_status,
            HalConfigMsg.MsgTypeDsOob552Perf:                req_oob552_mod_status,
            HalConfigMsg.MsgTypeNdfPerf:                     req_dummy,
            HalConfigMsg.MsgTypeUsRfPortPerf:                req_dummy,
            HalConfigMsg.MsgTypeUsScQamChannelConfig:        config_usatdma_channel,
            HalConfigMsg.MsgTypeUsOfdmaChannelConfig:        config_usofdma_channel,
            HalConfigMsg.MsgTypeUsOfdmaInitialRangingIuc:    config_dummy,
            HalConfigMsg.MsgTypeUsOfdmaFineRangingIuc:       config_dummy,
            HalConfigMsg.MsgTypeUsOfdmaDataRangingIuc:       config_dummy,
            HalConfigMsg.MsgTypeUsOfdmaSubcarrierCfgState:   req_dummy,
            HalConfigMsg.MsgTypeUsScQamChannelPerf:          req_dummy,
            HalConfigMsg.MsgTypeUsOfdmaChannelPerf:          req_dummy,
            HalConfigMsg.MsgTypeUsOob551IPerf:               req_oob551_demod_status,
            HalConfigMsg.MsgTypeUsOob552Perf:                req_oob552_demod_status,
            HalConfigMsg.MsgTypeNdrPerf:                     req_dummy,
            HalConfigMsg.MsgTypeSidQos:                      config_sid_qos,
            # # L2TPv3 messages
            HalConfigMsg.MsgTypeL2tpv3CapabilityQuery:       capabilities_get,
            HalConfigMsg.MsgTypeL2tpv3SessionReqNone:        req_depi_pw,
            HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdm:      req_depi_pw,
            HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdmPlc:   req_depi_pw,
            HalConfigMsg.MsgTypeL2tpv3SessionReqDsScqam:     req_depi_pw,
            HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma:     req_uepi_pw,
            HalConfigMsg.MsgTypeL2tpv3SessionReqUsOfdma:     req_uepi_pw,
            HalConfigMsg.MsgTypeL2tpv3SessionReqScte551Fwd:  req_dummy,
            HalConfigMsg.MsgTypeL2tpv3SessionReqScte551Ret:  req_dummy,
            HalConfigMsg.MsgTypeL2tpv3SessionReqScte552Fwd:  req_dummy,
            HalConfigMsg.MsgTypeL2tpv3SessionReqScte552Ret:  req_dummy,
            HalConfigMsg.MsgTypeL2tpv3SessionReqNdf:         req_ndf,
            HalConfigMsg.MsgTypeL2tpv3SessionReqNdr:         req_ndr,
            # Ptp
            #HalConfigMsg.MsgTypeRdtiConfig:                  config_docsis_timer

            HalConfigMsg.MsgTypeL2tpv3CinIfAssignment:       cin_if_assign,
            HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment:      lcce_id_assign,

            # VspAvpQuery
            HalConfigMsg.MsgTypeVspAvpExchange:              vsp_avp_handler,
            # RcpVendorSpecificTlv
            HalConfigMsg.MsgTypeRcpVendorSpecific:           vsp_tlv_handler,
        }

        self.disconnected = True
        self.dispatcher = Dispatcher()

        # setup the logging
        self.logger = get_msg_handler_logger()
        self.logger.info("OpenRPD Driver Initialized")
        self.seqNum = 0


    ## start modeled from HalPtpDriver.py

    def start(self, simulate_mode=False):
        """start poll the transport socket
        
        :return:
        
        """
        self.logger.info("Setup the Hal Transport connection...")
        self.connectionSetup()
        self.logger.info("Connection setup done...")

        self.logger.info("Register the driver with the Hal manager...")
        self.register(self.drvID)
        self.logger.info("End of register...")

        self.dispatcher.loop()

    def recv_register_msg_cb(self, cfg):
        """the callback handler for the configuration message
        Modified from base class by registering the sockets
        with dispatcher.
        
        :param cfg: the configuration message received from the Hal
        :return:
        
        """
        # self.logger.debug("Recv a Message from the Hal:" % str(cfg.msg))

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.error(
                "Cannot register to Hal, reason[%s]" % cfg.msg.Rsp.ErrorDescription)
            return

        self.drvID = cfg.msg.ClientID

        # Setup the push and pull connection
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

        # get the index of the path
        index = self._getIndexFromPath()
        if index == -1:
            self.logger.error(
                "Cannot get index from the path [%s]" % self.pushPath)
            return
        if self.index == -1:
            self.index = index
            self.pushSock = HalTransport(
                HalTransport.HalTransportClientAgentPull, HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPushMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            self.pullSock = HalTransport(
                HalTransport.HalTransportClientAgentPush, HalTransport.HalClientMode,
                index=index, socketMode=HalTransport.HalSocketPullMode,
                disconnectHandlerCb=self.connectionDisconnectCb)

            # register driver's sockets with the dispatcher
            self.dispatcher.fd_register(self.pullSock.socket,
                                        zmq.POLLIN, self.openrpd_drv_hal_cb)
            self.dispatcher.fd_register(self.pushSock.monitor,
                                        zmq.POLLIN, self.openrpd_drv_hal_cb)
            self.dispatcher.fd_register(self.pullSock.monitor,
                                        zmq.POLLIN, self.openrpd_drv_hal_cb)

        # send Hello To Hal
        self.sayHelloToHal()
        if (None is not self.interestedNotification):
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def connectionSetup(self):
        """Create the connection to the mgr
        
        :return:
        
        """
        self.logger.info("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr, HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.disconnectCb)
        self.mgrConnection.connects()

        self.HalMsgsHandler[self.mgrConnection.socket] = self.recv_register_msg_cb

        # register the mgr socket with the dispatcher
        self.dispatcher.fd_register(
            self.mgrConnection.socket, zmq.POLLIN, self.openrpd_drv_hal_cb)
        self.dispatcher.fd_register(
            self.mgrConnection.monitor, zmq.POLLIN, self.openrpd_drv_hal_cb)

    def connection_cleanup(self):
        """Close the connection to the mgr
        
        :return:
        
        """
        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return

        if self.mgrConnection is not None:
            self.dispatcher.fd_unregister(self.mgrConnection.socket)
            self.dispatcher.fd_unregister(self.mgrConnection.monitor)
            self.mgrConnection.socket.disable_monitor()
            self.mgrConnection.monitor.close()
            self.mgrConnection.socket.close()

        if self.pullSock is not None:
            self.dispatcher.fd_unregister(self.pullSock.socket)
            self.dispatcher.fd_unregister(self.pullSock.monitor)
            self.pullSock.socket.disable_monitor()
            self.pullSock.monitor.close()
            self.pullSock.socket.close()

        if self.pushSock is not None:
            self.dispatcher.fd_unregister(self.pushSock.monitor)
            self.pushSock.socket.disable_monitor()
            self.pushSock.monitor.close()
            self.pushSock.socket.close()

        self.disconnected = True


    def disconnectCb(self, msg):
        """A disconnect condition has been detected, 
        clean up the connection and then reconnect
        and re-register with the Hal.
        
        :param msg:
        :return:
        
        """
        self.logger.error("Detected disconnected condition")

        if self.disconnected:
            self.logger.info("A previous event has been processed, skip it!")
            return
        self.logger.info("Detected disconnected, registering again")
        # clean up the push and pull socket
        self.dispatcher.fd_unregister(self.mgrConnection.socket)
        self.dispatcher.fd_unregister(self.mgrConnection.monitor)
        self.mgrConnection.monitor.close()
        self.mgrConnection.close()

        # re-register the message
        self.connectionSetup()
        # The zmq lower part will handle the reconnect
        self.register(self.drvID)

        self.disconnected = True

    def openrpd_drv_hal_cb(self, sock, mask):
        self.logger.debug("Driver received hal cb event")
        if self.pushSock is not None and sock == self.pushSock.monitor:
            self.pushSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.pullSock is not None and sock == self.pullSock.monitor:
            self.pullSock.monitorHandler(recv_monitor_message(sock))
            return

        if sock == self.mgrConnection.monitor:
            self.mgrConnection.monitorHandler(recv_monitor_message(sock))
            return

        while sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
            try:
                bin = sock.recv(flags=zmq.NOBLOCK)
                msg = HalMessage.DeSerialize(bin)
                self.logger.debug(
                    "Got a zmq msg:%s type:%s" % (msg.msg, msg.type))
                if msg.type in self.HalMsgsHandler:
                    handler = self.HalMsgsHandler[msg.type]
                    handler(msg)
            except zmq.ZMQError as e:
                self.logger.debug(
                    "Got an error when trying with nonblock read:" + str(e))
                break
            except Exception as e:
                self.logger.error("Got an un-expected error:%s", str(e))
                break

    def recvNotificationCb(self, ntf):
        """Receive a notification message from the HAL.

        :param ntf:
        :return:

        """
        try:
            handler = self.hal_config_msg_handlers[ntf.msg.HalNotificationType]
            self.logger.info("Receive a interest notification message:" + str(ntf.msg))

            if not isinstance(ntf, HalMessage):
                raise AttributeError("Invalid HAL message passed")

            ntf = handler(ntf)
            if None is not ntf:
                self.send_cfg_msg(HalConfigMsg.MsgTypeVspAvpExchange, ntf.msg.HalNotificationPayLoad)
            else:
                self.logger.info("Notification message return is None")
        except Exception as e:
            self.logger.error(
                "Got an error:%s, the ntf msg:%s", str(e), ntf.msg)

    def send_cfg_msg(self, cfgMsgType, payload):
        msg = HalMessage(
            "HalConfig", SrcClientID=self.drvID, 
            CfgMsgType=cfgMsgType,
            SeqNum=self.seqNum,
            CfgMsgPayload=payload)
        self.logger.debug(
                "sending config - type: %d, msg: %s"% (cfgMsgType,msg))
        self.pushSock.send(msg.Serialize())
        self.seqNum += 1
        return

    def send_cfg_rsp_msg(self, cfg):
        """The configuration response routine
        
        :param cfg: The original configuration message
        :return:
        
        """
        result = HalCommon_pb2.SUCCESS
        cfgMsg = cfg.msg
        l2tpcfgmsgType = (HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdm,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdmPlc,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqDsScqam,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqUsAtdma,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqUsOfdma,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqScte551Fwd,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqScte551Ret,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqScte552Fwd,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqScte552Ret,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqNdf,
                          HalConfigMsg.MsgTypeL2tpv3SessionReqNdr,
                          HalConfigMsg.MsgTypeL2tpv3CinIfAssignment,
                          HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment)
        if cfgMsg.CfgMsgType in l2tpcfgmsgType:
            rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
            req = L2tpv3Hal_pb2.t_l2tpSessionReq()
            req.ParseFromString(cfgMsg.CfgMsgPayload)
            # fill session_selector
            rsp.session_selector.local_session_id = req.session_selector.local_session_id
            rsp.session_selector.remote_session_id = req.session_selector.remote_session_id
            rsp.session_selector.local_ip = req.session_selector.local_ip
            rsp.session_selector.remote_ip = req.session_selector.remote_ip
            rsp.result = True
        elif (cfgMsg.CfgMsgType == HalConfigMsg.MsgTypeVspAvpExchange):
            rsp = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
            rsp.ParseFromString(cfgMsg.CfgMsgPayload)
            self.logger.debug("vsp_avp_handler re-parse srcClientID: %s, Seq num:  %d, op: %d, vid %d, attr %d, strVal %s" %
                      (cfg.msg.SrcClientID, cfg.msg.SeqNum, rsp.oper, rsp.vendorId, rsp.attrType, rsp.attrValBuf))
            if rsp.rspCode == L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_FAILURE:
                # send HalConfigRsp with failure status if OpenRPD driver can't handle this.
                result = HalCommon_pb2.FAILED
        elif (cfgMsg.CfgMsgType == HalConfigMsg.MsgTypeRcpVendorSpecific):
            rsp = t_RcpMessage()
            rsp.ParseFromString(cfgMsg.CfgMsgPayload)
            self.logger.debug("send_cfg_rsp_msg payload: %s, result: %d" % (rsp.RpdDataMessage.RpdData, rsp.RcpDataResult))
        else:
            rsp = t_RcpMessage()
            rsp.ParseFromString(cfgMsg.CfgMsgPayload)
            self.logger.debug("send_cfg_rsp_msg payload: %s" % rsp.RpdDataMessage.RpdData)
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        payload = rsp.SerializeToString()

        self.logger.debug("cfg response srcClientID: %s, Seq num:  %d" %
                      (cfgMsg.SrcClientID, cfgMsg.SeqNum))
        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=cfgMsg.SeqNum,
            Rsp={
                "Status": HalCommon_pb2.SUCCESS,
                "ErrorDescription": ""
            },
            CfgMsgType=cfgMsg.CfgMsgType,
            CfgMsgPayload=payload)
        self.logger.debug(
                "sending cfg response - type: %d, msg: %s"% (cfgMsg.CfgMsgType,msg))
        self.pushSock.send(msg.Serialize())

    def recv_cfg_msg_rsp_cb(self, cfg):
        self.logger.debug(
                "receive cfg response - type: %d, msg: %s"% (cfgMsg.CfgMsgType,msg))
        pass
        
    def recv_cfg_msg_cb(self, cfg):
        """Receive a configuration message from the Hal, processing it
        
        :param cfg:
        :return:
        
        """
        try:
            handler = self.hal_config_msg_handlers[cfg.msg.CfgMsgType]
            self.logger.info(
                "Received a cfg message type: %d", cfg.msg.CfgMsgType)

            if not isinstance(cfg, HalMessage):
                raise AttributeError("Invalid HAL message passed")

            cfg = handler(cfg)
            self.send_cfg_rsp_msg(cfg)
        except Exception as e:
            self.logger.error(
                "Got an error:%s, the cfg msg:%s", str(e), cfg.msg)

    def cleanup_sockets(self):
        for fd in self.fd_to_socket:
            sock = self.fd_to_socket[fd]
            self.poller.unregister(sock)
            sock.close()
        self.fd_to_socket.clear()

def handle_interrupt_signal(signum, frame):
    sys.exit(0)


if __name__ == "__main__":
    setup_logging('HAL', filename="open_rpd_drv.log")
    signal.signal(signal.SIGINT, handle_interrupt_signal)
    driver = OpenRpdDriver("openrpd_generic_driver", "This is a Generic OpenRPD Driver", "1.0.0",
                             (default_supported_msg_types), (2, 3, 4))
    # test_cfg = HalMessage("HalConfigRsp")
    # test_cfg.msg.SeqNum = 123456
    # test_cfg.msg.Rsp.Status = HalCommon_pb2.SUCCESS
    # cfgMsg = capabilities_get(test_cfg)
    # driver.send_cfg_rsp_msg(cfgMsg)
    driver.start()
