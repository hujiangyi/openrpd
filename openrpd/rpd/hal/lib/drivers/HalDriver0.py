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
"""
    All the Driver code locates on a single file
    The driver sample code will cover the following part
    1. Driver registration/Connection setup/ Hello msg / MsgTpe /Notification Type
    2. Connection Monitor / Reconnection
"""

import re
import zmq
import signal
import sys
from time import time
import rpd.python_path_resolver
from rpd.hal.src.transport.HalTransport import HalTransport, HalPoller
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from zmq.utils.monitor import recv_monitor_message
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
import rpd.hal.src.HalConfigMsg as HalConfiMsg
from rpd.gpb.cfg_pb2 import config
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
from rpd.common.utils import Convert, SysTools
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
from rpd.hal.src.HalConfigMsg import MsgTypeRpdCapabilities
from rpd.common.rpdinfo_utils import RpdInfoUtils


class HalDriverClientError(Exception):

    def __init__(self, msg, expr=None):
        super(HalDriverClientError, self).__init__(msg)
        self.msg = msg
        self.expr = expr


class HalDriverClient(object):
    """The Driver Client for Hal."""

    __metaclass__ = AddLoggerToClass

    def __init__(self, drvName, drvDesc, drvVer, supportedMsgType,
                 supportedNotificationMsgs, interestedNotification=None):
        """Init.

        :param drvName: The driver name, such as BCM3160 Driver
        :param drvDesc: A brief description about this driver, such as the driver main functionality description
        :param drvVer: Driver specific version, such as 1.0.1
        :param supportedMsgType: a tuple or list for the driver supported msg types, the form will be (1, 2, 456, 10)
        :param supportedNotificationMsgs: the driver supported notification msg types the form will be (1, 3, 4)
        :return: HalDriverClient object

        """
        # sanity check the input args
        if not isinstance(drvName, str) or not isinstance(drvDesc, str) or not isinstance(drvVer, str):
            raise HalDriverClientError(
                "Driver name/desc/version should be a str type")

        if not isinstance(supportedMsgType, tuple) and not isinstance(supportedMsgType, list):
            raise HalDriverClientError(
                "supportedMsgType should be a tuple or list")

        if (supportedNotificationMsgs is not None) and (not isinstance(supportedNotificationMsgs, list) and
                                                        not isinstance(supportedNotificationMsgs, tuple)):
            raise HalDriverClientError(
                "supportedNotificationMsgs is allowed none or tuple or list")

        self.drvname = drvName
        self.drvDesc = drvDesc
        self.drvVer = drvVer
        if None is not interestedNotification:
            self.interestedNotification = list(interestedNotification)
        else:
            self.interestedNotification = None
        self.supportedMsgType = list(supportedMsgType)
        if supportedNotificationMsgs is not None:
            self.supportedNotificationMsgs = list(supportedNotificationMsgs)
        else:
            self.supportedNotificationMsgs = None
        self.recvNtf = 0

        self.pollTimeout = 1000

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfig": self.recvCfgMsgCb,
            "HalConfigRsp": self.recvCfgMsgRspCb,
            "HalClientInterestNotificationCfgRsp": self.sendInterestedNotificationsRspCb,
            "HalNotification": self.recvNotificationCb,
        }

        self.drvID = None

        self.mgrConnection = None
        self.pushSock = None
        self.pullSock = None

        self.pullPath = None
        self.pushPath = None

        self.disconnected = True
        self.poller = None

        self.index = -1
        self.seqNum = 0

    def start(self):
        """Start polling the transport socket.

        :return:

        """
        self.logger.debug("Start the driver client poll...")
        self.connectionSetup()

        self.register(self.drvID)
        lastTimeout = time()

        while True:  # Todo we should support quit flag?
            socks = self.poller.poll(self.pollTimeout)
            if time() - lastTimeout > self.pollTimeout / 1000:
                lastTimeout = time()
                # self.logger.debug("Got a timeout event")
                if self.recvNtf:
                    rcp_msg = t_RcpMessage()
                    rcp_msg.RpdDataMessage.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
                    rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
                    rcp_msg.RpdDataMessage.RpdData.CopyFrom(config())
                    payload = rcp_msg.SerializeToString()
                    self.sendCfgMsg(1025, payload)
                    self.recvNtf -= 1

            if not socks:
                continue
            for sock in socks:
                if self.pushSock is not None and sock == self.pushSock.monitor:
                    self.pushSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if self.pullSock is not None and sock == self.pullSock.monitor:
                    self.pullSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if sock == self.mgrConnection.monitor:
                    self.mgrConnection.monitorHandler(
                        recv_monitor_message(sock))
                    continue
                if socks[sock] == HalPoller.POLLIN:
                    try:
                        bin = sock.recv(flags=zmq.NOBLOCK)
                        msg = HalMessage.DeSerialize(bin)
                        self.logger.debug("Got a zmq msg:%s" % msg.msg)
                        if msg.type in self.HalMsgsHandler:
                            handler = self.HalMsgsHandler[msg.type]
                            handler(msg)
                        else:
                            self.logger.warn(
                                "Unsupported msg type:%s" % msg.type)
                    except zmq.ZMQError as e:
                        self.logger.debug(
                            "Geting an error when trying with nonblock read:" + str(e))
                    except Exception as e:
                        self.logger.debug(
                            "Geting an error:" + str(e))
                continue

    def connectionSetup(self):
        """Create the connection to the mgr and setup the poller.

        :return:

        """
        self.logger.debug("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(
            HalTransport.HalTransportClientMgr, HalTransport.HalClientMode)
        self.mgrConnection.connects()

        self.HalMsgsHandler[self.mgrConnection.socket] = self.recvRegisterMsgCb
        # create the poller
        if self.poller is None:
            self.poller = HalPoller()

        # register the mgr socket
        self.poller.register(self.mgrConnection.socket)
        self.poller.register(self.mgrConnection.monitor)

    def register(self, driverID):
        """Send a register message to Hal and get the client ID from the Hal.

        :return:

        """
        if driverID is None:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.drvname,
                                     ClientDescription=self.drvDesc,
                                     ClientVersion=self.drvVer,
                                     ClientSupportedMessages=self.supportedMsgType,
                                     ClientSupportedNotificationMessages=self.supportedNotificationMsgs)
        else:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.drvname,
                                     ClientDescription=self.drvDesc,
                                     ClientVersion=self.drvVer,
                                     ClientSupportedMessages=self.supportedMsgType,
                                     ClientSupportedNotificationMessages=self.supportedNotificationMsgs,
                                     ClientID=driverID
                                     )

        if self.mgrConnection is None:
            errMsg = "Cannot send the register since the mgr connection is not setup"
            self.logger.error(errMsg)
            raise HalDriverClientError(errMsg)
        self.logger.debug("Send the register msg to Hal...")
        self.mgrConnection.send(registerMsg.Serialize())

    def send(self, msg):
        if self.pushSock:
            self.pushSock.send(msg)
        else:
            self.logger.warning(" ".join([str(self.drvname), str(self.drvID), ":Cannot send the msg since the push socket is none"]))

    def sayHelloToHal(self):
        """Send a hello message to verify the agent path is correct.

        :return:

        """
        self.logger.debug(" ".join([str(self.drvname), str(self.drvID), ":Send a Hello message to Hal"]))
        helloMsg = HalMessage("HalClientHello", ClientID=self.drvID)
        self.send(helloMsg.Serialize())

    def recvHelloRspMsgCb(self, hello):
        """Call back for Hello Message.

        :param hello:
        :return:

        """
        self.logger.debug("Recv a hello message")

    def sendInterestedNotifications(self, notifications):
        """Send the notifications to the HAL.

        :param notifications:
        :return:

        """
        self.logger.debug(
            "Send a Interested notification configuration msg to HAL")
        if notifications is not None and not isinstance(notifications, tuple) and not isinstance(notifications, list):
            self.logger.error(
                "Cannot set an notification with wrong type, you can pass a tuple or list to it ")
            return
        configMsg = HalMessage(
            "HalClientInterestNotificationCfg", ClientID=self.drvID,
            ClientNotificationMessages=notifications)
        self.mgrConnection.send(configMsg.Serialize())

    def sendInterestedNotificationsRspCb(self, rsp):
        """Receive a response message from the HAL for the notification rsp
        callback.

        :param rsp:
        :return:

        """
        self.logger.debug(
            "Receive a interest notification response message:" + str(rsp.msg))

    def recvNotificationCb(self, ntf):
        """Receive a notification message from the HAL.

        :param ntf:
        :return:

        """
        self.logger.debug(
            "Receive a interest notification message:" + str(ntf.msg))
        self.recvNtf += 1

    def recvCfgMsgCb(self, cfg):
        """Receive a configuration message from the Hal, processing it.

        :param cfg:
        :return:

        """
        self.logger.debug(
            "Recv a configuration message, send a fake rsp to it")
        self.sendCfgRspMsg(cfg)

    def recvCfgMsgRspCb(self, cfg):
        """Receive a configuration response message from the Hal, processing it.

        :param cfg:
        :return:

        """
        self.logger.debug(
            "Recv a configuration response message:" + str(cfg.msg))

    def connectionSetupCb(self):
        pass

    def connectionDisconnectCb(self, msg):
        """The connection has been detected disconnected , register it again.

        :param msg:
        :return:

        """

        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return
        self.logger.debug("Detected disconnected, register again")
        # clean up the push and pull socket
        # self.poller.unregister(self.pullSock.socket)

        self.poller.unregister(self.mgrConnection.socket)
        self.poller.unregister(self.mgrConnection.monitor)
        self.mgrConnection.socket.disable_monitor()
        self.mgrConnection.monitor.close()
        self.mgrConnection.close()

        # re-register the message
        self.connectionSetup()
        self.register(self.drvID)
        # The zmq lower part will handle the reconnect

        self.disconnected = True

    def sendNotificationMsg(self, notificationType, notificationPayload):
        """Send a notification to Hal.

        :param notificationType: The notification type, the client must declare the notification type to Hal first
        :param notificationPayload: the string payload, Hal will not touch this part
        :return:

        """
        self.logger.debug("send a a notification message to Hal")
        notfication = HalMessage(
            "HalNotification", ClientID=self.drvID, HalNotificationType=notificationType,
            HalNotificationPayLoad=notificationPayload)
        self.send(notfication.Serialize())

    def sendCfgMsg(self, cfgMsgType, cfgMsgContent):
        """The configutaion response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :return:

        """
        self.logger.debug("Send a config message to HAL: %r", cfgMsgContent)

        if self.disconnected:
            self.logger.warn(
                "The client is on disconencted state, skip to send the message.")
            return

        if cfgMsgContent is None or not isinstance(cfgMsgContent, str):
            self.logger.error(
                "Cannot send a None or incorrect type to HAL, str is required for msg")
            return

        msg = HalMessage(
            "HalConfig", SrcClientID=self.drvID, SeqNum=self.seqNum,
            CfgMsgType=cfgMsgType,
            CfgMsgPayload=cfgMsgContent)
        self._sendMsg(msg.Serialize())

        seq = self.seqNum
        self.seqNum += 1
        return seq

    def sendCfgRspMsg(self, cfg, rsp=None):
        """The configuration response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :param rsp: respond
        :return:

        """
        cfgMsg = cfg.msg

        if rsp == None:
            rsp = {"Status": HalCommon_pb2.SUCCESS,
                   "ErrorDescription": ""}

        msg = HalMessage("HalConfigRsp", SrcClientID=cfgMsg.SrcClientID,
                         SeqNum=cfgMsg.SeqNum, Rsp=rsp,
                         CfgMsgType=cfgMsg.CfgMsgType,
                         CfgMsgPayload=cfgMsg.CfgMsgPayload)
        if None is not self.pushSock:
            self.pushSock.send(msg.Serialize())

    def recvRegisterMsgCb(self, cfg):
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
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

            # register to the poller
            self.poller.register(self.pushSock.monitor)
            self.poller.register(self.pullSock.monitor)
            self.poller.register(self.pullSock.socket)

        # send Hello To Hal
        self.sayHelloToHal()
        if None is not self.interestedNotification:
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def _getIndexFromPath(self):
        rePattern = r"/(\d+)/"
        ret = re.search(rePattern, self.pushPath)

        if ret is not None:
            digitStr = ret.group(1)
            return int(digitStr)

        return -1

    def _sendMsg(self, msg):
        if self.pushSock:
            self.pushSock.send(msg)
        else:
            self.logger.error(
                "Cannot send the msg since the push socket is NULL")


class HalDriver0(HalDriverClient):
    __metaclass__ = AddLoggerToClass

    def __init__(self, drvName, drvDesc, drvVer, supportedMsgType,
                 supportedNotificationMsgs, interestedNotification=None):
        super(HalDriver0, self).__init__(drvName, drvDesc, drvVer, supportedMsgType,
                                         supportedNotificationMsgs, interestedNotification)
        self.interface_dict = {
            'lo': 1,
            'eth0': 2,
        }

    def sendCfgRspMsg(self, cfg, rsp=None):
        """The configuration response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :param rsp: Reponse of the cfgmsg
        :return:

        """
        cfgMsg = cfg.msg
        hal_rsp = {
            "Status": HalCommon_pb2.SUCCESS,
            "ErrorDescription": ""
        }
        l2tpcfgSessionmsgType = (HalConfiMsg.MsgTypeL2tpv3SessionReqDsOfdm,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqDsOfdmPlc,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqDsScqam,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqUsAtdma,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqUsOfdma,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqScte551Fwd,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqScte551Ret,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqScte552Fwd,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqScte552Ret,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqNdf,
                                 HalConfiMsg.MsgTypeL2tpv3SessionReqNdr)
        if cfgMsg.CfgMsgType in l2tpcfgSessionmsgType:
            rsp = L2tpv3Hal_pb2.t_l2tpSessionRsp()
            req = L2tpv3Hal_pb2.t_l2tpSessionReq()
            req.ParseFromString(cfgMsg.CfgMsgPayload)
            # fill session_selector
            rsp.session_selector.local_session_id = req.session_selector.local_session_id
            rsp.session_selector.remote_session_id = req.session_selector.remote_session_id
            rsp.session_selector.local_ip = req.session_selector.local_ip
            rsp.session_selector.remote_ip = req.session_selector.remote_ip
            rsp.session_selector.lcce_id = req.session_selector.lcce_id
            rsp.result = True
            rsp.req_data.CopyFrom(req.req_data)
            payload = rsp.SerializeToString()

            try:
                self.logger.debug("msg content:%s", req)
                with open("/tmp/fakedriver-l2tp.db", "a+w") as db:
                    db.write(cfgMsg.CfgMsgPayload)
                    db.close()
            except Exception:
                self.logger.error("open file fakedriver-l2tp.db failure")

        elif cfgMsg.CfgMsgType == HalConfiMsg.MsgTypePtpStatusGet:
            payload = "ALIGNED"
        elif cfgMsg.CfgMsgType == HalConfiMsg.MsgTypeL2tpv3LcceIdAssignment:
            rsp = L2tpv3Hal_pb2.t_l2tpLcceAssignmentRsp()
            req = L2tpv3Hal_pb2.t_l2tpLcceAssignmentReq()
            req.ParseFromString(cfgMsg.CfgMsgPayload)
            # fill lcce info
            rsp.lcce_info.local_mac = req.lcce_info.local_mac
            rsp.lcce_info.remote_mac = req.lcce_info.remote_mac
            rsp.lcce_info.local_ip = req.lcce_info.local_ip
            rsp.lcce_info.remote_ip = req.lcce_info.remote_ip
            rsp.lcce_info.mtu = req.lcce_info.mtu
            rsp.lcce_id = req.lcce_id
            rsp.result = True
            payload = rsp.SerializeToString()
        elif cfgMsg.CfgMsgType == HalConfiMsg.MsgTypeRpdCapabilities:
            rsp = t_RcpMessage()
            rsp.ParseFromString(cfgMsg.CfgMsgPayload)
            self.dummy_rpd_cap(rsp.RpdDataMessage.RpdData.RpdCapabilities)
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            payload = rsp.SerializeToString()
            self.save_rsp_db(rsp, cfgMsg.CfgMsgPayload)
        elif cfgMsg.CfgMsgType == HalConfiMsg.MsgTypeRpdInfo:
            rsp = t_RcpMessage()
            rsp.ParseFromString(cfgMsg.CfgMsgPayload)
            hal_rsp = self.dummy_rpd_info(rsp)
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            payload = rsp.SerializeToString()
            self.save_rsp_db(rsp, cfgMsg.CfgMsgPayload)
        else:
            rsp = t_RcpMessage()
            rsp.ParseFromString(cfgMsg.CfgMsgPayload)
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            payload = rsp.SerializeToString()
            self.save_rsp_db(rsp, cfgMsg.CfgMsgPayload)

        msg = HalMessage(
            "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID, SeqNum=cfgMsg.SeqNum,
            Rsp=hal_rsp,
            CfgMsgType=cfgMsg.CfgMsgType,
            CfgMsgPayload=payload)
        # time.sleep(15)
        self.send(msg.Serialize())

    def notifyRpdCapabilites(self):
        """
        Notify MsgTypeRpdCapabilities to interrested Module Client.
        """
        rpd_cap = t_RpdCapabilities()
        self.dummy_rpd_cap(rpd_cap)
        self.sendNotificationMsg(HalConfiMsg.MsgTypeRpdCapabilities, rpd_cap.SerializeToString())
        self.logger.debug("notifyRpdCapabilities to interrested module client")

    def dummy_rpd_cap(self, cap):
        cap.NumBdirPorts = 3
        cap.NumDsRfPorts = 1
        cap.NumUsRfPorts = 2
        cap.NumTenGeNsPorts = 2
        cap.NumOneGeNsPorts = 1
        cap.NumDsScQamChannels = 158
        cap.NumDsOfdmChannels = 1
        cap.NumUsScQamChannels = 12
        cap.NumUsOfdmaChannels = 4
        cap.NumDsOob55d1Channels = 1
        cap.NumUsOob55d1Channels = 3
        cap.NumOob55d2Modules = 0
        cap.NumUsOob55d2Demodulators = 0
        cap.NumNdfChannels = 1
        cap.NumNdrChannels = 1
        cap.SupportsUdpEncap = 0
        cap.NumDsPspFlows = 8
        cap.NumUsPspFlows = 4

        cap.RpdIdentification.VendorName = "Cisco"
        cap.RpdIdentification.VendorId = 9
        cap.RpdIdentification.ModelNumber = "0"
        cap.RpdIdentification.DeviceMacAddress = SysTools.get_mac_address("eth0")
        cap.RpdIdentification.CurrentSwVersion = "dummy_cur_sw_ver"
        cap.RpdIdentification.BootRomVersion = "dummy_boot_rom_version"
        cap.RpdIdentification.DeviceDescription = "RPD"
        cap.RpdIdentification.DeviceAlias = "RPD"
        cap.RpdIdentification.SerialNumber = "NA"
        cap.RpdIdentification.UsBurstReceiverVendorId = 4413
        cap.RpdIdentification.UsBurstReceiverModelNumber = "NA"
        cap.RpdIdentification.UsBurstReceiverDriverVersion = "NA"
        cap.RpdIdentification.UsBurstReceiverSerialNumber = "00000000"
        cap.RpdIdentification.RpdRcpProtocolVersion = "1.0"
        cap.RpdIdentification.RpdRcpSchemaVersion = "1.0.8"
        cap.RpdIdentification.HwRevision = "NA"
        cap.RpdIdentification.AssetId = "NA"
        cap.RpdIdentification.VspSelector = ""
        cap.RpdIdentification.CurrentSwImageLastUpdate = Convert.pack_timestamp_to_string(0)
        cap.RpdIdentification.CurrentSwImageName = ""
        cap.RpdIdentification.CurrentSwImageServer = "0.0.0.0"

        cap.PilotToneCapabilities.NumCwToneGens = 4
        cap.PilotToneCapabilities.LowestCwToneFreq = 50000000
        cap.PilotToneCapabilities.HighestCwToneFreq = 1218000000
        cap.PilotToneCapabilities.MaxPowerDedCwTone = 100
        cap.PilotToneCapabilities.QamAsPilot = True
        cap.PilotToneCapabilities.MinPowerDedCwTone = -330
        cap.PilotToneCapabilities.MaxPowerQamCwTone = 90
        cap.PilotToneCapabilities.MinPowerQamCwTone = -30

        cap.DeviceLocation.DeviceLocationDescription = "NA"
        cap.DeviceLocation.GeoLocationLatitude = "+000000.0"
        cap.DeviceLocation.GeoLocationLongitude = "+0000000.0"

        cap.NumAsyncVideoChannels = 160
        cap.SupportsFlowTags = True
        cap.SupportsFrequencyTilt = True
        cap.TiltRange = 0
        cap.BufferDepthMonitorAlertSupport = 0
        cap.BufferDepthConfigurationSupport = 0
        cap.RpdUcdProcessingTime = 50
        cap.RpdUcdChangeNullGrantTime = 50
        cap.SupportMultiSectionTimingMerReporting = 0

        cap.RdtiCapabilities.NumPtpPortsPerEnetPort = 11

        cap.MaxDsPspSegCount = 10
        cap.DirectDsFlowQueueMapping = 1
        cap.DsSchedulerPhbIdList = "0 10 12 14 18 20 22 26 28 30 34 36 38 46"
        cap.RpdPendingEvRepQueueSize = 1000
        cap.RpdLocalEventLogSize = 1000
        cap.SupportsOpticalNodeRf = False
        cap.MaxDsFrequency = 1218000000
        cap.MinDsFrequency = 5700000
        cap.MaxBasePower = 0
        cap.MinTiltValue = 0
        cap.MinPowerAdjustScQam = 0
        cap.MaxPowerAdjustScQam = 0
        cap.MinPowerAdjustOfdm = 0
        cap.MaxPowerAdjustOfdm = 0
        cap.OfdmConfigurationCapabilities.RequiresOfdmaImDurationConfig = True

    def set_enetif(self, enetif):
        enetif.ifIndex = self.interface_dict['eth0']
        enetif.ifName = "eth0"
        enetif.ifAlias = "eth0"
        enetif.ifPhysAddress = SysTools.get_mac_address("eth0")
        enetif.ifType = 6
        enetif.ifMTU = 1500
        enetif.ifAdminStatus = 1
        enetif.ifOperStatus = 1

    def set_rcp_ipaddr(self, ipaddr_info_list, ipset, rcp_ipaddr):
        index = 0
        for ip in ipset:
            for ipaddr in ipaddr_info_list:
                if ip == ipaddr.get('ip'):
                    interface = ipaddr.get('interface', 0)
                    ipaddr['interface'] = self.interface_dict[interface]
                    if index != 0:
                        rcp_ipaddr.add()
                    RpdInfoUtils.set_ipaddr_info(ipaddr, rcp_ipaddr[index])
                    index = index + 1

    def dummy_rpd_info(self, rsp):
        rpdinfo = rsp.RpdDataMessage.RpdData.RpdInfo
        field_included = False
        if len(rpdinfo.EnetIfTable) > 0:
            field_included = True
            rcp_enetif = rpdinfo.EnetIfTable
            for enetif in rcp_enetif:
                if (not enetif.HasField("ifIndex")) or enetif.ifIndex == self.interface_dict['eth0']:
                    self.set_enetif(enetif)
                    break
        if len(rpdinfo.IpAddress) > 0:
            field_included = True
            rcp_ipaddr = rpdinfo.IpAddress
            ipaddr_info_list = RpdInfoUtils.get_ipaddr_info()
            for ipaddr in rcp_ipaddr:
                ipset = set()
                if ipaddr.HasField("AddrType") and ipaddr.HasField("IpAddress"):
                    ipset.add(ipaddr.IpAddress)
                elif (not ipaddr.HasField("AddrType")) and (not ipaddr.HasField("IpAddress")):
                    for ipaddr_info in ipaddr_info_list:
                        ipset.add(ipaddr_info.get('ip'))
                    break
                else:
                    rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR
                    self.logger.warn("input does not meet the requirements")
                    break
            self.set_rcp_ipaddr(ipaddr_info_list, ipset, rcp_ipaddr)

        if not field_included:
            return {
                "Status": HalCommon_pb2.SUCCESS_IGNORE_RESULT,
                "ErrorDescription": "no interested field included"
            }
        return {
            "Status": HalCommon_pb2.SUCCESS,
            "ErrorDescription": ""
        }

    def save_rsp_db(self, rsp, payload):
        try:
            self.logger.debug("msg content:%s", rsp)
            with open("/tmp/fakedriver-rcp.db", "a+w") as db:
                db.write(payload)
                db.close()
        except Exception:
            self.logger.error("open file fakedriver-rcp.db failure")


def handle_interrrupt_signal(signum, frame):
    sys.exit(0)


# register the ctrl C to handle this signal
if __name__ == "__main__":

    # setup the logging
    setup_logging('HAL', filename="hal_driver.log")
    signal.signal(signal.SIGINT, handle_interrrupt_signal)
    driver = HalDriver0(
        "driver0", "This is fake Driver for all message", "1.0.0",
        range(10000), (2, 3, 4),
        (1, 2, 100, 102))
    driver.start()
