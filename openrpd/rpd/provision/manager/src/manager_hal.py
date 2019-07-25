#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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

from rpd.dispatcher.dispatcher import Dispatcher
import zmq
from zmq.utils.monitor import recv_monitor_message
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient, HalDriverClientError
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg import HalCommon_pb2
from rpd.gpb.monitor_pb2 import t_LED
from rpd.hal.src.HalConfigMsg import MsgTypeCcapCoreIdentification, \
    MsgTypeRedundantCoreIpAddress, MsgTypeRpdCapabilities, MsgTypeRpdCtrl
from rpd.provision.proto.MonitorMsgType import MsgTypeSetLed
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPObject
from rpd.gpb.cfg_pb2 import config
from rpd.rcp.rcp_sessions import CcapCoreIdentification
from rpd.provision.manager.src.manager_ccap_core import CCAPCore
from rpd.common.utils import SysTools
from rpd.rcp.rcp_lib import rcp_tlv_def


class ProvMgrHalDriverError(HalDriverClientError):

    def __init__(self, msg, expr=None):
        super(ProvMgrHalDriverError, self).__init__(msg)
        self.msg = "ProvMgrHalDriverError: " + msg
        self.expr = expr


class ProvMgrHalDriver(HalDriverClient):
    __metaclass__ = AddLoggerToClass

    ntfmsg_list = [
        MsgTypeRpdCapabilities,
    ]
    cfgmsg_list = [
        MsgTypeCcapCoreIdentification,
        MsgTypeRedundantCoreIpAddress,
        MsgTypeRpdCtrl,
    ]

    def __init__(self, drvName, drvDesc, drvVer, supportedMsgType,
                 supportedNotificationMsgs, interestedNotification, dispatcher, logConfigurePath=None, mgr=None):
        """

        :param drvName:
        :param drvDesc:
        :param drvVer:
        :param supportedMsgType:
        :param supportedNotificationMsgs:
        :param dispatcher:
        :param logConfigurePath:
        :param mgr:
        """
        super(ProvMgrHalDriver, self).__init__(drvName, drvDesc, drvVer, supportedMsgType, supportedNotificationMsgs,
                                               interestedNotification)

        self.mgr = mgr
        self.rpd_cap = None
        self.dispatcher = dispatcher

        self.HalConfigMsgHandlers = {
            MsgTypeCcapCoreIdentification: self.recvCcapCoreIdentification,
            MsgTypeRedundantCoreIpAddress: self.recvRedundantCoreIpAddress,
            MsgTypeRpdCtrl: self.recvRpdResetCtrl,
        }

        self.HalNtfHandlers = {
            MsgTypeRpdCapabilities: self.recvRpdCapabilities,
        }

        self.HalConfigMsgRspHandlers = {
            MsgTypeRpdCapabilities: self.recMsgTypeRpdCapabilitiesRspCb,
        }

    RESET_CTRL_FILENAME = '/rpd/config/reset_ctrl'

    def recvRegisterMsgCb(self, cfg):
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
            self.dispatcher.fd_register(self.pullSock.socket,
                                        zmq.POLLIN, self.provmgr_cb)
            self.dispatcher.fd_register(self.pushSock.monitor,
                                        zmq.POLLIN, self.provmgr_cb)
            self.dispatcher.fd_register(self.pullSock.monitor,
                                        zmq.POLLIN, self.provmgr_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        if self.interestedNotification is not None:
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def sendCfgRspMsg(self, cfg, rsp=None):
        """The configuration response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :param rsp: respond
        :return:

        """
        cfgMsg = cfg.msg
        msg = HalMessage("HalConfigRsp", SrcClientID=cfgMsg.SrcClientID,
                         SeqNum=cfgMsg.SeqNum, Rsp=rsp,
                         CfgMsgType=cfgMsg.CfgMsgType,
                         CfgMsgPayload=cfgMsg.CfgMsgPayload)
        self.send(msg.Serialize())

    def recvCfgMsgCb(self, cfgMsg):
        """Receive a configuration message from the Hal, processing it.

        :param cfgMsg:
        :return:

        """
        try:
            msgType = cfgMsg.msg.CfgMsgType
            if msgType not in self.HalConfigMsgHandlers \
                    or self.HalConfigMsgHandlers[msgType] is None:
                rsp = {
                    "Status": HalCommon_pb2.NOTSUPPORTED,
                    "ErrorDescription": "msgType %d is not supported" % msgType
                }
            else:
                rsp = self.HalConfigMsgHandlers[msgType](cfgMsg.msg)

        except Exception as e:  # pragma: no cover
            self.logger.error("Got an error:%s, the cfg msg:%s",
                              str(e), cfgMsg.msg)
            rsp = {
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": "Process configuration failed, reason:%s"
                                    % str(e)
            }

        self.sendCfgRspMsg(cfgMsg, rsp)

    def recvCfgMsgRspCb(self, cfg):
        """Receive a configuration response message from the Hal, processing it.

        :param cfg:
        :return:

        """
        self.logger.debug(
            "Recv a configuration response message:" + str(cfg.msg.CfgMsgType))
        if cfg.msg.CfgMsgType in self.HalConfigMsgRspHandlers:
            cb = self.HalConfigMsgRspHandlers[cfg.msg.CfgMsgType]
            cb(cfg)

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
                                  ClientID=self.drvID,
                                  HalNotificationType=notificationType,
                                  HalNotificationPayLoad=notificationPayload)
        self.send(notification.Serialize())

    def recvNotificationCb(self, ntf):
        """Receive a notification message from the HAL.

        :param ntf:
        :return:

        """
        self.logger.info(
            "Receive a interest notification message:" + str(ntf.msg))
        self.recvNtf += 1
        try:
            msgType = ntf.msg.HalNotificationType
            if msgType in self.HalNtfHandlers:
                self.HalNtfHandlers[msgType](ntf.msg.HalNotificationPayLoad)
            else:
                self.logger.debug(
                    "Receive a interest notification message: no handler for %s", str(msgType))
        except Exception as e:
            self.logger.error("Got an error:%s, the ntf msg:%s",
                              str(e), str(msgType))

    def recvHelloRspMsgCb(self, hello):
        """Call back for Hello Message.

        :param hello:
        :return:

        """
        self.logger.debug("Recv a hello message")
        self.sendRpdCapReq()

    def connectionSetup(self, dispatcher):
        """Create the connection to the mgr and setup the poller.

        :return:

        """
        self.logger.debug("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr,
                                          HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)

        # create the poller
        if self.poller is None:
            self.poller = dispatcher.get_poll()

        # register the mgr socket
        dispatcher.fd_register(self.mgrConnection.socket,
                               zmq.POLLIN, self.provmgr_cb)
        dispatcher.fd_register(self.mgrConnection.monitor,
                               zmq.POLLIN, self.provmgr_cb)

    def connectionDisconnectCb(self, msg):
        """The connection has been detected disconnected , register it again.

        :param msg:
        :return:

        """

        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return
        self.logger.debug("Detected disconnected, register again")

        self.poller.unregister(self.mgrConnection.socket)
        self.poller.unregister(self.mgrConnection.monitor)
        self.mgrConnection.socket.disable_monitor()
        self.mgrConnection.monitor.close()
        self.mgrConnection.close()

        # re-register the message
        self.connectionSetup(self.dispatcher)
        self.register(self.drvID)
        # The zmq lower part will handle the reconnect

        self.disconnected = True

    def start(self):
        """start poll the transport socket.

        :return:

        """
        self.logger.debug("Start the driver poll...")
        try:
            self.connectionSetup(self.dispatcher)
            self.register(self.drvID)
        except Exception as e:
            self.logger.warn("ProvMgr hal client start fail exception %s", str(e))

    def provmgr_cb(self, sock, mask):
        if self.pushSock is not None and sock == self.pushSock.monitor:
            self.pushSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.pullSock is not None and sock == self.pullSock.monitor:
            self.pullSock.monitorHandler(recv_monitor_message(sock))
            return
        if self.mgrConnection is not None and sock == self.mgrConnection.monitor:
            self.mgrConnection.monitorHandler(recv_monitor_message(sock))
            return

        while sock.getsockopt(zmq.EVENTS) and zmq.POLLIN:
            try:
                bin = sock.recv(flags=zmq.NOBLOCK)
                msg = HalMessage.DeSerialize(bin)
                if msg.type in self.HalMsgsHandler:
                    handler = self.HalMsgsHandler[msg.type]
                    handler(msg)
            except zmq.ZMQError as e:
                self.logger.debug(
                    "Got an error when trying with non-block read:" + str(e))
                break
            except Exception as e:
                self.logger.warn("Exception happens when provmgr hal recv socket, reason:%s" % str(e))
                break

    def DeSerializeConfigMsgPayload(self, cfgMsg):
        if cfgMsg.CfgMsgPayload is None:
            return None
        cfgMsgPayload = t_RcpMessage()
        cfgMsgPayload.ParseFromString(cfgMsg.CfgMsgPayload)
        return cfgMsgPayload

    def recvCcapCoreIdentification(self, cfgMsg):
        rcp_msg = self.DeSerializeConfigMsgPayload(cfgMsg)
        if rcp_msg is None:
            return {"Status": HalCommon_pb2.FAILED,
                    "ErrorDescription": "DeSerialize ConfigMsgPayload fail"}
        self.logger.debug("ProvMgr driver receive Config CcapCoreIdentification %s"
                          % str(rcp_msg))
        if rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_READ:
            rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
            del rcp_msg.RpdDataMessage.RpdData.CcapCoreIdentification[0]
            for key in CcapCoreIdentification.get_keys():
                ccapCoreIdent = rcp_msg.RpdDataMessage.RpdData.CcapCoreIdentification.add()
                ccapCore = CcapCoreIdentification(key)
                ccapCore.read()

                ccapCoreIdent.Index = key
                ccapCoreIdent.CoreId = ccapCore.core_id
                ccapCoreIdent.CoreIpAddress = ccapCore.core_ip_addr
                ccapCoreIdent.IsPrincipal = ccapCore.is_principal
                ccapCoreIdent.CoreName = ccapCore.core_name
                ccapCoreIdent.VendorId = ccapCore.vendor_id
                ccapCoreIdent.InitialConfigurationComplete = ccapCore.initial_configuration_complete
                ccapCoreIdent.MoveToOperational = ccapCore.move_to_operational
                ccapCoreIdent.CoreFunction = ccapCore.core_function
                ccapCoreIdent.ResourceSetIndex = ccapCore.resource_set_index
                ccapCoreIdent.CoreMode = ccapCore.core_mode
                self.logger.debug("ProvMgr driver rsp ccapCoreIdent tlv %s" % ccapCoreIdent)
            cfgMsg.CfgMsgPayload = rcp_msg.SerializeToString()

            rsp = {"Status": HalCommon_pb2.SUCCESS,
                   "ErrorDescription": "Serialize ConfigMsgPayload success"}
            return rsp
        if rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_WRITE or \
           rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE:
            rsp = {"Status": HalCommon_pb2.SUCCESS_IGNORE_RESULT,
                   "ErrorDescription": "manager hal ignore write and allocate write for ccapCoreIdentification"}
            return rsp

    def recvRedundantCoreIpAddress(self, cfgMsg):
        rcp_msg = self.DeSerializeConfigMsgPayload(cfgMsg)
        self.logger.info("ProvMgr driver receive RedundantCoreIpAddress %s"
                         % str(rcp_msg))
        rsp = {
            "Status": HalCommon_pb2.SUCCESS,
            "ErrorDescription": "success"
        }
        return rsp

    def recvRpdResetCtrl(self, cfgMsg):
        rcp_msg = self.DeSerializeConfigMsgPayload(cfgMsg)
        if rcp_msg is None:
            return {"Status": HalCommon_pb2.FAILED,
                    "ErrorDescription": "DeSerialize ConfigMsgPayload fail"}
        self.logger.debug("\nProvMgr receive RpdResetCtrl:" + str(rcp_msg))
        operation = rcp_msg.RpdDataMessage.RpdDataOperation

        recv_rcp_msg = rcp_msg.RpdDataMessage.RpdData
        if recv_rcp_msg.HasField("RpdCtrl") and recv_rcp_msg.RpdCtrl.HasField("ResetCtrl"):
            if operation not in [t_RpdDataMessage.RPD_CFG_WRITE, t_RpdDataMessage.RPD_CFG_READ]:
                return {"Status": HalCommon_pb2.FAILED,
                        "ErrorDescription": "Operation %d for RpdResetCtrl is not supported" % operation}
            rcp_rpd_resetctrl = recv_rcp_msg.RpdCtrl.ResetCtrl
            if operation == t_RpdDataMessage.RPD_CFG_WRITE:
                reset = rcp_rpd_resetctrl.Reset
                reset_type = rcp_tlv_def.RESET_TYPE[reset]
                with open(self.RESET_CTRL_FILENAME, 'w') as f:
                    f.write(str(reset) + ":" + str(reset_type) + "\n")
                for ccap_core in CCAPCore.ccap_core_db.values():
                    ccap_core.del_ccap_core()
                SysTools.reboot(reset_type)
            if operation == t_RpdDataMessage.RPD_CFG_READ:
                try:
                    with open(self.RESET_CTRL_FILENAME, 'r') as fr:
                        reset_rd = fr.read()
                        rcp_rpd_resetctrl.Reset = int(reset_rd.strip(":")[0])
                except IOError:
                    # file don't exist,skip check
                    pass
            cfgMsg.CfgMsgPayload = rcp_msg.SerializeToString()
            return {"Status": HalCommon_pb2.SUCCESS,
                    "ErrorDescription": "ProMgr handle RpdResetCtrl success for %d" % operation}
        else:
            return {"Status": HalCommon_pb2.SUCCESS_IGNORE_RESULT,
                    "ErrorDescription": "ProvMgr Do not Have RpdCtrl Filed."}

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

    def recvRpdCapabilities(self, ntfMsg):
        rpd_cap = t_RpdCapabilities()
        rpd_cap.ParseFromString(ntfMsg)
        if not self.valid_rpd_cap(rpd_cap):
            self.logger.warning("ProvMgr receive invalid rpdCapabilities notification from driver")
            return
        self.rpd_cap = rpd_cap
        self.logger.debug("Receive rpdCapabilities notification:  %s", str(self.rpd_cap))
        return

    def sendRpdCapReq(self):
        try:
            if self.rpd_cap:
                self.logger.debug("Already has Rpd cap in store, no need to send req")
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
            msg = HalMessage("HalConfig", SrcClientID=self.drvID,
                             SeqNum=self.seqNum,
                             CfgMsgType=MsgTypeRpdCapabilities,
                             CfgMsgPayload=cfgMsgContent)
            self.send(msg.Serialize())
            self.seqNum += 1
            self.logger.debug("send RPD capabilities req to hal driver")
            return True
        except Exception as e:
            self.logger.warning("send RPD cap req failed :%s", str(e))
            return False

    def sendOperationalStatusNtf(self, operational):
        """
        :param operational:  True or False to represent the current operational status
        :return:
        """
        led_msg = t_LED()
        led_msg.setLed.ledType = led_msg.LED_TYPE_STATUS
        led_msg.setLed.color = led_msg.LED_COLOR_GREEN
        if operational:
            led_msg.setLed.action = led_msg.LED_ACTION_LIT
        else:
            led_msg.setLed.action = led_msg.LED_ACTION_DARK
        self.logger.debug("Set led notification message: %s", led_msg)
        self.sendNotificationMsg(MsgTypeSetLed, led_msg.SerializeToString())


class manager(object):

    def __init__(self):
        self.desc = "This is a test manager."


if __name__ == "__main__":
    setup_logging('HAL', filename="provmgr_hal.log")
    dispatcher = Dispatcher()
    mgr = manager()
    haldriver = ProvMgrHalDriver("ProvMgr_HAL_CLIENT", "This is provision manager hal driver", "1.0.0",
                                 ProvMgrHalDriver.cfgmsg_list, ProvMgrHalDriver.ntfmsg_list,
                                 ProvMgrHalDriver.ntfmsg_list,
                                 dispatcher=dispatcher,
                                 mgr=mgr
                                 )
    haldriver.start()
    dispatcher.loop()
