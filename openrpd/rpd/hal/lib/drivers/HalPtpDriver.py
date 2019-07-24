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
# distributed under the License is dist        DEBUG:ManagerProcess:Receive a event message from the agent:mgr_event {ributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
This is a PTP test driver to simulate PTP "LOSS OF SYNC" AND SYNC("ALIGNED")
"""
import zmq
import argparse
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.HalConfigMsg import *
from rpd.hal.src.transport.HalTransport import HalTransport
from rpd.hal.src.msg import HalCommon_pb2
from rpd.dispatcher.dispatcher import Dispatcher
from zmq.utils.monitor import recv_monitor_message
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient, HalDriverClientError


class HalPtpDriver(HalDriverClient):
    """The Driver Client for Hal."""

    SYNC = "ALIGNED"
    LOS = "LOSS OF SYNC"
    __metaclass__ = AddLoggerToClass

    def __init__(self, drvName, drvDesc, drvVer, supportedMsgType, supportedNotificationMsgs, logConfigurePath=None):
        """Init.

        :param drvName: The driver name, such as BCM3160 Driver
        :param drvDesc: A brief description about this driver, such as the 
         driver main functionality description
        :param drvVer: Driver specific version, such as 1.0.1
        :param supportedMsgType: a tuple or list for the driver supported 
         msg types, the form will be (1, 2, 456, 10)
        :param supportedNotificationMsgs: the driver supported notification 
         msg types the form will be (1, 3, 4)
        :return: HalDriverClient object

        """
        super(HalPtpDriver, self).__init__(drvName, drvDesc, drvVer,
                                           supportedMsgType,
                                           supportedNotificationMsgs,
                                           logConfigurePath)

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfig": self.recvCfgMsgCb,
        }

        self.HalConfigMsgHandlers = {
            MsgTypePtpStatusGet: self.ptp_status_get,
            MsgTypeRdtiConfig: self.config_rdti,
        }

        self.ptpStatus = self.LOS
        self.ptpNewStatus = self.LOS
        self.dispatcher = Dispatcher()

    def start(self, simulate_mode=False):
        """Start polling the transport socket.

        :return:

        """
        self.logger.info("Start the driver client poll...")
        self.connectionSetup()
        self.logger.info("Connection setup done...")

        self.logger.info("Begin register...")
        self.register(self.drvID)
        self.logger.info("End of register...")

        self.dispatcher.loop()

    def ptpdrv_hal_cb(self, sock, mask):
        self.logger.debug("Receive prp drv event")
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
                self.logger.debug("Got a zmq msg:%s type:%s" % (msg.msg, msg.type))
                if msg.type in self.HalMsgsHandler:
                    handler = self.HalMsgsHandler[msg.type]
                    handler(msg)
            except zmq.ZMQError as e:
                self.logger.debug("Got an error when trying with nonblock read:" + str(e))
                break
            except Exception as e:
                self.logger.warning("Got an un-expected error:%s", str(e))
                break

    def register(self, DriverID):
        """Send a register message to Hal and get the client ID from the Hal.

        :return:

        """
        if DriverID is None:
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
                                     ClientID=DriverID
                                     )

        if self.mgrConnection is None:
            errMsg = "Cannot send the register since the mgr connection is not setup"
            self.logger.error(errMsg)
            raise HalDriverClientError(errMsg)
        self.logger.debug("Send the register msg to Hal...")
        self.mgrConnection.send(registerMsg.Serialize())

    def recvRegisterMsgCb(self, cfg):
        """The callback handler for the configuration message.

        :param cfg: the configuration message received frm the Hal
        :return:

        """
        self.logger.debug("Recv a register rsp Message from the Hal: %s" % cfg.msg)

        if cfg.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
            self.logger.error("Cannot register to Hal, reason[%s]", cfg.msg.Rsp.ErrorDescription)
            return

        self.drvID = cfg.msg.ClientID

        # Setup the push and pull connection
        self.pullPath = cfg.msg.PathFromHalToClient
        self.pushPath = cfg.msg.PathFromClientToHal

        # get the index of the path
        index = self._getIndexFromPath()
        if index == -1:
            self.logger.error("Cannot get index from the path [%s]" % self.pushPath)
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
                                        zmq.POLLIN, self.ptpdrv_hal_cb)
            self.dispatcher.fd_register(self.pushSock.monitor,
                                        zmq.POLLIN, self.ptpdrv_hal_cb)
            self.dispatcher.fd_register(self.pullSock.monitor,
                                        zmq.POLLIN, self.ptpdrv_hal_cb)
        # send Hello To Hal
        self.sayHelloToHal()
        if self.interestedNotification is not None:
            self.sendInterestedNotifications(self.interestedNotification)

        self.disconnected = False

        return

    def connectionSetup(self):
        """Create the connection to the mgr and setup the poller.

        :return:

        """
        self.logger.info("Create the connection to the mgr....")
        # Create a connection to Hal driver mgr

        # Create a connection to Hal driver mgr
        self.mgrConnection = HalTransport(HalTransport.HalTransportClientMgr, HalTransport.HalClientMode,
                                          disconnectHandlerCb=self.connectionDisconnectCb)
        self.mgrConnection.connects()

        self.HalMsgsHandler[self.mgrConnection.socket] = self.recvRegisterMsgCb

        self.HalMsgsHandler[self.mgrConnection.socket] = self.recvRegisterMsgCb

        # register the mgr socket
        self.dispatcher.fd_register(self.mgrConnection.socket, zmq.POLLIN, self.ptpdrv_hal_cb)
        self.dispatcher.fd_register(self.mgrConnection.monitor, zmq.POLLIN, self.ptpdrv_hal_cb)

    def connection_cleanup(self):
        """Close the connection to the mgr.

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

    def connectionDisconnectCb(self, msg):
        """TODO: confusing comment here. Need clarification.

        The connection has been detected disconnected , register it again
        We have reconenct, we have to assure the regiter message is received
        by the HAL

        :param msg:
        :return:

        """
        if self.disconnected:
            self.logger.info("A previous event has been processed, skip it!")
            return
        self.logger.info("Detected disconnected, register again")
        # clean up the push and pull socket
        # self.poller.unregister(self.pullSock.socket)

        self.dispatcher.fd_unregister(self.mgrConnection.socket)
        self.dispatcher.fd_unregister(self.mgrConnection.monitor)
        self.mgrConnection.monitor.close()
        self.mgrConnection.close()

        # re-register the message
        self.connectionSetup()
        self.register(self.drvID)
        # The zmq lower part will handle the reconnect

        self.disconnected = True

    def recvHelloRspMsgCb(self, hello):
        """Call back for Hello Message.

        :param hello:
        :return:

        """
        self.logger.debug("Recv a hello message")

    def recvCfgMsgCb(self, cfg):
        """Receive a configuration message from the Hal, processing it.

        :param cfg:
        :return:

        """
        try:
            handler = self.HalConfigMsgHandlers[cfg.msg.CfgMsgType]
            handler(cfg)
        except Exception as e:
            self.logger.error(
                "Got an error:%s, the cfg msg:%s", str(e), cfg.msg)

    def ptp_status_get(self, cfg):
        cfg.msg.CfgMsgPayload = self.SYNC
        self.sendCfgRspMsg(cfg)

    def config_rdti(self, cfg):
        rdti_config_data = t_RcpMessage()
        rdti_config_data.ParseFromString(cfg.msg.CfgMsgPayload)
        self.logger.debug(
            "Recv ptp configuration message, %s" % rdti_config_data)
        self.sendCfgRspMsg(cfg)

    def sendCfgRspMsg(self, cfg, rsp=None):
        """The configuration response routine, the driver implementor should
        fill sth into this function.

        :param cfg: The original configuration message
        :return:

        """
        cfgMsg = cfg.msg
        rsp = {
            "Status": HalCommon_pb2.SUCCESS,
            "ErrorDescription": ""
        }
        msg = HalMessage("HalConfigRsp", SrcClientID=cfgMsg.SrcClientID,
                         SeqNum=cfgMsg.SeqNum, Rsp=rsp,
                         CfgMsgType=cfgMsg.CfgMsgType,
                         CfgMsgPayload=cfgMsg.CfgMsgPayload)
        self.pushSock.send(msg.Serialize())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ptp driver client process")
    # parse the daemon settings.
    parser.add_argument("-s", "--simulator",
                        action="store_true",
                        help="run the program with simulator mode")
    arg = parser.parse_args()
    setup_logging("HAL", filename="hal_ptp_driver.log")

    driver = HalPtpDriver("PTP_Driver", "This is PTP test Driver", "1.9.0",
                          (MsgTypeRdtiConfig, MsgTypePtpStatusGet), (MsgTypePtpClockStatus,))
    driver.start(simulate_mode=arg.simulator)
