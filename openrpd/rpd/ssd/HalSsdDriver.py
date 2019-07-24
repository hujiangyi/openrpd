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
# distributed under the License is dist
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""This is a SSD test driver to simulate SSD "LOSS OF SYNC" AND SYNC("ALIGNED").
"""

import argparse
import commands
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import tftpy
import urllib
import urllib2
import zmq
from random import uniform
from rpd.common import rpd_event_def
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import Convert, SysTools
from rpd.gpb.HalApi_pb2 import *
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient, HalDriverClientError
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.HalConfigMsg import *
from rpd.hal.src.transport.HalTransport import HalTransport, HalPoller
from rpd.hal.src.msg import HalCommon_pb2
from rpd.provision.proto.provision_pb2 import t_Provision
from rpd.ssd.codeFileVerify import CodeFileVerify, SsdVerifyResult
from tftpy.TftpShared import log as tftpLogger
from tftpy.TftpShared import TftpTimeout, TftpException
from zmq.utils.monitor import recv_monitor_message


class SsdManager(object):  # pragma: no cover

    PROVISION_MGR_PATH = '/tmp/rpd_provision_manager_api.sock'

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.ipc = None
        self.poller = HalPoller()

    def connectionSetup(self):
        context = zmq.Context()
        self.ipc = context.socket(zmq.REQ)
        self.ipc.connect('ipc://' + self.PROVISION_MGR_PATH)
        # register the provision manager api socket
        self.poller.register(self.ipc)

    def sendMsg(self, msg):
        """Send ipc to other module."""
        if not self.ipc:
            self.logger.error("The client is on disconencted "
                              "state, skip to send the message.")
            return False

        if msg is None:
            self.logger.error("Cannot send a None or incorrect msg")
            return False

        if msg.IsInitialized():
            self.ipc.send(msg.SerializeToString())
            return True
        return False

    def ipcEntry(self, msg, timeout=3000):
        """ipc entry."""
        ret = self.sendMsg(msg)
        if ret:
            try:
                sock = self.poller.poll(timeout=timeout)
                if sock:
                    bin = self.ipc.recv(flags=zmq.NOBLOCK)
                    rsp = t_Provision()
                    rsp.ParseFromString(bin)
                    return rsp
            except zmq.ZMQError as e:
                self.logger.error("Geting an error when trying "
                                  "with nonblock read:" + str(e))
            except Exception as e:
                self.logger.error("Geting an unhandled exception:"
                                  + str(e))
        else:
            self.logger.error("Cannot send the msg")
        return None

    def ssd_start(self, trigger):
        msg = t_Provision()
        msg.MsgType = t_Provision.SSD_START
        msg.parameter = str(trigger)

        rsp = self.ipcEntry(msg)

        if rsp is None:
            self.logger.error("recv Msg with None data")
            return False

        if rsp.MsgType != t_Provision.SSD_START:
            self.logger.error("recv Msg with incorrect type")
            return False

        if rsp.result != t_Provision.RESULT_OK:
            self.logger.error("recv Msg with respond result %s" % rsp.result)
            return False

        return True

    def get_af_type(self):
        msg = t_Provision()
        msg.MsgType = t_Provision.SSD_GET_AF_TYPE

        rsp = self.ipcEntry(msg)

        if rsp is None:
            self.logger.error("recv Msg with None data")
            return None

        if rsp.MsgType != t_Provision.SSD_GET_AF_TYPE:
            self.logger.error("recv Msg with incorrect type")
            return None

        if rsp.result != t_Provision.RESULT_OK:
            self.logger.error("recv Msg with respond result %s" % rsp.result)
            return None

        if not rsp.HasField("parameter"):
            self.logger.error("recv Msg without respond data")
            return None
        type = str(json.loads(rsp.parameter))
        if type not in ['ipv4', 'ipv6']:
            self.logger.error("recv Msg with invalid data:" + type)
            return None

        return type

    def ssd_end(self, result):
        msg = t_Provision()
        msg.MsgType = t_Provision.SSD_END
        if result not in SsdVerifyResult.ssdErrorMessage:
            self.logger.error("unsupported result: %s" % str(result))
            return False
        result = SsdVerifyResult.ssdErrorMessage[result]
        self.logger.info("SSD result: %s" % str(result))
        msg.parameter = str(result)

        rsp = self.ipcEntry(msg)

        if rsp is None:
            self.logger.error("recv Msg with None data")
            return False

        if rsp.MsgType != t_Provision.SSD_END:
            self.logger.error("recv Msg with incorrect type")
            return False

        if rsp.result != t_Provision.RESULT_OK:
            self.logger.error("recv Msg with respond result %s" % rsp.result)
            return False

        return True


class HalSsdDriver(HalDriverClient):
    """The Driver Client for Hal."""
    BOOT_ROOT_PATH = '/bootflash/'
    BOOT_IMAGE_PATH = '/bootflash/imagea'
    INIT_CODE_PATH = '/bootflash/initcode'
    LOCAL_FILE_PATH = '/bootflash/codefile.local'
    # fixme: remove when bootflash partition done
    TMP_FILE_PATH = '/tmp/ssd/codefile.tmp'
    TFTP_PORT = 69
    HTTP_PORT = 80
    TRANSPORT_TFTP = 1
    TRANSPORT_HTTP = 2

    TRIGGER_NONE = 0
    TRIGGER_GCP = 1
    TRIGGER_API = 2

    START = 2
    ABORT = 3

    # todo: move to proto buf def
    STATUS_OTHER = 1
    STATUS_IDEL = 2
    STATUS_INPROGRESS = 3
    STATUS_CVCVERIFIED = 4
    STATUS_CVCREJECTED = 5
    STATUS_CODEFILEVERIFIED = 6
    STATUS_CODEFILEREJECTED = 7
    STATUS_DOWNLOADING = 8
    STATUS_DOWNLOADSUCCEED = 9
    STATUS_DOWNLOADFAILED = 10
    STATUS_MISSROOTCA = 11

    SSD_MAX_DOWNLOAD_DELAY = 3
    SSD_RETRY_TIMEOUT = 10

    tftp_error_mapping = {
        0: "Not defined",
        1: "File not found",
        2: "Access violation",
        3: "Disk full or allocation exceed",
        4: "Illegal TFTP operation",
        5: "Unknown transfer ID",
        6: "File already exists",
        7: "No such user",
        8: "Option invalid",
    }
    __metaclass__ = AddLoggerToClass

    def __init__(self, drvName, drvDesc, drvVer, supportedMsgType,
                 supportedNotificationMsgs, logConfigurePath=None, rootca=None):
        """
        :param drvName: The driver name, such as BCM3160 Driver
        :param drvDesc: A brief description about this driver, such as the driver main functionality description
        :param drvVer: Driver specific version, such as 1.0.1
        :param supportedMsgType: a tuple or list for the driver supported msg types, the form will be (1, 2, 456, 10)
        :param supportedNotificationMsgs: the driver supported notification msg types the form will be (1, 3, 4)
        :return: HalDriverClient object
        """
        super(HalSsdDriver, self).__init__(drvName, drvDesc, drvVer, supportedMsgType, supportedNotificationMsgs,
                                           logConfigurePath)

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfig": self.recvCfgMsgCb,
        }

        self.HalConfigMsgHandlers = {
            MsgTypeSsd: self.recv_ssd_gcp,
            MsgTypeSsdApi: self.recv_ssd_api,
        }

        self.mgr = SsdManager()

        self.serverAddr = None
        self.transport = None
        self.fileName = None
        self.status = self.STATUS_IDEL
        self.mfrCvcChain = None
        self.coCvcChain = None

        self.ssdParam = dict()
        self.lastSsdParam = dict()
        self.initCode = dict()
        self.codeFile = None
        self.rootca = rootca

        self.mfrInitDone = False
        self.isProcessRunning = self.TRIGGER_NONE
        self.ssdProcess = None

        # set the tftpy lib log level and add the syslog handler
        self.tftplog = tftpLogger
        self.tftplog.setLevel(logging.ERROR)
        self.tftploghdr = logging.handlers.SysLogHandler(facility='local7')
        self.tftplog.addHandler(self.tftploghdr)

    def get_init_code(self):
        # todo: get the initial code version from non-volatile memory, act2? flash?
        try:
            if os.path.exists(self.INIT_CODE_PATH):
                with open(self.INIT_CODE_PATH, 'rt') as fp:
                    self.initCode = json.load(fp)
                    fp.close()
                    if "manufacturer" in self.initCode \
                            and isinstance(self.initCode["manufacturer"], dict) \
                            and "organizationName" in self.initCode["manufacturer"] \
                            and "codeAccessStart" in self.initCode["manufacturer"] \
                            and "cvcAccessStart" in self.initCode["manufacturer"]:
                        if "co-signer" in self.initCode:
                            self.initCode.pop("co-signer")
                        self.mfrInitDone = True
                        return
        except Exception as e:  # pragma: no cover
            self.logger.error("SSD:get_init_code fail:" + str(e))

        self.logger.info("SSD:can not get the init code file, create the default file")
        self.initCode["manufacturer"] = {"organizationName": "cisco",
                                         "codeAccessStart": "20160311122430Z",
                                         "cvcAccessStart": "20160311122430Z"}
        self.mfrInitDone = True

    def update_init_code(self, initcode):
        # todo: update the initial code version to non-volatile memory, act2? flash?
        # self.logger.info("SSD:update_init_code not implemented")
        self.logger.debug(str(initcode))
        self.initCode = initcode
        try:
            with open(self.INIT_CODE_PATH, "w") as fp:
                fp.write(json.dumps(initcode, indent=4))
                fp.close()
        except Exception as e:  # pragma: no cover
            self.logger.error("SSD:update_init_code fail:" + str(e))
            self.notify.error(rpd_event_def.RPD_EVENT_SSD_GENERAL_FAIL[0],
                              str(e),
                              self.ssdParam["SsdFilename"],
                              self.ssdParam["SsdServerAddress"],
                              "")

    def secure_boot(self, file_path):
        if SysTools.is_vrpd():
            self.logger.info("SSD:secure_boot not implemented in vRPD")
        else:  # pragma: no cover
            try:
                if os.path.exists(file_path):
                    os.system('rpd_upgrade.sh ' + file_path)
                    SysTools.reboot('software upgrade')
            except Exception as e:
                self.logger.error("SSD:secure_boot error:" + str(e))
                self.notify.error(rpd_event_def.RPD_EVENT_SSD_GENERAL_FAIL[0],
                                  str(e),
                                  self.ssdParam["SsdFilename"],
                                  self.ssdParam["SsdServerAddress"],
                                  "")

    def dropcache(self):
        """force to drop the cache & buffer."""

        status, output = commands.getstatusoutput("sync")
        self.logger.debug("sync result:[%s] %s", str(status), str(output))
        status, output = commands.getstatusoutput("echo 3 > /proc/sys/vm/drop_caches")
        self.logger.debug("drop cache result:[%s] %s", str(status), str(output))

    def connectionSetup(self):
        """Create the connection to the mgr and setup the poller.

        :return:

        """
        super(HalSsdDriver, self).connectionSetup()

        self.mgr.connectionSetup()

    def start(self, simulate_mode=False):
        """Start poll the transport socket.

        :return:

        """
        self.get_init_code()
        self.logger.info("initial code version fetch done...")
        self.codeFile = CodeFileVerify(self.initCode, rootca=self.rootca)

        self.logger.info("Start the driver client poll...")
        self.connectionSetup()
        self.logger.info("Connection setup done...")

        self.logger.info("Begin register...")
        self.register(self.drvID)
        self.logger.info("End of register...")

        lastTimeout = time.time()
        simulate_cnt = 0
        while True:
            socks = self.poller.poll(self.pollTimeout)
            if time.time() - lastTimeout > self.pollTimeout / 1000:
                lastTimeout = time.time()
                if simulate_mode:
                    simulate_cnt += 1
                    if simulate_cnt >= 5:
                        break
            if not socks:
                # self.logger.debug("Got a timeout event")
                continue
            for sock in socks:  # pragma: no cover
                if self.pushSock is not None and sock == self.pushSock.monitor:
                    self.pushSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if self.pullSock is not None and sock == self.pullSock.monitor:
                    self.pullSock.monitorHandler(recv_monitor_message(sock))
                    continue
                if sock == self.mgrConnection.monitor:
                    self.mgrConnection.monitorHandler(recv_monitor_message(sock))
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
                            self.logger.warn("recv a unsupport msg:" + msg.type)
                    except zmq.ZMQError as e:
                        self.logger.debug("Geting an error when trying with nonblock read:" + str(e))
                    except Exception as e:
                        self.logger.error("Geting an unhandled exception:" + str(e))

    def register(self, DriverID):
        """Send a register message to Hal and get the client ID from the Hal.

        :return:

        """
        if DriverID is None:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.drvname,
                                     ClientDescription=self.drvDesc,
                                     ClientVersion=self.drvVer,
                                     ClientSupportedMessages=self.supportedMsgType)
        else:
            registerMsg = HalMessage("HalClientRegister",
                                     ClientName=self.drvname,
                                     ClientDescription=self.drvDesc,
                                     ClientVersion=self.drvVer,
                                     ClientSupportedMessages=self.supportedMsgType,
                                     ClientID=DriverID
                                     )

        if self.mgrConnection is None:
            errMsg = "Cannot send the register since the mgr connection is not setup"
            self.logger.error(errMsg)
            raise HalDriverClientError(errMsg)
        self.logger.debug("Send the register msg to Hal...")
        self.mgrConnection.send(registerMsg.Serialize())

    def connection_cleanup(self):
        """Clean up after connection is closed.

        :return:

        """
        if self.disconnected:
            self.logger.debug("A previous event has been processed, skip it!")
            return

        if self.mgrConnection is not None:
            self.mgrConnection.socket.disable_monitor()
            self.mgrConnection.monitor.close()
            self.mgrConnection.socket.close()

        if self.pullSock is not None:
            self.pullSock.socket.disable_monitor()
            self.pullSock.monitor.close()
            self.pullSock.socket.close()

        if self.pushSock is not None:
            self.pushSock.socket.disable_monitor()
            self.pushSock.monitor.close()
            self.pushSock.socket.close()

        self.disconnected = True

    def recvHelloRspMsgCb(self, hello):
        """Call back for Hello Message.

        :param hello:
        :return:

        """
        self.logger.info("Recv a hello message")

    @staticmethod
    def _deSerializeConfigMsgPayload(cfgMsg, mask):
        """DeSerialize cfgMsgPayload to RcpMessage.

        :param cfgMsg:
        :param mask: 'gcp', 'api'
        :return:

        """
        if not hasattr(cfgMsg, "CfgMsgPayload") or cfgMsg.CfgMsgPayload is None:
            return None
        if mask == 'gcp':
            cfgMsgPayload = t_RcpMessage()
        elif mask == 'api':
            cfgMsgPayload = t_HalApi()
        else:
            return None
        cfgMsgPayload.ParseFromString(cfgMsg.CfgMsgPayload)
        return cfgMsgPayload

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

    def recv_ssd_api(self, cfgMsg):
        api_msg = self._deSerializeConfigMsgPayload(cfgMsg, 'api')
        if api_msg is None or not api_msg.HasField('ssdController'):
            return {
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": "DeSerialize ConfigMsgPayload fail"
            }
        if api_msg.ssdController.action == t_SsdController.SSD_START:
            rsp = self.configSsdApi(api_msg.ssdController)
            if isinstance(rsp, int):
                return {"Status": HalCommon_pb2.SUCCESS,
                        "ErrorDescription": "Receive ssd api success"}
            else:
                return rsp
        else:
            return {
                "Status": HalCommon_pb2.NOTSUPPORTED,
                "ErrorDescription": "Operation %d for ssd api is "
                                    "not supported" %
                                    api_msg.ssdController.action
            }

    def recv_ssd_gcp(self, cfgMsg):
        """Handle the ssd configuration messages.

        :param cfgMsg:
        :return:

        """
        rcp_msg = self._deSerializeConfigMsgPayload(cfgMsg, 'gcp')
        if rcp_msg is None:
            return {
                "Status": HalCommon_pb2.FAILED,
                "ErrorDescription": "DeSerialize ConfigMsgPayload fail"
            }
        if rcp_msg.RpdDataMessage.RpdDataOperation == \
                t_RpdDataMessage.RPD_CFG_WRITE:
            rsp = self.configSsd(rcp_msg.RpdDataMessage.RpdData)
            if isinstance(rsp, int):
                rcp_msg.RcpDataResult = rsp
                cfgMsg.CfgMsgPayload = rcp_msg.SerializeToString()
                return {"Status": HalCommon_pb2.SUCCESS,
                        "ErrorDescription": "Receive ssd success"}
            else:
                return rsp
        elif rcp_msg.RpdDataMessage.RpdDataOperation == t_RpdDataMessage.RPD_CFG_READ:
            rsp = self.getSsd(rcp_msg.RpdDataMessage.RpdData)
            if isinstance(rsp, int):
                rcp_msg.RcpDataResult = rsp
                cfgMsg.CfgMsgPayload = rcp_msg.SerializeToString()
                return {"Status": HalCommon_pb2.SUCCESS,
                        "ErrorDescription": "Receive ssd success"}
            else:
                return rsp
        else:
            return {
                "Status": HalCommon_pb2.NOTSUPPORTED,
                "ErrorDescription": "Operation %d for ssd is "
                                    "not supported" %
                                    rcp_msg.RpdDataMessage.RpdDataOperation
            }

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
        if None is not self.pushSock:
            self.pushSock.send(msg.Serialize())

    def configSsdApi(self, cfgMsg):
        Ssd = cfgMsg
        if self.isProcessRunning != self.TRIGGER_NONE:
            self.logger.warn("receive a SSD api config before "
                             "last request process done!")
            self.notify.warn(rpd_event_def.RPD_EVENT_SSD_SKIP_TRIGGER[0], "")
            return t_SsdController.SSD_RESULT_GENERAL_ERROR
        if Ssd.HasField("server"):
            self.ssdParam["SsdServerAddress"] = Ssd.server
        if Ssd.HasField("transport"):
            self.ssdParam["SsdTransport"] = Ssd.transport
        if Ssd.HasField("file"):
            self.ssdParam["SsdFilename"] = Ssd.file
        if Ssd.HasField("manufacturerCvc"):
            self.ssdParam["SsdManufCvcChain"] = Ssd.manufacturerCvc
        if Ssd.HasField("cosignerCvc"):
            self.ssdParam["SsdCosignerCvcChain"] = Ssd.cosignerCvc
        if Ssd.HasField("action"):
            self.ssdParam["SsdControl"] = Ssd.action
            if int(self.ssdParam["SsdControl"]) == self.START:
                if not isinstance(self.ssdProcess, threading.Thread) or not self.ssdProcess.isAlive():
                    self.isProcessRunning = self.TRIGGER_API
                    self.ssdProcess = threading.Thread(target=self._process_loop)
                    self.ssdProcess.start()
                    self.logger.info("SSD:triggered by API")
                else:
                    self.logger.warn("try ro trigger a SSD thread before "
                                     "last thread done!")
                    return t_RcpMessage.RCP_RESULT_GENERAL_ERROR
        return t_SsdController.SSD_RESULT_OK

    def configSsd(self, cfgMsg):
        """Receive a ssd configuration message from the Hal, processing it.

        :param cfgMsg:
        :return:

        """
        if cfgMsg.HasField("Ssd"):
            Ssd = cfgMsg.Ssd
            if self.isProcessRunning != self.TRIGGER_NONE:
                self.logger.warn("receive a SSD config before "
                                 "last request process done!")
                self.notify.warn(rpd_event_def.RPD_EVENT_SSD_SKIP_TRIGGER[0], "")
                return t_RcpMessage.RCP_RESULT_GENERAL_ERROR
            if Ssd.HasField("SsdServerAddress"):
                self.ssdParam["SsdServerAddress"] = Ssd.SsdServerAddress
            if Ssd.HasField("SsdTransport"):
                self.ssdParam["SsdTransport"] = Ssd.SsdTransport
            if Ssd.HasField("SsdFilename"):
                self.ssdParam["SsdFilename"] = Ssd.SsdFilename
            if Ssd.HasField("SsdManufCvcChain"):
                self.ssdParam["SsdManufCvcChain"] = Ssd.SsdManufCvcChain
            if Ssd.HasField("SsdCosignerCvcChain"):
                self.ssdParam["SsdCosignerCvcChain"] = Ssd.SsdCosignerCvcChain
            if Ssd.HasField("SsdControl"):
                self.ssdParam["SsdControl"] = Ssd.SsdControl
                if int(self.ssdParam["SsdControl"]) == self.START:
                    if not isinstance(self.ssdProcess, threading.Thread) or not self.ssdProcess.isAlive():
                        self.isProcessRunning = self.TRIGGER_GCP
                        self.ssdProcess = threading.Thread(target=self._process_loop)
                        self.ssdProcess.start()
                        self.logger.info("SSD:triggered by GCP")
                    else:
                        self.logger.warn("try ro trigger a SSD thread before "
                                         "last thread done!")
                        return t_RcpMessage.RCP_RESULT_GENERAL_ERROR
            return t_RcpMessage.RCP_RESULT_OK
        else:
            return {"Status": HalCommon_pb2.FAILED,
                    "ErrorDescription": "Message type mismatch"}

    def getSsd(self, cfgMsg):
        """Receive a ssd configuration message from the Hal, processing it.

        :param cfgMsg:
        :return:

        """
        if cfgMsg.HasField("Ssd"):
            Ssd = cfgMsg.Ssd
            if self.isProcessRunning != self.TRIGGER_NONE:
                ssdParam = self.ssdParam.copy()
            else:
                ssdParam = self.lastSsdParam.copy()
            if Ssd.HasField("SsdServerAddress"):
                if "SsdServerAddress" in ssdParam:
                    Ssd.SsdServerAddress = ssdParam["SsdServerAddress"]
                else:
                    Ssd.SsdServerAddress = "0.0.0.0"
            if Ssd.HasField("SsdTransport"):
                if "SsdTransport" in ssdParam:
                    Ssd.SsdTransport = ssdParam["SsdTransport"]
                else:
                    Ssd.SsdTransport = 0
            if Ssd.HasField("SsdFilename"):
                if "SsdFilename" in ssdParam:
                    Ssd.SsdFilename = ssdParam["SsdFilename"]
                else:
                    Ssd.SsdFilename = ""
            if Ssd.HasField("SsdManufCvcChain"):
                if "SsdManufCvcChain" in ssdParam:
                    Ssd.SsdManufCvcChain = ssdParam["SsdManufCvcChain"]
                else:
                    Ssd.SsdManufCvcChain = ""
            if Ssd.HasField("SsdCosignerCvcChain"):
                if "SsdCosignerCvcChain" in ssdParam:
                    Ssd.SsdCosignerCvcChain = ssdParam["SsdCosignerCvcChain"]
                else:
                    Ssd.SsdCosignerCvcChain = ""
            if Ssd.HasField("SsdControl"):
                if "SsdControl" in ssdParam:
                    Ssd.SsdControl = ssdParam["SsdControl"]
                else:
                    Ssd.SsdControl = 0
            if Ssd.HasField("SsdStatus"):
                Ssd.SsdStatus = int(self.status)
            return t_RcpMessage.RCP_RESULT_OK
        else:
            return {"Status": HalCommon_pb2.FAILED,
                    "ErrorDescription": "Message type mismatch"}

    def is_same_img(self, image):
        """Hook to watch the downloading process.

        :param image: image name
        :return: True
                 False

        """

        if None is image:
            return False
        newimg = os.path.basename(str(image)).strip().split('.')[0]
        if os.path.islink(self.BOOT_IMAGE_PATH):
            oldimg = subprocess.check_output("readlink " + self.BOOT_IMAGE_PATH,
                                             shell=True).strip()
            oldimg = os.path.basename(oldimg).split('.')[0]
            if newimg == oldimg:
                return True
        return False

    def _reporthook(self, block_read, block_size, total_size):
        """Hook to watch the downloading process.

        :param block_read:
        :param block_size:
        :param total_size:
        :return:

        """
        if not block_read:
            self.logger.debug("connection opened")
            return
        amount_count = block_read * block_size
        if total_size < 0:
            self.logger.debug("read %d blocks (%dbytes)" %
                              (block_read, amount_count))
        else:
            self.logger.debug("Read %d blocks,or %d/%d" %
                              (block_read, amount_count, total_size))

    def clean_download_file(self):
        """cleanup the temp Codefile downloaded.

        :return:

        """
        if os.path.exists(self.LOCAL_FILE_PATH):
            os.remove(self.LOCAL_FILE_PATH)

    def download_process(self, type, server, file):
        """Codefile download.

        request a block size of 1448 octets if using TFTP over IPv4
        request a block size of 1428 octets if using TFTP over IPv6

        :param type: tftp/http
        :param server: server address
        :param file: Software Upgrade File Name
        :return:file path
                None

        """
        retFile = None
        type = int(type)
        ipf = ''
        blksize = 0
        imagepath = file

        try:
            af = self.mgr.get_af_type()
            if af is None:
                self.notify.warn(rpd_event_def.RPD_EVENT_SSD_PROVISION_LOST[0], "")
            if Convert.is_valid_ipv4_address(str(server)):
                ipf = 'ipv4'
                blksize = 1448
            elif Convert.is_valid_ipv6_address(str(server)):
                ipf = 'ipv6'
                blksize = 1428

            if type == self.TRANSPORT_TFTP:
                if 'SsdServerPort' not in self.ssdParam:
                    port = self.TFTP_PORT
                else:
                    port = self.ssdParam['SsdServerPort']
                client = tftpy.TftpClient(server, int(port),
                                          options={'blksize': blksize})
                try:
                    client.download(file, self.TMP_FILE_PATH, timeout=self.SSD_RETRY_TIMEOUT)
                    retFile = self.TMP_FILE_PATH
                except TftpTimeout:  # pragma: no cover
                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_FAIL_SERVER_NOT_PRESENT[0],
                                      self.ssdParam["SsdFilename"],
                                      self.ssdParam["SsdServerAddress"],
                                      "")
                except TftpException, err:  # pragma: no cover
                    import re
                    errMatch = re.search(r'errorcode *= *(\d)', str(err), re.I)
                    if errMatch:
                        errId = errMatch.group(1)
                        errId = int(errId)
                        if errId == 1:
                            self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_FAIL_FILE_NOT_PRESENT[0],
                                              self.ssdParam["SsdFilename"],
                                              self.ssdParam["SsdServerAddress"],
                                              "")
                        self.logger.error("SSD TFTP download error %s",
                                          self.tftp_error_mapping[errId] if errId in self.tftp_error_mapping else None)

                except Exception as e:  # pragma: no cover
                    if client.context is not None:
                        client.context.end()
                    raise

            elif type == self.TRANSPORT_HTTP:  # pragma: no cover
                if 'SsdServerPort' not in self.ssdParam:
                    port = self.HTTP_PORT
                else:
                    port = self.ssdParam['SsdServerPort']
                # Per rfc2732, ipv6 URI has specific format
                server_format = "["+str(server)+"]" if Convert.is_valid_ipv6_address(str(server)) else str(server)
                imagepath = 'http://' + server_format + ':' + str(port) + '/' + str(file)
                try:
                    # urlopen would throw exception if HTTP or URL got any error.
                    urllib2.urlopen(imagepath, timeout=10)
                    urllib.urlretrieve(imagepath, self.TMP_FILE_PATH)
                    retFile = self.TMP_FILE_PATH
                except urllib2.HTTPError, e:
                    self.logger.error("SSD download %s fail:%s" % (imagepath, str(e)))
                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_FAIL_FILE_NOT_PRESENT[0],
                                      self.ssdParam["SsdFilename"],
                                      self.ssdParam["SsdServerAddress"],
                                      "")
                except urllib2.URLError, e:
                    self.logger.error("SSD download %s fail:%s" % (imagepath, str(e)))
                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_FAIL_SERVER_NOT_PRESENT[0],
                                      self.ssdParam["SsdFilename"],
                                      self.ssdParam["SsdServerAddress"],
                                      "")
            else:
                self.logger.error("invalid transport para:"
                                  "type[%d],server[%s],file[%s]"
                                  % (type, server, file))
                self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_GENERAL_FAIL[0],
                                  "invalid transport para",
                                  self.ssdParam["SsdFilename"],
                                  self.ssdParam["SsdServerAddress"],
                                  "")
        except Exception as e:
            self.logger.error("General SSD download %s fail:%s" % (imagepath, str(e)))
            self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_GENERAL_FAIL[0], str(e),
                              self.ssdParam["SsdFilename"],
                              self.ssdParam["SsdServerAddress"],
                              "")
        # fixme: remove when bootflash partition done
        finally:
            try:
                self.dropcache()
                if os.path.exists(self.TMP_FILE_PATH):
                    shutil.move(self.TMP_FILE_PATH, self.LOCAL_FILE_PATH)
                if retFile is not None:
                    retFile = self.LOCAL_FILE_PATH
            except Exception as e:
                self.logger.warn("hit file system error:%s" % str(e))

        if retFile is not None:
            if self.isProcessRunning == self.TRIGGER_GCP:
                self.notify.info(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_SUCCESSFUL_GCP[0],
                                 self.ssdParam["SsdFilename"],
                                 self.ssdParam["SsdServerAddress"],
                                 "")
            elif self.isProcessRunning == self.TRIGGER_API:
                self.notify.info(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_SUCCESSFUL_RPD[0],
                                 self.ssdParam["SsdFilename"],
                                 self.ssdParam["SsdServerAddress"],
                                 "")
        return retFile

    def _process_loop(self):
        """The ssd main process.

        :return:

        """
        if self.isProcessRunning:
            self.dropcache()
            self.status = self.STATUS_INPROGRESS
            result = SsdVerifyResult.SUCCESS
            ret = self.mgr.ssd_start(self.isProcessRunning)
            if not ret:
                self.notify.warn(rpd_event_def.RPD_EVENT_SSD_PROVISION_LOST[0], "")
                # fixme: need more action? stop the process?
                pass
            if self.codeFile.root_cert is None:
                self.status = self.STATUS_MISSROOTCA
                self.notify.error(rpd_event_def.RPD_EVENT_SSD_GENERAL_FAIL[0],
                                  "Miss root ca on node",
                                  self.ssdParam["SsdFilename"],
                                  self.ssdParam["SsdServerAddress"],
                                  "")
                result = SsdVerifyResult.ERROR_MISS_ROOT_CA
            else:
                validCVC = 0
                for cvc, isMfr in [("SsdManufCvcChain", True),
                                   ("SsdCosignerCvcChain", False)]:
                    if cvc in self.ssdParam:
                        ret, val = self.codeFile.verify_cvc(self.ssdParam[cvc], isMfr)
                        if ret:
                            validCVC += 1
                            self.update_init_code(self.codeFile.get_initcode())
                            self.status = self.STATUS_CVCVERIFIED
                        else:
                            self.logger.error("gcp %s verify fail" % cvc)
                            if val in [SsdVerifyResult.ERROR_GCP_MISS_MFR_CVC,
                                       SsdVerifyResult.ERROR_GCP_MISS_CO_CVC,
                                       SsdVerifyResult.ERROR_GCP_MISS_ISSUER_CVC,
                                       SsdVerifyResult.ERROR_GCP_CVC_MISS_OR_IMPROPER_KEY_USAGE,
                                       ]:
                                self.notify.error(rpd_event_def.RPD_EVENT_SSD_IMPROPER_GCP_CVC_FORMAT[0], "")
                            else:
                                self.notify.error(rpd_event_def.RPD_EVENT_SSD_GCP_CVC_VALIDATION_FAIL[0], "")
                            result = val
                            validCVC = -1
                            self.status = self.STATUS_CVCREJECTED
                            break
                if validCVC >= 0:
                    if "SsdTransport" not in self.ssdParam or \
                                    "SsdServerAddress" not in self.ssdParam or \
                                    "SsdFilename" not in self.ssdParam:
                        self.logger.error("miss required parameters, please check the ssd config!")
                        result = SsdVerifyResult.ERROR_MISS_PARAMETR
                    elif self.is_same_img(self.ssdParam["SsdFilename"]):
                        self.status = self.STATUS_IDEL
                        result = SsdVerifyResult.WARN_SAME_IMAGE
                    else:
                        self.status = self.STATUS_DOWNLOADING
                        if self.isProcessRunning == self.TRIGGER_GCP:
                            self.notify.info(rpd_event_def.RPD_EVENT_SSD_INIT_GCP[0],
                                             self.ssdParam["SsdFilename"],
                                             self.ssdParam["SsdServerAddress"],
                                             "")
                        elif self.isProcessRunning == self.TRIGGER_API:
                            self.notify.info(rpd_event_def.RPD_EVENT_SSD_INIT_RPD[0],
                                             self.ssdParam["SsdFilename"],
                                             self.ssdParam["SsdServerAddress"],
                                             "")

                        for i in range(0, 3):
                            imagepath = self.download_process(self.ssdParam["SsdTransport"],
                                                        self.ssdParam["SsdServerAddress"],
                                                        self.ssdParam["SsdFilename"])
                            if imagepath is not None:
                                break
                            else:
                                time.sleep(uniform(0, self.SSD_MAX_DOWNLOAD_DELAY))

                        if imagepath is None:
                            self.status = self.STATUS_DOWNLOADFAILED
                            self.logger.error("can not get the codefile "
                                              "via the gcp:[%s:%s]" %
                                              (self.ssdParam["SsdServerAddress"],
                                               self.ssdParam["SsdFilename"]))
                            result = SsdVerifyResult.ERROR_FILE_DOWNLOAD
                            self.notify.error(rpd_event_def.RPD_EVENT_SSD_DOWNLOAD_FAILED_AFTER_RETRY[0])

                        else:
                            self.status = self.STATUS_DOWNLOADSUCCEED
                            ret, val = self.codeFile.verify_file(imagepath)
                            if not ret:  # pragma: no cover
                                self.status = self.STATUS_CODEFILEREJECTED
                                self.logger.error("code file verify fail")
                                if val in [SsdVerifyResult.ERROR_FILE_INVALIDITY_PERIOD_MFR_CVC,
                                           SsdVerifyResult.ERROR_FILE_MFR_CVC_ROOT_CA_MISMATCH_GCP,
                                           SsdVerifyResult.ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_CVC,
                                           SsdVerifyResult.ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_RPD,
                                           SsdVerifyResult.ERROR_PKCS_MFR_VALIDITY_TIME_LESS_THAN_RPD]:
                                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_CODE_MFR_CVC_FAIL[0],
                                                      self.ssdParam["SsdFilename"],
                                                      self.ssdParam["SsdServerAddress"],
                                                      "")
                                elif val in [SsdVerifyResult.ERROR_FILE_INVALIDITY_PERIOD_CO_CVC,
                                             SsdVerifyResult.ERROR_FILE_CO_CVC_ROOT_CA_MISMATCH_GCP,
                                             SsdVerifyResult.ERROR_FILE_CO_MISMATCH_WITH_GCP,
                                             SsdVerifyResult.ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_CVC,
                                             SsdVerifyResult.ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_RPD,
                                             SsdVerifyResult.ERROR_PKCS_CO_VALIDITY_TIME_LESS_THAN_RPD]:
                                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_CODE_MSO_CVC_FAIL[0],

                                                      self.ssdParam["SsdFilename"],
                                                      self.ssdParam["SsdServerAddress"],
                                                      "")
                                elif val in [SsdVerifyResult.ERROR_FILE_MFR_CVS_VALIDATION, ]:
                                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_CODE_MFR_CVS_FAIL[0],
                                                      self.ssdParam["SsdFilename"],
                                                      self.ssdParam["SsdServerAddress"],
                                                      "")
                                elif val in [SsdVerifyResult.ERROR_FILE_CO_CVS_VALIDATION, ]:
                                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_CODE_MSO_CVS_FAIL[0],
                                                      self.ssdParam["SsdFilename"],
                                                      self.ssdParam["SsdServerAddress"],
                                                      "")
                                elif val in [SsdVerifyResult.ERROR_FILE_WRONG_FORMAT, ]:
                                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_IMPROPER_CODEFILE[0],
                                                      self.ssdParam["SsdFilename"],
                                                      self.ssdParam["SsdServerAddress"],
                                                      "")
                            else:
                                self.status = self.STATUS_CODEFILEVERIFIED
                            result = val
                        self.clean_download_file()
                else:
                    self.logger.error("gcp tlv contain a invalid CVC")
                    # result = SsdVerifyResult.ERROR_GCP_CVC_VALIDATION
            ret = self.mgr.ssd_end(result)
            if not ret:
                self.notify.warn(rpd_event_def.RPD_EVENT_SSD_PROVISION_LOST[0], "")
            if result == SsdVerifyResult.SUCCESS:
                self.logger.info("code file verify success, begin to upgrade the software.")
                self.update_init_code(self.codeFile.get_initcode())
                file_path = self.BOOT_ROOT_PATH + os.path.basename(str(self.ssdParam["SsdFilename"]))
                if self.codeFile.get_image(file_path):
                    self.secure_boot(file_path)
                else:
                    self.notify.error(rpd_event_def.RPD_EVENT_SSD_GENERAL_FAIL[0],
                                      "save image to bootflash fail",
                                      self.ssdParam["SsdFilename"],
                                      self.ssdParam["SsdServerAddress"],
                                      "")
            self.lastSsdParam = self.ssdParam.copy()
            self.ssdParam.clear()
            if isinstance(self.codeFile, CodeFileVerify):
                self.codeFile.__init__(self.initCode, rootca=self.rootca)
            self.logger.info("SSD:process Done")
            self.isProcessRunning = self.TRIGGER_NONE


if __name__ == "__main__":  # pragma: no cover

    parser = argparse.ArgumentParser(description="ssd driver client process")
    # parse the daemon settings.
    parser.add_argument("-s", "--simulator",
                        action="store_true",
                        help="run the program with simulator mode")
    arg = parser.parse_args()
    setup_logging("HAL", filename="hal_ssd_driver.log")

    # fixme: remove when released
    CL_ROOT_CA_FNAME = "/tmp/CableLabs-Root-CA.cert"
    rootCa = CL_ROOT_CA_FNAME
    if not os.path.exists(CL_ROOT_CA_FNAME):
        rootCa = None
    else:
        with open(CL_ROOT_CA_FNAME, "r") as fp:
            if fp.read().strip() == '':
                rootCa = None
    driver = HalSsdDriver("SSD_Driver", "This is SSD Driver", "0.1.0",
                          (MsgTypeSsd, MsgTypeSsdApi,), None, rootca=rootCa)
    driver.start(simulate_mode=arg.simulator)
