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

from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient
from rpd.hal.src.HalConfigMsg import MsgTypeIpv4Interface, MsgTypeRpdSysUpTime
from rpd.hal.src.HalConfigMsg import RCP_TO_HAL_MSG_TYPE
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.msg.HalMessage import HalMessage



class RpdInfoHalClient(HalDriverClient):
    __metaclass__ = AddLoggerToClass

    def __init__(self, appName, appDesc, appVer, supportedMsgType, supportedNotificationMsgs, logConfigurePath=None):
        super(RpdInfoHalClient, self).__init__(appName, appDesc, appVer, supportedMsgType, supportedNotificationMsgs)

        # update the supported messages
        self.HalMsgsHandler = {
            "HalClientRegisterRsp": self.recvRegisterMsgCb,
            "HalClientHelloRsp": self.recvHelloRspMsgCb,
            "HalConfig": self.recvCfgMsgCb,
        }

    def recvCfgMsgCb(self, cfg):
        """Receive a configuration message from the Hal, processing it.

        :param cfg:
        :return:

        """
        self.logger.debug(
            "Recv a RPDInfo configuration message, prepare to send a rsp to it")
        # cfg.msg.RpdSysUpTime
        self.sendCfgRspMsg(cfg)

    def getL2tpSessionInfo(self, info):
        info.RemoteLcceIpAddr = "8888.8888.8888"
        info.RemoteL2tpSessionId = 8
        info.CoreId = "888"
        info.ConnCtrlId = 8
        info.UdpPort = 8
        info.Description = "888"
        info.SessionType = 1
        info.SessionSubType = 8
        info.MaxPayload = 8
        info.PathPayload = 8
        info.RpdIfMtu = 8
        info.CoreIfMtu = 8
        info.ErrorCode = 1
        info.CreationTime = self.getSysUpTime()
        info.OperStatus = 1
        info.LocalStatus = 1
        info.LastChange = self.getSysUpTime()


    def sendCfgRspMsg(self, cfg):
        cfgMsg = cfg.msg
        self.logger.debug("RPDInfo configuration message:" + str(cfg.msg))
        if cfgMsg.CfgMsgType == MsgTypeRpdSysUpTime:
            rsp = t_RcpMessage()
            req = t_RcpMessage()
            req.ParseFromString(cfgMsg.CfgMsgPayload)
            rsp.RpdDataMessage.RpdDataOperation = req.RpdDataMessage.RpdDataOperation
            rsp.RcpMessageType = req.RcpMessageType

            self.logger.debug("%s" % str(req))

            req.RpdDataMessage.RpdData.RpdSysUptime = self.getSysUpTime()
            rsp = req
            rsp.RcpDataResult = t_RcpMessage.RCP_RESULT_OK

            self.logger.debug("%s"%str(rsp))
            payload = rsp.SerializeToString()

            msg = HalMessage(
                "HalConfigRsp", SrcClientID=cfgMsg.SrcClientID,
                SeqNum=cfgMsg.SeqNum,
                Rsp={
                    "Status": HalCommon_pb2.SUCCESS,
                    "ErrorDescription": ""
                },
                CfgMsgType=cfgMsg.CfgMsgType,
                CfgMsgPayload=payload)
            if self.pushSock:
                self.pushSock.send(msg.Serialize())

    def getSysUpTime(self):
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        self.logger.debug("Get sysuptime %f" % uptime_seconds)
        uptime_seconds = int(uptime_seconds*100)
        return uptime_seconds

if __name__ == "__main__":
    setup_logging("HAL", filename="RpdInfo_hal_client.log")
    driver = RpdInfoHalClient(
        "RpdInfo_hal",
        "This is RPDInfo hal client",
        "1.0.0", (), ())
    driver.start()
