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
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClient
from l2tpv3.src.L2tpv3Hal_pb2 import t_l2tpSessionCircuitStatus
from l2tpv3.src.L2tpv3Hal_pb2 import t_l2tpSessionReq
import l2tpv3.src.L2tpv3Hal_pb2 as L2tpv3Hal_pb2
import rpd.hal.src.HalConfigMsg as HalConfigMsg
import psutil


class VcmsDriverError(Exception):

    def __init__(self, msg, expr=None):
        super(VcmsDriverError, self).__init__(msg)
        self.msg = "VcmsDriverError: " + msg
        self.expr = expr


class L2tpSessData:

    def __init__(self):
        self.local_ipaddr = ""
        self.remote_ipaddr = ""
        self.local_mac = ""
        self.remote_mac = ""
        self.pw_type = 0
        self.sessionid_local = 0
        self.sessionid_remote = 0
        self.direction = 0
        self.mtu = 0
        self.flowid = 0
        self.channel_id = 0
        self.channel_freq = 0
        self.tag = 0

    def __str__(self):
        return "%s/%s/%s/%s, pw:%s, session_local:%s, session_remote:%s, dir:%s, mtu:%s,"\
            "flowid:%s, channel_id:%s, channel_freq:%s" % (self.local_ipaddr,
                                                           self.remote_ipaddr, self.local_mac,
                                                           self.remote_mac, self.pw_type, self.sessionid_local,
                                                           self.sessionid_remote, self.direction, self.mtu,
                                                           self.flowid,
                                                           self.channel_id,
                                                           self.channel_freq)


class testDriver(HalDriverClient):

    def __init__(self, supportedMsgType, supportedNotificationMsgs, logConfigurePath=None):
        super(
            testDriver, self).__init__("testl2tpDriver", "driver for test l2tp", "0.0.1",
                                       supportedMsgType, supportedNotificationMsgs, logConfigurePath)
        self.sess_list = list()

    def notify_vcms_client(self):
        pass

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
        self.logger.debug(
            "Recv a configuration message, send a fake rsp to it")
        print "vcms recvCfgMsgCb"
        print len(cfg.msg.CfgMsgPayload)
        self.sendCfgRspMsg(cfg)

        cfg_payload = t_l2tpSessionReq()
        cfg_payload.ParseFromString(cfg.msg.CfgMsgPayload)

if __name__ == "__main__":

    driver = testDriver((1, 100, 102, 3072, 1025, 2049, 3075, 3076, 3077, 3078, 3079), (
        2, 3, 4), "/home/cmts/ws/hal/conf/DriverLogging.conf")
    driver.start()
