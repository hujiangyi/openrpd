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

import unittest
from rpd.rcp.rcp_shadow_layer import *
from rpd.hal.src.HalConfigMsg import *
from rpd.gpb.rcp_pb2 import t_RpdDataMessage
from rpd.gpb.cfg_pb2 import config
import os
import subprocess
import time
import json

timeStampSock = "/tmp/testHalMgrRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"
json_dic = dict()
json_dic["CFG_DB_NUM"] = 1
json_dic["DB_SOCKET_PATH"] = timeStampSock
json_dic["ShadowLayerEnable"] = True
json_dic["ConfigFilterEnable"] = True
json_dic["InternalPolicyEnable"] = True
json_dic["InternalPolicy"] = dict()
json_dic["ExternalPolicyEnable"] = False
TMP_CFG_PATH = "/tmp/test_shadow_layer.conf"
with open(TMP_CFG_PATH, "w") as f:
    f.write(json.dumps(json_dic, indent=4))


def setupEnv():
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    filename = "/tmp/test_halmgr.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(timeStampSock):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")


def ClearUpEnv():
    subprocess.call(["killall", "redis-server"])
    time.sleep(2)


class ConfigFilterDsRfPort(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupEnv()

    @classmethod
    def tearDownClass(cls):
        ClearUpEnv()

    def setUp(self):
        self.shadow = RcpConfigFilter(TMP_CFG_PATH)
        self.shadow.cfg_db.flushdb()
        self.rspMsg = config()

    def test_save(self):
        cfg_msg = config()
        rf_port = cfg_msg.RfPort.add()
        rf_port.RfPortSelector.RfPortIndex = 0
        rf_port.RfPortSelector.RfPortType = 0
        rf_port.DsRfPort.AdminState = 2
        rf_port.DsRfPort.BasePower = 200
        rf_port.DsRfPort.RfMute = 0
        rf_port.DsRfPort.TiltSlope = 10
        rf_port.DsRfPort.TiltMaximumFrequency = 1
        key = str(MsgTypeDsRfPort) + "-" + \
            str(rf_port.RfPortSelector.RfPortIndex)

        ret = self.shadow.processDsRfPort(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "2")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "BasePower-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "BasePower"), "200")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute"), "0")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltSlope-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltSlope"), "10")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltMaximumFrequency-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltMaximumFrequency"), "1")

    def test_write(self):
        cfg_msg = config()
        rf_port = cfg_msg.RfPort.add()
        rf_port.RfPortSelector.RfPortIndex = 0
        rf_port.RfPortSelector.RfPortType = 0
        rf_port.DsRfPort.AdminState = 2
        rf_port.DsRfPort.BasePower = 200
        rf_port.DsRfPort.RfMute = 0
        rf_port.DsRfPort.TiltSlope = 10
        # rf_port.DsRfPort.TiltMaximumFrequency = 1
        key = str(MsgTypeDsRfPort) + "-" + \
            str(rf_port.RfPortSelector.RfPortIndex)

        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "2")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "BasePower-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "BasePower"), "200")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute"), "0")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltSlope-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltSlope"), "10")
        self.assertTrue(rf_port.DsRfPort.HasField("AdminState"))
        self.assertTrue(rf_port.DsRfPort.HasField("BasePower"))
        self.assertTrue(rf_port.DsRfPort.HasField("RfMute"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltSlope"))

        rf_port.DsRfPort.TiltMaximumFrequency = 1
        ret = self.shadow.processDsRfPort(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        rf_port.DsRfPort.AdminState = 1
        rf_port.DsRfPort.BasePower = 200

        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "1")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "BasePower-flag"), str(BIT_SYNC_CORE | BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "BasePower"), "200")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltMaximumFrequency-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TiltMaximumFrequency"), "1")
        self.assertTrue(rf_port.DsRfPort.HasField("AdminState"))
        self.assertFalse(rf_port.DsRfPort.HasField("BasePower"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltMaximumFrequency"))

        ret = self.shadow.processDsRfPort(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])

    def test_read(self):
        cfg_msg = config()
        rf_port = cfg_msg.RfPort.add()
        rf_port.RfPortSelector.RfPortIndex = 0
        rf_port.RfPortSelector.RfPortType = 0
        rf_port.DsRfPort.AdminState = 2
        rf_port.DsRfPort.BasePower = 200
        rf_port.DsRfPort.RfMute = 0
        rf_port.DsRfPort.TiltSlope = 10
        # rf_port.DsRfPort.TiltMaximumFrequency = 1
        key = str(MsgTypeDsRfPort) + "-" + \
            str(rf_port.RfPortSelector.RfPortIndex)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])
        self.assertTrue(rf_port.DsRfPort.HasField("AdminState"))
        self.assertTrue(rf_port.DsRfPort.HasField("BasePower"))
        self.assertTrue(rf_port.DsRfPort.HasField("RfMute"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltSlope"))

        ret = self.shadow.processDsRfPort(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        rf_port.DsRfPort.TiltMaximumFrequency = 1
        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])
        self.assertTrue(rf_port.DsRfPort.HasField("AdminState"))
        self.assertTrue(rf_port.DsRfPort.HasField("BasePower"))
        self.assertTrue(rf_port.DsRfPort.HasField("RfMute"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltSlope"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltMaximumFrequency"))

        ret = self.shadow.processDsRfPort(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])
        rf_port = self.rspMsg.RfPort[0]
        self.assertTrue(rf_port.DsRfPort.HasField("AdminState"))
        self.assertTrue(rf_port.DsRfPort.HasField("BasePower"))
        self.assertTrue(rf_port.DsRfPort.HasField("RfMute"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltSlope"))
        self.assertTrue(rf_port.DsRfPort.HasField("TiltMaximumFrequency"))


class ConfigFilterDsScQamChannelConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupEnv()

    @classmethod
    def tearDownClass(cls):
        ClearUpEnv()

    def setUp(self):
        self.shadow = RcpConfigFilter(TMP_CFG_PATH)
        self.shadow.cfg_db.flushdb()
        self.rspMsg = config()

    def test_save(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.DsScQamChannelConfig.AdminState = 2
        rf_channel.DsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.DsScQamChannelConfig.RfMute = 0
        rf_channel.DsScQamChannelConfig.TSID = 1
        rf_channel.DsScQamChannelConfig.CenterFrequency = 100000000
        rf_channel.DsScQamChannelConfig.OperationalMode = 2
        rf_channel.DsScQamChannelConfig.Modulation = 4
        rf_channel.DsScQamChannelConfig.InterleaverDepth = 8
        rf_channel.DsScQamChannelConfig.Annex = 4
        rf_channel.DsScQamChannelConfig.SyncInterval = 0
        rf_channel.DsScQamChannelConfig.SyncMacAddress = "\x00\x01\x02\x03\x04\x05"
        rf_channel.DsScQamChannelConfig.SymbolFrequencyDenominator = 0
        rf_channel.DsScQamChannelConfig.SymbolFrequencyNumerator = 0
        rf_channel.DsScQamChannelConfig.SymbolRateOverride = 0
        rf_channel.DsScQamChannelConfig.SpectrumInversionEnabled = 0
        rf_channel.DsScQamChannelConfig.PowerAdjust = 0
        key = str(MsgTypeDsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        ret = self.shadow.processDsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "2")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner"), "\x00\x01\x02\x03\x04\x05")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute"), "0")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TSID-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "TSID"), "1")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CenterFrequency-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CenterFrequency"), "100000000")

    def test_write(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.DsScQamChannelConfig.AdminState = 2
        rf_channel.DsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.DsScQamChannelConfig.RfMute = 0
        key = str(MsgTypeDsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "2")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner"), "\x00\x01\x02\x03\x04\x05")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "RfMute"), "0")
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("RfMute"))

        rf_channel.DsScQamChannelConfig.OperationalMode = 2
        ret = self.shadow.processDsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        rf_channel.DsScQamChannelConfig.AdminState = 1
        rf_channel.DsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"

        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "1")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner-flag"), str(BIT_SYNC_CORE | BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner"), "\x00\x01\x02\x03\x04\x05")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "OperationalMode-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "OperationalMode"), "2")
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("AdminState"))
        self.assertFalse(
            rf_channel.DsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("OperationalMode"))

        ret = self.shadow.processDsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])

    def test_read(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.DsScQamChannelConfig.AdminState = 2
        rf_channel.DsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.DsScQamChannelConfig.RfMute = 0
        key = str(MsgTypeDsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("RfMute"))

        ret = self.shadow.processDsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        rf_channel.DsScQamChannelConfig.OperationalMode = 2
        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("RfMute"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("OperationalMode"))

        ret = self.shadow.processDsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])
        rf_channel = self.rspMsg.RfChannel[0]
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.DsScQamChannelConfig.HasField("RfMute"))
        self.assertTrue(
            rf_channel.DsScQamChannelConfig.HasField("OperationalMode"))


class ConfigFilterMiscUT(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupEnv()

    @classmethod
    def tearDownClass(cls):
        ClearUpEnv()

    def setUp(self):
        self.shadow = RcpConfigFilter(TMP_CFG_PATH)
        self.shadow.cfg_db.flushdb()
        self.rspMsg = config()

    def test_misc(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.UsScQamChannelConfig.AdminState = 2
        iuc = rf_channel.UsScQamChannelConfig.IntervalUsageCode.add()
        iuc.Code = 10
        iuc.GuardTime = 100
        key = str(MsgTypeUsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE))

        ret = self.shadow._unmarkSyncCore(key, "AdminState")
        self.assertTrue(ret)

        ret = self.shadow._unmarkSyncCore(key, "AdminStateUTDUMMY")
        self.assertFalse(ret)

        ret = self.shadow._getSubMsgIndex("UTDUMMY", iuc)
        self.assertEqual(ret, None)


class ConfiFilterInvalidParamUT(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupEnv()

    @classmethod
    def tearDownClass(cls):
        ClearUpEnv()

    def setUp(self):
        self.shadow = RcpConfigFilter(TMP_CFG_PATH)
        self.shadow.cfg_db.flushdb()
        self.rspMsg = config()

    def test_invalid_param_case(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_port = cfg_msg.RfPort.add()
        self.rspMsg.CopyFrom(cfg_msg)

        ret = self.shadow.processUsScQamChannelConfig(
            "wrongop", cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        dumyop = 65535
        ret = self.shadow.processUsScQamChannelConfig(
            dumyop, cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        self.rspMsg.RfChannel.add()
        ret = self.shadow.processDsScQamChannelConfig(
            "wrongop", cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        ret = self.shadow.processDsScQamChannelConfig(
            dumyop, cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        ret = self.shadow.processDsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsRfPort("wrongop", cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        ret = self.shadow.processDsRfPort(dumyop, cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        ret = self.shadow.processDsRfPort(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processDsRfPort(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        self.rspMsg.RfChannel.add()

        ret = self.shadow.processSidQos(dumyop, cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        ret = self.shadow.processSidQos("wrongop", cfg_msg, self.rspMsg)
        self.assertFalse(ret)

        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)


class ConfigFilterUsScQamChannelConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupEnv()

    @classmethod
    def tearDownClass(cls):
        ClearUpEnv()

    def setUp(self):
        self.shadow = RcpConfigFilter(TMP_CFG_PATH)
        self.shadow.cfg_db.flushdb()
        self.rspMsg = config()

    def test_save(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.UsScQamChannelConfig.AdminState = 2
        rf_channel.UsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.UsScQamChannelConfig.Type = 0
        iuc = rf_channel.UsScQamChannelConfig.IntervalUsageCode.add()
        iuc.Code = 10
        iuc.GuardTime = 100
        key = str(MsgTypeUsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "2")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner"), "\x00\x01\x02\x03\x04\x05")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "Type-flag"), str(BIT_SYNC_PHY))
        self.assertEqual(ast.literal_eval(self.shadow.cfg_db.hget(key,
                                                                  "IntervalUsageCode-10")), {'Code': 10, 'GuardTime': 100})
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "IntervalUsageCode-10-flag"), str(BIT_SYNC_PHY))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("Code"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("GuardTime"))

    def test_write(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.UsScQamChannelConfig.AdminState = 2
        rf_channel.UsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.UsScQamChannelConfig.Type = 0
        iuc = rf_channel.UsScQamChannelConfig.IntervalUsageCode.add()
        iuc.Code = 10
        iuc.GuardTime = 100
        key = str(MsgTypeUsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState"), "2")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner"), "\x00\x01\x02\x03\x04\x05")
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "Type-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(ast.literal_eval(self.shadow.cfg_db.hget(key,
                                                                  "IntervalUsageCode-10")), {'Code': 10, 'GuardTime': 100})
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "IntervalUsageCode-10-flag"), str(BIT_SYNC_CORE))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("Code"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("GuardTime"))

        rf_channel.UsScQamChannelConfig.SlotSize = 256
        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        rf_channel.UsScQamChannelConfig.CcapCoreOwner = "\x05\x04\x03\x02\x01\x00"
        iuc.PreambleLen = 1000

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(self.shadow.cfg_db.exists(key))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "AdminState-flag"), str(BIT_SYNC_CORE | BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "CcapCoreOwner-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "Type-flag"), str(BIT_SYNC_CORE | BIT_SYNC_PHY))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "IntervalUsageCode-10-flag"), str(BIT_SYNC_CORE))
        self.assertEqual(self.shadow.cfg_db.hget(key,
                                                 "SlotSize-flag"), str(BIT_SYNC_CORE))
        self.assertFalse(
            rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertFalse(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("SlotSize"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("Code"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("GuardTime"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("PreambleLen"))

        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])

    def test_read(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.UsScQamChannelConfig.AdminState = 2
        rf_channel.UsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.UsScQamChannelConfig.Type = 0
        iuc = rf_channel.UsScQamChannelConfig.IntervalUsageCode.add()
        iuc.Code = 10
        iuc.GuardTime = 100
        key = str(MsgTypeUsScQamChannelConfig) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("Code"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("GuardTime"))

        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        iuc.PreambleLen = 1000
        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("Code"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("GuardTime"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("PreambleLen"))

        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])
        rf_channel = self.rspMsg.RfChannel[0]
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("Code"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("GuardTime"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.IntervalUsageCode[0].HasField("PreambleLen"))

    def test_intpolicy(self):
        self.shadow.config["InternalPolicy"][
            str(MsgTypeUsScQamChannelConfig)] = dict()
        self.shadow.config["InternalPolicy"][str(MsgTypeUsScQamChannelConfig)][
            "AdminState"] = ["CcapCoreOwner", "Type"]
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        rf_channel.UsScQamChannelConfig.AdminState = 2
        rf_channel.UsScQamChannelConfig.CcapCoreOwner = "\x00\x01\x02\x03\x04\x05"
        rf_channel.UsScQamChannelConfig.Type = 0

        ret = self.shadow.processUsScQamChannelConfig(
            RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)

        rf_channel.UsScQamChannelConfig.ClearField("CcapCoreOwner")
        rf_channel.UsScQamChannelConfig.ClearField("Type")

        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertFalse(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertFalse(rf_channel.UsScQamChannelConfig.HasField("Type"))
        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))

        self.shadow.config["InternalPolicy"][str(MsgTypeUsScQamChannelConfig)]["AdminState"] = \
            ["CcapCoreOwner", "Type", "SlotSize", "outDiscards", "UTDUMMY"]
        rf_channel.UsScQamChannelConfig.ClearField("CcapCoreOwner")
        rf_channel.UsScQamChannelConfig.ClearField("Type")

        ret = self.shadow.processUsScQamChannelConfig(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("AdminState"))
        self.assertTrue(
            rf_channel.UsScQamChannelConfig.HasField("CcapCoreOwner"))
        self.assertTrue(rf_channel.UsScQamChannelConfig.HasField("Type"))
        self.assertFalse(rf_channel.UsScQamChannelConfig.HasField("SlotSize"))


class ConfigFilterSidQosTest(unittest.TestCase):
    """flag:

    * blue        --->    sync with phy
    * yellow      --->    sync with core
    * green       --->    sync with core and phy

    """
    @classmethod
    def setUpClass(cls):
        setupEnv()

    @classmethod
    def tearDownClass(cls):
        ClearUpEnv()

    def setUp(self):
        self.shadow = RcpConfigFilter(TMP_CFG_PATH)
        self.shadow.cfg_db.flushdb()
        self.rspMsg = config()

    def test_save(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 1
        sid_qos.NumSids = 20
        sid_qos.SidSfType = 2
        sid_qos.SidUepiFlowId = 10
        # sid_qos.SidFlowTag = 100
        head_str = str(MsgTypeSidQos) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex) + "-"

        # write range [1,20], make it yellow
        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)
        self.assertEqual(len(self.shadow.cfg_db.keys()), 20)

        sid_qos.StartSid = 11
        sid_qos.NumSids = 20

        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)
        self.assertEqual(len(self.shadow.cfg_db.keys()), 30)

        # check range [11,20] green, range [21,30] blue
        for start, num, flag in [(11, 10, BIT_SYNC_PHY | BIT_SYNC_CORE), (21, 10, BIT_SYNC_PHY)]:
            for sid in range(start, start + num):
                self.assertTrue(self.shadow.cfg_db.exists(head_str + str(sid)))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType-flag"), str(flag))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType"), "2")
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidUepiFlowId-flag"), str(flag))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidUepiFlowId"), "10")
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag-flag"), None)
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag"), None)
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(31)))

        # update exists data
        sid_qos.StartSid = 1
        sid_qos.NumSids = 30
        sid_qos.SidSfType = 3
        sid_qos.SidFlowTag = 100

        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        # check range [1,20] yellow, range [21,30] blue
        for start, num, sftype, flag in [(1, 20, 2, BIT_SYNC_CORE), (21, 10, 3, BIT_SYNC_PHY)]:
            for sid in range(start, start + num):
                self.assertTrue(self.shadow.cfg_db.exists(head_str + str(sid)))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType-flag"), str(flag))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType"), str(sftype))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag-flag"), str(BIT_SYNC_PHY))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag"), "100")

    def test_repeated_save(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 1
        rf_channel.RfChannelSelector.RfChannelIndex = 1
        rf_channel.RfChannelSelector.RfChannelType = 0
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 1
        sid_qos.NumSids = 20
        sid_qos.SidSfType = 2
        sid_qos.SidUepiFlowId = 10
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 100
        sid_qos.NumSids = 100
        sid_qos.SidSfType = 1
        sid_qos.SidUepiFlowId = 50
        # sid_qos.SidFlowTag = 100
        head_str = str(MsgTypeSidQos) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex) + "-"

        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)
        self.assertEqual(len(self.shadow.cfg_db.keys()), 120)

        # check range [1,20] and [100,200] blue
        for start, num, sftype, uepifid in [(1, 20, 2, 10), (100, 100, 1, 50)]:
            for sid in range(start, start + num):
                self.assertTrue(self.shadow.cfg_db.exists(head_str + str(sid)))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType-flag"), str(BIT_SYNC_PHY))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType"), str(sftype))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidUepiFlowId-flag"), str(BIT_SYNC_PHY))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidUepiFlowId"), str(uepifid))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag-flag"), None)
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag"), None)
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(21)))
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(99)))
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(201)))

    def test_write(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 1
        sid_qos.NumSids = 3
        sid_qos.SidSfType = 2
        sid_qos.SidUepiFlowId = 10
        # sid_qos.SidFlowTag = 100
        head_str = str(MsgTypeSidQos) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex) + "-"

        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)
        # write filter partial (yellow:redis not sync with phy)
        for start, num in [(1, 5), (4, 7), (1, 20)]:
            sid_qos.StartSid = start
            sid_qos.NumSids = num
            ret = self.shadow.processSidQos(
                t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
            # self.printDBinfo()
            self.assertTrue(ret)
            self.assertTrue(sid_qos.HasField("StartSid"))
            self.assertEqual(sid_qos.StartSid, start)
            self.assertTrue(sid_qos.HasField("NumSids"))
            self.assertEqual(sid_qos.NumSids, num)
            self.assertTrue(sid_qos.HasField("SidSfType"))
            self.assertEqual(sid_qos.SidSfType, 2)
            self.assertTrue(sid_qos.HasField("SidUepiFlowId"))
            self.assertEqual(sid_qos.SidUepiFlowId, 10)
            self.assertFalse(sid_qos.HasField("SidFlowTag"))
            self.assertEqual(self.shadow.cfg_db.hget(head_str + str(start),
                                                     "SidSfType-flag"), str(BIT_SYNC_CORE))

        sid_qos.StartSid = 1
        sid_qos.NumSids = 10

        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        # write filter all(green:all sync)
        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertFalse(ret)

        # write filter with changed value
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 1
        sid_qos.NumSids = 3
        sid_qos.SidSfType = 1

        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        self.assertTrue(sid_qos.HasField("SidSfType"))
        self.assertEqual(sid_qos.SidSfType, 1)
        self.assertEqual(self.shadow.cfg_db.hget(head_str + str(3),
                                                 "SidSfType-flag"), str(BIT_SYNC_CORE))

    def test_repeated_write(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 1
        rf_channel.RfChannelSelector.RfChannelIndex = 1
        rf_channel.RfChannelSelector.RfChannelType = 0
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 1
        sid_qos.NumSids = 20
        sid_qos.SidSfType = 2
        sid_qos.SidUepiFlowId = 10
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 100
        sid_qos.NumSids = 100
        sid_qos.SidSfType = 1
        sid_qos.SidUepiFlowId = 50
        # sid_qos.SidFlowTag = 100
        head_str = str(MsgTypeSidQos) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex) + "-"

        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)
        self.assertEqual(len(self.shadow.cfg_db.keys()), 120)

        # check range [1,20] and [100,200] blue
        for start, num, sftype, uepifid in [(1, 20, 2, 10), (100, 100, 1, 50)]:
            for sid in range(start, start + num):
                self.assertTrue(self.shadow.cfg_db.exists(head_str + str(sid)))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType-flag"), str(BIT_SYNC_CORE))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidSfType"), str(sftype))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidUepiFlowId-flag"), str(BIT_SYNC_CORE))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidUepiFlowId"), str(uepifid))
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag-flag"), None)
                self.assertEqual(self.shadow.cfg_db.hget(head_str + str(sid),
                                                         "SidFlowTag"), None)
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(21)))
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(99)))
        self.assertFalse(self.shadow.cfg_db.exists(head_str + str(201)))

    def test_read(self):
        cfg_msg = config()
        rf_channel = cfg_msg.RfChannel.add()
        rf_channel.RfChannelSelector.RfPortIndex = 0
        rf_channel.RfChannelSelector.RfChannelIndex = 0
        rf_channel.RfChannelSelector.RfChannelType = 0
        sid_qos = rf_channel.SidQos.add()
        sid_qos.StartSid = 11
        sid_qos.NumSids = 10
        sid_qos.SidSfType = 2
        sid_qos.SidUepiFlowId = 10
        # sid_qos.SidFlowTag = 100
        head_str = str(MsgTypeSidQos) + "-" + \
            str(rf_channel.RfChannelSelector.RfPortIndex) + "-" + \
            str(rf_channel.RfChannelSelector.RfChannelIndex) + "-"

        # range [11,20] yellow
        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_WRITE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        self.assertTrue(ret)
        self.assertEqual(self.rspMsg.ListFields(), [])

        # range [11,20] green
        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        # range [21.30] blue
        sid_qos.StartSid = 21
        sid_qos.NumSids = 10
        sid_qos.SidSfType = 1
        sid_qos.SidUepiFlowId = 5
        # sid_qos.SidFlowTag = 100
        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        # range [31.40] blue
        sid_qos.StartSid = 31
        sid_qos.NumSids = 10
        sid_qos.SidSfType = 1
        sid_qos.SidUepiFlowId = 5
        sid_qos.SidFlowTag = 100
        ret = self.shadow.processSidQos(RPD_CFG_SAVE, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        self.assertTrue(ret)

        sid_qos.StartSid = 11
        sid_qos.NumSids = 30
        sid_qos.SidSfType = 0
        sid_qos.SidUepiFlowId = 0
        sid_qos.ClearField("SidFlowTag")
        self.rspMsg.CopyFrom(cfg_msg)
        ret = self.shadow.processSidQos(
            t_RpdDataMessage.RPD_CFG_READ, cfg_msg, self.rspMsg)
        # self.printDBinfo()
        # self.printMsginfo(cfg_msg,self.rspMsg)
        self.assertFalse(ret)
        self.assertEqual(cfg_msg.ListFields(), [])
        self.assertEqual(len(self.rspMsg.RfChannel), 1)
        self.assertEqual(len(self.rspMsg.RfChannel[0].SidQos), 2)

    def printDBinfo(self):
        print '*' * 40 + 'DBinfo Start' + '*' * 40
        print "key numbers:%d" % len(self.shadow.cfg_db.keys())
        # print sorted(self.shadow.cfg_db.keys())
        for key in sorted(self.shadow.cfg_db.keys()):
            print "%s %s" % (key, self.shadow.cfg_db.hgetall(key))
        print '*' * 40 + 'DBinfo End' + '*' * 40

    def printMsginfo(self, msg1, msg2):
        print '*' * 40 + 'msg 1' + '*' * 40
        print msg1
        print '*' * 40 + 'msg 2' + '*' * 40
        print msg2
        print '*' * 40 + 'msg end' + '*' * 40

if __name__ == '__main__':
    unittest.main()
