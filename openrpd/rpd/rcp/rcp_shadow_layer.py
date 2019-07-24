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

import redis
import json
import ast

from rpd.hal.src.HalConfigMsg import *
from rpd.gpb.rcp_pb2 import t_RpdDataMessage
from rpd.gpb.cfg_pb2 import config
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from rpd.common.rpd_logging import AddLoggerToClass

RPD_CFG_SAVE = 4
CONF_PATH = "/etc/config/rcp_shadow_layer.conf"

BIT_SYNC_PHY = 1 << 0
BIT_SYNC_CORE = 1 << 1


class RcpConfigFilter(object):
    """Filter rcp cfg before we send it to hal.

    Update rcp cfg to db when it changed.

    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, config_path=None):
        """Initializes an configuration filter."""
        self.ConfigFilterHandler = {
            MsgTypeRpdCapabilities: None,
            MsgTypeCcapCoreIdentification: None,
            MsgTypeSsd: None,
            MsgTypeDsRfPort: self.processDsRfPort,
            MsgTypeDsScQamChannelConfig: self.processDsScQamChannelConfig,
            MsgTypeDsOfdmChannelConfig: None,
            MsgTypeDsOfdmProfile: None,
            MsgTypeDsRfPortPerf: None,
            MsgTypeDsScQamChannelPerf: None,
            MsgTypeDsOfdmChannelPerf: None,
            MsgTypeDsOob551IPerf: None,
            MsgTypeDsOob552Perf: None,
            MsgTypeNdfPerf: None,
            MsgTypeUsRfPortPerf: None,
            MsgTypeUsScQamChannelConfig: self.processUsScQamChannelConfig,
            MsgTypeUsOfdmaChannelConfig: None,
            MsgTypeUsOfdmaInitialRangingIuc: None,
            MsgTypeUsOfdmaFineRangingIuc: None,
            MsgTypeUsOfdmaDataRangingIuc: None,
            MsgTypeUsOfdmaSubcarrierCfgState: None,
            MsgTypeUsScQamChannelPerf: None,
            MsgTypeUsOfdmaChannelPerf: None,
            MsgTypeUsOob551IPerf: None,
            MsgTypeUsOob552Perf: None,
            MsgTypeNdrPerf: None,
            MsgTypeSidQos: self.processSidQos,
        }
        if config_path is None:
            config_path = CONF_PATH
        with open(config_path, 'rt') as fp:
            self.config = json.load(fp)
        self.cfg_db = redis.StrictRedis(db=self.config["CFG_DB_NUM"],
                                        unix_socket_path=self.config["DB_SOCKET_PATH"])
        self.shadowLayerEnable = self.config["ShadowLayerEnable"]
        self.internalPolicyEnable = self.config["InternalPolicyEnable"]
        self.ConfigFilterEnable = self.config["ConfigFilterEnable"]

    def processFieldDepend(self, key, depend_list, msg):
        """Process field dependent."""
        for dependField in depend_list:
            try:
                desc = msg.DESCRIPTOR.fields_by_name[dependField]
            except KeyError:
                self.logger.warn("Message %s has no field %s"
                                 % (msg.DESCRIPTOR.name, dependField))
                continue
            if not msg.HasField(dependField):
                if desc.label != desc.LABEL_REPEATED and \
                   desc.type != desc.TYPE_MESSAGE:
                    if self.cfg_db.hexists(key, dependField):
                        value = self.cfg_db.hget(key, dependField)
                        if (desc.type != desc.TYPE_STRING and
                                desc.type != desc.TYPE_BYTES):
                            value = int(value)
                        setattr(msg, dependField, value)
                    else:
                        self.logger.warn(
                            "Can not get %s from db" % dependField)
                        continue
                else:
                    self.logger.warn("Do not support field %s" % dependField)
                    continue

    def processInternalPolicy(self, key, msgType, msg):
        """Process config msg internal policy."""
        msgType = str(msgType)
        policy = self.config["InternalPolicy"]
        if msgType in policy and policy[msgType]:
            for desc, value in msg.ListFields():
                if desc.name in policy[msgType]:
                    self.processFieldDepend(
                        key, policy[msgType][desc.name], msg)
        return True

    def filterOptionalField(self, key, cfgMsg, desc, value):
        """Filter protocbuf filed which type != TYPE_MESSAGE and label !=
        LABEL_REPEATED."""
        if self.cfg_db.hexists(key, desc.name) and \
           self._checkSyncCorePhy(key, desc.name):
            field = self.cfg_db.hget(key, desc.name)
            if (desc.type != desc.TYPE_STRING and
                    desc.type != desc.TYPE_BYTES):
                field = int(field)
            if value == field:
                cfgMsg.ClearField(desc.name)
                return
        self.cfg_db.hset(key, desc.name, value)
        self._unmarkSyncPhy(key, desc.name)
        self._markSyncCore(key, desc.name)

    def filterOptionalMessage(self, key, cfgMsg, name, value):
        """Filter protocbuf filed which type == TYPE_MESSAGE and label !=
        LABEL_REPEATED."""
        if self.cfg_db.hexists(key, name) and \
           self._checkSyncCorePhy(key, name):
            changed = False
            value_dict = ast.literal_eval(self.cfg_db.hget(key,
                                                           name))
            for des, val in value.ListFields():
                if des.name not in value_dict or \
                   val != value_dict[des.name]:
                    changed = True
                    break
            if not changed:
                if isinstance(cfgMsg, RepeatedCompositeFieldContainer):
                    cfgMsg.remove(value)
                else:
                    cfgMsg.ClearField(name)
                return
        value_dict = {}
        for des, val in value.ListFields():
            value_dict[des.name] = val
        self.cfg_db.hset(key, name, value_dict)
        self._unmarkSyncPhy(key, name)
        self._markSyncCore(key, name)

    def filterRepeatMessage(self, key, desc, value):
        """Filter protocbuf filed which type == TYPE_MESSAGE and label ==
        LABEL_REPEATED."""
        for field in value:
            identifier = self._getSubMsgIndex(desc.name, field)
            if identifier is None:
                self.logger.error(
                    "Do not support repeated message %s" % desc.name)
                continue
            field_name = desc.name + "-" + str(identifier)
            self.filterOptionalMessage(key, value, field_name, field)

    def filterCfgMsg(self, key, cfgMsg):
        """Filter config msg."""
        for desc, value in cfgMsg.ListFields():
            if desc.type != desc.TYPE_MESSAGE:
                if desc.label != desc.LABEL_REPEATED:
                    self.filterOptionalField(key, cfgMsg, desc, value)
                else:
                    self.logger.warn(
                        "Do not support repeated field %s" % desc.name)
                    continue
            else:
                if desc.label != desc.LABEL_REPEATED:
                    self.filterOptionalMessage(key, cfgMsg, desc.name, value)
                else:
                    self.filterRepeatMessage(key, desc, value)
        if cfgMsg.ListFields():
            return True
        else:
            return False

    def getOptionalField(self, key, desc, cfgRsp):
        """Get protocbuf filed which type != TYPE_MESSAGE and label !=
        LABEL_REPEATED."""
        if self.cfg_db.hexists(key, desc.name) and \
           self._checkSyncPhy(key, desc.name):
            value = self.cfg_db.hget(key, desc.name)
            if (desc.type != desc.TYPE_STRING and
                    desc.type != desc.TYPE_BYTES):
                value = int(value)
            setattr(cfgRsp, desc.name, value)
            return False
        return True

    def getOptionalMessage(self, key, name, value):
        """Get protocbuf filed which type == TYPE_MESSAGE and label !=
        LABEL_REPEATED."""
        if self.cfg_db.hexists(key, name) and \
           self._checkSyncPhy(key, name):
            field_dict = ast.literal_eval(self.cfg_db.hget(key,
                                                           name))
            for des, val in value.ListFields():
                if des.name not in field_dict:
                    return True
                setattr(value, des.name, field_dict[des.name])
            return False
        return True

    def getRepeatMessage(self, key, desc, value):
        """Get protocbuf filed which type == TYPE_MESSAGE and label ==
        LABEL_REPEATED."""
        for field in value:
            identifier = self._getSubMsgIndex(desc.name, field)
            if identifier is None:
                self.logger.error(
                    "Do not support repeated message %s" % desc.name)
                return True
            field_name = desc.name + "-" + str(identifier)
            ret = self.getOptionalMessage(key, field_name, field)
            if ret:
                return True
            else:
                continue
        return False

    def getCfgMsg(self, key, cfgRsp):
        """get config msg."""
        if self.cfg_db.exists(key):
            for desc, value in cfgRsp.ListFields():
                if desc.type != desc.TYPE_MESSAGE:
                    if desc.label != desc.LABEL_REPEATED:
                        ret = self.getOptionalField(key, desc, cfgRsp)
                    else:
                        self.logger.warn(
                            "Do not support repeated field %s" % desc.name)
                        continue
                else:
                    if desc.label != desc.LABEL_REPEATED:
                        ret = self.getOptionalMessage(key, desc.name, value)
                    else:
                        ret = self.getRepeatMessage(key, desc, value)
                if ret:
                    return True
            return False
        return True

    def saveOptionalField(self, key, desc, value):
        """Save protocbuf filed which type != TYPE_MESSAGE and label !=
        LABEL_REPEATED."""
        if self.cfg_db.hexists(key, desc.name):
            filed = self.cfg_db.hget(key, desc.name)
            if (desc.type != desc.TYPE_STRING and
                    desc.type != desc.TYPE_BYTES):
                filed = int(filed)
            if filed == value:
                self._markSyncPhy(key, desc.name)
                return
            else:
                if self._checkSyncCore(key, desc.name):
                    self._unmarkSyncPhy(key, desc.name)
                    return
        self.cfg_db.hset(key, desc.name, value)
        self._markSyncPhy(key, desc.name)

    def saveOptionalMessage(self, key, name, value):
        """Save protocbuf filed which type == TYPE_MESSAGE and label !=
        LABEL_REPEATED."""
        value_dict = {}
        for des, val in value.ListFields():
            value_dict[des.name] = val
        if self.cfg_db.hexists(key, name):
            field_dict = ast.literal_eval(self.cfg_db.hget(key,
                                                           name))
            if cmp(value_dict, field_dict) == 0:
                self._markSyncPhy(key, name)
                return
            else:
                if self._checkSyncCore(key, name):
                    self._unmarkSyncPhy(key, name)
                    return
        self.cfg_db.hset(key, name, value_dict)
        self._markSyncPhy(key, name)

    def saveRepeatMessage(self, key, desc, value):
        """Save protocbuf filed which type == TYPE_MESSAGE and label ==
        LABEL_REPEATED."""
        for field in value:
            identifier = self._getSubMsgIndex(desc.name, field)
            if identifier is None:
                self.logger.error(
                    "Do not support repeated message %s" % desc.name)
                continue
            field_name = desc.name + "-" + str(identifier)
            self.saveOptionalMessage(key, field_name, field)

    def saveCfgMsg(self, key, cfgRsp):
        """Save config rsp."""
        for desc, value in cfgRsp.ListFields():
            if desc.type != desc.TYPE_MESSAGE:
                if desc.label != desc.LABEL_REPEATED:
                    self.saveOptionalField(key, desc, value)
                else:
                    self.logger.warn(
                        "Do not support repeated field %s" % desc.name)
                    continue
            else:
                if desc.label != desc.LABEL_REPEATED:
                    self.saveOptionalMessage(key, desc.name, value)
                else:
                    self.saveRepeatMessage(key, desc, value)
        return True

    def writeDsRfPort(self, cfgMsg):
        """Filter DsRfPort config."""
        for RfPort in cfgMsg.RfPort:
            if (RfPort.HasField("DsRfPort") and
                    RfPort.HasField("RfPortSelector")):
                rfPort = RfPort.RfPortSelector.RfPortIndex
                key = str(MsgTypeDsRfPort) + "-" + str(rfPort)

                # filter DsRfPort
                if self.ConfigFilterEnable:
                    ret = self.filterCfgMsg(key, RfPort.DsRfPort)
                    if not ret:
                        cfgMsg.RfPort.remove(RfPort)
                        continue

                # process DsRfPort internal policy
                if self.internalPolicyEnable:
                    self.processInternalPolicy(key, MsgTypeDsRfPort,
                                               RfPort.DsRfPort)
            else:
                self.logger.warn("Msg type %d has no RfPortSelector "
                                 "or DsRfPort" % MsgTypeDsRfPort)
                continue
        if cfgMsg.RfPort:
            return True
        else:
            return False

    def readDsRfPort(self, cfgMsg, cfgRsp):
        """If all request fields can get valid value, For read operation will
        get the values from db directly."""
        for RfPort, RfPort_Rsp in zip(cfgMsg.RfPort, cfgRsp.RfPort):
            if (RfPort.HasField("DsRfPort") and
                    RfPort.HasField("RfPortSelector")):
                rfPort = RfPort.RfPortSelector.RfPortIndex
                key = str(MsgTypeDsRfPort) + "-" + str(rfPort)

                ret = self.getCfgMsg(key, RfPort_Rsp.DsRfPort)
                if ret:
                    cfgRsp.RfPort.remove(RfPort_Rsp)
                else:
                    cfgMsg.RfPort.remove(RfPort)
            else:
                self.logger.warn("Msg type %d has no RfPortSelector "
                                 "or DsRfPort" % MsgTypeDsRfPort)
                cfgRsp.RfPort.remove(RfPort_Rsp)
                continue
        if cfgMsg.RfPort:
            return True
        else:
            return False

    def saveDsRfPort(self, cfgRsp):
        """Save DsRfPort config to db when rcp hal receive success rsp."""
        for RfPort in cfgRsp.RfPort:
            if (RfPort.HasField("DsRfPort") and
                    RfPort.HasField("RfPortSelector")):
                rfPort = RfPort.RfPortSelector.RfPortIndex
                key = str(MsgTypeDsRfPort) + "-" + str(rfPort)

                self.saveCfgMsg(key, RfPort.DsRfPort)
            else:
                self.logger.warn("Msg type %d has no RfPortSelector or DsRfPort"
                                 % MsgTypeDsRfPort)
                continue
        return True

    def processDsRfPort(self, op, reqMsg, rspMsg):
        """Starts processing of all operations requested.

        First IPC message

        """
        if not isinstance(op, int) or not isinstance(reqMsg, config):
            self.logger.warn("processDsRfPort receive invalid parameter")
            return False

        self.logger.debug("Start processing DsRfPort op: %d, reqMsg: %s"
                          % (op, str(reqMsg)))
        if op == t_RpdDataMessage.RPD_CFG_WRITE:
            ret = self.writeDsRfPort(reqMsg)
        elif op == t_RpdDataMessage.RPD_CFG_READ:
            ret = self.readDsRfPort(reqMsg, rspMsg)
        elif op == RPD_CFG_SAVE:
            ret = self.saveDsRfPort(reqMsg)
        else:
            self.logger.warn("Invalid operation %d for DsRfPort" % op)
            return False
        return ret

    def writeDsScQamChannelConfig(self, cfgMsg):
        """Filter DsScQamChannelConfig config."""
        for RfChannel in cfgMsg.RfChannel:
            if (RfChannel.HasField("DsScQamChannelConfig") and
                    RfChannel.HasField("RfChannelSelector")):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                key = str(MsgTypeDsScQamChannelConfig) + "-" + str(rfPort) + \
                                                         "-" + str(rfChannel)
                # filter DsScQamChannelConfig
                if self.ConfigFilterEnable:
                    ret = self.filterCfgMsg(
                        key, RfChannel.DsScQamChannelConfig)
                    if not ret:
                        cfgMsg.RfChannel.remove(RfChannel)
                        continue

                # process DsScQamChannelConfig internal policy
                if self.internalPolicyEnable:
                    self.processInternalPolicy(
                        key, MsgTypeDsScQamChannelConfig,
                        RfChannel.DsScQamChannelConfig)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 " DsScQamChannelConfig" % MsgTypeDsScQamChannelConfig)
                continue
        if cfgMsg.RfChannel:
            return True
        else:
            return False

    def readDsScQamChannelConfig(self, cfgMsg, cfgRsp):
        """If all request fields can get valid value, For read operation will
        get the values from db directly."""
        for RfChannel, RfChannel_Rsp in zip(cfgMsg.RfChannel, cfgRsp.RfChannel):
            if RfChannel.HasField("RfChannelSelector"):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                key = str(MsgTypeDsScQamChannelConfig) + "-" + str(rfPort) + \
                                                         "-" + str(rfChannel)
                ret = self.getCfgMsg(key, RfChannel_Rsp.DsScQamChannelConfig)
                if ret:
                    cfgRsp.RfChannel.remove(RfChannel_Rsp)
                else:
                    cfgMsg.RfChannel.remove(RfChannel)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector"
                                 % MsgTypeDsScQamChannelConfig)
                cfgRsp.RfChannel.remove(RfChannel_Rsp)
                continue
        if cfgMsg.RfChannel:
            return True
        else:
            return False

    def saveDsScQamChannelConfig(self, cfgMsg):
        """Save DsScQamChannelConfig config to db when rcp hal receive success
        rsp."""
        for RfChannel in cfgMsg.RfChannel:
            if (RfChannel.HasField("DsScQamChannelConfig") and
                    RfChannel.HasField("RfChannelSelector")):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                key = str(MsgTypeDsScQamChannelConfig) + "-" + str(rfPort) + \
                                                         "-" + str(rfChannel)
                self.saveCfgMsg(key, RfChannel.DsScQamChannelConfig)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 " DsScQamChannelConfig" % MsgTypeDsScQamChannelConfig)
                continue
        return True

    def processDsScQamChannelConfig(self, op, reqMsg, rspMsg):
        """Start processing DsScQamChannelConfig."""
        if not isinstance(op, int) or not isinstance(reqMsg, config):
            self.logger.warn("processDsScQamChannelConfig receive invalid"
                             " parameter")
            return False

        self.logger.debug("Start processing DsScQamChannelConfig op: %d,"
                          " reqMsg: %s" % (op, str(reqMsg)))
        if op == t_RpdDataMessage.RPD_CFG_WRITE:
            ret = self.writeDsScQamChannelConfig(reqMsg)
        elif op == t_RpdDataMessage.RPD_CFG_READ:
            ret = self.readDsScQamChannelConfig(reqMsg, rspMsg)
        elif op == RPD_CFG_SAVE:
            ret = self.saveDsScQamChannelConfig(reqMsg)
        else:
            self.logger.warn("Invalid operation %d for DsScQamChannelConfig"
                             % op)
            return False
        return ret

    def writeUsScQamChannelConfig(self, cfgMsg):
        """Filter UsScQamChannelConfig config."""
        for RfChannel in cfgMsg.RfChannel:
            if (RfChannel.HasField("UsScQamChannelConfig") and
                    RfChannel.HasField("RfChannelSelector")):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                key = str(MsgTypeUsScQamChannelConfig) + "-" + str(rfPort) + \
                                                         "-" + str(rfChannel)
                # filter UsScQamChannelConfig
                if self.ConfigFilterEnable:
                    ret = self.filterCfgMsg(
                        key, RfChannel.UsScQamChannelConfig)
                    if not ret:
                        cfgMsg.RfChannel.remove(RfChannel)
                        continue

                # process UsScQamChannelConfig internal policy
                if self.internalPolicyEnable:
                    self.processInternalPolicy(
                        key, MsgTypeUsScQamChannelConfig,
                        RfChannel.UsScQamChannelConfig)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 " UsScQamChannelConfig" % MsgTypeUsScQamChannelConfig)
                continue
        if cfgMsg.RfChannel:
            return True
        else:
            return False

    def readUsScQamChannelConfig(self, cfgMsg, cfgRsp):
        """If all request fields can get valid value, For read operation will
        get the values from db directly."""
        for RfChannel, RfChannel_Rsp in zip(cfgMsg.RfChannel, cfgRsp.RfChannel):
            if RfChannel.HasField("RfChannelSelector"):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                key = str(MsgTypeUsScQamChannelConfig) + "-" + str(rfPort) + \
                                                         "-" + str(rfChannel)
                ret = self.getCfgMsg(key, RfChannel_Rsp.UsScQamChannelConfig)
                if ret:
                    cfgRsp.RfChannel.remove(RfChannel_Rsp)
                else:
                    cfgMsg.RfChannel.remove(RfChannel)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 " UsScQamChannelConfig" % MsgTypeUsScQamChannelConfig)
                cfgRsp.RfChannel.remove(RfChannel_Rsp)
                continue
        if cfgMsg.RfChannel:
            return True
        else:
            return False

    def saveUsScQamChannelConfig(self, cfgMsg):
        """Save UsScQamChannelConfig config to db when rcp hal receive success
        rsp."""
        for RfChannel in cfgMsg.RfChannel:
            if (RfChannel.HasField("UsScQamChannelConfig") and
                    RfChannel.HasField("RfChannelSelector")):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                key = str(MsgTypeUsScQamChannelConfig) + "-" + str(rfPort) + \
                                                         "-" + str(rfChannel)
                self.saveCfgMsg(key, RfChannel.UsScQamChannelConfig)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 " UsScQamChannelConfig" % MsgTypeUsScQamChannelConfig)
                continue
        return True

    def processUsScQamChannelConfig(self, op, reqMsg, rspMsg):
        """Start processing UsScQamChannelConfig."""
        if not isinstance(op, int) or not isinstance(reqMsg, config):
            self.logger.warn("processUsScQamChannelConfig receive invalid"
                             " parameter")
            return False

        self.logger.debug("Start processing UsScQamChannelConfig op: %d,"
                          " reqmsg: %s" % (op, str(reqMsg)))
        if op == t_RpdDataMessage.RPD_CFG_WRITE:
            ret = self.writeUsScQamChannelConfig(reqMsg)
        elif op == t_RpdDataMessage.RPD_CFG_READ:
            ret = self.readUsScQamChannelConfig(reqMsg, rspMsg)
        elif op == RPD_CFG_SAVE:
            ret = self.saveUsScQamChannelConfig(reqMsg)
        else:
            self.logger.warn("Invalid operation %d for UsScQamChannelConfig"
                             % op)
            return False
        return ret

    def _validSidQosField(self, name):
        if name in ["StartSid", "NumSids"]:
            return False
        return True

    def writeSidQos(self, cfgMsg):
        """Filter SidQos config."""
        for RfChannel in cfgMsg.RfChannel:
            if RfChannel.HasField("RfChannelSelector"):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                if self.ConfigFilterEnable:
                    for SidQos in RfChannel.SidQos:
                        beg = SidQos.StartSid
                        end = beg + SidQos.NumSids
                        changed = False
                        for SidId in range(beg, end):
                            key = str(MsgTypeSidQos) + "-" + str(rfPort) + \
                                "-" + str(rfChannel) + "-" + str(SidId)
                            for desc, value in SidQos.ListFields():
                                if self._validSidQosField(desc.name):
                                    if not (self.cfg_db.hexists(key, desc.name) and
                                            self._checkSyncCorePhy(key, desc.name) and
                                            value == int(self.cfg_db.hget(key, desc.name))):
                                        changed = True
                                        self.cfg_db.hset(key, desc.name, value)
                                        self._unmarkSyncPhy(key, desc.name)
                                        self._markSyncCore(key, desc.name)
                        if not changed:
                            RfChannel.SidQos.remove(SidQos)
                if not RfChannel.SidQos:
                    cfgMsg.RfChannel.remove(RfChannel)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 % MsgTypeSidQos)
        if not cfgMsg.RfChannel:
            return False
        else:
            return True

    def _checkSidQos(self, channelMsg):
        """check whether all request fields can get valid value from db."""
        rfPort = channelMsg.RfChannelSelector.RfPortIndex
        rfChannel = channelMsg.RfChannelSelector.RfChannelIndex
        for SidQos in channelMsg.SidQos:
            beg = SidQos.StartSid
            end = beg + SidQos.NumSids
            for SidId in range(beg, end):
                key = str(MsgTypeSidQos) + "-" + str(rfPort) + \
                    "-" + str(rfChannel) + "-" + str(SidId)
                for desc, value in SidQos.ListFields():
                    if self._validSidQosField(desc.name):
                        if not self.cfg_db.hexists(key, desc.name) \
                                or not self._checkSyncPhy(key, desc.name):
                            return False
        return True

    def _getSidQos(self, channelMsg):
        """generate the respond message with all request fields."""
        rfPort = channelMsg.RfChannelSelector.RfPortIndex
        rfChannel = channelMsg.RfChannelSelector.RfChannelIndex
        for SidQos in channelMsg.SidQos:
            beg = SidQos.StartSid
            end = beg + SidQos.NumSids
            last = beg
            lastDict = dict()
            for SidId in range(beg, end):
                key = str(MsgTypeSidQos) + "-" + str(rfPort) + \
                    "-" + str(rfChannel) + "-" + str(SidId)
                curDict = dict()
                for desc, value in SidQos.ListFields():
                    if self._validSidQosField(desc.name):
                        curDict[desc.name] = self.cfg_db.hget(key, desc.name)
                if lastDict == {}:
                    lastDict = curDict
                elif cmp(lastDict, curDict) != 0:
                    newSidQos = channelMsg.SidQos.add()
                    newSidQos.StartSid = last
                    newSidQos.NumSids = SidId - last
                    for desc, value in SidQos.ListFields():
                        if self._validSidQosField(desc.name):
                            setattr(
                                newSidQos, desc.name, int(lastDict[desc.name]))
                    last = SidId
                    lastDict = curDict
            if last == beg:
                for desc, value in SidQos.ListFields():
                    if self._validSidQosField(desc.name):
                        setattr(SidQos, desc.name, int(lastDict[desc.name]))
            else:
                newSidQos = channelMsg.SidQos.add()
                newSidQos.StartSid = last
                newSidQos.NumSids = end - last
                for desc, value in SidQos.ListFields():
                    if self._validSidQosField(desc.name):
                        setattr(newSidQos, desc.name, int(lastDict[desc.name]))
                channelMsg.SidQos.remove(SidQos)

    def readSidQos(self, cfgMsg, rspMsg):
        """If all request fields can get valid value, For read operation will
        get the values from db directly."""
        for RfChannel, RfChannel_Rsp in zip(cfgMsg.RfChannel, rspMsg.RfChannel):
            if RfChannel.HasField("RfChannelSelector"):
                ret = self._checkSidQos(RfChannel)
                if ret:
                    # add rspMsg here
                    self._getSidQos(RfChannel_Rsp)
                    cfgMsg.RfChannel.remove(RfChannel)
                else:
                    rspMsg.RfChannel.remove(RfChannel_Rsp)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 % MsgTypeSidQos)
                rspMsg.RfChannel.remove(RfChannel_Rsp)
        if not cfgMsg.RfChannel:
            return False
        else:
            return True

    def saveSidQos(self, cfgMsg):
        """Save SidQos config to db when rcp hal receive success rsp."""
        for RfChannel in cfgMsg.RfChannel:
            if RfChannel.HasField("RfChannelSelector"):
                rfPort = RfChannel.RfChannelSelector.RfPortIndex
                rfChannel = RfChannel.RfChannelSelector.RfChannelIndex
                for SidQos in RfChannel.SidQos:
                    beg = SidQos.StartSid
                    end = beg + SidQos.NumSids
                    for SidId in range(beg, end):
                        key = str(MsgTypeSidQos) + "-" + str(rfPort) + \
                            "-" + str(rfChannel) + "-" + str(SidId)
                        for desc, value in SidQos.ListFields():
                            if self._validSidQosField(desc.name):
                                if not self.cfg_db.hexists(key, desc.name):
                                    self.cfg_db.hset(key, desc.name, value)
                                    self._markSyncPhy(key, desc.name)
                                elif value == int(self.cfg_db.hget(key, desc.name)):
                                    self._markSyncPhy(key, desc.name)
                                else:
                                    if self._checkSyncCore(key, desc.name):
                                        self._unmarkSyncPhy(key, desc.name)
                                    else:
                                        self.cfg_db.hset(key, desc.name, value)
                                        self._markSyncPhy(key, desc.name)
            else:
                self.logger.warn("Msg type %d has no RfChannelSelector or"
                                 % MsgTypeSidQos)
        return True

    def processSidQos(self, op, reqMsg, rspMsg):
        """Start processing SidQos."""
        if not isinstance(op, int) or not isinstance(reqMsg, config):
            self.logger.warn("processSidQos receive invalid parameter")
            return False

        self.logger.debug("Start processing SidQos op: %d,"
                          " reqMsg: %s" % (op, str(reqMsg)))
        if op == t_RpdDataMessage.RPD_CFG_WRITE:
            ret = self.writeSidQos(reqMsg)
        elif op == t_RpdDataMessage.RPD_CFG_READ:
            ret = self.readSidQos(reqMsg, rspMsg)
        elif op == RPD_CFG_SAVE:
            ret = self.saveSidQos(reqMsg)
        else:
            self.logger.warn("Invalid operation %d for SidQos" % op)
            return False
        return ret

    def _getSubMsgIndex(self, name, field):
        """FIXME:need specific sub tlv field to identify the exclusive key."""
        ret = None
        if name == "IntervalUsageCode":
            ret = field.Code
        elif name == "DsOfdmSubcarrierState":
            ret = field.SubcarrierId
        else:
            self.logger.warn("Do not support repeated message %s" % name)
        return ret

    def _checkSyncCore(self, key, field):
        """check field sync with core."""
        fieldFlag = field + "-" + "flag"
        val = self.cfg_db.hget(key, fieldFlag)
        if val is not None:
            val = int(val)
            if val & BIT_SYNC_CORE:
                return True
        return False

    def _checkSyncPhy(self, key, field):
        """check field sync with phy."""
        fieldFlag = field + "-" + "flag"
        val = self.cfg_db.hget(key, fieldFlag)
        if val is not None:
            val = int(val)
            if val & BIT_SYNC_PHY:
                return True
        return False

    def _checkSyncCorePhy(self, key, field):
        """check field sync with core and phy."""
        if self._checkSyncCore(key, field) and \
                self._checkSyncPhy(key, field):
            return True
        else:
            return False

    def _markSyncCore(self, key, field):
        """mark field sync with core."""
        fieldFlag = field + "-" + "flag"
        val = self.cfg_db.hget(key, fieldFlag)
        if val is not None:
            val = int(val)
        else:
            val = 0
        val |= BIT_SYNC_CORE
        self.cfg_db.hset(key, fieldFlag, val)
        return True

    def _unmarkSyncCore(self, key, field):
        """mark field async with core."""
        fieldFlag = field + "-" + "flag"
        val = self.cfg_db.hget(key, fieldFlag)
        if val is not None:
            val = int(val)
            val &= ~BIT_SYNC_CORE
            self.cfg_db.hset(key, fieldFlag, val)
            return True
        else:
            return False

    def _markSyncPhy(self, key, field):
        """mark field sync with phy."""
        fieldFlag = field + "-" + "flag"
        val = self.cfg_db.hget(key, fieldFlag)
        if val is not None:
            val = int(val)
        else:
            val = 0
        val |= BIT_SYNC_PHY
        self.cfg_db.hset(key, fieldFlag, val)
        return True

    def _unmarkSyncPhy(self, key, field):
        """mark field async with phy."""
        fieldFlag = field + "-" + "flag"
        val = self.cfg_db.hget(key, fieldFlag)
        if val is not None:
            val = int(val)
            val &= ~BIT_SYNC_PHY
            self.cfg_db.hset(key, fieldFlag, val)
            return True
        else:
            return False
