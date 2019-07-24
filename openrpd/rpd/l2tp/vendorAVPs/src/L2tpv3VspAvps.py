#
# Copyright (c) 2016 Cisco and/or its affiliates,
#                    MaxLinear, Inc. ("MaxLinear"), and
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
This file contains l2tpv3VspAvps() that carries out operations in a Vendor specific
AVP (l2tpv3SampleVendorAvp) object

"""
#import rpd.python_path_resolver
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from l2tpv3.src.L2tpv3GlobalSettings import L2tpv3GlobalSettings
from l2tpv3.src.L2tpv3AVP import l2tpv3AVP, l2tpv3AVPerror, addDebugLogToHandle
import l2tpv3.src.L2tpv3VspAvp_pb2 as L2tpv3VspAvp_pb2
from L2tpv3SampleVspAvp import l2tpv3SampleVendorAvp, \
                                                DEFAULT_VENDOR_ID, ALLOW_UPDATE, NOTIFY_OPTION_ON, \
                                                NOTIFY_OPTION_ON_WITH_CONFIRM,\
                                                STANDARD_AVP_HEADER_LEN
import struct
import socket

from rpd.common.rpd_logging import AddLoggerToClass


class l2tpv3VspAvps (object):

    __metaclass__ = AddLoggerToClass
    vsp_avps = dict()
    def __init__(self, vID = DEFAULT_VENDOR_ID):
        self.vID = vID
        self.logger.debug("Create a L2tpv3VspAvp instance with VendorID: %d" %vID)
        return

    def add_VspAvp(self, v_avp):
        """

        This function adds single AVP which has Vendor ID = self.vID to the global 
        l2tpv3AVP.SubclassMapping[] and the local vsp_avps[] dictionaries.  
        The local vsp_avps[] dictionary may be used later for TBD purpose.
        
        : param v_avp: Vendor AVP the caller wants to add
        
        : return:

        """

        if (not isinstance(v_avp, l2tpv3AVP)):
            msg = "AVPs is not a l2tpv3AVP type"
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        if (v_avp.vendorID != self.vID):
            return

        """ Just replace if exist.  Otherwise, add it """
        l2tpv3AVP.SubclassMapping[(v_avp.vendorID, v_avp.attrType)] = v_avp
        l2tpv3VspAvps.vsp_avps[(v_avp.vendorID, v_avp.attrType)] = v_avp
        return

    def get_VspAvp (self, vsp_vid, vsp_attr):
        """

        This functions returns the AVP in l2tpv3AVP.SubclassMapping[] using
        the (vsp_vid, vsp_attr) as key.
        
        : param vsp_vid: Vendor ID of the AVP the caller wants to find
        : param vsp_attr: Attribute of the AVP the caller wants to find.
        
        : return: matching AVP

        """
        if (not isinstance(vsp_vid, int) or not isinstance(vsp_attr, int)):
            msg = "parameter is incorrect"
            print msg
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)
        return l2tpv3AVP.SubclassMapping.get((vsp_vid, vsp_attr))

    def sendnotify_VspAvps(self, avps_list):
        """

        This functions should be called by L2TP thread when it receives an incoming control packet 
        which contains VSP AVP (i.e. ICRQ).  If an item in the VSP AVPs has the flag 
        'notifyVendorOpt == NOTIFY_OPTION_ON', then the attrVal of the AVP is added to the
        HalNotification.MsgTypeVspAvpExchange message.
        This is how OpenRPD driver gets notified about a VSP AVP sent from the other side.
        
        : param avps_list: The list of AVPs in the received control packet.

        : return: None

        """

        hal_client = L2tpv3GlobalSettings.l2tp_hal_client

        if (None is hal_client) or (None is avps_list) or \
            not isinstance(avps_list, list):
            return

        # Check for AVPs with notifyVendorOpt = NOTIFY_OPTION_ON, send HalNotification
        vsp_avp_msg = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
        vsp_avp_msg.oper = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_INFO
        vsp_avp_msg.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_NA
        vspAvpContent = vsp_avp_msg.VspAvp
        sendNotify = 0
        for vsp_avp in avps_list:
            if (vsp_avp.vendorID == self.vID):
                #vsp_avp = l2tpv3AVP.SubclassMapping[(avp.vendorID, avp.attrType)]
                #self.logger.info("sendnotify_VspAvps: vid %d, attrType %d, is instance %d" \
                #        %(vsp_avp.vendorID, vsp_avp.attrType, isinstance(vsp_avp, l2tpv3SampleVendorAvp)))
                if isinstance(vsp_avp, l2tpv3SampleVendorAvp) and \
                    (vsp_avp.notifyVendorOpt == NOTIFY_OPTION_ON):
                    sendNotify = 1
                    vspAvpContent.add(vendorId=vsp_avp.vendorID,
                                          attrType=vsp_avp.attrType,
                                          attrValBuf=vsp_avp.attrValue,
                                          attrValLen=len(vsp_avp.attrValue))
        if sendNotify == 1:
            ntfMsgType = HalConfigMsg.MsgTypeVspAvpExchange
            ntfMsgContent = vsp_avp_msg.SerializeToString()
            hal_client.sendNotificationMsg(ntfMsgType, ntfMsgContent)

        """
        # Hold on to this idea for now!
        # Now, check for AVPs with notifyVendorOpt = NOTIFY_OPTION_ON_WITH_CONFIRM, send HalConfig, 
        # expect OpenRPD driver to send back HalConfigRsp
        vsp_avp_msg = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
        vsp_avp_msg.oper = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_INFO
        vsp_avp_msg.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_NA
        vspAvpContent = vsp_avp_msg.VspAvp
        sendConfig = 0
        for avp in avps_list:
            if (avp.vendorID == self.vID):
                vsp_avp = l2tpv3AVP.SubclassMapping[(avp.vendorID, avp.attrType)]
                #self.logger.info("sendnotify_VspAvps: vid %d, attrType %d, is instance %d" \
                #        %(vsp_avp.vendorID, vsp_avp.attrType, isinstance(vsp_avp, l2tpv3SampleVendorAvp)))
                if isinstance(vsp_avp, l2tpv3SampleVendorAvp) and \
                    (vsp_avp.notifyVendorOpt == NOTIFY_OPTION_ON_WITH_CONFIRM):
                    sendConfig = 1
                    vspAvpContent.add(vendorId=vsp_avp.vendorID,
                                          attrType=vsp_avp.attrType,
                                          attrValBuf=vsp_avp.attrValue,
                                          attrValLen=len(vsp_avp.attrValue))

        if sendConfig == 1:
            cfgMsgType = HalConfigMsg.MsgTypeVspAvpConfig
            cfgMsgContent = vsp_avp_msg.SerializeToString()
            hal_client.sendCfgMsg(cfgMsgType, cfgMsgContent)
        """

        return

    def sendupdate_VspAvp (self):
        """

        This functions should be called by L2TP thread at bootup ONLY.
        It will scan thru all AVPs in l2tpv3AVP.SubclassMapping[] to find all 
        matching AVPs with 'updateOpt == ALLOW_UPDATE' and then send
        a HalNotification message to OpenRPD driver to see if the driver wants
        to update the VSP AVPs' content.
        If OpenRPD drive needs to update the VSP AVPs, it should send back a HalConfig
        message contains the udpated attrVal of all VSP AVPs.
        
        : param : 

        : return: None

        """
        hal_client = L2tpv3GlobalSettings.l2tp_hal_client

        if hal_client is not None:
            self.logger.info("sendupdate_VspAvp:")
            vsp_avp_msg = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
            vsp_avp_msg.oper = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_UPDATE
            vsp_avp_msg.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_NA
            vspAvpContent = vsp_avp_msg.VspAvp

            sendUpdate = 0
            avps = l2tpv3AVP.SubclassMapping.keys()
            for avp in avps:
                (vendorID, attrType) = avp
                if (vendorID == self.vID):
                    vsp_avp = l2tpv3AVP.SubclassMapping[(vendorID, attrType)]
                    #self.logger.info("sendupdate_VspAvp: vid %d, attrType %d, is instance %d" \
                    #        %(vendorID, attrType, isinstance(vsp_avp, l2tpv3SampleVendorAvp)))

                    if (None is not vsp_avp) and                       \
                        isinstance(vsp_avp, l2tpv3SampleVendorAvp) and \
                        (vsp_avp.updateOpt == ALLOW_UPDATE):
                        sendUpdate = 1
                        vspAvpContent.add(vendorId=vsp_avp.vendorID,
                                          attrType=vsp_avp.attrType,
                                          attrValBuf=vsp_avp.attrValue,
                                          attrValLen=len(vsp_avp.attrValue))

            if sendUpdate == 1:
                ntfMsgType = HalConfigMsg.MsgTypeVspAvpExchange
                ntfMsgContent = vsp_avp_msg.SerializeToString()
                hal_client.sendNotificationMsg(ntfMsgType, ntfMsgContent)
        
    def update_VspAvp (self, cfg):
        """

        This functions should be called when L2TP layer (L2tpv3Hal.py) receives: 
        HalNotification.MsgTypeVspAvpExchange, with 'oper = VSP_AVP_OP_UPDATE'.
        It will update all AVPs in l2tpv3AVP.SubclassMapping[] which match 
        (vendorId,attrType) and have 'updateOpt == ALLOW_UPDATE'  
        
        : param cfg: HalConfig message which is sent from OpenRPD driver.

        : return: None

        """

        cfgMsg = cfg.msg
        try:
            rsp_avp = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
            rsp_avp.ParseFromString(cfgMsg.CfgMsgPayload)

            cfgRsp = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
            cfgRsp.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_SUCCESS
            cfgRsp.oper = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_UPDATE
            
            if rsp_avp.oper == L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_UPDATE:
                vspAvpContent = rsp_avp.VspAvp
                for avp in vspAvpContent:
                    self.logger.info("update_VspAvp srcClientID: %s, op: %d, vid %d, attr %d, strVal %s" %
                         (cfg.msg.SrcClientID, rsp_avp.oper, avp.vendorId, avp.attrType, avp.attrValBuf))

                    vsp_avp = l2tpv3AVP.SubclassMapping[(avp.vendorId, avp.attrType)]

                    # If any AVP retrieved from l2tpv3AVP.SubclassMapping not fulfills
                    # the below conditions, break out and send a ConfigRsp with FAILURE status
                    if (None is vsp_avp) or not isinstance(vsp_avp, l2tpv3SampleVendorAvp):
                        continue

                    if (vsp_avp.vendorID != self.vID) or (vsp_avp.updateOpt != ALLOW_UPDATE):
                        cfgRsp.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_FAILURE
                        break
                    
                    vsp_avp.attrValue = str(avp.attrValBuf)
                    vsp_avp.length = len(vsp_avp.attrValue) + STANDARD_AVP_HEADER_LEN
                    self.logger.info("update_VspAvp: %s " % vsp_avp.attrValue)
                    self.logger.info(vsp_avp)

            else:
                cfgRsp.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_FAILURE

            return cfgRsp

        except Exception as e:
            self.logger.error("Error happens when handle VSP AVP exchange msg: " + str(e))
            raise l2tpv3AVPerror("cfg message MsgTypeVspAvpExchange rsp error")

    def append_VspAvp (self, out_avps, ctrlPktNumber):
        """

        This function blindly appends VSP AVPs to an outgoing control packet if the VSP AVPs have 
        the ctrlPktNumber is in the list of outCtrlPktList.

        This function should be called before L2tpv3ControlPacket.L2tpv3ControlPacket() which 
        builds the Control packet.
        
        : param out_avps: The list of avps which is used to build a L2tpv3ControlPacket.
        : param ctrlPktNumber: One of the values of L2tpv3RFC3931AVPs.ControlMessageAVP: SCCRQ, SCCRP, ICRQ, ICRP, etc.
        : return: None

        """

        if not isinstance(out_avps, list):
            raise l2tpv3AVPerror("Outgoing AVP must be a list")        

        avps = l2tpv3AVP.SubclassMapping.keys()
        for avp in avps:
            (vendorId, attrType) = avp
            if (vendorId == self.vID):
                vsp_avp = l2tpv3AVP.SubclassMapping[(vendorId, attrType)]
                if (None is not vsp_avp and \
                    isinstance(vsp_avp, l2tpv3SampleVendorAvp) and \
                    ctrlPktNumber in vsp_avp.OutCtrlIdList):
                    self.logger.info("append_VspAvp vid %d, attr %d, ctrl number %d" %
                             (vendorId, attrType, ctrlPktNumber))

                    self.logger.info(vsp_avp)
                    out_avps.append(vsp_avp)
        return

