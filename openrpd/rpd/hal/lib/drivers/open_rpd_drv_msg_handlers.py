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
import sys
#import time
from time import time
import rpd.python_path_resolver
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.gpb.rcp_pb2 import t_RcpMessage, t_RpdDataMessage
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities
import rpd.hal.src.HalConfigMsg as HalConfigMsg
from rpd.gpb.cfg_pb2 import config
from rpd.common.rpd_logging import AddLoggerToClass, setup_logging
import l2tpv3.src.L2tpv3VspAvp_pb2 as L2tpv3VspAvp_pb2
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClientError
from rpd.hal.lib.drivers.HalDriver0 import HalDriverClientError
import rpd.gpb.VendorSpecificExtension_pb2 as VendorSpecificExtension_pb2
from rpd.rcp.vendorTLVs.src.RcpVspTlv import RcpVendorTlv, DEFAULT_VENDOR_ID

default_supported_msg_types = (
    HalConfigMsg.MsgTypeRpdCapabilities,
    # DS PHY configure message type
    HalConfigMsg.MsgTypeDsRfPort,
    HalConfigMsg.MsgTypeDsScQamChannelConfig,
    HalConfigMsg.MsgTypeDsOfdmChannelConfig,
    HalConfigMsg.MsgTypeDsOfdmProfile,
    HalConfigMsg.MsgTypeDsRfPortPerf,
    HalConfigMsg.MsgTypeDsScQamChannelPerf,
    HalConfigMsg.MsgTypeDsOfdmChannelPerf,
    HalConfigMsg.MsgTypeDsOob551IPerf,
    HalConfigMsg.MsgTypeDsOob552Perf,
    HalConfigMsg.MsgTypeNdfPerf,

    # US PHY configure message type
    HalConfigMsg.MsgTypeUsRfPortPerf,
    HalConfigMsg.MsgTypeUsScQamChannelConfig,
    HalConfigMsg.MsgTypeUsOfdmaChannelConfig,
    HalConfigMsg.MsgTypeUsOfdmaInitialRangingIuc,
    HalConfigMsg.MsgTypeUsOfdmaFineRangingIuc,
    HalConfigMsg.MsgTypeUsOfdmaDataRangingIuc,
    HalConfigMsg.MsgTypeUsOfdmaSubcarrierCfgState,
    HalConfigMsg.MsgTypeUsScQamChannelPerf,
    HalConfigMsg.MsgTypeUsOfdmaChannelPerf,
    HalConfigMsg.MsgTypeUsOob551IPerf,
    HalConfigMsg.MsgTypeUsOob552Perf,
    HalConfigMsg.MsgTypeNdrPerf,
    HalConfigMsg.MsgTypeSidQos,

    # L2TP message type
    HalConfigMsg.MsgTypeL2tpv3SessionStatusNotification,
    HalConfigMsg.MsgTypeL2tpv3CapabilityQuery,

    # HalConfig + t_l2tpSessionReq
    HalConfigMsg.MsgTypeL2tpv3SessionReqNone,
    HalConfigMsg.MsgTypeL2tpv3SessionReqDsOfdm,
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

    # Ptp related message type
    #HalConfigMsg.MsgTypePtpClockStatus,
    #HalConfigMsg.MsgTypeRdtiConfig

    # CIN and LCCE ID assignment
    HalConfigMsg.MsgTypeL2tpv3CinIfAssignment,
    HalConfigMsg.MsgTypeL2tpv3LcceIdAssignment,

    # VspAvpExchange
    HalConfigMsg.MsgTypeVspAvpExchange,

    # RcpVendorSpecificTlv
    HalConfigMsg.MsgTypeRcpVendorSpecific,
    )


def capabilities_get(cfg):
    logger = get_msg_handler_logger()
    logger.info("Get Capabilities srcClientID: %s, Seq num:  %d" %
                      (cfg.msg.SrcClientID, cfg.msg.SeqNum))
    global_caps = {}
    pw_caps = {}
    ptp_caps = {}
    # Call vendor driver to update global_caps, pw_caps, ptp_caps dictionaries
    rcp_msg = t_RcpMessage()
    rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
    rcp_msg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
    rpd_data_msg = t_RpdDataMessage()
    rpd_data_msg.RpdDataOperation = t_RpdDataMessage.RPD_CFG_READ
    payload = config()
    if True:  # check vendor driver return status
#        payload.RpdCapabilities.NumBdirPorts.set_val(0)
        payload.RpdCapabilities.NumBdirPorts = 0
        payload.RpdCapabilities.NumDsRfPorts = 1
        # Note typo bug 'Mum' that comes from RpdCapabilities.proto file
        payload.RpdCapabilities.NumUsRfPorts = 2
        payload.RpdCapabilities.NumTenGeNsPorts = 1
        payload.RpdCapabilities.NumOneGeNsPorts = 1
        payload.RpdCapabilities.NumDsScQamChannels = 160
        payload.RpdCapabilities.NumDsOfdmChannels = 5
        payload.RpdCapabilities.NumUsScQamChannels = 5
        payload.RpdCapabilities.NumUsOfdmaChannels = 5
        payload.RpdCapabilities.NumDsOob55d1Channels = 16
        payload.RpdCapabilities.NumUsOob55d1Channels = 16
        payload.RpdCapabilities.NumOob55d2Modules = 1
        payload.RpdCapabilities.NumUsOob55d2Demodulators = 10
        payload.RpdCapabilities.NumNdfChannels = 8
        payload.RpdCapabilities.NumNdrChannels = 8
        payload.RpdCapabilities.SupportsUdpEncap = 1
        payload.RpdCapabilities.NumDsPspFlows = 4
        payload.RpdCapabilities.NumUsPspFlows = 4
        payload.RpdCapabilities.PilotToneCapabilities.NumCwToneGens = 5
        payload.RpdCapabilities.PilotToneCapabilities.LowestCwToneFreq = 54000000
        payload.RpdCapabilities.PilotToneCapabilities.HighestCwToneFreq = 999000000
        payload.RpdCapabilities.PilotToneCapabilities.MaxPowerDedCwTone = 330
        payload.RpdCapabilities.PilotToneCapabilities.QamAsPilot = 1
        payload.RpdCapabilities.PilotToneCapabilities.MinPowerDedCwTone = -330
        payload.RpdCapabilities.PilotToneCapabilities.MaxPowerQamCwTone = 90
        payload.RpdCapabilities.PilotToneCapabilities.MinPowerQamCwTone = -30

        payload.RpdCapabilities.NumAsyncVideoChannels = 20
        payload.RpdCapabilities.SupportsFlowTags = 1
        payload.RpdCapabilities.SupportsFrequencyTilt = 1
        payload.RpdCapabilities.TiltRange = 10
        #payload.RpdCapabilities.RdtiCapabilities.NumPtpPortsPerEnetPort = 1 # TODO - FIX this when support added.
        payload.RpdCapabilities.RpdIdentification.VendorName = "MaxLinear"
        payload.RpdCapabilities.RpdIdentification.VendorId = "XX"   # This shouldn't be a string but a 16 bit integer
        payload.RpdCapabilities.RpdIdentification.ModelNumber = "x1"
        payload.RpdCapabilities.RpdIdentification.DeviceMacAddress = "66:55:44:33:22:11"
        payload.RpdCapabilities.RpdIdentification.CurrentSwVersion = "V1.0.5"
        payload.RpdCapabilities.RpdIdentification.BootRomVersion = "V0.0.1"
        payload.RpdCapabilities.RpdIdentification.DeviceDescription = "R-PHY from MaxLinear"
        payload.RpdCapabilities.RpdIdentification.DeviceAlias = "RPD"
        payload.RpdCapabilities.RpdIdentification.SerialNumber = "991234"
        payload.RpdCapabilities.RpdIdentification.UsBurstReceiverVendorId = "XX"   # This shouldn't be a string but a 16 bit integer
        payload.RpdCapabilities.RpdIdentification.UsBurstReceiverModelNumber = "ven1456"
        payload.RpdCapabilities.RpdIdentification.UsBurstReceiverDriverVersion = "V1.1"
        payload.RpdCapabilities.RpdIdentification.UsBurstReceiverSerialNumber = "99901"
        payload.RpdCapabilities.RpdIdentification.RpdRcpProtocolVersion = "V1.0.0"
        payload.RpdCapabilities.RpdIdentification.RpdRcpSchemaVersion = "V1.0.10"
        reachAbility = payload.RpdCapabilities.LcceChannelReachability.add()
        reachAbility.EnetPortIndex = 1
        reachAbility.ChannelType = 2
        reachAbility.RfPortIndex = 1
        reachAbility.StartChannelIndex = 9
        reachAbility.EndChannelIndex = 20
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK
        logger.info("Get Capabilities payload: %s" % payload)
    else:
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR
    rpd_data_msg.RpdData.CopyFrom(payload)
    rcp_msg.RpdDataMessage.CopyFrom(rpd_data_msg)
    cfg.msg.CfgMsgPayload = rcp_msg.SerializeToString()
    return cfg

def config_dummy(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_ds_port(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_dsqam_channel(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_dsofdm_channel(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_dsofdm_profile(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_usatdma_channel(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_usofdma_channel(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_sid_qos(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def config_docsis_timer(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_dummy(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_dsqam_channel_status(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_dsofdm_channel_status(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_oob551_mod_status(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_oob552_mod_status(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_oob551_demod_status(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_oob552_demod_status(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_depi_pw(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_uepi_pw(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_ndf(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def req_ndr(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def cin_if_assign(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    pass

def lcce_id_assign(cfg):
    logger = get_msg_handler_logger()
    logger.debug("handler called with msg: %s" % cfg)
    return cfg

def vsp_avp_handler(ntf):
    logger = get_msg_handler_logger()
    ori_avp = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
    ori_avp.ParseFromString(ntf.msg.HalNotificationPayLoad)
    ori_vsp_avp_content = ori_avp.VspAvp
    # OpenRPD Driver should have a list of Vendor AVPs, and it must handle this message according to these rules:
    # 1. If the key (vendorID, attrType) is not in its database, ignore the Notification.
    # 2. If the key (vendorID, attrType) is in its database:
    #    2.a: if the field 'vsp_avp_msg.oper == VSP_AVP_OP_INFO' in the notification message: This is a notification
    #         that the AVP was in an incoming packet which was received by L2TP layer.
    #         Handle the AVP according to the intended design of this AVP.
    #    2.b: if the field 'vsp_avp_msg.oper == VSP_AVP_OP_UDPATE' in the notification message: This is a message
    #         that L2TP layer wants to update the content of the AVP at boot time.
    #         Vendor should update that AVP content in L2TP layer by sending back another HalNotification message
    #         with the content of the AVP so that L2TP layer would update it.

    # Check if ori_avp.vendorId and ori_avp.attrType are in a list of AVPs that this OpenRPD driver support.
    # If not, set returns status:
    # vsp_avp_msg.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_FAILURE
    # and quit


    vsp_avp_msg = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg()
    vsp_avp_msg.rspCode = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_STATUS_SUCCESS

    """ The below logic and loop build a list of AVPs to update bases on the HalNotification, but
    in reality, this Driver should have its own database of VSP AVPs, and it should base on
    that database to send the HalConfig message to ask L2TP layer to update the VSP AVPs.
    """
    vspAvpContent = vsp_avp_msg.VspAvp
    if ori_avp.oper == L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_UPDATE:
        # This will tell L2TP layer to update the matching AVP.
        vsp_avp_msg.oper = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_UPDATE
    else :
        # Otherwise, L2TP layer just receive HalNotification with information of the AVP received by L2TP
        vsp_avp_msg.oper = L2tpv3VspAvp_pb2.t_l2tpVspAvpMsg().VSP_AVP_OP_INFO
        return None
    i = 0
    for avp in ori_vsp_avp_content:
        logger.info("[%d] vsp_avp_handler ClientID: %s, op: %d, vid %d, attr %d, strVal %s" %
                      (i, ntf.msg.ClientID, vsp_avp_msg.oper, avp.vendorId, avp.attrType, avp.attrValBuf))

        attrBuff = "content_of_avp_id = " + str(i)
        vspAvpContent.add(vendorId=avp.vendorId,
                          attrType=avp.attrType,
                          attrValBuf=attrBuff,
                          attrValLen=len(attrBuff))
        i += 1
    
    ntf.msg.HalNotificationPayLoad = vsp_avp_msg.SerializeToString()
    return ntf    
def vsp_tlv_handler(cfg):
    logger = get_msg_handler_logger()
    logger.info("Receive Vsp TLV from %s, Seq num:  %d" %
                      (cfg.msg.SrcClientID, cfg.msg.SeqNum))

    """
    Vendor should check for t_RcpMessage().t_RpdDataMessage().RpdDataOperation: 
        (RPD_CFG_WRITE/RPD_CFG_READ/RPD_CFG_DELETE)
        and build a response based on these.
    Vendor should check for t_RcpMessage().t_RpdDataMessage().RpdData.VendorSpecificExtension.VendorId:
        Matched with his Vendor ID

    """
    rsp = t_RcpMessage()
    rsp.ParseFromString(cfg.msg.CfgMsgPayload)
    rcp_vsp_tlv = rsp.RpdDataMessage.RpdData.VendorSpecificExtension
    dataOp = rsp.RpdDataMessage.RpdDataOperation
    logger.info("vsp_tlv_handler ClientID: %s, VSP Data %s, dataOp %d" %
                      (cfg.msg.SrcClientID, rsp.RpdDataMessage.RpdData, dataOp))

    rcp_msg = t_RcpMessage()
    rcp_msg.RcpMessageType = t_RcpMessage.RCP_MESSAGE_TYPE_NONE
    rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_OK

    if rcp_vsp_tlv.VendorId != DEFAULT_VENDOR_ID:
        rcp_msg.RcpDataResult = t_RcpMessage.RCP_RESULT_GENERAL_ERROR    
        logger.info("vsp_tlv_handler: vid NOT matched. %d" %(rcp_vsp_tlv.VendorId))

    rpd_data_msg = t_RpdDataMessage()
    rpd_data_msg.RpdDataOperation = dataOp 
    # If Vendor ID matched, and dataOp == READ, then fill the Values of all TLVs
    if (rcp_msg.RcpDataResult == t_RcpMessage.RCP_RESULT_OK):
        if (dataOp == t_RpdDataMessage.RPD_CFG_READ):
            # Vendor should fill the sub-TLVs.
            rpd_data_msg.RpdData.CopyFrom(rsp.RpdDataMessage.RpdData)
            vsp_tlv = rpd_data_msg.RpdData.VendorSpecificExtension

            vsp_tlv.FWVersion = 0x0101
            vsp_tlv.HWVersion = 0x0A0B
            rfChannel = vsp_tlv.RfChannel.add()
            rfChannel.RfChannelSelector.RfPortIndex = 1
            rfChannel.RfChannelSelector.RfChannelType = 2
            rfChannel.RfChannelSelector.RfChannelIndex = 3

            rfChannel.DsScQamChannelPerf.outDiscards = 1024
            rfChannel.DsScQamChannelPerf.outErrors = 2048


            rfChannel.DsOfdmChannelPerf.outDiscards = 1024 * 3
            rfChannel.DsOfdmChannelPerf.outErrors = 2048 * 3
            rfChannel.DsOfdmChannelPerf.DsOfdmProfilePerf.ProfileIndex = 3
            rfChannel.DsOfdmChannelPerf.DsOfdmProfilePerf.outCodewords = 123456789
        elif (dataOp == t_RpdDataMessage.RPD_CFG_WRITE):
            # Apply the values of RfChannel TVL.
            logger.info("vsp_tlv_handler: RPD_CFG_WRITE.  Perform WRITE...")
            pass

    rcp_msg.RpdDataMessage.CopyFrom(rpd_data_msg)
    cfg.msg.CfgMsgPayload = rcp_msg.SerializeToString()
    return cfg

def get_msg_handler_logger():
    setup_logging('HAL', filename="hal.log")
    logger = logging.getLogger("open_rpd_drv_std_logger")
    return logger
    
if __name__ == "__main__":
    logger = get_msg_handler_logger()

    hal_msg = HalMessage("HalConfig",
                               SrcClientID="123",
                               SeqNum=1003,
                               # The first cfg.msg.CfgMsgType is 1024
                               CfgMsgType=HalConfigMsg.MsgTypeRpdCapabilities,
                               CfgMsgPayload="test open_rpd_drv_msg_handlers")
    capabilities_get(hal_msg)
#    pass
