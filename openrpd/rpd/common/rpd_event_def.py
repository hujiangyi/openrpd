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

from time import time
import json
import os
import shutil
from uuid import uuid4
from collections import OrderedDict

from rpd.rcp.rcp_lib import rcp_tlv_def

# Authentication and Encryption
RPD_EVENT_NET_AUTH_ERROR = 66070100, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Network Authentication Error: %s %s")
RPD_EVENT_MUTUAL_AUTH_ERROR = 66070101, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Mutual Authentication Error: %s %s")

RPD_EVENT_AUTH_ENCRYPTION_102 = 66070102, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE,
                                           "SSH Authentication Successful from: %s %s %s")
RPD_EVENT_AUTH_ENCRYPTION_103 = 66070103, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING,
                                           "SSH Authentication Error from: %s %s %s")

# Connectivity
RPD_EVENT_CONNECTIVITY_AUXILIARY_LOST = 66070200, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                   "Connection lost - Auxiliary CCAP Core %s")
RPD_EVENT_CONNECTIVITY_PRINCIPAL_LOST = 66070201, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                                   "Connection lost - Principal CCAP Core %s")
RPD_EVENT_CONNECTIVITY_NO_PRINCIPAL = 66070202, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Principal Core Not Found %s")
RPD_EVENT_CONNECTIVITY_MUL_ACTIVE_PRINCIPAL = 66070203, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING,
                                                         "Multiple Active Principal Cores Found; %s")
RPD_EVENT_CONNECTIVITY_GCP_FAILURE = 66070204, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "GCP Connection Failure; %s")
RPD_EVENT_CONNECTIVITY_LOSS_SYNC = 66070205, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Loss of Clock Sync %s")
RPD_EVENT_CONNECTIVITY_SYNC = 66070206, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE, "Clock Sync Reestablished %s")
RPD_EVENT_CONNECTIVITY_207 = 66070207, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Loss of Clock Slave %s")
RPD_EVENT_CONNECTIVITY_208 = 66070208, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE, "Clock Slave Reestablished %s")
RPD_EVENT_CONNECTIVITY_FAILOVER_STANDBY = 66070210, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING,
                                                     "Failover to Standby Core %s")
RPD_EVENT_CONNECTIVITY_211 = 66070211, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Failback to Active Core %s")

RPD_EVENT_CONNECTIVITY_REBOOT = 66070212, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE, "Reboot %s %s %s")
RPD_EVENT_CONNECTIVITY_ETH_DOWN = 66070213, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Ethernet Link Down %s %s")
RPD_EVENT_CONNECTIVITY_ETH_UP = 66070214, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE, "Ethernet Link Up %s %s")
RPD_EVENT_CONNECTIVITY_SYS_REBOOT = 66070217, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "System Failure Reboot %s %s %s")
RPD_EVENT_CONNECTIVITY_218 = 66070218, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Diagnostic Self Test Failure %s %s %s %s")

# DHCP, TOD
RPD_EVENT_DHCP_RENEW_NO_RESP = 66070300, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "DHCP RENEW sent - No response for %s")
RPD_EVENT_DHCP_REBIND_NO_RESP = 66070301, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                           "DHCP REBIND sent - No response for %s")
RPD_EVENT_DHCP_302 = 66070302, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                "DHCP RENEW WARNING - Field invalid in response v4 %s")
RPD_EVENT_DHCP_303 = 66070303, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                "DHCP RENEW FAILED - Critical field invalid in response %s")
RPD_EVENT_DHCP_304 = 66070304, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                "DHCP REBIND WARNING - Field invalid in response %s")
RPD_EVENT_DHCP_305 = 66070305, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                "DHCP REBIND FAILED - Critical field invalid in response %s")
RPD_EVENT_DHCP_RENEW_PARA_MODIFIED = 66070307, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE,
                                                "DHCP Renew - lease parameters %s modified %s")
RPD_EVENT_DHCP_CORE_LIST_MISSING = 66070309, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                              "DHCP Failed - CCAP Core list missing %s")
RPD_EVENT_DHCP_DISCOVER_NO_OFFER = 66070310, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                              "DHCP FAILED - Discover sent, no offer received %s")
RPD_EVENT_DHCP_REQ_NO_RSP = 66070311, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                       "DHCP FAILED - Request sent, No response %s")
RPD_EVENT_DHCP_RSP_NON_CRITICAL_INVALID_FIELD = 66070312, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING,
                                                           "DHCP FAILED - Non-critical field invalid in response")
RPD_EVENT_DHCP_RSP_CRITICAL_INVALID_FIELD = 66070313, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                                       "DHCP FAILED - Critical field invalid in response")
RPD_EVENT_DHCPV6_REQ_NO_REP = 66070316, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                         "DHCP failed - DHCP Solicit sent, No DHCP Advertise received %s")
RPD_EVENT_DHCP_REQ_NO_REP = 66070317, (rcp_tlv_def.RPD_EVENT_LEVEL_CRITICAL,
                                       "DHCP failed - DHCP Request sent, No DHCP REPLY received %s")

RPD_EVENT_TOD_NO_RESPONSE = 66070322, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "ToD request sent - No Response received %s")
RPD_EVENT_TOD_INVALID_FMT = 66070323, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                       "ToD Response received - Invalid data format %s")

# Secure Software Download
RPD_EVENT_SSD_INIT_RPD = 66070400, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE,
                                    "SW Download INIT - Via RPD CLI: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_INIT_GCP = 66070401, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE,
                                    "SW Download INIT - Via GCP: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_DOWNLOAD_FAILED_AFTER_RETRY = 66070402, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                       "SW Upgrade Failed during download: Max retry exceed (3)")
RPD_EVENT_SSD_DOWNLOAD_FAIL_SERVER_NOT_PRESENT = 66070403, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                            "SW upgrade Failed before download - Server not Present: "
                                                            "SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_DOWNLOAD_FAIL_FILE_NOT_PRESENT = 66070404, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                          "SW upgrade Failed before download - File not Present: "
                                                          "SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_DOWNLOAD_SUCCESSFUL_RPD = 66070410, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE,
                                                   "SW download Successful - Via RPD CLI: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_DOWNLOAD_SUCCESSFUL_GCP = 66070411, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE,
                                                   "SW download Successful - Via GCP: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_IMPROPER_CODEFILE = 66070412, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                             "Improper Code File Controls: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_CODE_MFR_CVC_FAIL = 66070413, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                             "Code File Manufacturer CVC Validation Failure: "
                                             "SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_CODE_MFR_CVS_FAIL = 66070414, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                             "Code File Manufacturer CVS Validation Failure: "
                                             "SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_CODE_MSO_CVC_FAIL = 66070415, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                             "Code File Co-Signer CVC Validation Failure: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_CODE_MSO_CVS_FAIL = 66070416, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                             "Code File Co-Signer CVS Validation Failure: SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_IMPROPER_GCP_CVC_FORMAT = 66070417, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                   "Improper GCP CVC Format %s")
RPD_EVENT_SSD_GCP_CVC_VALIDATION_FAIL = 66070418, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                   "GCP CVC Validation Failure %s")

# L2tp
RPD_EVENT_L2TP_CONN_ERR = 66070209, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "L2TPv3 Connection Error %s")
RPD_EVENT_L2TP_SESSION_DOWN = 66070215, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Pseudowire Connection Down %s %s %s")
RPD_EVENT_L2TP_SESSION_UP = 66070216, (rcp_tlv_def.RPD_EVENT_LEVEL_NOTICE, "Pseudowire Connection Up: %s %s;%s")

# Physical and Environmental
RPD_EVENT_PHYSICAL_ENV_507 = 66070507, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "%s %s %s")

# emd event
RPD_EVENT_EMD_TEMP_ERR = 66070500, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Rpd temperature abnormal %s")
RPD_EVENT_EMD_TEMP_WARN = 66070501, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Rpd temperature abnormal %s")


# The CMTS MUST implement EventIds ranging from 231 to (232 - 1) as
# vendor-specific EventIds using the following format:
# Bit 31 is set to indicate vendor-specific event.
# Bits 30-16 contain the lower 15 bits of the vendor's SNMP enterprise number. (cisco 9)
# Bits 15-0 are used by the vendor to number events.
# so cisco event id start from 0x80090000

# provision event
RPD_EVENT_PROVISION_NO_INTERFACE_UP = 0x80090000, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "RPD has no interface up %s")
RPD_EVENT_PROVISION_ENTER_OPERATIONAL = 0x80090001, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION,
                                                     "RPD system enter operational %s")
RPD_EVENT_PROVISION_EXIT_OPERATIONAL = 0x80090002, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                    "RPD system exit operational %s")
RPD_EVENT_PROVISION_TOD_DONE = 0x80090003, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION,
                                            "ToD Response received %s")

# macsec event
RPD_EVENT_MAC_SEC_TSET = 0x80090100, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION, "TEST %s")

# dhcp event
RPD_EVENT_DHCP_TEST = 0x80090200, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION, "TEST %s")

# gcp event
RPD_EVENT_GCP_TEST = 0x80090300, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION, "TEST %s")
RPD_EVENT_GCP_FAILED_EVENT = 0x80090301, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Session failed:%s, @%s")
# ptp event
RPD_EVENT_PTP_TEST = 0x80090400, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION, "TEST %s")

# l2tp event
RPD_EVENT_L2TP_WARN = 0x80090500, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Cisco L2TP warn event: %s %s")
RPD_EVENT_L2TP_INFO = 0x80090501, (rcp_tlv_def.RPD_EVENT_LEVEL_INFORMATION, "Cisco L2TP info event: %s %s")
RPD_EVENT_L2TP_DEBUG = 0x80090502, (rcp_tlv_def.RPD_EVENT_LEVEL_DEBUG, "Cisco L2TP debug event: %s %s")

# ssh event
RPD_EVENT_SSH_LIMITED = 0x80090600, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "SSH quit: %s")

# ssd event
RPD_EVENT_SSD_GENERAL_FAIL = 0x80090700, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                          "Ssd general fail: %s, SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_PROVISION_LOST = 0x80090701, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING,
                                            "Ssd process lost connect with provision %s")
RPD_EVENT_SSD_DOWNLOAD_GENERAL_FAIL = 0x80090702, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR,
                                                   "Ssd general download fail: %s, SW file:%s - SW server:%s %s")
RPD_EVENT_SSD_SKIP_TRIGGER = 0x80090703, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Skip Ssd control %s")

# shelf rpd monitor related
RPD_EVENT_EMD_SHELF_TEMP_WARN = 0x80090800, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING,
                                             "Rpd shelf temperature abnormal %s %s")
RPD_EVENT_EMD_SHELF_TEMP_ERR = 0x80090801, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Rpd shelf temperature abnormal %s %s")
RPD_EVENT_EMD_SHELF_FAN_WARN = 0x80090802, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Rpd shelf fan is not present %s")
RPD_EVENT_EMD_SHELF_FAN_ERR = 0x80090803, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Rpd shelf fan fail %s")
RPD_EVENT_EMD_SHELF_POWER_WARN = 0x80090804, (rcp_tlv_def.RPD_EVENT_LEVEL_WARNING, "Rpd shelf power is not present %s")
RPD_EVENT_EMD_SHELF_POWER_ERR = 0x80090805, (rcp_tlv_def.RPD_EVENT_LEVEL_ERROR, "Rpd shelf power fail %s")


RPD_EVENT_ALL = (
    RPD_EVENT_NET_AUTH_ERROR,
    RPD_EVENT_MUTUAL_AUTH_ERROR,
    RPD_EVENT_AUTH_ENCRYPTION_102,
    RPD_EVENT_AUTH_ENCRYPTION_103,

    RPD_EVENT_CONNECTIVITY_AUXILIARY_LOST,
    RPD_EVENT_CONNECTIVITY_PRINCIPAL_LOST,
    RPD_EVENT_CONNECTIVITY_NO_PRINCIPAL,
    RPD_EVENT_CONNECTIVITY_MUL_ACTIVE_PRINCIPAL,
    RPD_EVENT_CONNECTIVITY_GCP_FAILURE,
    RPD_EVENT_CONNECTIVITY_LOSS_SYNC,
    RPD_EVENT_CONNECTIVITY_SYNC,
    RPD_EVENT_CONNECTIVITY_207,
    RPD_EVENT_CONNECTIVITY_208,
    RPD_EVENT_L2TP_CONN_ERR,
    RPD_EVENT_CONNECTIVITY_FAILOVER_STANDBY,
    RPD_EVENT_CONNECTIVITY_211,
    RPD_EVENT_CONNECTIVITY_REBOOT,
    RPD_EVENT_CONNECTIVITY_ETH_DOWN,
    RPD_EVENT_CONNECTIVITY_ETH_UP,
    RPD_EVENT_CONNECTIVITY_SYS_REBOOT,
    RPD_EVENT_L2TP_SESSION_DOWN,
    RPD_EVENT_L2TP_SESSION_UP,
    RPD_EVENT_CONNECTIVITY_218,

    RPD_EVENT_DHCP_RENEW_NO_RESP,
    RPD_EVENT_DHCP_REBIND_NO_RESP,
    RPD_EVENT_DHCP_302,
    RPD_EVENT_DHCP_303,
    RPD_EVENT_DHCP_304,
    RPD_EVENT_DHCP_305,
    RPD_EVENT_DHCP_RENEW_PARA_MODIFIED,
    RPD_EVENT_DHCP_CORE_LIST_MISSING,
    RPD_EVENT_DHCP_DISCOVER_NO_OFFER,
    RPD_EVENT_DHCP_REQ_NO_RSP,
    RPD_EVENT_DHCPV6_REQ_NO_REP,
    RPD_EVENT_DHCP_REQ_NO_REP,
    RPD_EVENT_DHCP_RSP_NON_CRITICAL_INVALID_FIELD,
    RPD_EVENT_DHCP_RSP_CRITICAL_INVALID_FIELD,
    RPD_EVENT_TOD_NO_RESPONSE,
    RPD_EVENT_TOD_INVALID_FMT,

    RPD_EVENT_SSD_INIT_RPD,
    RPD_EVENT_SSD_INIT_GCP,
    RPD_EVENT_SSD_DOWNLOAD_FAILED_AFTER_RETRY,
    RPD_EVENT_SSD_DOWNLOAD_FAIL_SERVER_NOT_PRESENT,
    RPD_EVENT_SSD_DOWNLOAD_FAIL_FILE_NOT_PRESENT,
    RPD_EVENT_SSD_DOWNLOAD_SUCCESSFUL_RPD,
    RPD_EVENT_SSD_DOWNLOAD_SUCCESSFUL_GCP,
    RPD_EVENT_SSD_IMPROPER_CODEFILE,
    RPD_EVENT_SSD_CODE_MFR_CVC_FAIL,
    RPD_EVENT_SSD_CODE_MFR_CVS_FAIL,
    RPD_EVENT_SSD_CODE_MSO_CVC_FAIL,
    RPD_EVENT_SSD_CODE_MSO_CVS_FAIL,
    RPD_EVENT_SSD_IMPROPER_GCP_CVC_FORMAT,
    RPD_EVENT_SSD_GCP_CVC_VALIDATION_FAIL,

    RPD_EVENT_PHYSICAL_ENV_507,
    # emd event
    RPD_EVENT_EMD_TEMP_ERR,
    RPD_EVENT_EMD_TEMP_WARN,

    RPD_EVENT_PROVISION_NO_INTERFACE_UP,
    RPD_EVENT_PROVISION_ENTER_OPERATIONAL,
    RPD_EVENT_PROVISION_EXIT_OPERATIONAL,
    RPD_EVENT_PROVISION_TOD_DONE,

    RPD_EVENT_SSH_LIMITED,
    # l2tp event
    RPD_EVENT_L2TP_WARN,
    RPD_EVENT_L2TP_INFO,
    RPD_EVENT_L2TP_DEBUG,

    # ssd event
    RPD_EVENT_SSD_GENERAL_FAIL,
    RPD_EVENT_SSD_PROVISION_LOST,
    RPD_EVENT_SSD_DOWNLOAD_GENERAL_FAIL,
    RPD_EVENT_SSD_SKIP_TRIGGER,

    RPD_EVENT_GCP_FAILED_EVENT,

    # Shelf RPD related
    RPD_EVENT_EMD_SHELF_TEMP_WARN,
    RPD_EVENT_EMD_SHELF_TEMP_ERR,
    RPD_EVENT_EMD_SHELF_FAN_WARN,
    RPD_EVENT_EMD_SHELF_FAN_ERR,
    RPD_EVENT_EMD_SHELF_POWER_WARN,
    RPD_EVENT_EMD_SHELF_POWER_ERR,

)
RPD_EVENT_DICT = {n: s for n, s in RPD_EVENT_ALL}
RPD_EVENT_TYPES = tuple([n for n, s in RPD_EVENT_ALL])


class RpdEventTag(object):
    """RPD event tag object."""

    RPD_TAGS_FMT = {
        "RPD-MAC": "RPD-MAC=",
        "CCAP-IP": "CCAP-IP=",
        "RPD-MHA-VER": "RPD-VER=",
    }

    @classmethod
    def rpd_mac(cls, mac):
        """return the Event tags about RPD Mac.

        :param mac: rpd mac
        :return:

        """

        return cls.RPD_TAGS_FMT["RPD-MAC"] + mac

    @classmethod
    def ccap_ip(cls, ip):
        """return the Event tags about ccap core ip.

        :param ip: CCAP Core ip
        :return:

        """

        return cls.RPD_TAGS_FMT["CCAP-IP"] + ip

    @classmethod
    def rpd_ver(cls, ver):
        """return the Event tags about RPD version.

        :param ver: rpd version
        :return:

        """

        return cls.RPD_TAGS_FMT["RPD-MHA-VER"] + ver


class RpdEventOrderedBuffer(object):
    """rpd event stores in order."""

    BUFFER_SIZE_LIMIT = 1000

    @staticmethod
    def read_json(file_name):
        ret_value = {}
        if os.path.exists(file_name):
            with open(file_name, 'r') as fd:
                data = fd.read()
                if len(data):
                    try:
                        ret_value = json.loads(data, object_pairs_hook=OrderedDict)
                    except Exception:  # as e:
                        return ret_value
        return ret_value

    @staticmethod
    def write_json(file_name, content):
        with open(file_name, 'w') as fd:
            json.dump(content, fd, indent=4)

    @staticmethod
    def new_dict(event, text, pending_local):
        """create a new dict."""

        event_dict = dict()
        current_t = time()
        event_dict["FirstTime"] = current_t
        event_dict['LastTime'] = current_t
        event_dict["Counts"] = 1
        event_dict["text"] = text
        event_dict["PENDING_LOCAL"] = pending_local
        event_dict["Level"] = RPD_EVENT_DICT[eval(event)][0][0]

        return [event, event_dict]

    @staticmethod
    def update_dict(event_dict, text):
        """update dict."""

        event_dict[1]['Counts'] += 1
        event_dict[1]["text"] = text
        event_dict[1]['LastTime'] = time()

    @staticmethod
    def generate_event_dict(event_data, event, text, buffered, operational):
        """generate event dict for storing."""

        if buffered == EventCommonOperation.BUFFERED_PENDING:
            pending_local = rcp_tlv_def.RPD_EVENT_NOTIFICATION_PENDING_LOG[0]
        else:
            pending_local = rcp_tlv_def.RPD_EVENT_NOTIFICATION_LOCAL_LOG[0]

        op_str = "/operational" if operational else ""
        event_cnt = len(event_data)
        if event_cnt:
            if event_cnt >= RpdEventOrderedBuffer.BUFFER_SIZE_LIMIT:
                for _ in range(RpdEventOrderedBuffer.BUFFER_SIZE_LIMIT - 1, event_cnt):
                    event_data.popitem(last=False)
            key, last_value = event_data.popitem()
            if event == last_value[0]:

                if (operational and "operational" in key) or (not operational and "operational" not in key):
                    RpdEventOrderedBuffer.update_dict(last_value, text)
                    event_data.update({key: last_value})
                else:
                    event_data.update({key: last_value})

                    ret = RpdEventOrderedBuffer.new_dict(event, text, pending_local)
                    new_key = str(uuid4()) + op_str
                    event_data.update({new_key: ret})
                return
            else:
                event_data.update({key: last_value})

        # add a new event
        ret = RpdEventOrderedBuffer.new_dict(event, text, pending_local)

        key = str(uuid4()) + op_str
        event_data.update({key: ret})

        return

    @staticmethod
    def store_event(buffered, event, text, operational):
        """store the event with text to file, event must be exist in RPD_EVENT_DICT."""

        event_data = RpdEventOrderedBuffer.read_json(EventCommonOperation.BUFFERED_TYPE[buffered])
        RpdEventOrderedBuffer.generate_event_dict(event_data, event, text, buffered, operational)
        RpdEventOrderedBuffer.write_json(EventCommonOperation.BUFFERED_TYPE[buffered], event_data)

    @staticmethod
    def move_all_event_to_nonoperational():
        """remove all operational keyword in pending file."""

        total_msg = EventCommonOperation.read_log(EventCommonOperation.BUFFERED_PENDING)
        update_msg = OrderedDict()
        for key, data in total_msg.items():
            if "/operational" in key:
                update_key = str(key).replace("/operational", "")
                update_msg.update({update_key: data})
            else:
                update_msg.update({key: data})
        EventCommonOperation.write_log(update_msg, EventCommonOperation.BUFFERED_PENDING)

    @staticmethod
    def pop_operational_event(total):
        """pop event from total, operational or not."""

        ret = None
        for key, data in total.items():
            if "operational" in key:
                event, event_dict = data
                ret = (event, event_dict['text'], event_dict)
                total.pop(key)
                break
        return ret

    @staticmethod
    def pop_event(total):
        """pop event from total, operational or not."""

        ret = None
        for key, data in total.items():
            event, event_dict = data
            ret = (event, event_dict['text'], event_dict)
            total.pop(key)
            break
        return ret


class RpdEventConfig(object):
    """event configuration via gcp or default."""

    GLOBAL_CONFIG = {}
    LOCAL_MAK = 1
    PENDING_MARK = 1 << 1

    event_config_file = "/rpd/config/fault_config.json"

    @classmethod
    def read_config(cls):
        return RpdEventOrderedBuffer.read_json(cls.event_config_file)

    @classmethod
    def write_config(cls, content):
        RpdEventOrderedBuffer.write_json(cls.event_config_file, content)

    @classmethod
    def init_config(cls):
        """set event global configuration to default value or read cfg from local.

        reporting --> control
            bit 0: 1: lvl 1-4 local log, 0: lvl 5-8 not local
            bit 1: 1: log to pending queue, 0: not log

        """

        if os.path.exists(cls.event_config_file):
            cls.GLOBAL_CONFIG = cls.read_config()
            return

        control = cls.GLOBAL_CONFIG["Control"] = {}
        for lvl, _ in rcp_tlv_def.RPD_EVENT_LEVEL:
            if lvl <= rcp_tlv_def.RPD_EVENT_LEVEL_ERROR[0]:
                control[str(lvl)] = cls.LOCAL_MAK
            else:
                control[str(lvl)] = 0
        cls.GLOBAL_CONFIG['Throttle'] = rcp_tlv_def.RPD_EVENT_THROTTLE_UNCONSTRAINED[0]
        cls.GLOBAL_CONFIG['Threshold'] = 5
        cls.GLOBAL_CONFIG['Interval'] = 1
        cls.GLOBAL_CONFIG['Enable'] = rcp_tlv_def.RPD_EVENT_NTF_DISABLE[0]

    @classmethod
    def set_config(cls, config):
        """set notification configuration."""

        if config.HasField("RpdGlobal"):
            if config.RpdGlobal.HasField("EvCfg"):
                cfg = config.RpdGlobal.EvCfg
                for desc, v in cfg.ListFields():
                    if desc.name == "EvControl":
                        control = cls.GLOBAL_CONFIG["Control"]
                        for ctrl in cfg.EvControl:
                            control[str(ctrl.EvPriority)] = ctrl.EvReporting
                    if desc.name == "EvThrottleAdminStatus":
                        cls.GLOBAL_CONFIG['Throttle'] = cfg.EvThrottleAdminStatus
                    if desc.name == "EvThrottleThreshold":
                        cls.GLOBAL_CONFIG['Threshold'] = cfg.EvThrottleThreshold
                    if desc.name == "EvThrottleInterval":
                        cls.GLOBAL_CONFIG['Interval'] = cfg.EvThrottleInterval
                    if desc.name == "NotifyEnable":
                        cls.GLOBAL_CONFIG['Enable'] = cfg.NotifyEnable

                cls.write_config(cls.GLOBAL_CONFIG)

    @classmethod
    def is_unconstrained(cls):
        return int(cls.GLOBAL_CONFIG['Throttle']) == rcp_tlv_def.RPD_EVENT_THROTTLE_UNCONSTRAINED[0]

    @classmethod
    def is_belowcfg(cls):
        return int(cls.GLOBAL_CONFIG['Throttle']) == rcp_tlv_def.RPD_EVENT_THROTTLE_BELOW[0]

    @classmethod
    def is_inhibit(cls):
        return int(cls.GLOBAL_CONFIG['Throttle']) == rcp_tlv_def.RPD_EVENT_THROTTLE_INHIBITED[0]

    @classmethod
    def is_stopcfg(cls):
        return int(cls.GLOBAL_CONFIG['Throttle']) == rcp_tlv_def.RPD_EVENT_THROTTLE_STOP[0]

    @classmethod
    def is_notify_en(cls):
        return int(cls.GLOBAL_CONFIG['Enable']) == rcp_tlv_def.RPD_EVENT_NTF_ENABLE[0]


class EventCommonOperation(object):
    """event common operation, such as json file read, write, timestamp conversion."""

    EVENT_VER = '0.0.1'
    event_buffered_local_file = "/tmp/fault_local_%s.json" % EVENT_VER
    event_buffered_pending_file = "/tmp/fault_pending_%s.json" % EVENT_VER

    event_saved_local_file = "/rpd/log/fault_local_%s.json" % EVENT_VER
    event_saved_pending_file = "/rpd/log/fault_pending_%s.json" % EVENT_VER

    BUFFERED_LOCAL = 1
    BUFFERED_PENDING = 2

    BUFFERED_TYPE = {
        BUFFERED_LOCAL: event_buffered_local_file,
        BUFFERED_PENDING: event_buffered_pending_file,
    }

    @classmethod
    def restore_log(cls):
        """restore log message."""
        if os.path.exists(cls.event_saved_local_file):
            shutil.move(cls.event_saved_local_file, cls.event_buffered_local_file)
        if os.path.exists(cls.event_saved_pending_file):
            shutil.move(cls.event_saved_pending_file, cls.event_buffered_pending_file)

    @classmethod
    def read_log(cls, buffered):
        """read log message."""

        ret_value = RpdEventOrderedBuffer.read_json(cls.BUFFERED_TYPE[buffered])
        if os.path.exists(cls.BUFFERED_TYPE[buffered]):
            os.remove(cls.BUFFERED_TYPE[buffered])
        return ret_value

    @classmethod
    def write_log(cls, data, buffered):
        """write a dict to log file."""

        if not isinstance(data, dict):
            return
        RpdEventOrderedBuffer.write_json(cls.BUFFERED_TYPE[buffered], data)

    @staticmethod
    def store_fault_message(msg, operational=False):
        """store fault message to local or pending. operational."""

        ret_value = True, 'success'
        file_list = []
        try:
            event_index = msg.index(":")

            event = msg[0: event_index]
            text = msg[event_index + 1:]

            event = event.strip()
            text = text.strip()

            event_dec = "%d" % eval(event)

            if eval(event) in RPD_EVENT_DICT:
                event_lvl = RPD_EVENT_DICT[eval(event)][0][0]

                if RpdEventConfig.GLOBAL_CONFIG["Control"][str(event_lvl)] & RpdEventConfig.PENDING_MARK:
                    file_list.append(EventCommonOperation.BUFFERED_PENDING)
                if RpdEventConfig.GLOBAL_CONFIG["Control"][str(event_lvl)] & RpdEventConfig.LOCAL_MAK:
                    file_list.append(EventCommonOperation.BUFFERED_LOCAL)

                for buffered in file_list:
                    RpdEventOrderedBuffer.store_event(buffered, event_dec, text, operational)
            else:
                ret_value = False, "unrecognised event %s" % event
            return ret_value
        except Exception as e:
            return False, "store fault management message fail, %s" % str(e)

    @staticmethod
    def event_id_format(event_id):
        """
        This func reformats event_id to align with OpenRPD spec, 
        where id starts with 0x8009 means vendor-specific id of Cisco. 
        These ids should be in hexdecimal form for recognition.
        """
        if (event_id >= 0x80090000) and (event_id <= 0x8009ffff):
            return hex(event_id)
        else:
            return str(event_id)

    @staticmethod
    def construct_event_msg(event, *args):
        """construct the text for fault management.

        :param event: event defined by CM-SP-OSSI-I04.
        :param args: text message parameters.
        :return:

        """

        try:
            if event not in RPD_EVENT_DICT:
                msg = "Event id[%d] is unexpected" % event
            else:
                msg = RPD_EVENT_DICT[event][1] % args
            return EventCommonOperation.event_id_format(event) + ":" + msg
        except Exception as e:
            msg = "Got an Exception: %s" % str(e)
            return msg
