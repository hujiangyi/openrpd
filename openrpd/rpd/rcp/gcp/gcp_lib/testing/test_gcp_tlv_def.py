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

from rpd.rcp.gcp.gcp_lib.gcp_tlv_def import TLVDescriptionSet, TLVDesc
from rpd.rcp.gcp.gcp_lib.gcp_data_description import *

# global GCP TLV databases
Testing_GCP_TLV_SET = TLVDescriptionSet(
    hierarchy_name="Testing_TLVs")
Testing_GCP_TLV_SET_NTF_Error = TLVDescriptionSet(
    hierarchy_name="Testing_GCP_TLVs")
Testing_GCP_TLV_SET_NTF_REQ = TLVDescriptionSet(
    hierarchy_name="Testing_GCP_TLVs")


class TEST_TLV(TLVDesc):
    """Implements description of the GCP TLV data format.

    Used to enforce usage of 1B long TLV length field for GCP TLVs.

    """

    def __init__(self, tlv_id, name, parent=None,
                 format_str=None, length=None, constraint=None,
                 rw=DataDescription.RW_FLAG_rw):
        super(TEST_TLV, self).__init__(tlv_id, name, parent, format_str,
                                       length, constraint,
                                       length_field_len=1, rw=rw)


TestCapabilities = TEST_TLV(43, "TestCapabilities",
                            parent=(Testing_GCP_TLV_SET,
                                    Testing_GCP_TLV_SET_NTF_Error,
                                    Testing_GCP_TLV_SET_NTF_REQ),
                            rw=DataDescription.RW_FLAG_row)
TEST_TLV(32, "NumBdirPorts", TestCapabilities, "!B",
         rw=DataDescription.RW_FLAG_r)
TEST_TLV(43, "NumDsRfPorts", TestCapabilities, "!B",
         rw=DataDescription.RW_FLAG_r)
TEST_TLV(34, "SupportsUdpEncap", TestCapabilities, "!B",
         rw=DataDescription.RW_FLAG_r, constraint=BOOL_CONSTR)

LCR = TEST_TLV(20, "LcceChannelReachability", TestCapabilities,
               rw=DataDescription.RW_FLAG_row)
TEST_TLV(2, "ChannelType", LCR, "!B", rw=DataDescription.RW_FLAG_key)

TestIdentification = TEST_TLV(54, "TestIdentification", TestCapabilities,
                              rw=DataDescription.RW_FLAG_row)
TEST_TLV(13, "VendorName", TestIdentification, "var",
         rw=DataDescription.RW_FLAG_r, constraint=StringLenConstraint(255))

TestRpdIdentification = TEST_TLV(31, "TestRpdIdentification", TestCapabilities,
                                 rw=DataDescription.RW_FLAG_row)
TEST_TLV(23, "DeviceMacAddress", TestRpdIdentification, "B_SEQ",
         rw=DataDescription.RW_FLAG_r, constraint=MAC_CONSTR)

AllocDsRes = TEST_TLV(22, "AllocDsChanResources", TestCapabilities,
                      rw=DataDescription.RW_FLAG_row)
TEST_TLV(1, "DsPortIndex", AllocDsRes, "!B", rw=DataDescription.RW_FLAG_key)
TEST_TLV(2, "AllocatedDsOfdmChannels", AllocDsRes, "!H",
         rw=DataDescription.RW_FLAG_r)
TEST_TLV(3, "AllocatedDsScQamChannels", AllocDsRes, "!H",
         rw=DataDescription.RW_FLAG_r)

TestCcapCoreId = \
    TEST_TLV(42, "TestCcapCoreId",
             parent=(Testing_GCP_TLV_SET,
                     Testing_GCP_TLV_SET_NTF_Error),
             rw=DataDescription.RW_FLAG_row)
TEST_TLV(32, "Index", TestCcapCoreId, "!B", rw=DataDescription.RW_FLAG_key)
TEST_TLV(34, "CoreIpAddress", TestCcapCoreId, "B_SEQ",
         length=(DataDescription.B_SEQ_IPv4_LEN,
                 DataDescription.B_SEQ_IPv6_LEN))
