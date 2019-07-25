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

from collections import namedtuple

from rpd.rcp.gcp.gcp_lib.gcp_data_description import *


class GCPFieldConstructError(GCPInternalException):
    """This exception is raised in case of invalid message fields during
    initialization of the descriptions."""


GCP_Return_Codes = {
    # Filled from GCP_ReturnCode in format "id : GCP_ReturnCode"
}

_GCP_RC = namedtuple('GCP_RC', 'rc name')


class GCP_RC(_GCP_RC):

    def __new__(cls, rc, name):
        self = super(GCP_RC, cls).__new__(cls, rc, name)
        GCP_Return_Codes[rc] = self
        return self


# GCP Return codes - Section 6.4 of GCP Specification
GCP_RC_SUCCESS = GCP_RC(0, "Message Successful")
GCP_RC_UNSUPPORTED = GCP_RC(1, "Unsupported Message")
GCP_RC_INV_LENGTH = GCP_RC(2, "Illegal Message Length")
GCP_RC_INV_TRAN_ID = GCP_RC(3, "Illegal Transaction ID")
GCP_RC_INV_MODE = GCP_RC(4, "Illegal Mode")
GCP_RC_INV_PORT = GCP_RC(5, "Illegal Port")
GCP_RC_INV_CHANNEL = GCP_RC(6, "Illegal Channel")
GCP_RC_INV_COMMAND = GCP_RC(7, "Illegal Command")
GCP_RC_INV_VENDOR_ID = GCP_RC(8, "Illegal Vendor ID")
GCP_RC_INV_VENDOR_INDEX = GCP_RC(9, "Illegal Vendor Index")
GCP_RC_INV_ADDRESS = GCP_RC(10, "Illegal Address")
GCP_RC_INV_DATA = GCP_RC(11, "Illegal Data Value")
GCP_RC_MESSAGE_FAILURE = GCP_RC(12, "Message Failure")
GCP_RC_SLAVE_FAILURE = GCP_RC(255, "Slave Device Failure")
# TODO: User defined RCs -- are there any?


GDM_CMD_SET = {
    # Filled from GDM command in format "id : GDM_COMMAND"
}
_GDM_CMD = namedtuple('GDM_CMD', 'cmd name')


class GDM_CMD(_GDM_CMD):

    def __new__(cls, cmd, name):
        self = super(GDM_CMD, cls).__new__(cls, cmd, name)
        GDM_CMD_SET[cmd] = self
        return self


# GDM commands - Section B.2.3 of GCP Specification
GDM_NULL = GDM_CMD(0, 'Null')
GDM_COLD_RESET = GDM_CMD(1, 'Cold Reset')
GDM_WARM_RESET = GDM_CMD(2, 'Warm Reset')
GDM_STANDBY = GDM_CMD(3, 'Standby')
GDM_WAKE_UP = GDM_CMD(4, 'Wake Up')
GDM_POWER_DOWN = GDM_CMD(5, 'Power Down')
GDM_POWER_UP = GDM_CMD(6, 'Power Up')


class GCP_MSG_DescriptionSet(DescriptionSet):
    """Holds definitions of all supported GCP messages."""

    def __init__(self):
        super(GCP_MSG_DescriptionSet, self).__init__(
            hierarchy_name="GCP_MSG_Base")


# global reference to the set of descriptions of supported GCP messages
GCP_MSG_SET = GCP_MSG_DescriptionSet()


class MSGFieldsSet(object):
    """Message fields and supported TLVs holder."""
    # static variable
    _last_object = None

    def __init__(self, message_id, message_name):
        if message_id is None or message_name is None:
            raise AttributeError("Unspecified message id or message name")

        self.fields = []
        self.tlvs = DescriptionSet(message_name + "_TLVs")
        self.name = message_name
        self.message_id = message_id

        GCP_MSG_SET.child_dict_by_id[self.message_id] = self
        GCP_MSG_SET.child_dict_by_name[self.name] = self

        MSGFieldsSet._last_object = self
        globals().update({self.name: self.message_id})

    @staticmethod
    def add_field(field):
        """Appends message field for the last instantiated MSGObject."""
        if MSGFieldsSet._last_object is None:
            raise GCPFieldConstructError()
        MSGFieldsSet._last_object.fields.append(field)

    def add_tlv_set(self, tlv_set):
        """Adds set of TLV DataDescriptions to be supported in the GCP
        message."""
        self.tlvs.update_descriptions(tlv_set)


class MSGFieldDesc(DataDescription):
    """Implements description of the data format of the message fields."""

    def __init__(self, name, format_str, val_constraints=None):
        if None is name:
            raise AttributeError("Unspecified message field's name")

        DataDescription.__init__(self, None, name,
                                 format_str, None, val_constraints)
        MSGFieldsSet.add_field(self)


#
# Construction of message fields
#
# Each of MSGFieldDesc and MessageTLV instances belong to a MSGObject.
# The relationship is defined by order of object creation. When a MSGObject
# is created each MSGFieldDesc/MessageTLV created after that is assigned to
# that MSGObject.
#
# Construction of a MSGFieldDesc or MessageTLV before any MSGObject will
# result in GCPFieldConstructError exception thrown.
#
M_NotifyREQ = MSGFieldsSet(2, "NotifyREQ")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("Mode", "!B", FlagsConstraint(0b11000000))
MSGFieldDesc("Status", "!B", RangeConstraint(0, 6))
MSGFieldDesc("EventCode", "!I")

# Example of GCP TLV association with lastly created MSGObject
# MessageTLV(GCP_TLV_instance)

M_NotifyRSP = MSGFieldsSet(3, "NotifyRSP")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("Mode", "!B", FlagsConstraint(0))
MSGFieldDesc("EventCode", "!I")

M_ManagementREQ = MSGFieldsSet(4, "ManagementREQ")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("Mode", "!B", FlagsConstraint(0b10000000))
MSGFieldDesc("Port", "!H")
MSGFieldDesc("Channel", "!H")
MSGFieldDesc("Command", "!B", RangeConstraint(0, 6))

M_ManagementRSP = MSGFieldsSet(5, "ManagementRSP")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("Mode", "!B", FlagsConstraint(0))
MSGFieldDesc("ReturnCode", "!B", EnumConstraint([GCP_RC_SUCCESS.rc,
                                                 GCP_RC_UNSUPPORTED.rc,
                                                 GCP_RC_MESSAGE_FAILURE.rc]))

M_DataStructREQ = MSGFieldsSet(6, "DataStructREQ")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("Mode", "!B", FlagsConstraint(0))
MSGFieldDesc("Port", "!H")
MSGFieldDesc("Channel", "!H")
MSGFieldDesc("VendorID", "!I")
MSGFieldDesc("VendorIndex", "!B")

M_DataStructRSP = MSGFieldsSet(7, "DataStructRSP")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("Mode", "!B", FlagsConstraint(0))
MSGFieldDesc("Port", "!H")
MSGFieldDesc("Channel", "!H")
MSGFieldDesc("VendorID", "!I")
MSGFieldDesc("VendorIndex", "!B")

M_NotifyError = MSGFieldsSet(131, "NotifyError")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("ReturnCode", "!B", EnumConstraint([GCP_RC_SUCCESS.rc,
                                                 GCP_RC_INV_LENGTH.rc,
                                                 GCP_RC_INV_TRAN_ID.rc,
                                                 GCP_RC_INV_MODE.rc,
                                                 GCP_RC_MESSAGE_FAILURE.rc,
                                                 GCP_RC_SLAVE_FAILURE.rc]))

M_ManagementError = MSGFieldsSet(133, "ManagementError")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("ReturnCode", "!B", EnumConstraint([GCP_RC_SUCCESS.rc,
                                                 GCP_RC_UNSUPPORTED.rc,
                                                 GCP_RC_INV_LENGTH.rc,
                                                 GCP_RC_INV_TRAN_ID.rc,
                                                 GCP_RC_INV_MODE.rc,
                                                 GCP_RC_INV_PORT.rc,
                                                 GCP_RC_INV_CHANNEL.rc,
                                                 GCP_RC_INV_COMMAND.rc,
                                                 GCP_RC_MESSAGE_FAILURE.rc,
                                                 GCP_RC_SLAVE_FAILURE.rc]))

M_DataStructError = MSGFieldsSet(135, "DataStructError")
MSGFieldDesc("TransactionID", "!H")
MSGFieldDesc("ExceptionCode", "!B", EnumConstraint([GCP_RC_SUCCESS.rc,
                                                    GCP_RC_UNSUPPORTED.rc,
                                                    GCP_RC_INV_LENGTH.rc,
                                                    GCP_RC_INV_TRAN_ID.rc,
                                                    GCP_RC_INV_MODE.rc,
                                                    GCP_RC_INV_PORT.rc,
                                                    GCP_RC_INV_CHANNEL.rc,
                                                    GCP_RC_INV_VENDOR_ID.rc,
                                                    GCP_RC_INV_VENDOR_INDEX.rc,
                                                    GCP_RC_MESSAGE_FAILURE.rc,
                                                    GCP_RC_SLAVE_FAILURE.rc]))
