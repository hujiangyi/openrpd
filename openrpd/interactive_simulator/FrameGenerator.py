# Copyright (c) VECTOR TECHNOLOGIES SA Gdynia, Poland, and
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
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.rcp.gcp.gcp_lib.gcp_object import GCPEncodeError
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.gcp.gcp_lib.gcp_data_description import GCPInvalidDataValueError
from rpd.rcp.rcp_lib.rcp import RCPPacketBuilder
from rpd.rcp.rcp_lib.rcp import RCPPacketBuildError
from rpd.common.rpd_logging import AddLoggerToClass
from time import time


class ChannelTypeNotFound(Exception):
    pass


class InvalidAttributeValue(Exception):
    pass


class RequiredAttributeNotPresent(Exception):
    pass


class Frame(object):

    def __init__(self, packet):
        self.id = packet.transaction_identifier
        self.content = self.encode_packet(packet)
        self.send_time = 0
        self.receive_time = 0

    def prepare_to_send(self):
        self.start_timer()

    def received(self):
        self.stop_timer()

    def start_timer(self):
        self.send_time = time()

    def stop_timer(self):
        self.receive_time = time()

    def encode_packet(self, packet, offset=0):
        try:
            buf_data_len = packet.compute_buffer_len()
            result = packet.encode(
                buffer=None, offset=offset, buf_data_len=buf_data_len)
        except GCPEncodeError:
            print "Failed to encode packet"

        return packet.get_data_sub_buffer(offset)


class FrameGenerator(object):
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.builder = RCPPacketBuilder()
        self.transaction_id = 0
        self.rcp_sequence_id = 0

    def transaction_incrementator(f):
        def wrapped(self, *args, **kwargs):
            self.builder.clear()
            self.transaction_id += 1
            self.rcp_sequence_id += 1
            return f(self, *args, **kwargs)
        return wrapped

    @staticmethod
    def parse_value(value):
        try:
            return int(value)
        except ValueError:
            return value

    @staticmethod
    def set_attribute(attribute, key, value):
        if hasattr(attribute, key):
            value = FrameGenerator.parse_value(value)
            try:
                if value != -1:
                    getattr(attribute, key).set_val(value)
                else:
                    getattr(attribute, key).set_is_used()
            except GCPInvalidDataValueError:
                print "-- Invalid value {} for {}. Attribute has been skipped. --".format(value, key)
            return True
        else:
            return False

    @staticmethod
    def find_repeated_parent(repeated_map, name):
        for key, value in repeated_map.iteritems():
            if name in value:
                return key
        return ""

    @staticmethod
    def create_new_repeated(root, repeated_name):
        if hasattr(root, repeated_name):
            new_repeated = getattr(root, repeated_name).add_new_repeated()
            new_repeated.set_is_used()
            return new_repeated
        return None

    def handle_repeated_attributes(self, parent_attr, repeated_dict, created_repeated, attr_name, root):
        for key, value in repeated_dict.iteritems():
            repeated_key = "{}{}".format(parent_attr, key)
            if repeated_key not in created_repeated:
                new_repeated = self.create_new_repeated(root, parent_attr)
                if new_repeated is not None:
                    self.set_attribute(new_repeated, attr_name, value)
                    created_repeated[repeated_key] = new_repeated
            else:
                self.set_attribute(created_repeated[repeated_key], attr_name, value)

    def set_frame_attributes(self, root, attributes):
        for key, value in attributes.iteritems():
            if type(value) is not dict:
                self.set_attribute(root, key, value)

    @staticmethod
    def set_nested_attribute(root_attribute, created_attributes, attribute, value):
        path = ""
        while attribute:
            current_attribute = attribute.pop(0)
            name = current_attribute["name"]
            if not current_attribute["is_repeated"] and hasattr(root_attribute, name):
                if len(attribute) == 0:
                    FrameGenerator.set_attribute(root_attribute, name, value)
                else:
                    root_attribute = getattr(root_attribute, name)
                    path += "{}.".format(name)
            elif hasattr(root_attribute, name):
                repeated_name = "{}[{}]".format(name, current_attribute["index"])
                root_attribute = getattr(root_attribute, name)
                path += repeated_name
                if path not in created_attributes:
                    created_attributes[path] = root_attribute.add_new_repeated()
                    created_attributes[path].set_is_used()
                root_attribute = created_attributes[path]
                path += "."
            else:
                print "Can't find attribute", name

    @transaction_incrementator
    def rfport_config(self, **kwargs):
        self.builder.add_packet(transaction_id=self.transaction_id)

        self.builder.add_gcp_msg(
            gcp_msg_def.DataStructREQ, self.transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(self.rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)
        # mandatory attributes

        # at least one rcp sequence attribute has to be set
        seq = self.builder.last_rcp_sequence
        sub_tlv = seq.RfPort.add_new_repeated()
        sub_tlv.set_is_used()
        FrameGenerator.set_attribute(sub_tlv.RfPortSelector, "RfPortIndex", kwargs.pop("RfPortIndex", 0))
        FrameGenerator.set_attribute(sub_tlv.RfPortSelector, "RfPortType", kwargs.pop("RfPortType", 1))
        ds_rf_port = sub_tlv.DsRfPort
        nested_args = kwargs.pop("nested_attrs", [])
        created = {}
        self.set_frame_attributes(sub_tlv, kwargs)
        self.set_frame_attributes(ds_rf_port, kwargs)

        for nested in nested_args:
            try:
                FrameGenerator.set_nested_attribute(sub_tlv, created, nested[0], nested[1])
            except GCPInvalidDataValueError:
                print "-- invalid value: {} --".format(nested[1])

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return Frame(pkts[0])

    @transaction_incrementator
    def rfchannel_config(self, **kwargs):
        self.builder.add_packet(transaction_id=self.transaction_id)

        self.builder.add_gcp_msg(
            gcp_msg_def.DataStructREQ, self.transaction_id)
        self.builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.builder.add_rcp_seq(self.rcp_sequence_id,
                                 rcp_tlv_def.RCP_OPERATION_TYPE_WRITE,
                                 gpb_config=None, unittest=True)
        self.builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Port.set_val(0)
        self.builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        self.builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)
        # at least one rcp sequence attribute has to be set

        seq = self.builder.last_rcp_sequence
        sub_tlv = seq.RfChannel.add_new_repeated()
        sub_tlv.set_is_used()

        nested_args = kwargs.pop("nested_attrs", [])
        self.set_frame_attributes(sub_tlv, kwargs)

        created = {}
        for nested in nested_args:
            try:
                FrameGenerator.set_nested_attribute(sub_tlv, created, nested[0], nested[1])
            except GCPInvalidDataValueError:
                print "-- invalid value: {} --".format(nested[1])

        pkts = self.builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return Frame(pkts[0])
