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

from rpd.common.rpd_rsyslog import AddLoggerToClass
from rpd.common.utils import SysTools
from collections import OrderedDict
from datetime import datetime
from time import time


class ProvisionStateMachineRecord(object):
    """provision statistics"""
    __metaclass__ = AddLoggerToClass

    RECORD_CCAP_CORE_CNT_MAX = 20
    RECORD_CORE_ID_PER_CCAP_CORE_MAX = 5
    RECORD_EVENT_PER_CORE_ID_MAX = 100

    RPD_MAC = SysTools.get_sys_mac_address()

    def __init__(self):
        self.statistics = dict()

    def cleanup(self):
        self.statistics = dict()

    @staticmethod
    def fmt_timestamp(timestamp):
        return datetime.utcfromtimestamp(timestamp).strftime('%Y %b %d %H:%M:%S:%f')

    def update(self, core_instance, event):
        """update the statistics info.

        :param core_instance: CCAP core instance
        :param event: fsm event instance
        :return:
        """

        if SysTools.is_vrpd():
            self.RPD_MAC = SysTools.get_mac_address(core_instance.interface)

        ccap_core_id = core_instance.ccap_core_id
        added_by = core_instance.added_by
        item = "{}/{}".format(core_instance.interface, core_instance.ccap_core_network_address)

        # limit the core ip count to 20 each node
        if len(self.statistics) >= self.RECORD_CCAP_CORE_CNT_MAX:
            self.logger.warning("Ccap core already exceed the max count %d, ignore %s ",
                                self.RECORD_CCAP_CORE_CNT_MAX, item)
            return

        if item not in self.statistics:
            self.statistics[item] = OrderedDict()
        if ccap_core_id not in self.statistics[item]:
            self.statistics[item][ccap_core_id] = OrderedDict()

        # limit the core id count to 5 under each core ip
        while len(self.statistics[item]) >= self.RECORD_CORE_ID_PER_CCAP_CORE_MAX:
            self.statistics[item].popitem(last=False)

        # limit the event count to 100 each core id
        while len(self.statistics[item][ccap_core_id]) >= self.RECORD_EVENT_PER_CORE_ID_MAX:
            self.statistics[item][ccap_core_id].popitem(last=False)

        current = time()
        self.statistics[item][ccap_core_id].update(
            {self.fmt_timestamp(current): {"interface": core_instance.interface,
                                           "core-ip": core_instance.ccap_core_network_address,
                                           "mac": self.RPD_MAC, "src": event.src, "dst": event.dst,
                                           "event": event.event, "Added-By": added_by}})





