#
# Copyright (c) 2017 Cisco and/or its affiliates, and
#                    Cable Television Laboratories, Inc. ("CableLabs")
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
import collections
from datetime import datetime
from time import time


class ManagerProvisionStateMachineRecord(object):
    """provision statistics"""
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.statistics = collections.OrderedDict()

    def cleanup(self):
        self.statistics = collections.OrderedDict()

    @staticmethod
    def fmt_timestamp(timestamp):
        return datetime.utcfromtimestamp(timestamp).strftime('%Y %b %d %H:%M:%S:%f')

    def update(self, manager_instance, event):
        """update the statistics info.

        :param manager_instance
        :param event: fsm event instance
        :return:
        """

        mgr_id = manager_instance.mgr_id
        current = time()
        self.statistics[self.fmt_timestamp(current)] = {"src": event.src, "dst": event.dst,
                                                        "event": event.event, 'id': mgr_id}
