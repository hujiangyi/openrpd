# Copyright (c) 2018 Cisco and/or its affiliates, and
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

from rpd.confdb.rpd_redis_db import DBRecord


class RpdEnetRec(DBRecord):
    def __init__(self, index=None):
        self.index = index

        self.ifName = ""
        self.ifDescr = ""
        self.ifAlias = ""
        self.ifPhysAddress = ""
        self.ifType = 6
        self.ifMTU = 0
        self.ifAdminStatus = 2
        self.ifOperStatus = 2
        self.ifLastChange = 0
        self.ifConnectorPresent = 2
        self.ifHighSpeed = 0
        self.ifPromiscuousMode = 2
        self.ifLinkUpDownTrapEnable = 2
        self.ifInOctets = 0
        self.ifInUnicastOctets = 0
        self.ifInMulticastOctets = 0
        self.ifInFrames = 0
        self.ifInUnicastFrames = 0
        self.ifInMulticastFrames = 0
        self.ifInBroadcastFrames = 0
        self.ifInErrors = 0
        self.ifOutOctets = 0
        self.ifOutUnicastOctets = 0
        self.ifOutMulticastOctets = 0
        self.ifOutFrames = 0
        self.ifOutUnicastFrames = 0
        self.ifOutMulticastFrames = 0
        self.ifOutBroadcastFrames = 0

    def updateRec(self, item):
        if 'EnetPortIndex' in item:
            self.index = item['EnetPortIndex']
        if 'ifName' in item:
            self.ifName = item['ifName']
        if 'ifDescr' in item:
            self.ifDescr = item['ifDescr']
        if 'ifAlias' in item:
            self.ifAlias = item['ifAlias']
        if 'ifPhysAddress' in item:
            self.ifPhysAddress = item['ifPhysAddress']
        if 'ifType' in item:
            self.ifType = item['ifType']
        if 'ifMTU' in item:
            self.ifMTU = item['ifMTU']
        if 'ifAdminStatus' in item:
            self.ifAdminStatus = item['ifAdminStatus']
        if 'ifOperStatus' in item:
            self.ifOperStatus = item['ifOperStatus']
        if 'ifLastChange' in item:
            self.ifLastChange = item['ifLastChange']
        if 'ifConnectorPresent' in item:
            self.ifConnectorPresent = item['ifConnectorPresent']
        if 'ifHighSpeed' in item:
            self.ifHighSpeed = item['ifHighSpeed']
        if 'ifPromiscuousMode' in item:
            self.ifPromiscuousMode = item['ifPromiscuousMode']
        if 'ifLinkUpDownTrapEnable' in item:
            self.ifLinkUpDownTrapEnable = item['ifLinkUpDownTrapEnable']
        if 'ifInOctets' in item:
            self.ifInOctets = item['ifInOctets']
        if 'ifInUnicastOctets' in item:
            self.ifInUnicastOctets = item['ifInUnicastOctets']
        if 'ifInMulticastOctets' in item:
            self.ifInMulticastOctets = item['ifInMulticastOctets']
        if 'ifInFrames' in item:
            self.ifInFrames = item['ifInFrames']
        if 'ifInUnicastFrames' in item:
            self.ifInUnicastFrames = item['ifInUnicastFrames']
        if 'ifInMulticastFrames' in item:
            self.ifInMulticastFrames = item['ifInMulticastFrames']
        if 'ifInBroadcastFrames' in item:
            self.ifInBroadcastFrames = item['ifInBroadcastFrames']
        if 'ifInErrors' in item:
            self.ifInErrors = item['ifInErrors']
        if 'ifOutOctets' in item:
            self.ifOutOctets = item['ifOutOctets']
        if 'ifOutUnicastOctets' in item:
            self.ifOutUnicastOctets = item['ifOutUnicastOctets']
        if 'ifOutMulticastOctets' in item:
            self.ifOutMulticastOctets = item['ifOutMulticastOctets']
        if 'ifOutFrames' in item:
            self.ifOutFrames = item['ifOutFrames']
        if 'ifOutUnicastFrames' in item:
            self.ifOutUnicastFrames = item['ifOutUnicastFrames']
        if 'ifOutMulticastFrames' in item:
            self.ifOutMulticastFrames = item['ifOutMulticastFrames']
        if 'ifOutBroadcastFrames' in item:
            self.ifOutBroadcastFrames = item['ifOutBroadcastFrames']

    def delete_all(self):
        for rec in self.get_all():
            rec.delete()
