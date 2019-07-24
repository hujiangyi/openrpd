#!/bin/sh
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

echo "Starting OpenRPD "
/usr/bin/python -m rpd.provision.manager.src.manager_main 1>/dev/null 2>>/rpd/log/openrpd_traceback.log || { echo "$(date):manager_main sig:$?" >> /rpd/log/resetlog; sync; reboot || reboot -f; }
