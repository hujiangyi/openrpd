#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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
This module define the redis Key macro
"""

# CLI Basic config key
ENABLE_PWD = "enable_pwd"
HOST_NAME = "host_name"
BANNER = "banner_login"
AUTHORIZED_DIR = "authorized_dir"
USER_PASS = "username_password"

# Redis key
REDIS_SERVER_PORT = 6379
GCP_DB = 0
DHCP_DB = 2
CONFIG_DB = 3
CLI_DB = 10
UNIX_SOCKET_PATH = "/tmp/redis.sock"
