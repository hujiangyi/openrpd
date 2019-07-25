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

"""Define macroes which used by CLI"""
SET_CONFIG_FLAG = 1
DEL_CONFIG_FLAG = (1 << 1)
SHOW_CONFIG_FLAG = (1 << 2)

FUNC_ARG_TYPE_WORD = 'WORD'
FUNC_ARG_TYPE_LINE = 'LINE'
FUNC_ARG_TYPE_NUMBER = 'NUMBER'
FUNC_ARG_TYPE_IP = 'A.B.C.D'
FUNC_ARG_TYPE_MAC = 'H.H.H'

HIDDEN_MODE = 1
USER_MODE = (1 << 1)
ADMIN_MODE = (1 << 2)
CONFIG_MODE = (1 << 3)
CONFIG_INTERFACE_MODE = (1 << 4)
CONFIG_INTERFACE_SUB_MODE = (1 << 5)
MAX_MODE = CONFIG_INTERFACE_SUB_MODE
MIN_MODE = HIDDEN_MODE

USER_MODE_STRING = '>'
ADMIN_MODE_STRING = '#'
CONFIG_MODE_STRING = '(config)#'
CONFIG_INTERFACE_MODE_STRING = '(config-if)#'
CONFIG_INTERFACE_SUB_MODE_STRING = '(config-if-sub)#'

ADMIN_MODE_PREFIX = ['enable']
CONFIG_MODE_PREFIX = ['enable', 'configure', 'terminal']
CONFIG_INTERFACE_MODE_PREFIX = ['enable', 'configure',
                                'terminal', 'interface', 'loopback',
                                FUNC_ARG_TYPE_NUMBER]
CONFIG_INTERFACE_SUB_MODE_PREFIX = CONFIG_INTERFACE_MODE_PREFIX + ['sub', FUNC_ARG_TYPE_NUMBER]

DEF_HOST_NAME = 'R-PHY'
DEF_CONF_FILE_NAME = '/mnt/uspace/rphy.conf'
DEF_INTRO = '\n\n        Welcome to R-PHY\n\n'
CONF_INDENT = 2
CLI_MODULE_NAME = 'CLI'

# ipc config
PROVISION_IPC = 1
IKEV2_IPC = 2
L2TP_IPC = 3
GCP_IPC = 4
MACSEC_IPC = 5

IPC_CONF_DICT = {
    PROVISION_IPC: r"/tmp/rpd_provision_manager_api.sock",
    IKEV2_IPC: r"/tmp/zmq-ikev2.ipc",
    L2TP_IPC: r"/tmp/l2tpDaemonSock",
    GCP_IPC: r"/tmp/zmq-gcp.ipc",
    MACSEC_IPC: r"/tmp/zmq-8021x.ipc",
}
