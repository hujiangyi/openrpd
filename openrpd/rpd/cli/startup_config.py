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


"""It used for parse startup config when system bootup"""
import os
from cli.cmd_rpd.cmd_rpd import CmdRpd
from cli.basic_cfg.basic_cli import BasicCli
from cli.cli_framework_def import DEF_CONF_FILE_NAME


def start_up(config_file=None):
    """parse startup config file"""
    cli = CmdRpd(config_file)
    if cli.rphy_cfg:
        if os.path.exists(cli.rphy_cfg):
            BasicCli(cli)
            cli.config_db.flushdb()
            cli.parse_startup_config()
        else:
            try:
                filep = open(cli.rphy_cfg, 'w')
                filep.close()
                cli.config_db.flushdb()
            except IOError, err:
                print 'Create startup config file fail,', err


if __name__ == '__main__':
    start_up(DEF_CONF_FILE_NAME)
