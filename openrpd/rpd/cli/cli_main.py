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


"""The entry for CLI"""
import redis
import time
import termios
import os
import psutil
import sys
import signal
import rpd.python_path_resolver
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from cli.cmd_rpd.cmd_rpd import CmdRpd
from cli.basic_cfg.basic_cli import BasicCli
from cli.provision_cli.provision_cli import ProvisionCli
from cli.ikev2_cli.ikev2_cli import Ikev2Cli
from cli.macsec_cli.macsec_cli import MacsecCli
from cli.l2tp_cli.l2tp_cli import L2tpCli
from cli.gcp_cli.gcp_cli import GcpCli
from cli.ssd_cli.ssd_cli import SsdCli
from cli.cli_framework_def import DEF_CONF_FILE_NAME
from cli import db_defs


class RPDCLI():
    """
    This RPDCLI class.
    """

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        return

    def ignore_signal(self, signo, stack):
        pass

    def orphan_cli_cleanup(self):
        for proc in psutil.process_iter():
            try:
                cli_proc = 'cat ' + '/proc/' + str(proc.pid) + '/cmdline'
                cli_cmdline = os.popen(cli_proc).read()
                if cli_cmdline.find('cli_main.py') >= 0:
                    cli_ppid = psutil.Process(proc.pid).ppid()
                    if cli_ppid == 1:
                        os.kill(proc.pid, signal.SIGKILL)
            except psutil.NoSuchProcess:
                pass

    def init_signal(self):
        signal.signal(signal.SIGTSTP, self.ignore_signal)
        signal.signal(signal.SIGQUIT, self.ignore_signal)
        signal.signal(signal.SIGTSTP, self.ignore_signal)
        signal.signal(signal.SIGTERM, self.ignore_signal)
        signal.signal(signal.SIGABRT, self.ignore_signal)
        signal.signal(signal.SIGINT, self.ignore_signal)
        pass

    def init_termios(self):
        """termios init"""
        fd = sys.stdin.fileno()
        attr = termios.tcgetattr(fd)
        attr[3] = attr[3] | termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, attr)

    def create_cli(self, conf_file=None):
        """setup cli."""

        cli_db = redis.StrictRedis(unix_socket_path=db_defs.UNIX_SOCKET_PATH,
                                   db=db_defs.CLI_DB)
        while True:
            try:
                cli_db.exists(db_defs.ENABLE_PWD)
                break
            except redis.exceptions.ConnectionError:
                time.sleep(1)
                continue

        cli = CmdRpd(conf_file)
        allow = cli.authenticate()
        if allow:
            BasicCli(cli)
            SsdCli(cli)
            GcpCli(cli)
            ProvisionCli(cli)
            Ikev2Cli(cli)
            MacsecCli(cli)
            L2tpCli(cli)
            cli.cmdloop(cli.intro)


if __name__ == '__main__':
    # setup the logging.
    setup_logging("CLI", "cli.log")
    cli = RPDCLI()
    cli.create_cli(DEF_CONF_FILE_NAME)
