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


"""basic command for CLI"""
import fcntl
import os
from cli import cli_framework_def as cli_def
from cli import db_defs
from datetime import datetime
from getpass import getpass


class BasicCli(object):
    """Basic cli class."""

    PING_REPEAT_MAX_COUNT = 2147483647
    PING_REPEAT_MIN_COUNT = 1
    PING_REPEAT_COUNT = '<1-2147483647>'
    SSH_TIMEOUT = '<1-30>'
    SSH_CONFIG_FILE = '/etc/config/dropbear'

    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli
        '''
        'RPD_IMAGE_VERSION', 'RPD_XX', 'RPD_BRANCH', 'OPENRPD_BRANCH',
        'SERESRPD_BRANCH', 'RPD_TAG', 'RPD_BUILD_TIME', 'RPD_TYPE'
        '''
        self.rpd_info = dict()
        if os.path.exists('/etc/rpd_image_info'):
            fd = open('/etc/rpd_image_info')
            lines = fd.readlines()
            fd.close()
            for line in lines:
                pair = line.split("=")
                self.rpd_info.update({pair[0]: pair[1].strip()})

        self.cli_table = (
            ('enable', 'Turn on privileged commands',
                self.enable_admin_mode, None, cli_def.USER_MODE),

            ('show', 'Show running system information',
                None, None, cli_def.ADMIN_MODE),
            ('clear', 'Clear running system information',
                None, None, cli_def.ADMIN_MODE),

            ('exit', 'Exit from the SSH',
             self.exit_mode, None, cli_def.USER_MODE),

            ('exit', 'Exit from the EXEC',
             self.exit_mode, None, cli_def.ADMIN_MODE),

            ('shell', 'enter shell',
             BasicCli.run_shell, None, cli_def.ADMIN_MODE),

            ('ping', 'ping',
             None, None, cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_IP, 'ip address',
             BasicCli.ping, ['ping'], cli_def.ADMIN_MODE),


            ('repeat', 'specify repeat count',
             None, ['ping', cli_def.FUNC_ARG_TYPE_IP], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_NUMBER, 'Repeat count,' + self.PING_REPEAT_COUNT,
             self.ping_repeat, ['ping', cli_def.FUNC_ARG_TYPE_IP, 'repeat'], cli_def.ADMIN_MODE),

            ('ipv6', 'IPv6 echo',
             None, ['ping'], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, 'IPv6 echo',
             BasicCli.ping6, ['ping', 'ipv6'], cli_def.ADMIN_MODE),
            ('repeat', 'specify repeat count',
             None, ['ping', 'ipv6', cli_def.FUNC_ARG_TYPE_WORD], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_NUMBER, 'Repeat count,' + self.PING_REPEAT_COUNT,
             self.ping6_repeat, ['ping', 'ipv6', cli_def.FUNC_ARG_TYPE_WORD, 'repeat'], cli_def.ADMIN_MODE),

            ('clock', 'Display the system clock',
                BasicCli.show_clock, ['show'], cli_def.ADMIN_MODE),
            ('version', 'System hardware and software status',
                self.show_version, ['show'], cli_def.ADMIN_MODE),
            ('configure', 'Enter configuration mode',
                None, None, cli_def.ADMIN_MODE),
            ('terminal', 'Configure from the terminal',
                self.config_term, ['configure'], cli_def.ADMIN_MODE),

            ('ipv4', 'IPv4',
                None, ['show'], cli_def.ADMIN_MODE),
            ('route', 'IPv4 route info',
                self.show_ipv4_route, ['show', 'ipv4'], cli_def.ADMIN_MODE),

            ('ipv6', 'IPv6',
                None, ['show'], cli_def.ADMIN_MODE),
            ('route', 'IPv6 route info',
                self.show_ipv6_route, ['show', 'ipv6'], cli_def.ADMIN_MODE),

            ('address', 'IPv6 address info',
                self.show_ipv6_address, ['show', 'ipv6'], cli_def.ADMIN_MODE),
            ('no', 'Negate a command or set its defaults',
                None, None, cli_def.CONFIG_MODE),
            ('enable', 'Modify enable password parameters',
                None, None, cli_def.CONFIG_MODE),
            ('exit', 'Exit from configure mode',
                self.cli.exit_config_mode, None, cli_def.CONFIG_MODE),
            ('password', 'Assign the privileged level password',
                None, ['enable'], cli_def.CONFIG_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "The UNENCRYPTED (cleartext) "
                "'enable' password", self.set_enable_pw, ['enable',
                                                          'password'], cli_def.CONFIG_MODE),
            ('end', 'Exit from configure mode',
                self.cli.end_config_mode, None, cli_def.CONFIG_MODE),

            ('test', 'Test subsystems, memory, and interfaces',
                None, None, cli_def.ADMIN_MODE),
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

    @staticmethod
    def run_shell():
        """'shell' cabllback."""
        shellcmd = '/bin/sh'
        os.system("stty isig")
        os.system(shellcmd)

    @staticmethod
    def ping(parameters):
        """'ping' cabllback."""
        pingcmd = 'ping ' + parameters[0] + ' -c 5'
        os.system(pingcmd)

    def ping_repeat_count_check(self, count):
        if int(count) > self.PING_REPEAT_MAX_COUNT or int(count) < self.PING_REPEAT_MIN_COUNT:
            return -1
        else:
            return 0

    def ping_repeat(self, parameters):
        """'ping repeat' cabllback."""
        if self.ping_repeat_count_check(int(parameters[1])):
            print 'please specify repeat count within ' + self.PING_REPEAT_COUNT
            return
        pingcmd = 'ping ' + parameters[0] + ' -c ' + parameters[1]
        os.system(pingcmd)

    @staticmethod
    def ping6(parameters):
        """'ping6 ' cabllback."""
        pingcmd = 'ping6 ' + parameters[0] + ' -c 5'
        ret = os.system(pingcmd)
        if ret != 0:
            print 'ping6: No valid address/route for destination'

    def ping6_repeat(self, parameters):
        """'ping6 repeat' cabllback."""
        if self.ping_repeat_count_check(int(parameters[1])):
            print 'please specify repeat count within ' + self.PING_REPEAT_COUNT
            return
        pingcmd = 'ping6 ' + parameters[0] + ' -c ' + parameters[1]
        ret = os.system(pingcmd)
        if ret != 0:
            print 'ping6: No valid address/route for destination'

    @staticmethod
    def show_ipv4_route():
        """'show ipv4 route' cabllback."""
        v4route = 'route'
        os.system(v4route)

    @staticmethod
    def show_ipv6_route():
        """'show ipv6 route' cabllback."""
        v6route = 'route -A inet6'
        os.system(v6route)

    @staticmethod
    def show_ipv6_address():
        """'show ipv6 address' cabllback."""
        for ifindex in range(2):
            ifname = 'vbh' + str(ifindex)
            ifcmd = 'ip -6 addr show ' + ifname
            ifshow = os.popen(ifcmd).read()
            if ifshow.strip():
                v6index = ifshow.index("vbh")
                print ifshow[v6index:].strip()

    @staticmethod
    def show_clock():
        """'show clock' cabllback."""

        times = datetime.utcnow()
        print times.strftime('%H:%M:%S.') + times.strftime('%f')[:3] + times.strftime(' %a %b %d %Y')

    def show_version(self):
        """'show version' cabllback."""

        if os.path.exists('/etc/rpd_image_info'):
            print "OpenRPD v{0}.{1}.{2}{3} Software, RPD-OS version v{4}.{5}.{6}{7}, build by {8} on {9}"\
                .format(self.rpd_info['OPENRPD_MAJOR_REV'],
                        self.rpd_info['OPENRPD_MINOR_REV'],
                        self.rpd_info['OPENRPD_PATCH_REV'],
                        self.rpd_info['OPENRPD_REV_SUFFIX'],
                        self.rpd_info['RPDOS_MAJOR_REV'],
                        self.rpd_info['RPDOS_MINOR_REV'],
                        self.rpd_info['RPDOS_PATCH_REV'],
                        self.rpd_info['RPDOS_REV_SUFFIX'],
                        self.rpd_info['RPD_BUILDER'],
                        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(self.rpd_info['RPD_BUILD_TIME']))))
        else:
            print "Warning! OpenRPD version information is missing!"

    def enable_admin_mode(self, test=False, pwd=''):
        """'enable' cabllback."""

        if not self.cli.config_db.exists(db_defs.ENABLE_PWD):
            self.cli.update_mode_and_string(cli_def.ADMIN_MODE)
            return None

        num = 0
        while num < 3:
            try:
                if not test:
                    password = getpass('Password: ')
                else:
                    password = pwd
            except EOFError:
                num += 1
                print
                continue
            except KeyboardInterrupt:
                num += 1
                print
                continue
            if password == self.cli.config_db.get(db_defs.ENABLE_PWD):
                self.cli.update_mode_and_string(cli_def.ADMIN_MODE)
                break
            num += 1

        if num == 3:
            print '% Bad passwords\n'

    def exit_mode(self):
        """'exit' cabllback."""

        if self.cli.mode == cli_def.USER_MODE:
            return True
        elif self.cli.mode == cli_def.ADMIN_MODE:
            self.cli.update_mode_and_string(cli_def.USER_MODE)
        else:
            self.cli.log.error("Unknowned mode:%d" % self.cli.mode)

    def show_startup(self):
        """'show startup-config' cabllback."""

        if self.cli.rphy_cfg:
            try:
                filep = open(self.cli.rphy_cfg, 'r')
                startup_config = filep.readlines()
                for line in startup_config:
                    self.cli.stdout.write(line)
                self.cli.stdout.flush()
            except IOError, err:
                self.cli.log.error('Open startup config file fail,%s' % err)
        else:
            self.cli.log.error('Can not find startup config file')

    def show_run(self):
        """'show running-config' cabllback."""

        print 'Building configuration...\n'
        config_tree = self.cli.get_current_tree(cli_def.CONFIG_MODE, True)
        line, parent, indent, self.cli.run_config = '', [], 0, []

        self.cli.get_run_config(config_tree, line, parent, indent)
        for item in self.cli.run_config:
            self.cli.stdout.write(item)
        self.cli.stdout.flush()

    def copy_run_to_start(self):
        """'write' cabllback."""

        print 'Building configuration...'
        config_tree = self.cli.get_current_tree(cli_def.CONFIG_MODE, True)
        line, parent, indent, self.cli.run_config = '', [], 0, []

        self.cli.get_run_config(config_tree, line, parent, indent)
        try:
            filep = open(self.cli.rphy_cfg, 'w')
            try:
                fcntl.flock(filep, fcntl.LOCK_EX)
                filep.writelines(self.cli.run_config)
                print '[OK]'
            except IOError:
                print '[Fail]'
            finally:
                filep.close()
        except IOError:
            self.cli.log.error('Open startup config file fail')

    def config_term(self):
        """'configure terminal' cabllback."""

        if self.cli.mode == cli_def.ADMIN_MODE:
            self.cli.config_parent = []
            self.cli.update_mode_and_string(cli_def.CONFIG_MODE)

    # For All configure command callback, the 'parameters' is one list
    # 'parameters[0]' is flag, it will be SET_CONFIG_FLAG, DEL_CONFIG_FLAG or
    #                 SHOW_CONFIG_FLAG
    # 'parameters[1]' is the parent of this command.
    #                 For 'enable password xxx', parameters[1] is None.
    #                 For 'ip address xxx', parameters[1] is
    #                     ['interface loopback xxx']
    # 'parameters[2]' is the config parameter.
    # if this command has more than one parameter,
    # they will in turn stored in 'parameter[3]' ...
    def set_enable_pw(self, parameters):
        """'enable password WORD' cabllback."""

        if not isinstance(parameters, list):
            self.cli.log.error('Unrecognized parameters type')
            return None
        flag = parameters[0]
        if flag == cli_def.SET_CONFIG_FLAG:
            self.cli.config_db.set(db_defs.ENABLE_PWD, parameters[2])
            return None
        elif flag == cli_def.DEL_CONFIG_FLAG:
            self.cli.config_db.delete(db_defs.ENABLE_PWD)
            return None
        elif flag == cli_def.SHOW_CONFIG_FLAG:
            config = None
            if self.cli.config_db.exists(db_defs.ENABLE_PWD):
                config = parameters[2] % self.cli.config_db.get(db_defs.ENABLE_PWD)
            return config
        else:
            self.cli.log.error('Unsupported flag:%d' % flag)
            return None
