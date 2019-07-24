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
import os
import shutil
import psutil
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.common.utils import Convert, SysTools


class RSyslog(object):  # pragma: no cover
    """This rsyslog class is to config rsyslog.conf for pushing log to
    central log server.

    This is rsyslog connected to rsyslog server for remote logging.
    OpenRPD python logging -> /dev/log -> rsyslog -> local log &
    remote log server.

    """
    # default log rotate size,default is 10M
    DEFAULT_LOGGING_ROTATE_SIZE = '10485760'
    # default debug level for pushing to rsyslog server,default is all
    # rsyslog server/log analyzer can filter the log level to output
    DEFAULT_LOGGING_LEVEL = 'info'
    # default log file
    DEFAULT_LOGGING_FILENAME = '/bootflash/openrpd.log'

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.rsyslog_filename = self.DEFAULT_LOGGING_FILENAME
        self.rsyslog_loglevel = self.DEFAULT_LOGGING_LEVEL
        self.rsyslog_rotatesize = self.DEFAULT_LOGGING_ROTATE_SIZE
        return

    def restart_rsyslog(self):
        # kill & restart rsyslog
        for proc in psutil.process_iter():
            # check whether the process name matches
            try:
                if proc.name() == "rsyslogd":
                    proc.kill()
            except psutil.NoSuchProcess:
                pass
        # start rsyslog
        psutil.Popen("rsyslogd")
        return

    def config_rsyslog_local(self):
        conf = open('/etc/rsyslog.conf', 'a+')
        # not using this api. local syslog config is at rsyslog.conf
        # format string to rsyslog reg conizable conf, outchannel for rsyslog
        conf.write("\n")
        out_channel = "$outchannel log_rotation," + self.rsyslog_filename + ", " + self.rsyslog_rotatesize + \
                      ", /usr/sbin/log_rotate.sh " + self.rsyslog_filename
        conf.write(out_channel)
        conf.write("\n")
        conf.write("local7.*   :omfile:$log_rotation")
        conf.write("\n")
        conf.close()
        return

    def config_rsyslog_remote(self, address):
        # write to remote server, check whether it's been configured already.
        conf = open('/etc/rsyslog.conf', 'r')
        server_configed = conf.read()
        address_configed = server_configed.find(address)
        conf.close()
        if address_configed > 0:
            self.logger.info("Log Server IP address provided for remote logging already configed")
            return

        conf = open('/etc/rsyslog.conf', 'a+')
        # write to remote logserver, TCP to logserver
        conf.write("\n")
        remote_channel = "*." + self.rsyslog_loglevel + "    @" + address
        conf.write(remote_channel)
        conf.write("\n")
        conf.close()

        if SysTools.is_vrpd():
            hostmac = SysTools.get_mac_address("eth0")
        else:
            hostmac = SysTools.get_sys_mac_address()

        hostname = 'RPD' + hostmac.replace(':', '')
        set_host_cmd = 'echo ' + hostname + '>/proc/sys/kernel/hostname'
        os.system(set_host_cmd)

        new_hostline = hostname + " localhost"
        # write to /etc/hosts
        new_host = open('/tmp/new_hosts', 'w')
        old_host = open('/etc/hosts', 'r')
        line = old_host.read()
        found = line.find('localhost')
        configed = line.find('RPD')
        if found > 0 and configed < 0:
            new_host.write(line.replace('localhost', str(new_hostline)))
        else:
            new_host.write(line)
        old_host.close()
        new_host.flush()
        new_host.close()
        os.remove('/etc/hosts')
        shutil.move('/tmp/new_hosts', '/etc/hosts')
        return

    def config_rsyslog(self, address):
        """Set address of remote log server,support rsyslog.

        - For now only one log-server(rsyslog) is supported (TCP is used)

        :param address: rsyslog server IP address (v4 or v6) or None to
         disable remotelogging feature
        :param logging_level: string or None
        :param rotate_size: rotatation size for log file
        :return:

        """
        if None is address:
            # disable remote logging feature
            # restart rsyslog
            self.restart_rsyslog()
            return

        if not Convert.is_valid_ip_address(address):
            self.logger.warning("Invalid IP address provided for remote logging: %s", address)
            return

        try:
            # enable remote logging feature
            self.config_rsyslog_remote(address)
            # restart rsyslogd
            self.restart_rsyslog()
        except (OSError, ValueError):
            self.logger.error("Failed remote logging configuration")

    def config_rsyslog_loglevel(self, loglevel):
        """Set loglevel to push to remote log server,support rsyslog.

        - For now only one log-server(rsyslog) is supported (TCP is used)
        - emerg,alert,cri,error,warn,notice,info,debug
        - debug-level:0-error,1-warn,2-info,3-debug

        :param loglevel:log level int string <0-7>
        :return:

        """

        levelmap = {
            0: 'emerg',
            1: 'alert',
            2: 'cri',
            3: 'error',
            4: 'warn',
            5: 'notice',
            6: 'info',
            7: 'debug'
        }
        if loglevel not in levelmap:
            self.logger.warning("Remote logging loglevel reject Error level:" + loglevel)
            return

        self.rsyslog_loglevel = levelmap[loglevel]
        # find @ line and change the loglevel
        shutil.move('/etc/rsyslog.conf', '/etc/rsyslog.conf.loglevel')
        with open('/etc/rsyslog.conf', 'w') as loglevel_conf:
            with open('/etc/rsyslog.conf.loglevel', 'r') as conf:
                for line in conf.readlines():
                    if "@" in line:
                        address = line.split('@')
                        # write to remote logserver, TCP to logserver
                        remote_channel = "*." + self.rsyslog_loglevel + "    @" + address[1]
                        loglevel_conf.write(remote_channel)
                        loglevel_conf.write("\n")

                        loglevel_conf.close()
                        conf.close()
                        break
                    loglevel_conf.write(line)

        # restart rsyslogd
        self.restart_rsyslog()
        return


if __name__ == "__main__":  # pragma: no cover
    rsyslog = RSyslog()
    # rsyslog.config_rsyslog("10.79.41.60")
    rsyslog.config_rsyslog_loglevel(3)
