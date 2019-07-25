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
import sys
import time
from rpd.common.rpd_event_def import RPD_EVENT_AUTH_ENCRYPTION_102, RPD_EVENT_AUTH_ENCRYPTION_103
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass


class SystemMonitorFault():
    __metaclass__ = AddLoggerToClass

    def __init__(self):
        pass

    def fm_ssh_event(self):  # pragma: no cover
        # SSH Auth Log Event
        ssh_ip = ''
        ssh_user = 'admin'
        while True:
            ssh_tag = ''

            time.sleep(0.03)
            ssh_log = sys.stdin.readline()
            if not ssh_log:
                return
            ssh_log_op = ssh_log
            if ssh_log and ssh_log.find("Child connection from") >= 0:
                try:
                    log_index = ssh_log.index("from")
                    ssh_ip_port = ssh_log[log_index:]
                    ssh_ip_port = ssh_ip_port.replace("from ", "")
                    if ssh_ip_port.count(":") > 1:
                        # ipv6
                        last_index = ssh_ip_port.rindex(':')
                        ssh_ip = ssh_ip_port[0:last_index]
                        ssh_port = ssh_ip_port[last_index:]
                        ssh_port = ssh_port.replace(":", "")
                    else:
                        ssh_ip_port = ssh_ip_port.split(':')
                        ssh_ip = ssh_ip_port[0]
                        ssh_port = ssh_ip_port[1]
                except ValueError:
                    pass
            if ssh_log and ssh_log.find("0 fails") >= 0:
                # when password ssh is off and no pubkey,add a event
                self.notify.error(RPD_EVENT_AUTH_ENCRYPTION_103[0], ssh_ip, ssh_user, ssh_tag)
                self.logger.error('SSH Password login failed')
                return

            if ssh_log and ssh_log.find("Pubkey auth succeeded") >= 0:
                # Pubkey login ssh fault event
                try:
                    log_index = ssh_log_op.index("for '")
                    ssh_user = ssh_log_op[log_index:]
                    ssh_user = ssh_user.replace("for '", "")
                    log_index = ssh_user.index("'")
                    ssh_user = ssh_user[0:log_index]

                    log_index = ssh_log_op.index("from")
                    ssh_ip_port = ssh_log_op[log_index:]
                    ssh_ip_port = ssh_ip_port.replace("from", "")
                    if ssh_ip_port.count(":") > 1:
                        # ipv6
                        last_index = ssh_ip_port.rindex(':')
                        ssh_ip = ssh_ip_port[0:last_index]
                        ssh_port = ssh_ip_port[last_index:]
                        ssh_port = ssh_port.replace(":", "")
                    else:
                        ssh_ip_port = ssh_ip_port.split(':')
                        ssh_ip = ssh_ip_port[0]
                        ssh_port = ssh_ip_port[1]
                except ValueError:
                    pass

                if ssh_log and ssh_log.find("Pubkey auth succeeded") >= 0:
                    self.notify.info(RPD_EVENT_AUTH_ENCRYPTION_102[0], ssh_ip, ssh_user, ssh_tag)
                    self.logger.info('SSH Pubkey login successfully')
                return

            # try auth with password
            # password attempt for 'root' from 127.0.0.1:38258
            # string op to get root and IP
            try:
                log_index = ssh_log_op.index("for ")
                ssh_log_op = ssh_log_op[log_index:]
                ssh_log_op = ssh_log_op.replace("for '", "")
                ssh_log_op = ssh_log_op.replace("' from", "")
                # now is root 127.0.0.1:38258

                ssh_log_op = ssh_log_op.split()
                ssh_user = ssh_log_op[0]

                ssh_ip_port = ssh_log_op[1]
                if ssh_ip_port.count(":") > 1:
                    # ipv6
                    last_index = ssh_ip_port.rindex(':')
                    ssh_ip = ssh_ip_port[0:last_index]
                    ssh_port = ssh_ip_port[last_index:]
                    ssh_port = ssh_port.replace(":", "")
                else:
                    ssh_ip_port = ssh_ip_port.split(':')
                    ssh_ip = ssh_ip_port[0]
                    ssh_port = ssh_ip_port[1]
            except ValueError:
                pass

            if ssh_log and ssh_log.find("Password auth succeeded") >= 0:
                self.notify.info(RPD_EVENT_AUTH_ENCRYPTION_102[0], ssh_ip, ssh_user, ssh_tag)
                self.logger.info('SSH Password login successfully')
                return
            if ssh_log and ssh_log.find("Bad password") >= 0:
                self.notify.error(RPD_EVENT_AUTH_ENCRYPTION_103[0], ssh_ip, ssh_user, ssh_tag)
                self.logger.error('SSH Password login failed')
                return

    def fm_system_monitor(self):  # pragma: no cover
        # SSH Auth Log Event
        if str(sys.argv[1]).find("SSH") >= 0:
            self.fm_ssh_event()
        else:
            # Glances alert system monitor critical event and call this python file to handle
            # and we just log a error event let fault_manager to handle it.
            self.logger.error('System Monitor Alert ' + sys.argv[1])

        return


if __name__ == "__main__":  # pragma: no cover
    setup_logging("CLI", filename="cli.log")
    driver = SystemMonitorFault()
    driver.fm_system_monitor()
