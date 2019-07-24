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
import time
import psutil
import fcntl
import os
from datetime import datetime
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import SysTools


class Debugability(object):
    """
    This Debugability class is used to figure out some issue easily.

    Debugablity:
     1. python crash
        catch traceback to traceback.log & syslog
     2. OpenRPD status
        catch provision status.
        For now to figure issue we have to look a lot of log file.
     3. memory leak check

    TODO: we should write class instance to file for multiple process to write and show to USE.

    """
    # default traceback
    DEFAULT_TRACEBACK_FILENAME = '/tmp/openrpd_traceback.log'
    DEFAULT_TRACEBACK_SIZE = 1024 * 1024 * 1

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.trace_filename = self.DEFAULT_TRACEBACK_FILENAME

        # python process debugability
        self.proc_monitor = []
        return

    def rpd_dependency(self):
        rpd_rsyslogd = 0
        rpd_redis_server = 0
        rpd_platform = 0
        while rpd_rsyslogd == 0 or rpd_redis_server == 0:
            for proc in psutil.process_iter():
                # check rsyslogd
                try:
                    if proc.name() == "rsyslogd":
                        rpd_rsyslogd = 1
                    if proc.name() == "redis-server":
                        rpd_redis_server = 1
                except psutil.NoSuchProcess:  # pragma: no cover
                    pass
            # if dependencies software not up, check 8 seconds later
            time.sleep(3)
        while rpd_platform == 0 and not SysTools.is_vrpd():  # pragma: no cover
            if os.path.exists("/tmp/platform_ok"):
                rpd_platform = 1
            time.sleep(3)
        print "rpd dependencies software is up"
        return

    def debugability_process_monitor(self, popen_obj):
        # monitor the all process and catch all traceback when process crashed.
        self.proc_monitor.append(popen_obj)
        try:
            fd = popen_obj['process'].stderr.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        except Exception, e:
            self.logger.info("set %s non-blocking fail, %s", \
                    str(popen_obj['process'].name), e)
        pass

    def debugability_traceback(self):  # pragma: no cover
        # monitor the all process and catch all traceback when process crashed.
        for p in self.proc_monitor:
            try:
                proc_stderr = None
                proc_stderr = os.read(p['process'].stderr.fileno(), 2048)

                if proc_stderr:
                    # print traceback to console
                    print proc_stderr
                    # print traceback to file
                    trace_file = open(self.trace_filename,"a+")
                    err_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + \
                        " - Found error for - " + str(p['process'].name) + "\n"
                    trace_file.write(err_str)
                    trace_file.write(proc_stderr)
                    trace_file.close()
                    # print traceback to syslog
                    self.logger.error(err_str)
                    self.logger.error(str(proc_stderr))
                    # Rotate if needed
                    trace_size = os.path.getsize(self.trace_filename)
                    if trace_size > self.DEFAULT_TRACEBACK_SIZE:
                        os.system('/usr/sbin/log_rotate_archive.sh openrpd_traceback.log')
            except OSError:
                # nothing to read here
                pass
            except Exception as e:
                self.logger.error("error in debugability:%s", e)

            proc_status = p['process'].poll()
            if proc_status is not None:
                # process crash,Debugability Support
                self.logger.info("%s - is dead", str(p['process'].name))
                self.proc_monitor.remove(p)

        pass


if __name__ == "__main__":  # pragma: no cover
    debug = Debugability()
