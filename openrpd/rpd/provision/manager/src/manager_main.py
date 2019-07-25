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

import subprocess
import sys
import os
from os.path import exists
from os import access, R_OK
import json
import psutil
import time
import shutil

from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import SysTools
import argparse
from rpd.provision.process_agent.agent.agent import ProcessAgent
from rpd.common.rpd_debugability import Debugability


class AgentsStarter(object):
    __metaclass__ = AddLoggerToClass

    PROCESSSTATE_ALIVE = 0
    PROCESSSTATE_DEAD = -1
    AGENT_RETRIES_MAX = 3
    PROCESS_INIT_PERIOD = 3
    WAITING_FOR_AGENT_STARTUP_RETRY = 60

    # RAW_RPD_DEBUG_JSON is present in the original packet, instead of
    # WORKING_RPD_DEBUG_JSON.
    #
    # RPD will read the WORKING_RPD_DEBUG_JSON to impact the startup.
    # If there is no WORKING_RPD_DEBUG_JSON (first startup), RPD will copy
    # RAW_RPD_DEBUG_JSON to WORKING_RPD_DEBUG_JSON
    #
    # Note, RAW_RPD_DEBUG_JSON will be restored after reboot RPD.
    # WORKING_RPD_DEBUG_JSON won't be impacted by reboot RPD.
    RAW_RPD_DEBUG_JSON = '/etc/config/rpd_debug.json'
    WORKING_RPD_DEBUG_JSON = '/rpd/config/rpd_debug.json'

    def __init__(self, simulator=False):
        """
        :param simulator: Simulator is used to run the program with
         interface simulator mode

        """
        # initiate agent dict which need to start, and corresponding instance created
        self.agent_dict = self.build_agent_dict(simulator)
        self.simulator_flag = simulator
        if simulator:
            self.manager_cmd_line = "python -m rpd.provision.manager.src.manager_process -s".split()
            self.hal_cmd_line = None
            self.fake_driver_cmd_line = None
            self.ptp_driver_cmd_line = None
            self.ssd_driver_cmd_line = None
            self.res_hal_cmd_line = None
        else:
            self.manager_cmd_line = "python -m rpd.provision.manager.src.manager_process".split()
            self.hal_cmd_line = "python -m rpd.hal.src.HalMain --conf=/etc/config/hal.conf".split()
            self.res_hal_cmd_line = "python -m rpd.resource.src.RpdResHalClient".split()

            if SysTools.is_vrpd():
                self.fake_driver_cmd_line = "python -m rpd.hal.lib.drivers.HalDriver0".split()
                self.ptp_driver_cmd_line = "python -m rpd.hal.lib.drivers.HalPtpDriver".split()
                self.ssd_driver_cmd_line = None
            else:  # pragma: no cover
                self.fake_driver_cmd_line = "python -m rpdHalDrv.HalDriverClient".split()
                self.ptp_driver_cmd_line = "python -m rpdPtpHalDrv.PtpHalDriverClient".split()
                self.ssd_driver_cmd_line = "python -m rpd.ssd.HalSsdDriver".split()

        self.fault_manager_cmd_line = "python -m rpd.common.rpd_fault_manager".split()

        self.agent_obj = {}
        self.manager_process = None
        self.hal_process = None
        self.fake_driver_process = None
        self.ptp_driver_process = None
        self.monitor_driver_process = None
        self.res_driver_process = None
        self.ssd_driver_process = None

    def check_debug_conf_file(self, target_file):
        Dir = os.path.dirname(target_file)
        try:
            if not exists(Dir):
                os.makedirs(Dir)
            if not exists(target_file):
                shutil.copyfile(self.RAW_RPD_DEBUG_JSON, target_file)

        except OSError as err:
            self.logger.warning("Can't make dir " + Dir + ":" + "({0})".format(err))
        except IOError as err:
            self.logger.warning("Can't copy to " + target_file + ":" + "({0})".format(err))

    def build_agent_dict(self, simulator):
        rpd_init_file = self.WORKING_RPD_DEBUG_JSON
        self.check_debug_conf_file(rpd_init_file)
        self.real_agent_dict = {
            "interface": "python -m rpd.provision.process_agent.interface_status.interface_status_agent".split(),
            "macsec": "python -m rpd.provision.process_agent.macsec.macsec_agent".split(),
            "dhcp": "python -m rpd.provision.process_agent.dhcp.dhcp_agent".split(),
            "tod": "python -m rpd.provision.process_agent.tod.tod_agent".split(),
            "rcp": "python -m rpd.provision.process_agent.rcp.rcp_agent".split(),
            "ipsec": "python -m rpd.provision.testing.fake_ipsec_agent".split(),
            "ptp_1588": "python -m rpd.provision.process_agent.ptp1588.ptp_agent".split(),
            "l2tpv3": "python -m rpd.provision.process_agent.l2tp.l2tp_agent".split(),
        }

        self.fake_agent_dict = {
            "interface": "python -m rpd.provision.process_agent.interface_status.interface_status_agent".split(),
            "macsec": "python -m rpd.provision.testing.fake_macsec_agent".split(),
            "dhcp": "python -m rpd.provision.testing.fake_dhcp_agent".split(),
            "tod": "python -m rpd.provision.testing.fake_tod_agent".split(),
            "rcp": "python -m rpd.provision.testing.fake_gcp_agent".split(),
            "ipsec": "python -m rpd.provision.testing.fake_ipsec_agent".split(),
            "ptp_1588": "python -m rpd.provision.testing.fake_ptp_agent".split(),
            "l2tpv3": "python -m rpd.provision.testing.fake_l2tp_agent".split(),
        }

        if simulator:
            self.logger.warning("return fake agent dict")
            return self.fake_agent_dict

        if exists(rpd_init_file) and access(rpd_init_file, R_OK):
            try:
                with open(rpd_init_file) as f:
                    tmp = json.load(f)
                    if tmp is not None and 'fake_agent' in tmp:
                        self.logger.warning("return agent dict by " + rpd_init_file)
                        return self.select_agent(tmp['fake_agent'])
            except EnvironmentError:
                self.logger.debug(rpd_init_file + " does not exist")
            except (ValueError, KeyError):
                self.logger.warning("Wrong format of " + rpd_init_file +
                                    "ignoring ...")
            except:
                self.logger.warning("Unexpected error:", sys.exc_info()[0])
        else:
            self.logger.warning("Can't read " + rpd_init_file)

        self.logger.warning("return real agent dict")
        return self.real_agent_dict

    def select_agent(self, fake_agent_conf):
        agents = {}
        for agent_name in self.real_agent_dict:
            if fake_agent_conf.get(agent_name, 'real') == 'real':
                agents[agent_name] = self.real_agent_dict[agent_name]
            else:
                agents[agent_name] = self.fake_agent_dict[agent_name]
        return agents

    def start_process(self, args):
        """Will not capture this error and let the process crash.

        :param args: The args includes the command, and the it should be a  tuple or a list.
        :return: Popen process instance

        """
        try:
            with open(os.devnull, 'w') as devnull:
                popenObj = subprocess.Popen(
                    args, stdout=devnull, stderr=subprocess.PIPE, cwd="/tmp/")
                popenObj.name = args
                return popenObj
        except Exception as e:
            self.logger.error(
                "Cannot start process %s due to reason:%s", args, e)
            raise e

    def check_process_status(self, popenObj):
        """Check the status of the process.

        :param popenObj: this is a obj returned by the start process
        :return: Terminated/Alive

        """
        if not isinstance(popenObj, subprocess.Popen):
            self.logger.error(
                "Cannot terminate a process since the arg is not Popen object.")
            return False, -1

        popenObj.poll()
        retcode = popenObj.returncode

        if retcode is None:
            return self.PROCESSSTATE_ALIVE
        return self.PROCESSSTATE_DEAD

    def cleanup(self):
        """Clean up process started."""
        process_set = [self.hal_process,
                       self.manager_process, self.ptp_driver_process, self.fake_driver_process,
                       self.res_driver_process,
                       self.monitor_driver_process, self.ssd_driver_process]
        process_set.extend(self.agent_obj)

        for process_info in process_set:
            if None is not process_info:
                process = process_info['process']
                if None is not process \
                        and self.check_process_status(process) == self.PROCESSSTATE_ALIVE:
                    process.terminate()

    def start(self):  # pragma: no cover
        """Start all agent here, need to pay attention to the error case
        when start agent fail."""
        # Start the HAL and Fake Driver
        if self.hal_cmd_line:
            self.logger.info("Start the hal main process...")
            process_obj = self.start_process(self.hal_cmd_line)
            self.hal_process = {
                "process": process_obj,
                "retries": 0,
            }
            manager_debugability.debugability_process_monitor(self.hal_process)

        # wait a period for process start and init complete
        time.sleep(self.PROCESS_INIT_PERIOD)
        if self.fake_driver_cmd_line:
            self.logger.info("Start the fake driver process...")
            process_obj = self.start_process(self.fake_driver_cmd_line)
            self.fake_driver_process = {
                "process": process_obj,
                "retries": 0,
            }
            manager_debugability.debugability_process_monitor(self.fake_driver_process)

        for agent_name in self.agent_dict:
            self.logger.info("start agent process {}...".format(agent_name))
            popenObj = self.start_process(self.agent_dict[agent_name])
            self.agent_obj[agent_name] = {
                "process": popenObj,
                "retries": 0,
            }
            manager_debugability.debugability_process_monitor(self.agent_obj[agent_name])

        # wait a period for agent start and init complete
        alive_status = False
        for timeout in range(self.WAITING_FOR_AGENT_STARTUP_RETRY):
            alive_status = ProcessAgent.is_all_agent_started()
            if not alive_status:
                time.sleep(1)
        if not alive_status:
            self.logger.error('Not all agent startup normally, reboot the system.')
            SysTools.sys_failure_reboot(reason='Not all agent startup')
            SysTools.diagnostic_self_test_fail('Communication error', 'Not all agent startup', 'Severity level=error')

        # start the manager process
        self.logger.info("Start the manager process...")
        process_obj = self.start_process(self.manager_cmd_line)
        self.manager_process = {
            "process": process_obj,
            "retries": 0,
        }
        manager_debugability.debugability_process_monitor(self.manager_process)

        # start the fault_manager process
        self.logger.info("Start the fault manager process...")
        process_obj = self.start_process(self.fault_manager_cmd_line)
        self.manager_process = {
            "process": process_obj,
            "retries": 0,
        }
        manager_debugability.debugability_process_monitor(self.manager_process)

        if self.ptp_driver_cmd_line:
            self.logger.info("Start the ptp driver client process...")
            process_obj = self.start_process(self.ptp_driver_cmd_line)
            self.ptp_driver_process = {
                "process": process_obj,
                "retries": 0,
            }
            manager_debugability.debugability_process_monitor(self.ptp_driver_process)

        if self.res_hal_cmd_line:
            self.logger.info("Start the resource hal client process...")
            process_obj = self.start_process(self.res_hal_cmd_line)
            self.res_driver_process = {
                "process": process_obj,
                "retries": 0,
            }
            manager_debugability.debugability_process_monitor(self.res_driver_process)

        if self.ssd_driver_cmd_line:
            self.logger.info("Start the ssd driver client process...")
            process_obj = self.start_process(self.ssd_driver_cmd_line)
            self.ssd_driver_process = {
                "process": process_obj,
                "retries": 0,
            }
            manager_debugability.debugability_process_monitor(self.ssd_driver_process)

        while True:
            time.sleep(5)
            #  monitor the all process
            manager_debugability.debugability_traceback()

            # monitor the manager process, will not retry....
            if self.manager_process is not None and self.manager_process['process'] is None:
                self.logger.error(
                    "Manager process is not up, reboot the system.")
                if self.simulator_flag:
                    sys.exit(-1)
                else:
                    SysTools.sys_failure_reboot(reason="Manager process is not up")
                    SysTools.diagnostic_self_test_fail('Processing error', 'Manager process is not up',
                                                       'Severity level=error')

            for agent in self.agent_obj:
                # check if agent instance create succeed, retry if failure
                if None is self.agent_obj[agent]["process"]:
                    if self.agent_obj[agent]["retries"] < self.AGENT_RETRIES_MAX:
                        self.logger.warn(
                            'Agent %s retries %d times', agent, self.agent_obj[agent]["retries"])
                        self.agent_obj[agent]["process"] = self.start_process(self.agent_dict[agent_name])
                        self.agent_obj[agent]["retries"] += 1
                        self.logger.warn('Agent %s retries %d times', agent, self.agent_obj[agent]["retries"])
                        manager_debugability.debugability_process_monitor(self.agent_obj[agent])
                        continue
                    else:
                        # FixMe: reboot system or ?
                        self.logger.error('Agent %s retries times exceed, will reboot...', agent)
                        SysTools.sys_failure_reboot(reason="Agent {0} retries times exceed".format(agent))
                        SysTools.diagnostic_self_test_fail('Communication error',
                                                           "Agent {0} retries times exceed".format(agent),
                                                           'Severity level=error')

                if self.check_process_status(self.agent_obj[agent]["process"]) != self.PROCESSSTATE_ALIVE:
                    self.logger.error(
                        '%s process is dead, reboot the system.', agent)
                    # FixMe: reboot system or restart agent
                    SysTools.sys_failure_reboot(reason="{0} process is dead".format(agent))
                    SysTools.diagnostic_self_test_fail('Processing error', "{0} process is dead".format(agent),
                                                       'Severity level=error')
            # check other critical processes
            if self.ptp_driver_cmd_line:
                if self.check_process_status(self.ptp_driver_process["process"]) != self.PROCESSSTATE_ALIVE:
                    self.logger.error("ptp hal driver process is dead")
                    SysTools.sys_failure_reboot(reason="ptp hal driver process is dead")
                    SysTools.diagnostic_self_test_fail('Processing error', "ptp hal driver process is dead",
                                                       'Severity level=error')


if __name__ == "__main__":  # pragma: no cover
    # Check if we have started this manager main process
    file_name = "/tmp/ProcessManagerMain.pid"
    if os.path.exists(file_name):
        process_file = open(file_name, "r")
        # get the pid
        pidbuff = process_file.read()
        process_file.close()

        if pidbuff:
            pid = int(pidbuff)
            # check if the pid is alive
            if psutil.pid_exists(pid):
                sys.exit(0)

    process_file = open(file_name, "w")
    process_file.write(str(os.getpid()))
    process_file.close()

    # check dependencies
    manager_debugability = Debugability()
    manager_debugability.rpd_dependency()

    parser = argparse.ArgumentParser(description="RCP provision")
    # parse the daemon settings.
    parser.add_argument("-s", "--simulator",
                        action="store_true",
                        help="run the program with simulator mode")
    arg = parser.parse_args()
    setup_logging("PROVISION", filename="provision_mgr_starter.log")
    starter = AgentsStarter(simulator=arg.simulator)
    starter.start()
