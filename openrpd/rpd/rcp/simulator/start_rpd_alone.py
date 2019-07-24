#!/usr/bin/python
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
import zmq
import time
import psutil
from rpd.gpb.rcp_pb2 import t_RcpMessage
import signal
import sys

ROOT_DIRECTORY = 'rpd'
SEARCH_STR_REDIS = "redis-server"
SEARCH_STR_RCP = "rcp_process"
SEARCH_STR_FAKE_DRIVER = "HalDriver0"
REDIS_WITH_UNIX_FILE_PATTERN = "*:0"
REDIS_CONF_NAME = "/tmp/.rpd-test-start-rpd-alone.conf"
REDIS_SEARCH_DIRECTORY = "/usr/bin/"
RPD_RCP_IPC_SOCK = "ipc:///tmp/rpd-test-rcp-process-ipc.sock"
RPD_CORE_ADDRESS = ["lo;127.0.0.1",]
# RPD_CORE_ADDRESS1 = ["lo:0;127.0.0.2",]

# Start the Redis
def check_process_is_running(process_name):
    for process in psutil.process_iter():
        if process.is_running() and len(process.cmdline()):
            result_list = [cmd.find(process_name) >= 0 for cmd in process.cmdline()]
            for ret in result_list:
                if ret:
                    return process
            else:
                continue
    else:
        return None


def check_system_redis_is_running():
    redis_processes = []
    for process in psutil.process_iter():
        if process.is_running() and len(process.cmdline()):
            result_list = [cmd.find(SEARCH_STR_REDIS) >= 0 for cmd in process.cmdline()]
            for ret in result_list:
                if ret:
                    break
            else:
                continue
            redis_processes.append(process)

    for redis_process in redis_processes:
        cmd_line = redis_process.cmdline()
        print cmd_line
        for cmd in cmd_line:
            if cmd == "":
                continue
            if cmd.find(REDIS_WITH_UNIX_FILE_PATTERN) > 0:
                return redis_process
    else:
        return None


def prepare_redis_server_config():
    with open(REDIS_CONF_NAME, 'w') as f:
        content = '''
            pidfile /var/run/rpd-test-start-rpd-alone.pid
            port 0
            unixsocket /tmp/redis.sock
            unixsocketperm 700
            timeout 0
            databases 16
            stop-writes-on-bgsave-error yes
            dbfilename dump.rdb
            dir /tmp/
        '''

        for line in content.split('\n'):
            f.write(line.strip() + "\n")


def check_system_redis_is_installed():
    files = os.listdir(REDIS_SEARCH_DIRECTORY)
    for file in files:
        if file == SEARCH_STR_REDIS:
            return True
    else:
        return False


# The logic to start the redis

def start_redis():
    redis_process = check_system_redis_is_running()

    if redis_process:
        print "The Redis server has been running, ignore this step."
        return redis_process
    prepare_redis_server_config()
    redis_cmd_line = REDIS_SEARCH_DIRECTORY + "/" + SEARCH_STR_REDIS + " " + REDIS_CONF_NAME
    return psutil.Popen(redis_cmd_line.split())


# Start the Hal Process
def get_openrpd_root_dir():
    current_dir_name = os.path.dirname(os.path.realpath(__file__))
    dir_list = current_dir_name.split(os.path.sep)

    # Try to find the rpd dir
    index = 0
    root_dir = ""
    for dir_name in dir_list:
        index += 1
        if dir_name == ROOT_DIRECTORY:
            root_dir = os.path.sep.join(dir_list[:index])
            break
    if root_dir == "":
        raise IOError("Cannot find the %s directory, please check your file hierarchy.")

    return root_dir


def get_hal_directory():
    return get_openrpd_root_dir() + '/hal/'


def start_hal():
    hal_cfg_file = get_hal_directory() + "conf/hal.conf"
    hal_main = get_hal_directory() + "src/HalMain.py"
    hal_process_cmd_line = 'python ' + hal_main + " --conf=" + hal_cfg_file

    process = check_process_is_running("HalMain")
    if process:
        return process

    process = psutil.Popen(hal_process_cmd_line.split())
    return process


# Start the Fake Driver
def get_fake_driver():
    return get_openrpd_root_dir() + "/hal/lib/drivers/HalDriver0.py"


def start_fake_driver():
    fake_driver_cmd_line = "python " + get_fake_driver()
    process = check_process_is_running(SEARCH_STR_FAKE_DRIVER)
    if process:
        return process

    process = psutil.Popen(fake_driver_cmd_line.split())
    return process


# Start the rpd
def get_rcp_process_dir():
    return get_openrpd_root_dir() + '/rcp/'


def start_rcp_process():
    rcp_cmdline = "python " + get_rcp_process_dir() + 'rcp_process.py --ipc-address ' + RPD_RCP_IPC_SOCK

    process = check_process_is_running(SEARCH_STR_RCP)
    if process:
        return process

    process = psutil.Popen(rcp_cmdline.split())
    return process


# Create a Core
def create_core():
    # create a zmq and connect to socekt address

    context = zmq.Context.instance()
    ipc_sock = context.socket(zmq.PAIR)
    ipc_sock.bind(RPD_RCP_IPC_SOCK)


    rcp_msg = t_RcpMessage()
    rcp_msg.RcpMessageType = rcp_msg.ADD_CCAP_CORES
    rcp_msg.RedirectCCAPAddresses.extend(RPD_CORE_ADDRESS)
    msg_str = rcp_msg.SerializeToString()
    ipc_sock.send(msg_str)

    # sleep 20s, as rcp_orchestrator will timeout in 15s for per pkt
    # time.sleep(20)
    #
    # rcp_msg = t_RcpMessage()
    # rcp_msg.RcpMessageType = rcp_msg.ADD_CCAP_CORES
    # rcp_msg.RedirectCCAPAddresses.extend(RPD_CORE_ADDRESS1)
    # msg_str = rcp_msg.SerializeToString()
    # ipc_sock.send(msg_str)


# main function
def interrupt_handler(signum, frame):
    # gracefully stop
    print "Terminate all the processes!!!"
    hal = frame.f_locals["hal"]
    redis = frame.f_locals["redis"]
    rcp = frame.f_locals["rcp"]
    fake_driver = frame.f_locals["fake_driver"]

    if isinstance(rcp, psutil.Process) and rcp.is_running():
        rcp.terminate()

    if isinstance(fake_driver, psutil.Process) and fake_driver.is_running():
        fake_driver.terminate()

    if isinstance(redis, psutil.Process) and redis.is_running():
        redis.terminate()

    if isinstance(hal, psutil.Process) and hal.is_running():
        hal.terminate()

    sys.exit(0)


def main():
    redis = start_redis()
    time.sleep(2)
    hal = start_hal()
    time.sleep(2)
    fake_driver = start_fake_driver()
    rcp = start_rcp_process()
    time.sleep(1)
    create_core()
    print "redis = %s, hal = %s, fake_driver = %s, rcp = %s" % (redis, hal, fake_driver, rcp)
    signal.signal(signal.SIGINT, interrupt_handler)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        inet = str(sys.argv[1])
        if inet == "ipv6":
            RPD_CORE_ADDRESS = ["lo;::1", ]
    main()
