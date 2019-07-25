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

import socket
import sys
from rpd.rcp.rcp_sessions import RCPMasterDescriptor
from rpd.rcp.rcp_orchestrator import log_measured_values
from rpd.rcp import rcp_master_orchestrator
from rpd.dispatcher import dispatcher
from rpd.rcp.gcp import gcp_sessions
from rpd.rcp.rcp_sessions import CcapCoreIdentification
from rpd.rcp.rcp_lib import rcp_tlv_def
import zmq
from rpd.gpb import master_sim_pb2 as master_sim_def
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.utils import Convert
from rpd.confdb.rpd_redis_db import RCPDB
from rpd.hal.simulator.start_hal import start_redis
from rpd.rcp.rcp_process import set_test_res_db
import json
import os
import time


# IPv4 session description
addr_family = socket.AF_INET
local_ip = ("0.0.0.0" if addr_family == socket.AF_INET else "::")
local_interface = 'lo'

# IPv6 session description
# addr_family = socket.AF_INET6
# local_ip = "fd00:dead:1::1"
# set only for link local IPv6 addresses, otherwise it will fail to establish
# connection
local_interface = "lo"
# local_interface = "eth0"

# common for v4 and v6
local_port = gcp_sessions.GCPSessionDescriptor.DEFAULT_PORT_MASTER


def initiated_cb(session):
    MasterAPI.logger.info("Session initiated")


class MasterAPI(object):
    context = zmq.Context()
    MasterZMQPath = "ipc:///tmp/Rcp_master_simulator.sock"
    __metaclass__ = AddLoggerToClass

    def __init__(self, dispatcher, orch, path=MasterZMQPath):
        self.path = path
        self.dispatcher = dispatcher
        self.orch = orch
        self.socket = self.context.socket(zmq.REP)
        self.socket.bind(self.path)

    def register(self):
        self.dispatcher.fd_register(
            self.socket, self.dispatcher.EV_FD_IN | self.dispatcher.EV_FD_ERR,
            self._handle_master_msg)

    def _handle_master_msg(self, sock, event):
        if event & dispatcher.Dispatcher.EV_FD_IN == 0:
            MasterAPI.logger.error("Got a fake master event, ignore it!")
            return
        try:
            data = self.socket.recv(flags=zmq.NOBLOCK)
            msg = master_sim_def.t_MasterSimApiMessage()
            msg.ParseFromString(data)
            if msg.HasField("slave_descriptor"):
                # Construct the salve descriptor
                slave_desc = msg.slave_descriptor

                slave_descriptor = gcp_sessions.GCPSlaveDescriptor(
                    addr_master=slave_desc.addr_master,
                    port_master=slave_desc.port_master,
                    interface_master=slave_desc.interface_master,
                    addr_local=slave_desc.addr_local,
                    port_local=slave_desc.port_local,
                    interface_local=slave_desc.interface_local,
                    addr_family=slave_desc.addr_family)
            else:
                slave_descriptor = None  # the msg will send to all the slaves

            operation = msg.operation
            cfg = msg.cfg

            # change the dict to pdb
            data = rcp_master_orchestrator.RCPMasterOrchestrator.RCPDataForSlave(
                slave_descriptor, cfg, rcp_message_id=rcp_tlv_def.RCP_MSG_TYPE_IRA, rcp_operation=operation)

            self.orch.add_data_to_send(data)

            print msg
            self.socket.send("")
        except Exception as e:
            MasterAPI.logger.error("")
            print "Error happnens when handle message:" + str(e)


if __name__ == "__main__":

    # setup logging, will search the config files
    setup_logging("MasterSim", filename="rcp_master_sim.log")
    set_test_res_db()
    redis = start_redis()
    time.sleep(2)

    scale_test_packets = 1
    send_no_wait = False

    arg_send_no_wait = '--no_wait'
    arg_pkt_count = '--pkt_count'
    arg_use_interface = '--use_interface'
    arg_ipv6 = "--ipv6"
    identification_file = "/conf/conf_core_identification_v4.json"
    i07_file = "/conf/I07Field_v4.json"

    if sys.argv[-1] != "--help" and sys.argv[-1] != arg_ipv6:
        # check if there are some arguments
        try:
            while len(sys.argv) >= 2:
                if sys.argv[-1] == arg_send_no_wait:
                    send_no_wait = True

                    # pop the argument
                    sys.argv.pop()

                elif sys.argv[-2] == arg_use_interface:
                    local_ip = str(sys.argv[-1])
                    addr_family = (socket.AF_INET, socket.AF_INET6)[Convert.is_valid_ipv6_address(local_ip)]
                    # pop argument and it's value
                    sys.argv.pop()
                    sys.argv.pop()

                elif sys.argv[-2] == arg_pkt_count:
                    scale_test_packets = int(sys.argv[-1])

                    # pop argument and it's value
                    sys.argv.pop()
                    sys.argv.pop()
                else:
                    raise Exception()

        except Exception as ex:
            MasterAPI.logger.info("Invalid arguments: %s:: %s", sys.argv, ex)
            sys.exit()
    elif sys.argv[-1] == arg_ipv6:
        local_ip = "::"   # use this for simulator in Docker to avoid socket bind error
        addr_family = socket.AF_INET6
    else:
        MasterAPI.logger.info("""

        Supported arguments:
            %s (False is default)
            %s N (N == %u is default)
            --help

        """, arg_send_no_wait, arg_pkt_count, scale_test_packets)
        sys.exit()

    MasterAPI.logger.info("Starting master orchestrator: "
                          "addr_family: %s, IP addr: %s, port: %u, "
                          "pkt_count: %u, send_no_wait: %s",
                          addr_family, local_ip, local_port, scale_test_packets,
                          send_no_wait)

    disp = dispatcher.Dispatcher()
    if addr_family is socket.AF_INET6:
        identification_file = "/conf/conf_core_identification_v6.json"
        i07_file = "/conf/I07Field_v6.json"

    with open(os.path.dirname(os.path.abspath(__file__)) + identification_file) as core_identification:
        ccap_core_identification = json.load(core_identification)
    with open(os.path.dirname(os.path.abspath(__file__)) + i07_file) as i07data:
        customize_data = json.load(i07data)
    caps = CcapCoreIdentification(index=ccap_core_identification["index"],
                                  core_id=ccap_core_identification["core_id"],
                                  core_ip_addr=ccap_core_identification["core_ip_addr"],
                                  is_principal=ccap_core_identification["is_principal"] == str(True),
                                  core_name=ccap_core_identification["core_name"],
                                  vendor_id=ccap_core_identification["vendor_id"],
                                  core_mode=ccap_core_identification["core_mode"],
                                  initial_configuration_complete=ccap_core_identification["initial_configuration_complete"] == str(True),
                                  move_to_operational=ccap_core_identification["move_to_operational"] == str(True),
                                  core_function=ccap_core_identification["core_function"],
                                  resource_set_index=ccap_core_identification["resource_set_index"],
                                  data=customize_data
                                  )

    desc = RCPMasterDescriptor(
        caps,
        addr=local_ip,
        port=local_port,
        addr_family=addr_family,
        interface_name=local_interface)

    orch = rcp_master_orchestrator.RCPMasterOrchestrator(disp)
    MasterAPI.logger.info("Master orchestrator created")
    orch.add_sessions([desc])
    MasterAPI.logger.info("Master session added")
    MasterAPI.logger.info("Preparing configurations")
    '''
    seq = test_rcp.TestRCPSpecifics.create_testing_ds_cfg_sequence(
                gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX)
    data = rcp_master_orchestrator.RCPMasterOrchestrator.RCPDataForSlave(
                                                                None,
                                                                seq.parent_gpb)
    i = 0
    while i < scale_test_packets:
        if not send_no_wait:
            orch.add_data_to_send(data)
        else:
            orch.add_data_to_send_no_wait(data)
        i += 1
    MasterAPI.logger.info("Added configuration (%u times)", scale_test_packets)
    '''

    MasterAPI.logger.info("Starting dispatcher loop")

    masterApi = MasterAPI(dispatcher=disp, orch=orch)
    masterApi.register()

    MasterAPI.logger.info("Create the master API instance\n")
    try:
        disp.loop()
    except Exception as ex:
        print("Orchestration finished: %s", ex)

    MasterAPI.logger.info("Orchestration finished")
    log_measured_values(orch)
