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

#!/usr/bin/env python
import zmq
import sys
import rpd.provision.proto.cli_pb2 as cli_pb2
import rpd.provision.proto.MacsecMsgType as MacsecMsgType
from rpd.provision.proto.cli_pb2 import t_CliMessage


class CliRequest:
    CMD_TO_AGENT_MAP = {
        "macsec": "ipc:///tmp/zmq-8021x.ipc"
    }

    REQ_MAPPING = {
        "macsec": {
            "status": {
                "msg_type": MacsecMsgType.Show8021xSummary,
                "operation": "CLI_CFG_READ"
            },
            "details": {
                "msg_type": MacsecMsgType.Show8021xDetail,
                "operation": "CLI_CFG_READ"
            }
        }
    }

    def __init__(self, cmd):
        agent = CliRequest.CMD_TO_AGENT_MAP.get(cmd, "")
        if not agent:
            raise Exception("Command not found")
        self.__param_mapping = CliRequest.REQ_MAPPING[cmd]
        self.__connect_with_agent(agent)

    def __connect_with_agent(self, agent):
        zmq_context = zmq.Context()
        self.socket = zmq_context.socket(zmq.REQ)
        self.socket.connect(agent)

    def ask_agent(self, p_param):
        self.socket.send(self.__generate_request(p_param))
        data = self.socket.recv()
        return self.__parse_response(data)

    def __generate_request(self, p_param):
        param = self.__param_mapping.get(p_param, "")
        if not param:
            raise Exception("Command parameter not recognized")
        cli_msg = t_CliMessage()
        cli_msg.CliMsgType = param["msg_type"]
        cli_msg.CliDataOperation = t_CliMessage.t_CliDataOperation.DESCRIPTOR.values_by_name[
            param["operation"]].number
        return cli_msg.SerializeToString()

    def __parse_response(self, response):
        msg = t_CliMessage()
        msg.ParseFromString(response)
        response = msg.CliDataResult
        return t_CliMessage.t_CliDataResult.DESCRIPTOR.values_by_number[response].name


if __name__ == "__main__":
    cmd, param = sys.argv[1], sys.argv[2]
    try:
        cli = CliRequest(cmd)
        print cli.ask_agent(param)
    except Exception as ex:
        print ex
