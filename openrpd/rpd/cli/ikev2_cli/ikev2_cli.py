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


from cli import cli_framework_def as cli_def
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.proto import Ikev2MsgType
import json


class Ikev2Cli(object):
    """Ikev2 cli class."""

    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli

        self.cli_table = (
            ('ikev2', 'ike information',
                None, ["show"], cli_def.ADMIN_MODE),
            ('session', 'basic ikev2 status',
                self.show_ikev2_status, ["show", "ikev2"], cli_def.ADMIN_MODE),
            ('detail', 'detailed ikev2 status',
             self.show_ikev2_status_detail, ["show", "ikev2", "session"], cli_def.ADMIN_MODE),
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

    def cliEntry(self, msg, timeout=2500):
        """
        cli entry for module
        """
        return self.cli.cliEntry(cli_def.IKEV2_IPC, msg, timeout)

    def show_ikev2_status(self):
        """'show ikev2' cabllback."""
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = Ikev2MsgType.ShowIkev2Session

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.CliMsgType != Ikev2MsgType.ShowIkev2Session:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.CliDataResult != rsp.CLI_RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.CliDataResult)
            return

        if not rsp.HasField("CliIkev2"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.CliIkev2.ShowIkev2Status.status)
        name = ("Core-id", "Local", "Remote", "Status")
        print_list = list()
        print_list.append(name)
        for dic in para:
            try:
                print_list.append((dic["Core-id"], dic["Local"],
                                   dic["Remote"], dic["Status"]))
            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return

        for field in print_list:
            print "%-17s%-17s%-17s%-17s" % field

    def show_ikev2_status_detail(self):
        """'show ikev2' cabllback."""
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = Ikev2MsgType.ShowIkev2SessionDetail

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.CliMsgType != Ikev2MsgType.ShowIkev2SessionDetail:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.CliDataResult != rsp.CLI_RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.CliDataResult)
            return

        if not rsp.HasField("CliIkev2"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.CliIkev2.ShowIkev2Status.status)
        print para
        name = "%-17s%-20s%-20s%-17s" % ("Core-id", "Local", "Remote", "Status")
        print_list = list()
        print_list.append(name)
        for ike_conn in para:
            for key in ike_conn.keys():
                core_id = key
                value = ike_conn[key]

            try:
                ip_info = "%-17s%-20s%-20s%-17s" % (core_id,
                                                    value["local-host"] + "/" + value["local-port"],
                                                    value["remote-host"] + "/" + value["remote-port"],
                                                    value["state"])
                print_list.append(ip_info)
                print_list.append(" ")
                print_list.append(("   Encr:" + value["encr-alg"] + "," +
                                   "keysize:" + value["encr-keysize"] + "," +
                                   "PRF:" + value["prf-alg"] + "," +
                                   "DH Grp:" + value["dh-group"] + "," +
                                   "Hash:" + value["integ-alg"]))
                # no this field if the node is a responder
                if "reauth-time" not in value:
                    value["reauth-time"] = "unknown"

                print_list.append(("   Active time:" + value["established"] + "," +
                                   "Reauth time:" + value["reauth-time"]))

                # no this field if the node is a responder
                if "initiator" not in value:
                    value["initiator"] = "No"
                print_list.append(("   Local spi:" + value["initiator-spi"] + "   "
                                   "Remote spi:" + value["responder-spi"] + ", " +
                                   "Initiator:" + value["initiator"]))
                print_list.append(("   Local id:" + value["local-id"]))
                print_list.append(("   Remote id:" + value["remote-id"]))

                # print the child sa info
                print_list.append(" ")
                print_list.append("Child sa:")

                for child_sa in value["child-sas"]:
                    child_value = value["child-sas"][child_sa]
                    local_ts = ""
                    remote_ts = ""
                    for item in child_value["local-ts"]:
                        local_ts += item + " "
                    for item in child_value["remote-ts"]:
                        remote_ts += item + " "
                    print_list.append(("  " + child_sa + ":"))
                    print_list.append(("   Local Selector:" + local_ts))
                    print_list.append(("   Remote Selector:" + remote_ts))
                    print_list.append(("   Protocol:" + child_value["protocol"] + "," +
                                       "mode:" + child_value["mode"]))
                    print_list.append(("   spi in/out:" + child_value["spi-in"] + "/" +
                                       child_value["spi-out"]))

                    # no encr-keysize if use null encryption
                    if "encr-keysize" not in child_value:
                        child_value["encr-keysize"] = "Null"

                    print_list.append(("   Encr:" + child_value["encr-alg"] + "," +
                                       "keysize:" + child_value["encr-keysize"] +
                                       ",Hash:" + child_value["integ-alg"]))
                    print_list.append(("   Bytes-in/out:" + child_value["bytes-in"] + "/" + child_value["bytes-out"]))
                    print_list.append(("   Packets-in/out:" + child_value["packets-in"] + "/" + child_value["packets-out"]))
                    print_list.append(("   Active time:" + child_value["install-time"] + "s," +
                                       "life time:" + child_value["life-time"] + "s," +
                                       "rekey time:" + child_value["rekey-time"] + "s"))
                    print_list.append(" ")

            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return

        for field in print_list:
            print field

        # continue print other info
