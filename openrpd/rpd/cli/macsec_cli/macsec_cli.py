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
from rpd.provision.proto import MacsecMsgType
import json


class MacsecCli(object):
    """Macsec cli class."""

    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli

        self.cli_table = (
            ('dot1x', '8021x information',
                None, ["show"], cli_def.ADMIN_MODE),
            ('summary', 'basic 8021x status',
                self.show_8021x_summary, ["show", "dot1x"], cli_def.ADMIN_MODE),
            ('detail', 'detailed 8021x status',
             self.show_8021x_detail, ["show", "dot1x"], cli_def.ADMIN_MODE),
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

    def cliEntry(self, msg, timeout=2500):
        """
        cli entry for module
        """
        return self.cli.cliEntry(cli_def.MACSEC_IPC, msg, timeout)

    def show_8021x_summary(self):
        """'show 8021x' cabllback."""
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = MacsecMsgType.Show8021xSummary

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.CliMsgType != MacsecMsgType.Show8021xSummary:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.CliDataResult != rsp.CLI_RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.CliDataResult)
            return

        if not rsp.HasField("Cli8021x"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.Cli8021x.Show8021xStatus.status)
        name = ("Interface", "Core-id", "EAP_Received", "Status")
        print_list = list()
        print_list.append(name)
        for dic in para:
            try:
                print_list.append((dic["Interface"], dic["Core ID"],
                                   dic["eap"], dic["Status"]))
            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return

        for field in print_list:
            print "%-17s%-25s%-17s%-17s" % field

    def show_8021x_detail(self):
        """'show 8021x cabllback."""
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = MacsecMsgType.Show8021xDetail

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.CliMsgType != MacsecMsgType.Show8021xDetail:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.CliDataResult != rsp.CLI_RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.CliDataResult)
            return

        if not rsp.HasField("Cli8021x"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.Cli8021x.Show8021xStatus.status)

        name = "%-17s%-25s%-20s%-17s" % ("Interface", "Core-id", "EAP_Received", "Status")
        print_list = list()
        print_list.append(name)
        for dic in para:
            try:
                summary_info = "%-17s%-25s%-20s%-17s" % (dic["Interface"], dic["Core ID"], dic["eap"], dic["Status"])

                print_list.append(summary_info)
                print_list.append(" ")
                print_list.append(dic["Details"])
                print_list.append(" ")
            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return

        for field in print_list:
            print field

        #continue print other info
