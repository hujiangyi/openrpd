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
from rpd.provision.proto import GcpMsgType


class GcpCli(object):
    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli

        self.cli_table = (
            ('gcp', 'gcp information',
                None, ["show"], cli_def.ADMIN_MODE),
            ('session', 'gcp session overall status',
                self.show_gcp_session, ["show", "gcp"], cli_def.ADMIN_MODE),
            ('statistics', 'detailed gcp statistics per session',
             self.show_gcp_session_detail, ["show", "gcp", "session"], cli_def.ADMIN_MODE),
            ('set', 'set',
             None, None, cli_def.ADMIN_MODE),
            ('logging', 'set logging level', None, ['set'], cli_def.ADMIN_MODE),
            ('gcp', 'set GCP logging level', None, ['set', 'logging'], cli_def.ADMIN_MODE),

            ('all', 'GCP all modules', None, ['set', 'logging', 'gcp'], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, 'level: debug, info, warning or error',
             self.gcp_set_all_logging_level, ['set', 'logging', 'gcp', 'all'], cli_def.ADMIN_MODE),

            ('gdm', 'GCP GDM message', None, ['set', 'logging', 'gcp'], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, 'level: debug, info, warning or error',
             self.gcp_set_gdm_logging_level, ['set', 'logging', 'gcp', 'gdm'], cli_def.ADMIN_MODE),

            ('packet', 'GCP packet handling', None, ['set', 'logging', 'gcp'], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, 'level: debug, info, warning or error',
             self.gcp_set_packet_logging_level, ['set', 'logging', 'gcp', 'packet'], cli_def.ADMIN_MODE),

            ('session', 'GCP session handling', None, ['set', 'logging', 'gcp'], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, 'level: debug, info, warning or error',
             self.gcp_set_session__logging_level, ['set', 'logging', 'gcp', 'session'], cli_def.ADMIN_MODE),

            ('tlv', 'GCP TLV data handling', None, ['set', 'logging', 'gcp'], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, 'level: debug, info, warning or error',
             self.gcp_set_tlv_logging_level, ['set', 'logging', 'gcp', 'tlv'], cli_def.ADMIN_MODE),
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

    def cliEntry(self, msg, timeout=2500):
        """
        cli entry for module
        """
        return self.cli.cliEntry(cli_def.GCP_IPC, msg, timeout)

    def show_gcp_session(self):
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = GcpMsgType.ShowGcpSession

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)

        if rsp.CliMsgType != GcpMsgType.ShowGcpSession:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.CliDataResult != rsp.CLI_RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.CliDataResult)
            return

        if not rsp.HasField("CliGcp"):
            self.cli.log.error("recv Msg without respond data")
            return
        if not rsp.CliGcp.HasField("ShowGcpSession"):
            self.cli.log.error("recv Msg without GCP session data")
            return

        gs = rsp.CliGcp.ShowGcpSession
        print "GCP session information"
        print "\nActive sessions:"
        for session in gs.ActiveSessions:
            print session.session

        print "\nPrincipal session:"
        for session in gs.PrincipalSessions:
            print session.session
        if len(gs.PrincipalSessions) == 0:
            print "None"

        print "\nPrincipal candidate session"
        print gs.PrincipalCandidateSession.session

        print "\nNon Principal sessions:"
        for session in gs.NonPrincipalSessions:
            print session.session
        if len(gs.NonPrincipalSessions) == 0:
            print "None"

        print "\nFailed sessions:"
        for session in gs.FailedSessions:
            print session.session
        if len(gs.FailedSessions) == 0:
            print "None"

        print "\n"

    def show_gcp_session_detail(self):
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_READ
        msg.CliMsgType = GcpMsgType.ShowGcpSessionDetail

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)

        if rsp.CliMsgType != GcpMsgType.ShowGcpSessionDetail:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.CliDataResult != rsp.CLI_RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.CliDataResult)
            return

        if not rsp.HasField("CliGcp"):
            self.cli.log.error("recv Msg without respond data")
            return
        if len(rsp.CliGcp.ShowGcpStats) == 0:
            self.cli.log.error("recv Msg without GCP session statistics data")
            return

        print "GCP session statistics:"
        for session_stats in rsp.CliGcp.ShowGcpStats:
            print "\n" + session_stats.sessions.session
            session_stats.ClearField("sessions")
            for (field, value) in session_stats.ListFields():
                print "{}:{}".format(field.name, value)

    def gcp_logging_entry(self, module, parameters):
        msg = t_CliMessage()
        msg.CliDataOperation = t_CliMessage.CLI_CFG_WRITE
        msg.CliMsgType = GcpMsgType.ChangeGcpLoggingLevel

        if parameters[0] not in ['debug', 'info', 'warning', 'error', 'critical']:
            print "invalid logging level {}".format(parameters[0])

        msg.CliGcp.GcpLogging.module = module
        msg.CliGcp.GcpLogging.level = parameters[0]

        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_CliMessage()
        rsp.ParseFromString(rspData)
        if rsp.CliDataResult == t_CliMessage.CLI_RESULT_OK:
            print "set gcp debug level({}) successfully".format(parameters[0])
        else:
            print "set gcp debug level({}) failed".format(parameters[0])

    def gcp_set_all_logging_level(self, parameters):
        self.gcp_logging_entry(GcpMsgType.GcpAll, parameters)

    def gcp_set_gdm_logging_level(self, parameters):
        self.gcp_logging_entry(GcpMsgType.GcpGDM, parameters)

    def gcp_set_packet_logging_level(self, parameters):
        self.gcp_logging_entry(GcpMsgType.GcpPacketHandling, parameters)

    def gcp_set_tlv_logging_level(self, parameters):
        self.gcp_logging_entry(GcpMsgType.GcpTLV, parameters)

    def gcp_set_session__logging_level(self, parameters):
        self.gcp_logging_entry(GcpMsgType.GcpSession, parameters)
