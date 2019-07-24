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


from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.HalConfigMsg import *
from rpd.gpb.HalApi_pb2 import *
from cli import cli_framework_def as cli_def
import os


class SsdCli(object):
    """Provision cli class."""
    TRANSPORT_TFTP = 1
    TRANSPORT_HTTP = 2
    transport_mapping = {TRANSPORT_TFTP: 'TFTP', TRANSPORT_HTTP: 'HTTP'}

    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli

        self.cli_table = (
            ("ssd", "secure software download", None, None, cli_def.ADMIN_MODE),
            ("set", "set parameters", None, ["ssd"], cli_def.ADMIN_MODE),
            ("server", "server", None,
             ["ssd", "set"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_IP, "ip address", None,
             ["ssd", "set", "server"], cli_def.ADMIN_MODE),
            ("filename", "filename", None,
             ["ssd", "set", "server", cli_def.FUNC_ARG_TYPE_IP], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "software file", None,
             ["ssd", "set", "server", cli_def.FUNC_ARG_TYPE_IP, "filename"], cli_def.ADMIN_MODE),
            ("transport", "transport", None,
             ["ssd", "set", "server", cli_def.FUNC_ARG_TYPE_IP, "filename", cli_def.FUNC_ARG_TYPE_WORD],
             cli_def.ADMIN_MODE),
            ("tftp", "tftp mode", self.ssd_set_file_tftp,
             ["ssd", "set", "server", cli_def.FUNC_ARG_TYPE_IP, "filename", cli_def.FUNC_ARG_TYPE_WORD, "transport"],
             cli_def.ADMIN_MODE),
            ("http", "http mode", self.ssd_set_file_http,
             ["ssd", "set", "server", cli_def.FUNC_ARG_TYPE_IP, "filename", cli_def.FUNC_ARG_TYPE_WORD, "transport"],
             cli_def.ADMIN_MODE),

            ("cvc", "code verification certificate", None, ["ssd", "set"], cli_def.ADMIN_MODE),
            ("manufacturer", "manufacturer", None, ["ssd", "set", "cvc"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "cvc chain file", self.ssd_set_mfr_cvc,
             ["ssd", "set", "cvc", "manufacturer"], cli_def.ADMIN_MODE),
            ("clear", "clear", self.ssd_clr_mfr_cvc,
             ["ssd", "set", "cvc", "manufacturer"], cli_def.ADMIN_MODE),
            ("co-signer", "co-signer", None, ["ssd", "set", "cvc"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "cvc chain file", self.ssd_set_co_cvc,
             ["ssd", "set", "cvc", "co-signer"], cli_def.ADMIN_MODE),
            ("clear", "clear", self.ssd_clr_co_cvc,
             ["ssd", "set", "cvc", "co-signer"], cli_def.ADMIN_MODE),

            ("control", "control", None, ["ssd"], cli_def.ADMIN_MODE),
            ("start", "start", self.ssd_start, ["ssd", "control"], cli_def.ADMIN_MODE),
            # ("abort", "abort", self.ssd_abort, ["ssd", "control"], cli_def.ADMIN_MODE),
            ("show", "show the SSD config", self.ssd_get_status, ["ssd", "control"], cli_def.ADMIN_MODE),
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

        self.CfgMsgId_dict = dict(API_TO_HAL_MSG_TYPE.items())
        self.transport = None
        self.server = None
        self.filename = None
        self.mfrcvc = None
        self.cocvc = None

    def sendHalMsg(self, cfgMsg):
        hal_ipc = self.cli.hal_ipc
        if hal_ipc.disconnected:
            hal_ipc.logger.error("The client is on disconencted state,"
                                 "skip to send the message.")
            return

        if cfgMsg is None:
            hal_ipc.logger.error("Cannot send a None or incorrect type to HAL")
            return

        for desc, value in cfgMsg.ListFields():
            if desc.name not in self.CfgMsgId_dict:
                hal_ipc.logger.error("Cannot not find %s" % desc.name)
                return
            msg = HalMessage("HalConfig", SrcClientID=hal_ipc.clientID,
                             SeqNum=hal_ipc.seqNum,
                             CfgMsgType=self.CfgMsgId_dict[desc.name],
                             CfgMsgPayload=cfgMsg.SerializeToString())
            hal_ipc._send(msg.Serialize())

            seq = hal_ipc.seqNum
            hal_ipc.seqNum += 1
            return seq

    def RecvHalMsg(self, timeout=None):
        hal_ipc = self.cli.hal_ipc
        if hal_ipc.pullSock:
            try:
                bin = hal_ipc.pullSock.recv()
            except Exception as e:
                print("Got exception when receiving the msg, reason:%s" % str(e))
                return None
            rsp = HalMessage.DeSerialize(bin)
            if rsp.msg.Rsp.Status != HalCommon_pb2.SUCCESS:
                hal_ipc.logger.error("Get rsp msg fail, reason[%s]" % rsp.msg.Rsp.ErrorDescription)
                return None
            return rsp.msg.CfgMsgPayload
        else:
            hal_ipc.logger.error("Cannot receive msg since the pull socket is NULL")
            return None

    def ssd_set_file_tftp(self, parameters):
        self.ssd_set_file(parameters, self.TRANSPORT_TFTP)

    def ssd_set_file_http(self, parameters):
        self.ssd_set_file(parameters, self.TRANSPORT_HTTP)

    def ssd_set_file(self, parameters, transport):
        server = str(parameters[0])
        filename = str(parameters[1])
        if transport not in self.transport_mapping:
            print 'unsupported transport mode!!!'
            return
        self.transport = transport
        self.server = server
        self.filename = filename

    def ssd_set_mfr_cvc(self, parameters):
        mfrcvc = str(parameters[0])
        if not os.path.exists(mfrcvc) or os.stat(mfrcvc).st_size > 1 * 1024 * 1024:
            print 'manufacturer cvc chain file not exists or invalid!!!'
        else:
            self.mfrcvc = mfrcvc

    def ssd_set_co_cvc(self, parameters):
        cocvc = str(parameters[0])
        if not os.path.exists(cocvc) or os.stat(cocvc).st_size > 1 * 1024 * 1024:
            print 'co-signer cvc chain file not exists or invalid!!!'
        else:
            self.cocvc = cocvc

    def ssd_clr_mfr_cvc(self):
        self.mfrcvc = None

    def ssd_clr_co_cvc(self):
        self.cocvc = None

    def ssd_start(self):
        # construct a message and send to driver
        if self.transport is None or self.server is None \
                or self.filename is None:
            print('miss required parameters!!! '
                  'please confirm the [server, filename, transport]')
            return

        halApi = t_HalApi()
        ssd = halApi.ssdController
        ssd.action = ssd.SSD_START
        ssd.server = str(self.server)
        ssd.file = str(self.filename)
        if self.transport_mapping[self.transport] == 'TFTP':
            ssd.transport = ssd.SSD_TRANSPORT_TFTP
        else:
            ssd.transport = ssd.SSD_TRANSPORT_HTTP
        try:
            if self.mfrcvc is not None:
                ssd.manufacturerCvc = open(self.mfrcvc, 'r').read()
            if self.cocvc is not None:
                ssd.cosignerCvc = open(self.cocvc, 'r').read()
        except Exception as e:
            print("Got exception when read the cvc file:%s" % str(e))
            return

        seq = self.sendHalMsg(halApi)
        if seq is None:
            print("Cannot send the request to remote, please check the log for details.")
            return

        # Wait the msg back
        try:
            rsp_data = self.RecvHalMsg()
            if rsp_data is None:
                print("Cannot receive the msg from remote, please check log for details.")
                return
            rsp_msg = t_HalApi()
            rsp_msg.ParseFromString(rsp_data)
            if not rsp_msg.HasField('ssdController') \
                    or rsp_msg.ssdController.action != rsp_msg.ssdController.SSD_START:
                print("Rsp message type is not correct, msg:\n%s" % str(rsp_msg))
                return

        except Exception as e:
            print("Got exception when receiving the msg, reason:%s" % str(e))
            return

    def ssd_abort(self):
        print 'may support later'

    def ssd_get_status(self):
        if self.transport is not None:
            transport = self.transport_mapping[self.transport]
        else:
            transport = None
        print_data = {'transport: ': transport,
                      'server: ': self.server,
                      'file path: ': self.filename,
                      'manufacturer cvc path: ': self.mfrcvc,
                      'co-signer cvc path: ': self.cocvc}
        for head, data in print_data.iteritems():
            if data is not None:
                print head + str(data)
