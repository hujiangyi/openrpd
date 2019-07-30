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
from rpd.gpb.provision_pb2 import *
from collections import OrderedDict
import json
import time
import socket
from subprocess import call

TEST_CODE = False


class ProvisionCli(object):
    """Provision cli class."""

    TRIGGER_CLEAR = 0
    TRIGGER_FAIL = 1
    TRIGGER_SUCCESS = 2

    TRIGGER_ACTION_DIC = {
        TRIGGER_CLEAR: "clear",
        TRIGGER_FAIL: "fail",
        TRIGGER_SUCCESS: "success"
    }

    DEBUG_LVL_DIC = {
        0: 'emerg',
        1: 'alert',
        2: 'cri',
        3: 'error',
        4: 'warn',
        5: 'notice',
        6: 'info',
        7: 'debug'
    }

    def __init__(self, cli):
        """Instantiate a basic cli class"""
        self.cli = cli

        self.cli_table = (
            ("provision", "Provision", None, ["show"], cli_def.ADMIN_MODE),
            ("all", "all ccap cores information", self.show_provision_all, ["show", "provision"], cli_def.ADMIN_MODE),
            ("ccap-core", "a single ccap-core information", None, ["show", "provision"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "ccap-core", self.show_provision_ccap_core,
                ["show", "provision", "ccap-core"], cli_def.ADMIN_MODE),
            ("history", "state machine history", self.show_provision_state_history,
             ["show", "provision"], cli_def.ADMIN_MODE),
            ("provision", "Provision", None, ["clear"], cli_def.ADMIN_MODE),
            ("history", "Provision history", self.clear_provision_history, ["clear", "provision"], cli_def.ADMIN_MODE),
            ("statistics", "statistics per state", self.show_provision_ccap_core_statistic,
                ["show", "provision", "ccap-core", cli_def.FUNC_ARG_TYPE_WORD], cli_def.ADMIN_MODE),
            ("tod", "time of day", self.show_provision_tod, ["show"], cli_def.ADMIN_MODE),
            ("dhcp", "dhcp information", self.show_provision_dhcp, ["show"], cli_def.ADMIN_MODE),
            ("if-status", "interface status", self.show_provision_if_status, ["show"], cli_def.ADMIN_MODE),
            ("gcp", "gcp provision information", self.show_provision_gcp, ["show", "provision"], cli_def.ADMIN_MODE),

            ("provision", "provision", None, ["test"], cli_def.ADMIN_MODE),
            ("ccap-core", "ccap-core", None, ["test", "provision"], cli_def.ADMIN_MODE),
            ("remove", "remove", None, ["test", "provision", "ccap-core"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "core-id", self.test_provision_core_remove,
                ["test", "provision", "ccap-core", "remove"], cli_def.ADMIN_MODE),
            ("add", "add", None, ["test", "provision", "ccap-core"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_IP, "core-ip", None, ["test", "provision", "ccap-core", "add"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "interface", self.test_provision_core_add,
                ["test", "provision", "ccap-core", "add", cli_def.FUNC_ARG_TYPE_IP], cli_def.ADMIN_MODE),
            ("change_state", "change_state", None, ["test", "provision", "ccap-core"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "core-id", None,
                ["test", "provision", "ccap-core", "change_state"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "state", self.test_provision_core_change,
                ["test", "provision", "ccap-core", "change_state", cli_def.FUNC_ARG_TYPE_WORD], cli_def.ADMIN_MODE),
            ("trigger", "trigger", None, ["test", "provision"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_NUMBER, "agent id (1-8)", None,
             ["test", "provision", "trigger"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_WORD, "core-id", None,
             ["test", "provision", "trigger", cli_def.FUNC_ARG_TYPE_NUMBER], cli_def.ADMIN_MODE),
            ("fail", "fail", self.test_provision_trigger_fail,
             ["test", "provision", "trigger", cli_def.FUNC_ARG_TYPE_NUMBER, cli_def.FUNC_ARG_TYPE_WORD],
             cli_def.ADMIN_MODE),
            ("success", "success", self.test_provision_trigger_success,
             ["test", "provision", "trigger", cli_def.FUNC_ARG_TYPE_NUMBER, cli_def.FUNC_ARG_TYPE_WORD],
             cli_def.ADMIN_MODE),
            ("clear", "clear", self.test_provision_trigger_clear,
             ["test", "provision", "trigger", cli_def.FUNC_ARG_TYPE_NUMBER, cli_def.FUNC_ARG_TYPE_WORD],
             cli_def.ADMIN_MODE),

            ('debug', 'debug', None, None, cli_def.ADMIN_MODE),
            ("provision", "Provison", None, ["debug"], cli_def.ADMIN_MODE),
            ("manager", "manager", None, ["debug", "provision"], cli_def.ADMIN_MODE),
            ("debug-level", "debug-level", None, ["debug", "provision", "manager"], cli_def.ADMIN_MODE),
            (cli_def.FUNC_ARG_TYPE_NUMBER, "debug-level:0-error,1-warn,2-info,3-debug", self.debug_provision_debug_lvl,
             ["debug", "provision", "manager", "debug-level"], cli_def.ADMIN_MODE),

            ('reboot', 'PC reboot',
             None, ['set'], cli_def.ADMIN_MODE),
            ('hold', 'Blocking system from reboot',
             self.set_pc_reboot_hold, ['set', 'reboot'], cli_def.ADMIN_MODE),
            ('reboot', 'PC reboot',
             None, ['clear'], cli_def.ADMIN_MODE),
            ('hold', 'Unblocking system from reboot',
             self.clear_pc_reboot_hold, ['clear', 'reboot'], cli_def.ADMIN_MODE),

            ('reboot', 'reboot',
             self.reboot, None, cli_def.ADMIN_MODE),
            ('force', 'force reboot',
             self.force_reboot, ['reboot'], cli_def.ADMIN_MODE),

            ('reboot', 'PC reboot',
             None, ['show'], cli_def.ADMIN_MODE),
            ('hold', 'Blocking system from reboot',
             self.show_pc_reboot_hold, ['show', 'reboot'], cli_def.ADMIN_MODE),
        )

        # Add cli_table to cli parser tree
        self.cli.add_cli_table_to_cli_tree(self.cli_table)

    def format_ipv6(self, str):
        grp_addrinfo = socket.getaddrinfo(str, None)[0]
        return grp_addrinfo[4][0]

    def cliEntry(self, msg, timeout=2500):
        """
        cli entry for module
        """
        return self.cli.cliEntry(cli_def.PROVISION_IPC, msg, timeout)

    def show_provision_all(self):
        """'show provision all' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_ALL

        try:
            rspData = self.cliEntry(msg)
            if rspData is None:
                raise Exception("Cannot receive message from provision module.")

            rsp = t_Provision()
            rsp.ParseFromString(rspData)

            if rsp is None:
                raise Exception("Cannot parse the provision data.")

            if rsp.MsgType != t_Provision.SHOW_PROVISION_ALL:
                raise Exception("MsgType %d is not correct, expect:%d" % (rsp.MsgType,
                                                                          t_Provision.SHOW_PROVISION_ALL))

            if rsp.result != t_Provision.RESULT_OK:
                raise Exception("Result is not correct.")

            if not rsp.HasField("parameter"):
                raise Exception("There is no parameter field.")

            para = json.loads(rsp.parameter)
            header = ("ID", "Interface", "IP", "Name", "State",
                      "Role", "HA-Mode", "Initiated-By")
            print_list = list()
            print_list.append(header)

            # Sort by Core Name
            def name_key(s):
                return s['core_name']
            sorted_para = sorted(para, key=name_key)
            max_len = [len(a) for a in header]
            for dic in sorted_para:
                para_tuple = (dic["Core-id"],
                              dic["Interface"],
                              self.format_ipv6(dic["Core-ip"]),
                              dic["core_name"],
                              dic["Current-State"],
                              dic["Core-Role"],
                              dic["HA-Mode"],
                              dic["Initiated-By"])
                print_list.append(para_tuple)
                max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                           for i in range(len(max_len))]
        except Exception as e:
            print("Encounter error when paring provision data. error:%s" % (str(e)))
            return

        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"

        for field in print_list:
            print generate_format % field

    def show_provision_ccap_core(self, parameters):
        """'show provision ccap-core <core-id> ' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_CCAP_CORE
        msg.parameter = str(parameters[0])
        # print msg

        try:
            rspData = self.cliEntry(msg)
            if rspData is None:
                raise Exception("Cannot receive message from provision module.")

            rsp = t_Provision()
            rsp.ParseFromString(rspData)

            if rsp is None:
                raise Exception("Cannot parse the provision data.")

            if rsp.MsgType != t_Provision.SHOW_PROVISION_CCAP_CORE:
                raise Exception("MsgType %d is not correct, expect:%d" % (rsp.MsgType,
                                                                          t_Provision.SHOW_PROVISION_CCAP_CORE))

            if rsp.result != t_Provision.RESULT_OK:
                raise Exception("Result is not correct.")

            if not rsp.HasField("parameter"):
                raise Exception("There is no parameter field.")

            para = json.loads(rsp.parameter)
            name = ["Core ID:", "Core IP:", "Current State:", "Core Role:",
                    "Core HA:", "Initiated By:", "Core StartTime:",
                    "Remote ID:",
                    "Core Name:",
                    "Vendor ID:",
                    "Interface Status Parameter:", "802.1X Parameter:",
                    "DHCP Parameter:", "TOD Parameter:", "IKEV2 Parameter:",
                    "GCP Parameter:", "PTP Parameter:", "L2tp Parameter:"]
            sub_dic = para["parameter"]
            value = [para["Core-id"], para["Core-ip"], para["Current-State"],
                     para["Core-Role"], para["HA-Mode"], para["Initiated-By"],
                     para["Core-StartTime"],
                     para["remote_id"],
                     para["core_name"],
                     para["vendor_id"],
                     sub_dic[str(AGENTTYPE_INTERFACE_STATUS)],
                     sub_dic[str(AGENTTYPE_8021X)],
                     sub_dic[str(AGENTTYPE_DHCP)],
                     sub_dic[str(AGENTTYPE_TOD)],
                     sub_dic[str(AGENTTYPE_IPSEC)],
                     sub_dic[str(AGENTTYPE_GCP)],
                     sub_dic[str(AGENTTYPE_PTP)],
                     sub_dic[str(AGENTTYPE_L2TP)]]
        except Exception as e:
            print("Encounter error when paring provision data. error:%s" % (str(e)))
            return

        for i in range(len(name)):
            print "%-30s%s" % (name[i], value[i])

    def show_provision_state_history(self):
        """'show provision state ' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_STATE_HISTORY

        try:
            rspData = self.cliEntry(msg)
            if rspData is None:
                raise Exception("Cannot receive message from provision module.")

            rsp = t_Provision()
            rsp.ParseFromString(rspData)

            if rsp is None:
                raise Exception("Cannot parse the provision data.")

            if rsp.MsgType != t_Provision.SHOW_PROVISION_STATE_HISTORY:
                raise Exception("MsgType %d is not correct, expect:%d"
                                % (rsp.MsgType, t_Provision.SHOW_PROVISION_STATE_HISTORY))

            if rsp.result != t_Provision.RESULT_OK:
                raise Exception("Result is not correct.")

            if not rsp.HasField("parameter"):
                raise Exception("There is no parameter field.")

            para = json.loads(rsp.parameter, object_pairs_hook=OrderedDict)
            header = ("ID", "Interface", "IP", "Mac", "From-State", "To-State",
                      "event", "Added-By", "Time")
            print_list = list()
            print_list.append(header)

            max_len = [len(a) for a in header]
            for item in para:
                for ccap_core_id in para[item]:
                    info = para[item][ccap_core_id]
                    for timestamp in info:
                        dic = info[timestamp]
                        para_tuple = (ccap_core_id,
                                      dic['interface'],
                                      "NA" if None is dic['core-ip'] else self.format_ipv6(dic['core-ip']),
                                      dic["mac"],
                                      dic["src"],
                                      dic["dst"],
                                      dic["event"],
                                      dic["Added-By"],
                                      timestamp)
                        print_list.append(para_tuple)
                        max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                                   for i in range(len(max_len))]

        except Exception as e:
            print("Encounter error when paring provision data. error:%s" % (str(e)))
            return

        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"

        for field in print_list:
            print generate_format % field

    def clear_provision_history(self):
        """
        clear provision state machine history record.
        """
        msg = t_Provision()
        msg.MsgType = t_Provision.CLEAR_PROVISION_STATE_HISTORY
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.CLEAR_PROVISION_STATE_HISTORY:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if json.loads(rsp.parameter) != "success":
            print "fail"
            return

        print "success"

    def show_provision_ccap_core_statistic(self, parameters):
        """'show provision ccap core statistics ' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_CORE_STATISTIC
        msg.parameter = str(parameters[0])

        try:
            rspData = self.cliEntry(msg)
            if rspData is None:
                raise Exception("Cannot receive message from provision module.")

            rsp = t_Provision()
            rsp.ParseFromString(rspData)

            if rsp is None:
                raise Exception("Cannot parse the provision data.")

            if rsp.MsgType != t_Provision.SHOW_PROVISION_CORE_STATISTIC:
                raise Exception("MsgType %d is not correct, expect:%d"
                                % (rsp.MsgType, t_Provision.SHOW_PROVISION_CORE_STATISTIC))

            if rsp.result != t_Provision.RESULT_OK:
                raise Exception("Result is not correct.")

            if not rsp.HasField("parameter"):
                raise Exception("There is no parameter field.")

            para = json.loads(rsp.parameter, object_pairs_hook=OrderedDict)
            header = ("Agent", "Tx", "Rx", "Error")
            print_list = list()
            print_list.append(header)

            max_len = [len(a) for a in header]
            for agent_id in para:
                dic = para[agent_id]
                para_tuple = (t_event_id.Name(int(agent_id)), str(dic["tx"]), str(dic["rx"]), str(dic["error"]))
                print_list.append(para_tuple)
                max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                           for i in range(len(max_len))]

        except Exception as e:
            print("Encounter error when paring provision data. error:%s" % (str(e)))
            return

        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"

        for field in print_list:
            print generate_format % field

    def show_provision_tod(self):
        """'show provision tod' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_TOD
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.SHOW_PROVISION_TOD:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.parameter)
        name = ("Server", "TimeOffset", "Time", "Status")
        print_list = list()
        print_list.append(name)
        max_len = [len(a) for a in name]
        for dic in para:
            try:
                para_tuple = (','.join(dic["Server"]), str(dic["TimeOffset"]),
                              str(dic["Time"]), "OK" if dic["Status"] else "Fail")
                print_list.append(para_tuple)
                max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                           for i in range(len(max_len))]
            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return

        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"
        for field in print_list:
            print generate_format % field

    def show_provision_dhcp(self):
        """'show provision dhcp' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_DHCP
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.SHOW_PROVISION_DHCP:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.parameter)
        name = ("Interface", "IP-Address", 'Subnet-Mask')
        print_list = list()
        print_list.append(name)
        max_len = [len(a) for a in name]
        detail_name = ["Interface:", "TimeServers:", "TimeOffset:", "LogServers:", "CCAPCores:"]
        print_dlist = list()
        try:
            if 'Interface' in para:
                intf_info = para['Interface']
                for item in intf_info:
                    para_tuple = (item["Interface"], self.format_ipv6(item["IP-Address"]), item['Subnet-Mask'])
                    print_list.append(para_tuple)
                    max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                               for i in range(len(max_len))]
            if "Details" in para:
                detail = para["Details"]
                for intf, item in detail:
                    detail_value = [intf, ', '.join(item["TimeServers"]), item["TimeOffset"],
                                    ', '.join(item["LogServers"]), ', '.join(item["CCAPCores"])]
                    print_dlist.append(detail_value)
        except KeyError as e:
            self.cli.log.error("can't get key[%s] from msg" % str(e))
            return

        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"

        for field in print_list:
            print generate_format % field

        for detail_item in print_dlist:
            print "\nDetails:"
            print '-' * 80
            for idx in range(len(detail_item)):
                print "%-30s%s" % (detail_name[idx], detail_item[idx])

    def show_provision_if_status(self):
        """'show provision if-status' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_INTERFACE_STATUS
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.SHOW_PROVISION_INTERFACE_STATUS:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.parameter)
        name = ("Registered Cores", "Interface", "IP", "Status")
        print_list = list()
        print_list.append(name)
        for dic in para:
            try:
                print_list.append((dic["Registered-Cores"], dic["Interface"],
                                   dic["IP"], "OK" if dic["Status"] else 'Fail'))
            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return

        for field in print_list:
            print "%-20s%-15s%-20s%-9s" % field

    def show_provision_gcp(self):
        """'show provision gcp' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PROVISION_GCP
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.SHOW_PROVISION_GCP:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.parameter)
        name = ("Core-ID", "Core-IP", "Local-IP", "Principal", "Status")
        print_list = list()
        print_list.append(name)
        max_len = [len(a) for a in name]
        for dic in para:
            try:
                para_tuple = (dic["Core-ID"], self.format_ipv6(dic["Core-IP"]),
                              self.format_ipv6(dic["Local-IP"]), dic["Principal"],
                              "OK" if dic["Status"] else 'Fail')
                print_list.append(para_tuple)
                max_len = [max_len[i] if max_len[i] > len(para_tuple[i]) else len(para_tuple[i])
                           for i in range(len(max_len))]
            except KeyError as e:
                self.cli.log.error("can't get key[%s] from msg" % str(e))
                return
        generate_format = ""
        for len_str in max_len:
            generate_format += "%-" + str(len_str + 2) + "s"

        for field in print_list:
            print generate_format % field

    def test_provision_core_remove(self, parameters):
        """'test provision ccap-core remove <core-id>' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.TEST_PROVISION_CCAP_CORE_REMOVE_CORE
        ctrl = msg_magager_api()
        ctrl.core_ctrl.ccap_core_id = str(parameters[0])
        ctrl.core_ctrl.action = msg_ccap_core_ctrl.DEL
        msg.parameter = ctrl.SerializeToString()
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.TEST_PROVISION_CCAP_CORE_REMOVE_CORE:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        ctrl_rsp = msg_magager_api_rsp()
        parameter = str(json.loads(rsp.parameter))
        ctrl_rsp.ParseFromString(parameter)

        if not ctrl_rsp.HasField("core_ctrl_rsp") or \
                ctrl_rsp.core_ctrl_rsp.status != msg_ccap_core_ctrl_rsp.OK:
            print "fail"

        print "success"

    def test_provision_core_add(self, parameters):
        """'test provision ccap-core remove <core-id>' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.TEST_PROVISION_CCAP_CORE_ADD_CORE
        ret = self.send(msg)
        return ret

    def test_provision_core_change(self, parameters):
        """'test provision ccap-core remove <core-id>' cabllback."""
        msg = t_Provision()
        msg.MsgType = t_Provision.TEST_PROVISION_CHANGE_STATE
        ret = self.send(msg)
        return ret

    def _test_provision_trigger_common(self, action, parameters):
        """'
        test provision trigger <process agent>
        <core-id> fail/success/clear' cabllback.
        """
        agentId = int(parameters[0])
        if agentId < 1 or agentId > 8:
            msg = "invalid agent id(%d), should be in [1, 8]" \
                  % int(parameters[0])
            self.cli.log.error(msg)
            print msg
            return

        msg = t_Provision()
        msg.MsgType = t_Provision.TEST_PROVISION_TRIGGER_STATUS
        msg.parameter = ";".join([str(parameters[0]), str(parameters[1]),
                                  self.TRIGGER_ACTION_DIC[action]])
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.TEST_PROVISION_TRIGGER_STATUS:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        if json.loads(rsp.parameter) != "success":
            print "fail"
            return

        print "success"

    def test_provision_trigger_fail(self, parameters):
        """'
        test provision trigger <process agent> <core-id> fail' cabllback.
        """
        self._test_provision_trigger_common(self.TRIGGER_FAIL, parameters)

    def test_provision_trigger_success(self, parameters):
        """'
        test provision trigger <process agent> <core-id> success' cabllback.
        """
        self._test_provision_trigger_common(self.TRIGGER_SUCCESS, parameters)

    def test_provision_trigger_clear(self, parameters):
        """'
        test provision trigger <process agent> <core-id> fail' cabllback.
        """
        self._test_provision_trigger_common(self.TRIGGER_CLEAR, parameters)

    def debug_provision_debug_lvl(self, parameters):
        debugLvl = int(parameters[0])
        if debugLvl not in self.DEBUG_LVL_DIC:
            msg = "invalid debug level(%d)" % debugLvl
            self.cli.log.error(msg)
            print msg
            return

        print "success"

    def set_pc_reboot_hold(self):
        """
        set PC_REBOOT_HOLD, block the system from reboot
        """
        msg = t_Provision()
        msg.MsgType = t_Provision.SET_PC_REBOOT_HOLD
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.SET_PC_REBOOT_HOLD:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if json.loads(rsp.parameter) != "success":
            print "fail"
            return

        print "success"

    def clear_pc_reboot_hold(self):
        """
        clear PC_REBOOT_HOLD, the system can reboot as wish
        """
        msg = t_Provision()
        msg.MsgType = t_Provision.CLEAR_PC_REBOOT_HOLD
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.CLEAR_PC_REBOOT_HOLD:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if json.loads(rsp.parameter) != "success":
            print "fail"
            return

        print "success"

    def reboot(self):
        """
        send a reboot request
        """
        msg = t_Provision()
        msg.MsgType = t_Provision.REBOOT
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.REBOOT:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        if not rsp.HasField("parameter"):
            self.cli.log.error("recv Msg without respond data")
            return

        para = json.loads(rsp.parameter)
        print para

    def force_reboot(self):
        if 1==1 :
            return
        """
        send a force reboot request
        """
        reason = "Force rebooting by provision CLI."
        fd = open("/bootflash/resetlog", 'a+')
        fd.write(time.ctime() + ': ' + reason + '\n')
        fd.close()
        call(["sync"])
        call(["reboot"])

    def show_pc_reboot_hold(self):
        """
        show PC_REBOOT_HOLD set or not
        """
        msg = t_Provision()
        msg.MsgType = t_Provision.SHOW_PC_REBOOT_HOLD
        rspData = self.cliEntry(msg)
        if rspData is None:
            self.cli.log.error("recv Msg with None string data")
            return

        rsp = t_Provision()
        rsp.ParseFromString(rspData)

        if rsp is None:
            self.cli.log.error("recv Msg with None data")
            return

        if rsp.MsgType != t_Provision.SHOW_PC_REBOOT_HOLD:
            self.cli.log.error("recv Msg with incorrect type")
            return

        if rsp.result != t_Provision.RESULT_OK:
            self.cli.log.error("recv Msg with respond result %s" % rsp.result)
            return

        status = json.loads(rsp.parameter)
        print status
