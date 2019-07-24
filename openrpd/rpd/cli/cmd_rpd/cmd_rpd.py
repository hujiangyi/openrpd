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


"""This modules implements CLI based on Python CMD module"""
import cmd
import re
import readline
import redis
import signal
import os
import commands
from getpass import getpass
import sys
import tempfile
import zmq
from cli import cli_framework_def as cli_def
from cli import db_defs
from rpd.common.rpd_logging import AddLoggerToClass
from cli.cmd_rpd.cli_hal_ipc import CliHalIpc


class CmdRpd(cmd.Cmd, object):
    """A simple framework for writing line-oriented command interpreters.
    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, rphy_cfg=None):
        """Instantiate a line-oriented interpreter framework."""

        cmd.Cmd.__init__(self)
        self.mode_string_table = {
            cli_def.USER_MODE: cli_def.USER_MODE_STRING,
            cli_def.ADMIN_MODE: cli_def.ADMIN_MODE_STRING,
            cli_def.CONFIG_MODE: cli_def.CONFIG_MODE_STRING,
            cli_def.CONFIG_INTERFACE_MODE:
                cli_def.CONFIG_INTERFACE_MODE_STRING,
            cli_def.CONFIG_INTERFACE_SUB_MODE:
                cli_def.CONFIG_INTERFACE_SUB_MODE_STRING,
        }
        self.cmd_prefix_table = {
            cli_def.ADMIN_MODE: cli_def.ADMIN_MODE_PREFIX,
            cli_def.ADMIN_MODE | cli_def.HIDDEN_MODE:
                cli_def.ADMIN_MODE_PREFIX,
            cli_def.CONFIG_MODE: cli_def.CONFIG_MODE_PREFIX,
            cli_def.CONFIG_MODE | cli_def.HIDDEN_MODE:
                cli_def.CONFIG_MODE_PREFIX,
            cli_def.CONFIG_INTERFACE_MODE:
                cli_def.CONFIG_INTERFACE_MODE_PREFIX,
            cli_def.CONFIG_INTERFACE_MODE | cli_def.HIDDEN_MODE:
                cli_def.CONFIG_INTERFACE_MODE_PREFIX,
            cli_def.CONFIG_INTERFACE_SUB_MODE:
                cli_def.CONFIG_INTERFACE_SUB_MODE_PREFIX,
            cli_def.CONFIG_INTERFACE_SUB_MODE | cli_def.HIDDEN_MODE:
                cli_def.CONFIG_INTERFACE_SUB_MODE_PREFIX,
        }
        self.arg_pattern_table = {
            cli_def.FUNC_ARG_TYPE_WORD: re.compile(r'^(\S{1,255})$'),
            cli_def.FUNC_ARG_TYPE_LINE: re.compile(r'^(\^C[\s\S]*\^C\n)$'),
            cli_def.FUNC_ARG_TYPE_NUMBER: re.compile(r'^(-?\d{1,10})$'),
            cli_def.FUNC_ARG_TYPE_IP: re.compile(r'^(\d{1,3}\.){3}\d{1,3}$'),
            cli_def.FUNC_ARG_TYPE_MAC:
                re.compile(r'^([\dA-Fa-f]{4}\.){2}[\dA-Fa-f]{4}$'),
        }

        self.config_db = redis.StrictRedis(unix_socket_path=db_defs.UNIX_SOCKET_PATH,
                                           db=db_defs.CLI_DB)
        self.mode = cli_def.USER_MODE
        self.mode_string = self.mode_string_table[self.mode]
        try:
            if self.config_db.exists(db_defs.HOST_NAME):
                self.prompt = ''.join([self.config_db.get(db_defs.HOST_NAME),
                                       self.mode_string])
            else:
                self.prompt = ''.join([cli_def.DEF_HOST_NAME, self.mode_string])
            if self.config_db.exists(db_defs.BANNER):
                self.intro = self.config_db.get(db_defs.BANNER).replace('^C',
                                                                        '')[:-1]
            else:
                self.intro = cli_def.DEF_INTRO
        except redis.exceptions.ConnectionError:
            self.prompt = ''.join([cli_def.DEF_HOST_NAME, self.mode_string])
            self.intro = cli_def.DEF_INTRO

        self.rphy_cfg = rphy_cfg
        self.cmd_attribute_prefix = '$'
        self.cli_tree = {}
        self.run_config = []
        self.config_parent = []
        self.line_buff_length = 0
        self.get_banner = False
        self.log = self.logger
        self.pipe_cmd_list = ['show', 'more', 'dir']
        self.pipe_mode_list = ['begin', 'include', 'exclude', 'section']

        # These two global params are used to tell handlers whether they are
        # called inside the pipeline. So give them a chance to decide if any
        # aditional action should be taken.
        self.pipe_mode = None
        self.pipe_re_str = None

        self.pipeline_tree = {
            '|': {
                'begin':
                    {'LINE': {}, self.cmd_attribute_prefix +
                                 'LINE': ('Regular Expression', self.beg_pipe, cli_def.ADMIN_MODE)},

                self.cmd_attribute_prefix + 'begin':
                    ('Begin with the line that matches',
                     None, cli_def.ADMIN_MODE),

                'include':
                    {'LINE': {},
                     self.cmd_attribute_prefix + 'LINE': ('Regular Expression',
                                                          self.inc_pipe, cli_def.ADMIN_MODE)},

                self.cmd_attribute_prefix + 'include':
                    ('Include lines that match', None, cli_def.ADMIN_MODE),

                'exclude':
                    {'LINE': {},
                     self.cmd_attribute_prefix + 'LINE': ('Regular Expression',
                                                          self.exc_pipe, cli_def.ADMIN_MODE)},

                self.cmd_attribute_prefix + 'exclude':
                    ('Exclude lines that match', None, cli_def.ADMIN_MODE),

                'section':
                    {'LINE': {},
                     self.cmd_attribute_prefix + 'LINE': ('Regular Expression',
                                                          self.sec_pipe, cli_def.ADMIN_MODE)},

                self.cmd_attribute_prefix + 'section':
                    ('Filter a section of output', None, cli_def.ADMIN_MODE)},
            self.cmd_attribute_prefix + '|':
                ('Output modifiers', None, cli_def.ADMIN_MODE)
        }

        self.test_flag = False
        self.begin_index = 0
        self.end_index = 0
        self.hal_ipc = CliHalIpc("CLI", "CLI application", "1.0.0",
                                 (1, 100, 102))
        self.hal_ipc.start()
        self.context = zmq.Context()
        self.ipc = {}
        self.poll = {}
        self.create_ipc()
        self.log.debug("=" * 80)

    def create_ipc(self):
        """
        Connect cli with other module
        """
        for module, ipc_path in cli_def.IPC_CONF_DICT.iteritems():
            if not os.path.exists(os.path.dirname(ipc_path)):
                os.makedirs(os.path.dirname(ipc_path))
            socket = self.context.socket(zmq.REQ)
            socket.connect("ipc://" + ipc_path)
            self.create_ipc_module(module, ipc_path)

    def create_ipc_module(self, module, ipc_path):
        """
        Connect cli with other module
        """
        socket = self.context.socket(zmq.REQ)
        socket.connect("ipc://" + ipc_path)
        self.ipc[module] = socket
        self.poll[module] = zmq.Poller()
        self.poll[module].register(socket, zmq.POLLIN)

    def sendMsg(self, module, msg):
        """
        send ipc to other module
        """
        if module not in self.ipc or not self.ipc[module]:
            self.log.error("The client is on disconencted state,"
                           "skip to send the message.")
            return False

        if msg is None:
            self.log.error("Cannot send a None or incorrect msg to %d" % module)
            return False

        if msg.IsInitialized():
            self.ipc[module].send(msg.SerializeToString())
            return True
        return False

    def recvMsg(self, module, timeout=None):
        """
        recv ipc from other module
        """
        if module in self.ipc and self.ipc[module]:
            try:
                bin = self.ipc[module].recv(flags=zmq.NOBLOCK)
            except KeyboardInterrupt:
                self.log.error("receive KeyboardInterrupt")
                return None
            except zmq.Again:
                return None
            except Exception as e:
                self.log.error("Cannot process the cli, reason:%s" % str(e))
                return None

            return bin
        else:
            self.log.error("Cannot receive msg since module %d socket is NULL"
                           % module)
            return None

    def cliEntry(self, module, msg, timeout=2500):
        """
        cli entry for function module
        """
        ret = self.sendMsg(module, msg)
        if ret:
            ipc_client = self.ipc[module]
            try:
                socks = dict(self.poll[module].poll(timeout))
                if socks and socks.get(ipc_client) == zmq.POLLIN:
                    out_rsp = ipc_client.recv(flags=zmq.NOBLOCK)
                    return out_rsp
            except KeyboardInterrupt:
                self.log.error("receive KeyboardInterrupt")
            except zmq.Again:
                self.log.error("receive zmq Again")
            except Exception as e:
                self.log.error("Cannot process the cli, reason:%s" % str(e))

            ipc_client.setsockopt(zmq.LINGER, 0)
            ipc_client.close()
            self.poll[module].unregister(ipc_client)
            self.create_ipc_module(module, cli_def.IPC_CONF_DICT[module])
            return None
        else:
            self.log.error("Cannot send msg for module %d cli" % module)
            return None

    def get_cmd_attribute(self, cur_tree, key):
        """Return command attribute"""
        if cur_tree and isinstance(cur_tree, dict) and key and \
                (key in cur_tree):
            return cur_tree[''.join([self.cmd_attribute_prefix, key])]
        else:
            self.log.error('Get cmd attribute fail')
            return (None, None, None)

    def get_cmd_help(self, cur_tree, key):
        """Return command help string."""
        if cur_tree and isinstance(cur_tree, dict) and key and\
                (key in cur_tree):
            return cur_tree[''.join([self.cmd_attribute_prefix, key])][0]
        else:
            self.log.error('Get cmd help fail')
            return None

    def get_cmd_func(self, cur_tree, key):
        """Return command callback function."""
        if cur_tree and isinstance(cur_tree, dict) and key and \
                (key in cur_tree):
            return cur_tree[''.join([self.cmd_attribute_prefix, key])][1]
        else:
            self.log.error('Get cmd func fail')
            return None

    def get_cmd_mode(self, cur_tree, key):
        """Return command mode."""
        if cur_tree and isinstance(cur_tree, dict) and key and \
                (key in cur_tree):
            return cur_tree[''.join([self.cmd_attribute_prefix, key])][2]
        else:
            self.log.error('Get cmd mode fail')
            return None

    @staticmethod
    def sorted_key(item):
        """Return the key which used for sorted function."""

        return item[0]

    def get_sub_config(self, config_string, config_tree, parent, indent):
        """Get sub mode configuration"""

        parent.append(config_string.strip())
        self.run_config.append(''.join([config_string.rstrip(), '\n']))
        self.get_run_config(config_tree, '', parent, indent +
                            cli_def.CONF_INDENT)
        parent.pop()
        if len(parent) == 0:
            self.run_config.append('\n')

    def get_run_config(self, config_tree, line, parent, indent):
        """Retrieve cli tree to build running config."""

        cmd_list = sorted(config_tree.iteritems(), key=CmdRpd.sorted_key)
        if line == '':
            line = ''.join([line, ' ' * indent])
        line_bak = line
        parent_bak = parent

        for items in cmd_list:
            command = items[0]
            # Looking for commands which are not 'end', 'exit' and 'no'
            if isinstance(config_tree[command], dict) and command != 'end'\
                    and command != 'exit' and command != 'no':
                if command in self.arg_pattern_table:
                    # We will add '%s ' to the line when it's parameter
                    line = ''.join([line, '%s '])
                else:
                    # We will add cmd name to the line when it's command
                    line = ''.join([line, '%s ' % command])

                callback = self.get_cmd_func(config_tree, command)
                mode = self.get_cmd_mode(config_tree, command)
                # If this command has subcommand
                if config_tree[command]:
                    # If this command has callback function.
                    # Exp:'intface loopback 1' has subcommand('ip' and so on)
                    # and callback function
                    if callback:
                        config_string = callback([cli_def.SHOW_CONFIG_FLAG,
                                                  parent, line])
                        if mode == self.get_cmd_mode(config_tree[command],
                                                     sorted(config_tree[command].keys())[-1]):
                            if config_string:
                                self.run_config.append(''.join
                                                       ([config_string.rstrip(), '\n']))
                            self.get_run_config(config_tree[command], line,
                                                parent, indent)
                        else:
                            # when we got one interface, config_string will be
                            # 'interface loopback 1'
                            if isinstance(config_string, str):
                                self.get_sub_config(config_string,
                                                    config_tree[command], parent, indent)
                            # when we got several interfaces, config_string is
                            # ['interface loopback 1', 'intface loopback 2', ...]
                            elif isinstance(config_string, list):
                                config_string.sort()
                                for item in config_string:
                                    self.get_sub_config(item,
                                                        config_tree[command], parent, indent)
                    else:
                        self.get_run_config(config_tree[command], line, parent,
                                            indent)
                # We got end of line
                else:
                    config_string = callback([cli_def.SHOW_CONFIG_FLAG,
                                              parent, line])
                    if isinstance(config_string, str):
                        self.run_config.append(''.join
                                               ([config_string.rstrip(), '\n']))

                line = line_bak
                parent = parent_bak

    def parse_config(self, config):
        """Add one command to global cli tree."""

        last_indent, index = 0, 0
        mode_changed = False

        while index < len(config):
            item = config[index]
            index += 1
            if item == '\n':
                continue
            indent = len(item) - len(item.lstrip())
            mode = self.mode
            # banner configuration may be spread accross several lines
            # we shoud put them together
            if item.startswith('banner ^C') and item.count('^C') == 1:
                while True:
                    item = ''.join([item, config[index]])
                    index += 1
                    if config[index - 1].endswith('^C\n'):
                        break

            if indent == last_indent:
                # Exp:intface loopback 1
                #     intface loopback 2
                # their indent are all 0, but we can not execute
                # 'intface loopback 2' after 'interface loopback 1',
                # we shoud execute 'exit' firt
                if mode_changed:
                    self.onecmd('exit')
                    mode = self.mode
                    self.onecmd(item)
                else:
                    self.onecmd(item)
            elif indent == last_indent + cli_def.CONF_INDENT:
                self.onecmd(item)
            elif indent < last_indent:
                if mode_changed:
                    last_indent += cli_def.CONF_INDENT
                num, times = 0, (last_indent - indent) / cli_def.CONF_INDENT
                while num < times:
                    self.onecmd('exit')
                    num += 1
                mode = self.mode
                self.onecmd(item)
            else:
                self.log.error('Unsupported command:%s' % item)
                continue

            if mode < self.mode:
                mode_changed = True
            else:
                mode_changed = False
            last_indent = indent

    def parse_startup_config(self):
        """Read startup config from rphy_cfg file and then set startup config.
        """

        if self.rphy_cfg:
            try:
                filep = open(self.rphy_cfg, 'r')
                startup_config = filep.readlines()
                if startup_config:
                    self.onecmd('enable')
                    self.onecmd('config terminal')
                    self.parse_config(startup_config)
                filep.close()
            except IOError:
                self.log.error("Open startup config file '%s' fail"
                               % self.rphy_cfg)
                return None
        else:
            return None

    def get_current_tree(self, mode, allow_hid):
        """Get current cli paser tree."""

        cur_tree = self.cli_tree
        if mode >= cli_def.ADMIN_MODE:
            try:
                cli_array = self.cmd_prefix_table[mode]
                for item in cli_array:
                    if not allow_hid:
                        item_attribute = self.get_cmd_attribute(cur_tree, item)
                        if item_attribute[2] and \
                                (item_attribute[2] & cli_def.HIDDEN_MODE):
                            return None
                    cur_tree = cur_tree[item]
                return cur_tree
            except KeyError:
                self.log.error('get currnt tree fail:%d' % mode)
                return None
        else:
            return self.cli_tree

    def print_no_hid_cmd(self, cur_tree, leading_line=True):
        """Print all no hidden command under current parser tree."""

        cmd_list = sorted(cur_tree.iteritems(), key=CmdRpd.sorted_key)
        if leading_line:
            print
        for item in cmd_list:
            if isinstance(cur_tree[item[0]], dict) and \
               (self.get_cmd_mode(cur_tree, item[0]) &
               cli_def.HIDDEN_MODE == 0) and \
               (self.get_cmd_mode(cur_tree, item[0]) == self.mode):
                print '%-20s' % item[0], self.get_cmd_help(cur_tree, item[0])

    def tab_help_parse_cmd(self, cmds, cur_tree, allow_multi_match):
        """Parse cmds. It will return None if the cmds couldn't be parsed.
        """

        index, last_key, length = 0, '', len(cmds)
        pipeline_supported = False
        pipeline_ready = False
        inside_pipeline = False

        while index < length:
            cmd_num, arg_num = 0, 0
            command, arg = '', ''
            cmd_match = []
            for key in cur_tree:
                if key in self.arg_pattern_table:
                    if self.get_cmd_mode(cur_tree, key) & cli_def.HIDDEN_MODE == 0 \
                            and not (cmds[index] == '|' and pipeline_ready == True and not inside_pipeline):
                        arg_num += 1
                        arg = key
                else:
                    if key.startswith(cmds[index]) and \
                       isinstance(cur_tree[key], dict):
                        if self.get_cmd_mode(cur_tree, key) &\
                                cli_def.HIDDEN_MODE == 0:
                            cmd_num += 1
                            command = key
                            if allow_multi_match:
                                cmd_match.append(command)

            if cmd_num == 1:
                # For cmd starts with "show/more/...", a pipeline cmd could
                # be added after the complete cmd list.
                if index == 0 and command in self.pipe_cmd_list \
                        and self.mode == cli_def.ADMIN_MODE:
                    pipeline_supported = True

                if pipeline_supported and self.get_cmd_func(cur_tree, command) != None:
                    pipeline_ready = True
                else:
                    pipeline_ready = False

                index += 1
                if index < length:
                    cur_tree = cur_tree[command]
                last_key = command
                continue
            elif cmd_num > 1:
                # Multipule matches, it's usefull when we end '?'.
                # Exp:we should return all the commands which under 'show' and
                # startwith 'r' when we enter 'show r?'
                if allow_multi_match and index == length - 1:
                    last_key = cmd_match
                    index += 1
                    continue
                print "\nInvalid input detected at '%s'" % cmds[index]
                return (None, None)
            elif cmd_num == 0:
                # No command match, but there is one arg, it's an parameter
                if arg_num == 1:
                    if pipeline_supported and \
                                    self.get_cmd_func(cur_tree, arg) != None:
                        pipeline_ready = True
                    else:
                        pipeline_ready = False

                    if arg != 'LINE':
                        if self.arg_pattern_table[arg].match(cmds[index]):
                            index += 1
                            if index < length:
                                cur_tree = cur_tree[arg]
                            last_key = arg
                            continue
                    else:
                        last_key = arg
                        break

                # check if the unrecognized cli is a pipe
                if not inside_pipeline and pipeline_ready:
                    cur_tree = self.pipeline_tree
                    inside_pipeline = True
                    continue

                print "\nInvalid input detected at '%s'" % cmds[index]
                return (None, None)

        return (cur_tree, last_key)

    def complete(self, text, state):
        """Handle Tab to autocompletet."""
        if state == 0 and not self.get_banner:
            if not self.test_flag:
                line = readline.get_line_buffer()
                begidx = readline.get_begidx()
                endidx = readline.get_endidx()
            else:
                line = text
                begidx = self.begin_index
                endidx = self.end_index

            cur_tree = self.get_current_tree(self.mode, False)
            if cur_tree is None:
                self.stdout.write(''.join(['\n', self.prompt, line]))
                self.stdout.flush()
                return None

            cmds = line.split()
            # Empty line
            if not cmds:
                print
            else:
                # There is nothing to complete.
                # !!!readline will treat pipeline mark differently, it will set
                # begidx to the same value of endidx. so we still need to
                # complete for this case.
                if begidx == endidx and not re.search(r'\s\|$', line):
                    result = self.tab_help_parse_cmd(cmds, cur_tree, False)
                    if result != (None, None):
                        print
                else:
                    result = self.tab_help_parse_cmd(cmds, cur_tree, True)
                    if result != (None, None):
                        (cur_tree, last_key) = result
                        if last_key and isinstance(last_key, str):
                            if last_key in self.arg_pattern_table:
                                # It is parameter, not command, can not complete
                                self.stdout.write(''.join(['\n', self.prompt,
                                                           line]))
                                self.stdout.flush()
                                return None
                            (_, _, mode) = self.get_cmd_attribute(
                                cur_tree, last_key)
                            if mode != self.mode:
                                print '\nUnrecognized command.'
                                self.stdout.write(''.join([self.prompt, line]))
                                self.stdout.flush()
                                return None
                            # return the matched command
                            # !!!if last_key is '|', should return whitespace
                            # to readline because readline will treat pipe
                            # differently when completion
                            if last_key == '|':
                                return ' '
                            return ''.join([last_key, ' '])
                        elif last_key and isinstance(last_key, list):
                            print
            # Print one new line
            self.stdout.write(''.join([self.prompt, line]))
            self.stdout.flush()
            return None

    def show_help_str(self, _, test=False, text=''):
        """Handle ? to show help text."""
        if self.get_banner:
            return None

        if not test:
            line = readline.get_line_buffer()
        else:
            line = text

        cur_tree = self.get_current_tree(self.mode, False)
        if cur_tree is None:
            self.stdout.write(''.join(['\n', self.prompt, line]))
            self.stdout.flush()
            return None

        if not line.strip() or len(line) != len(line.rstrip()):
            cmds = line.split()
            if not cmds:
                self.print_no_hid_cmd(cur_tree)
            else:
                result = self.tab_help_parse_cmd(cmds, cur_tree, False)
                if result != (None, None):
                    (cur_tree, last_key) = result
                    if last_key and isinstance(last_key, str):
                        (_, func, mode) = self.get_cmd_attribute(
                            cur_tree, last_key)
                        if mode != self.mode:
                            print '\nUnrecognized command.'
                            self.stdout.write(''.join([self.prompt, line]))
                            self.stdout.flush()
                            return None
                        # We have got one end of line
                        if func:
                            self.print_no_hid_cmd(cur_tree[last_key])
                            for pipe_cmd in self.pipe_cmd_list:
                                if pipe_cmd.startswith(cmds[0]) \
                                        and self.mode == cli_def.ADMIN_MODE:
                                    self.print_no_hid_cmd(self.pipeline_tree,
                                                          False)
                                    break
                            print '<cr>'
                        else:
                            self.print_no_hid_cmd(cur_tree[last_key])
        else:
            cmds = line.split()
            result = self.tab_help_parse_cmd(cmds, cur_tree, True)
            if result != (None, None):
                (cur_tree, last_key) = result
                if last_key and isinstance(last_key, list):
                    print
                    if self.get_cmd_mode(cur_tree, last_key[0]) == self.mode:
                        last_key.sort()
                        for item in last_key:
                            print '%-20s' % item, self.get_cmd_help(cur_tree,
                                                                    item)
                    else:
                        print 'Unrecognized command.'
                elif last_key and isinstance(last_key, str):
                    print
                    if self.get_cmd_mode(cur_tree, last_key) == self.mode:
                        print '%-20s' % last_key, self.get_cmd_help(cur_tree,
                                                                    last_key)
        self.stdout.write(''.join([self.prompt, line]))
        self.stdout.flush()
        return None

    def onecmd_parse_cmd(self, line, cur_tree):
        """Parse line into a full command name and a string containing
        the arguments.  Returns a tuple containing (cur_tree, last_key,
        func_args_list, full_command).
        'cur_tree' and 'last_key' used to find the callback of this cmd.
        'func_args_list' is the parameters of the callback.
        When the mode is bigger than cli_def.CONFIG_MODE, We need 'full_command'
        to build config_parent.
        It will return None if the cmds couldn't be parsed.
        """
        cmds = line.split()
        func_args_list = []
        index, last_key, length = 0, '', len(cmds)
        full_command = ''

        cmd_tree = cur_tree
        pipe_tree = None
        pipe_key = None
        pipe_arg = None
        pipeline_supported = False
        pipeline_ready = False
        inside_pipeline = False

        while index < length:
            cmd_num, arg_num = 0, 0
            command, arg = '', ''
            for key in cur_tree:
                if key in self.arg_pattern_table \
                        and not (cmds[index] == '|' and pipeline_ready == True and not inside_pipeline):
                    arg_num += 1
                    arg = key
                else:
                    if key.startswith(cmds[index]) and \
                       isinstance(cur_tree[key], dict):
                        cmd_num += 1
                        command = key

            if cmd_num == 1:
                if not inside_pipeline:
                    # For cmd starts with "show/more/...", a pipeline cmd could
                    # be added after the complete cmd list.
                    if index == 0 and command in self.pipe_cmd_list \
                            and self.mode == cli_def.ADMIN_MODE:
                        pipeline_supported = True

                    if pipeline_supported and \
                                    self.get_cmd_func(cur_tree, command) != None:
                        pipeline_ready = True
                    else:
                        pipeline_ready = False

                    if index == 0 and self.mode >= cli_def.CONFIG_MODE:
                        # For config command, we add two parameters in front of
                        # func_args_list. fist(flag), it tells callback
                        # function to set or del this configuration.
                        # second(parent), it tells callback function this
                        # configuration is whose subcommand
                        if command == 'no':
                            func_args_list.extend([cli_def.DEL_CONFIG_FLAG,
                                                   self.config_parent])
                        else:
                            func_args_list.extend([cli_def.SET_CONFIG_FLAG,
                                                   self.config_parent])
                    full_command = ''.join([full_command, command])
                    index += 1
                    cmd_tree = cur_tree
                    if index < length:
                        cur_tree = cur_tree[command]
                        full_command = ''.join([full_command, ' '])
                    last_key = command
                    continue
                else:
                    # we are inside pipiline_tree
                    index += 1
                    if index < length:
                        cur_tree = cur_tree[command]
                    pipe_tree = cur_tree
                    pipe_key = command
                    continue
            elif cmd_num > 1:
                print "Invalid input detected at '%s'" % cmds[index]
                return (None, None, None, None, None, None, None)
            elif cmd_num == 0:
                if not inside_pipeline:
                    if arg_num == 1:
                        cmd_tree = cur_tree
                        if pipeline_supported and \
                            self.get_cmd_func(cur_tree, arg) != None:
                            pipeline_ready = True
                        else:
                            pipeline_ready = False

                        # Put one parameter into func_args_list
                        if arg != 'LINE':
                            if self.arg_pattern_table[arg].match(cmds[index]):
                                func_args_list.append(cmds[index])
                                full_command = ''.join([full_command, cmds[index]])
                                index += 1
                                if index < length:
                                    cur_tree = cur_tree[arg]
                                    full_command = ''.join([full_command, ' '])
                                last_key = arg
                                continue
                        # For 'LINE', we take the rest of this line as
                        # one parameter
                        else:
                            parameter = line
                            for line_index in range(index):
                                parameter = parameter.lstrip()
                                parameter = parameter[len(cmds[line_index]):]
                            parameter = parameter.lstrip()
                            last_key = arg
                            func_args_list.append(parameter)
                            full_command = ''.join([full_command, parameter])
                            break

                    # check if the unrecognized cli is a pipe
                    if not inside_pipeline and pipeline_ready:
                        cur_tree = self.pipeline_tree
                        inside_pipeline = True
                        continue

                    print "Invalid input detected at '%s'" % cmds[index]
                    return (None, None, None, None, None, None, None)
                else:
                    # we are inside pipeline_tree
                    if arg_num == 1:
                        if arg != 'LINE':
                            self.log.error("CLI pipeline should have LINE arg")
                            return (None, None, None, None, None, None, None)
                        # For 'LINE', we take the rest of this line
                        # as one parameter
                        else:
                            parameter = line
                            for line_index in range(index):
                                parameter = parameter.lstrip()
                                parameter = parameter[len(cmds[line_index]):]
                            parameter = parameter.lstrip()
                            pipe_key = arg
                            pipe_arg = parameter
                            break

                    print "Invalid input detected at '%s'" % cmds[index]
                    return (None, None, None, None, None, None, None)

        return (cmd_tree, last_key, func_args_list,
                full_command, pipe_tree, pipe_key, pipe_arg)

    def onecmd(self, line):
        """Interpret the argument as though it had been typed in response
        to the prompt.

        This may be overridden, but should not normally need to be;
        see the precmd() and postcmd() methods for useful execution hooks.
        The return value is a flag indicating whether interpretation of
        commands by the interpreter should stop.
        """

        self.update_mode_and_string(self.mode)
        cmds = line.split()
        if not cmds:
            return None

        cur_tree = self.get_current_tree(self.mode, True)
        if cur_tree is None:
            return None

        parse_result = self.onecmd_parse_cmd(line, cur_tree)
        if parse_result[0] is not None:
            (cur_tree, last_key, func_args_list, full_command,
                pipe_tree, pipe_key, pipe_arg) = parse_result
        else:
            return None

        try:
            (_, func, mode) = self.get_cmd_attribute(cur_tree, last_key)
            if pipe_tree and pipe_key:
                if not pipe_arg:
                    print 'Incomplete command.'
                    return None
                (_, pipe_func, pipe_mode) = \
                    self.get_cmd_attribute(pipe_tree, pipe_key)
                if pipe_mode != cli_def.ADMIN_MODE:
                    print 'Unrecognized command.'
                    return None
                if not pipe_func:
                    if pipe_mode != cli_def.ADMIN_MODE:
                        print 'Unrecognized command.'
                    else:
                        print 'Incomplete command.'
                    return None
                else:
                    if func:
                        if mode == self.mode or mode - 1 == self.mode:
                            mode = self.mode
                            if func_args_list:
                                stop = pipe_func(func, func_args_list, pipe_arg)
                            else:
                                stop = pipe_func(func, None, pipe_arg)
                            return stop
                        else:
                            print 'Unrecognized command.'
                            return None
                    else:
                        self.log.error("Unrecognized command before pipe")
            else:
                if func:
                    if mode == self.mode or mode - 1 == self.mode:
                        mode = self.mode
                        if func_args_list:
                            stop = func(func_args_list)
                        else:
                            stop = func()
                        if mode >= cli_def.CONFIG_MODE and mode < self.mode:
                            self.config_parent.append(full_command)
                        return stop
                    else:
                        print 'Unrecognized command.'
                        return None
                else:
                    if mode == self.mode or mode - 1 == self.mode:
                        print 'Incomplete command.'
                    else:
                        print 'Unrecognized command.'
                    return None
        except KeyError:
            self.log.error("can not find command:'%s' attribute field"
                           % last_key)
            return None

    def cmdloop(self, intro=None):
        """Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.
        """

        self.preloop()
        if self.use_rawinput and self.completekey:
            old_completer = readline.get_completer()
            readline.set_completer(self.complete)
            readline.parse_and_bind(''.join([self.completekey, ": complete"]))
            readline.set_customer(self.show_help_str)
            readline.parse_and_bind("?: custom")
            readline.set_completer_delims(" \t\n`~!@#$%^&*()=+[{]}\\|;:'\",<>/?")
        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(''.join([str(self.intro), "\n"]))
            stop = None
            while not stop:
                if self.use_rawinput:
                    try:
                        line = raw_input(self.prompt)
                    except EOFError:
                        print
                        continue
                    except KeyboardInterrupt:
                        self.end_config_mode([cli_def.SET_CONFIG_FLAG])
                        print
                        continue
                try:
                    line = self.precmd(line)
                    stop = self.onecmd(line)
                    stop = self.postcmd(stop, line)
                except Exception, exp:
                    self.log.error('cli error:%s' % exp)
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey:
                readline.set_completer(old_completer)
            tty = commands.getoutput('tty')
            if tty == '/dev/console':
                os.system("/bin/bash")

    def add_item_to_cli_tree(self, item_tuple):
        """Add one command to global cli tree."""

        (cli, help_text, func, parent, mode) = item_tuple

        if not isinstance(cli, str) or not isinstance(help_text, str):
            self.log.error('cli type error: %s %s' % (type(cli), type(help_text)))
            return -1
        if parent and not isinstance(parent, list):
            self.log.error('parent type error:%s' % type(parent))
            return -1
        if mode is None or mode < cli_def.MIN_MODE or mode > cli_def.MAX_MODE:
            self.log.error('mode error:%d' % mode)
            return -1

        cur_tree = self.cli_tree

        cli_array = []
        if mode >= cli_def.ADMIN_MODE and (mode in self.cmd_prefix_table):
            cli_array.extend(self.cmd_prefix_table[mode])
        if parent:
            cli_array.extend(parent)
        cli_array.append(cli)

        cmd_count = 0
        for item in cli_array:
            cmd_count += 1
            try:
                cur_tree = cur_tree[item]
                if cmd_count == len(cli_array):
                    self.log.error('This command has already added:%s' % item)
            except KeyError:
                if cmd_count == len(cli_array):
                    # Add cmd and its attribute(help, func, mode) to cur_tree.
                    # For all cmd, the key of its attribute is
                    # 'self.cmd_attribute_prefix+cmd', the value of its attribut
                    # is one tuple, it contains (help_text, callback_func, mode)
                    cur_tree[item] = {}
                    cur_tree[''.join([self.cmd_attribute_prefix, item])] = (help_text, func, mode)
                else:
                    self.log.error("parent cmd has not added:%s" % item)
                    return -1

    def add_cli_table_to_cli_tree(self, cli_table):
        """Add cli table to global cli tree
        """

        for item_tuple in cli_table:
            (command, help_text, func, parent, mode) = item_tuple
            self.add_item_to_cli_tree(item_tuple)
            # For config command, we will help them add 'no' automatically,
            # except 'end', 'exit', 'no'
            if mode >= cli_def.CONFIG_MODE \
                    and (not ((command == 'end' or command == 'exit' or command == 'no') and parent == None)):
                if parent:
                    parent.insert(0, 'no')
                else:
                    parent = ['no']
                self.add_item_to_cli_tree((command, help_text, func, parent,
                                           mode))

    def get_config_key(self, parent):
        """Before we set/del/show config, we will find out if config_parent
        exist. It will return the config key when config_parent exist.
        It will return None when config_parent does not exist.
        """

        key = ''
        if parent:
            for item in range(len(parent)):
                command = parent[item].split()
                for index in range(len(command)):
                    if index < len(command) - 1:
                        key = ''.join([key, '%s ' % command[index]])
                    else:
                        key = ''.join([key, command[index]])
                if not self.config_db.exists(key):
                    print "Can not find configuration:", parent[item]
                    return None

                if item < len(parent) - 1:
                    key = ''.join([key, ':'])
        return key

    def update_mode_and_string(self, mode):
        """Update cli mode and prompt."""
        try:
            self.mode_string = self.mode_string_table[mode]
            self.mode = mode
            if self.config_db.exists(db_defs.HOST_NAME):
                self.prompt = ''.join([self.config_db.get(db_defs.HOST_NAME),
                                       self.mode_string])
            else:
                self.prompt = ''.join([cli_def.DEF_HOST_NAME, self.mode_string])
        except KeyError:
            self.log.error('Unsupported mode:%d' % mode)

    def end_config_mode(self, parameters):
        """The callback of 'end' command."""
        if parameters and self.mode >= cli_def.CONFIG_MODE:
            self.config_parent = []
            self.update_mode_and_string(cli_def.ADMIN_MODE)

        return None

    def exit_config_mode(self, parameters):
        """'exit' cabllback."""
        if not parameters:
            return None

        if self.mode == cli_def.CONFIG_MODE:
            self.update_mode_and_string(cli_def.ADMIN_MODE)
        elif self.mode == cli_def.CONFIG_INTERFACE_MODE:
            self.update_mode_and_string(cli_def.CONFIG_MODE)
        elif self.mode == cli_def.CONFIG_INTERFACE_SUB_MODE:
            self.update_mode_and_string(cli_def.CONFIG_INTERFACE_MODE)
        else:
            self.log.error("Unknowned mode:%s" % self.mode)
            return None

        if self.mode >= cli_def.CONFIG_MODE:
            self.config_parent.pop()

        return None

    def timeout_handler(self, signum, frame):
        '''get username and passwrd timeout handler'''
        self.log.debug(str(signum) + str(frame))
        raise AssertionError

    def authenticate(self, test=False, strs=''):
        """authenticate before enter cli."""
        if not self.config_db.hlen(db_defs.USER_PASS):
            return True

        num = 0
        signal.signal(signal.SIGALRM, self.timeout_handler)
        while num < 3:
            try:
                try:
                    if not test:
                        get_user = True
                        # system will send signal.SIGALRM when 10s elapsed
                        signal.alarm(10)
                        user = raw_input('Username: ')
                        get_user = False
                        # update the alarm timer
                        signal.alarm(10)
                        pwd = getpass('Password: ')
                    else:
                        user = strs
                        pwd = strs
                except EOFError:
                    if not get_user:
                        print '\n% Login invalid\n'
                    else:
                        print
                    num += 1
                    continue
                except KeyboardInterrupt:
                    if not get_user:
                        print '\n% Login invalid\n'
                    else:
                        print
                    num += 1
                    continue

                if self.config_db.hexists(db_defs.USER_PASS, user) \
                        and pwd == self.config_db.hget(db_defs.USER_PASS, user):
                    # Disable the alarm
                    signal.alarm(0)
                    return True
                else:
                    print '% Login invalid\n'
                    num += 1
            except AssertionError:
                if get_user:
                    print '\n% Username:  timeout expired!'
                    num += 1
                    continue
                else:
                    print '\n% Password:  timeout expired!'
                    print '% Login invalid\n'
                    num += 1
                    continue

    @staticmethod
    def pipe_lines_to_fd(lines, temp_fd, mode, re_str):
        """ read from lines and do RE match, pipe to another temp file """
        if mode == "begin":
            start_print = False
            for line in lines:
                try:
                    if not start_print and re.search(re_str, line):
                        start_print = True
                except re.error:
                    print "Regular Expression Not Valid"
                    break
                if start_print:
                    temp_fd.write(line)

        elif mode == "include":
            for line in lines:
                try:
                    if re.search(re_str, line):
                        temp_fd.write(line)
                except re.error:
                    print "Regular Expression Not Valid"
                    break

        elif mode == "exclude":
            for line in lines:
                try:
                    if not re.search(re_str, line):
                        temp_fd.write(line)
                except re.error:
                    print "Regular Expression Not Valid"
                    break

        elif mode == "section":
            inside_sec = False
            for line in lines:
                try:
                    if not inside_sec:
                        if re.search(re_str, line):
                            if len(line) == len(line.lstrip()):
                                inside_sec = True
                            temp_fd.write(line)
                    else:
                        if len(line) == len(line.lstrip()) or line.strip() == '':
                            inside_sec = False
                            if re.search(re_str, line):
                                if len(line) == len(line.lstrip()):
                                    inside_sec = True
                                temp_fd.write(line)
                        else:
                            temp_fd.write(line)
                except re.error:
                    print "Regular Expression Not Valid"
                    break

        temp_fd.flush()

    def pipe_fd_to_fd(self, orig_fd, temp_fd, mode, re_str):
        """ read from orig and do RE match, pipe to another temp file """
        lines = orig_fd.readlines()
        self.pipe_lines_to_fd(lines, temp_fd, mode, re_str)

    def do_pipe(self, func, param, re_str, mode):
        """ call a function within pipeline mode """
        self.pipe_mode = mode
        self.pipe_re_str = re_str
        temp_file = tempfile.NamedTemporaryFile(mode='r')
        temp_fd = open(temp_file.name, 'w')

        old_stdout = sys.stdout
        old_cli_stdout = self.stdout
        sys.stdout = temp_fd
        self.stdout = temp_fd

        if param:
            stop = func(param)
        else:
            stop = func()

        sys.stdout = old_stdout
        self.stdout = old_cli_stdout

        temp_fd = open(temp_file.name, 'r')
        self.pipe_fd_to_fd(temp_fd, self.stdout, mode, re_str)
        temp_fd.close()

        self.stdout.flush()
        self.pipe_mode = None
        self.pipe_re_str = None
        return stop

    def beg_pipe(self, func, param, re_str):
        """ call function in a begin pipe """
        return self.do_pipe(func, param, re_str, 'begin')

    def inc_pipe(self, func, param, re_str):
        """ call function in a include pipe """
        return self.do_pipe(func, param, re_str, 'include')

    def sec_pipe(self, func, param, re_str):
        """ call function in a section pipe """
        return self.do_pipe(func, param, re_str, 'section')

    def exc_pipe(self, func, param, re_str):
        """ call function in a exclude pipe """
        return self.do_pipe(func, param, re_str, 'exclude')
