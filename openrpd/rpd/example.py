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

import argparse
import zmq
import time
from os import EX_OK, EX_OSERR, EX_DATAERR
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.example_pb2 import t_ExampleMessage

__all__ = ['ExampleClient']


class ExampleClient(object):

    __metaclass__ = AddLoggerToClass

    def __init__(self, ipc_sock_addr):
        self.ipc_sock = None
        try:
            context = zmq.Context.instance()
            self.ipc_sock = context.socket(zmq.PUSH)
            self.ipc_sock.connect(ipc_sock_addr)
        except zmq.ZMQError:
            self.logger.error("Failed to open IPC socket")
            exit(EX_OSERR)

    def do_something(self):
        """Do something and send results to manager.

        :return:

        """
        self.logger.debug("Doing something ...")
        time.sleep(5)
        if self.ipc_sock is not None:
            msg = t_ExampleMessage()
            msg.Message = "Hello world!"
            self.send_ipc_msg(msg)

    def send_ipc_msg(self, ipc_msg):
        """Notify manager about progress.

        :param ipc_msg: GPB message to be sent
        :type ipc_msg: t_ExampleMessage
        :return:

        """
        if not isinstance(ipc_msg, t_ExampleMessage) or \
                not ipc_msg.IsInitialized():
            self.logger.error('Invalid IPC message provided')
            exit(EX_DATAERR)
        msg_str = ipc_msg.SerializeToString()
        if 0 == len(msg_str):
            self.logger.warn('Empty IPC msg, dropping ...')
            return
        self.ipc_sock.send(msg_str)
        self.logger.info("Data sent to manager, length[%d]", len(msg_str))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipc-address', required=True,
                        help='Address for IPC communication')
    args = parser.parse_args()
    ExampleClient(args.ipc_address).do_something()
    exit(EX_OK)


if __name__ == "__main__":
    setup_logging("Example", filename="example.log")
    main()
