#!/usr/bin/env python
# Copyright (c) VECTOR TECHNOLOGIES SA Gdynia, Poland, and
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
import zmq
import argparse
from pickle import loads, dumps
from os.path import isfile


class Client(object):

    def __init__(self):
        context = zmq.Context()
        self.socket = context.socket(zmq.REQ)
        self.socket.connect("ipc:///tmp/rpd_tester.ipc")

    def ask(self, p_args):
        self.socket.send(dumps(p_args))
        received = self.socket.recv()
        result = loads(received)
        self.socket.close()
        return result

    def close(self):
        self.socket.close()


def load_attrs_from_file(file_path):
    if isfile(file_path):
        with open(file_path) as f:
            return [line.strip() for line in f]
    else:
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    Client.py is used to communicate with simulator.
    To set channel: python client.py --scenarios select rfchannelscenario --attrs ...
    To set port: python client.py --scenarios select rfportscenario --attrs ...
    To set default: python client.py --scenarios set_default rfportscenario --attrs ...
    To check status: python client.py --scenarios status
    To break executing scenario: python client.py --scenarios break

    """)
    parser.add_argument('--scenarios', nargs="*")
    parser.add_argument('--attrs', nargs="*")
    parser.add_argument('--file', nargs="?")
    args = vars(parser.parse_args())
    if args["file"]:
        args["file"] = load_attrs_from_file(args["file"])
    client = Client()
    print client.ask(args)
