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

import zmq
from rpd.common.rpd_logging import AddLoggerToClass

class Transport(object):
    PULLSOCK = zmq.PULL
    PUSHSOCK = zmq.PUSH
    REPSOCK = zmq.REP
    REQSOCK = zmq.REQ
    PAIRSOCK = zmq.PAIR

    TRANSPORT_SERVER = 1
    TRANSPORT_CLIENT = 2

    # Put the ctx into class
    ctx = zmq.Context.instance()

    __metaclass__ = AddLoggerToClass

    def __init__(self, path, sock_type, mode=1):
        # save the configuration
        self.path = path
        self.sock_type = sock_type
        # the socket instance
        self.logger.info("create transport socket for %s, %s, %s",
                         str(self.path), str(self.sock_type), str(mode))
        self.sock = self.ctx.socket(socket_type=sock_type)
        try:
            self.logger.info("transport socket bind/connect begin")
            if mode == self.TRANSPORT_SERVER:
                self.sock.bind(path)
            else:
                self.sock.connect(path)
            self.logger.info("transport socket bind/connect end")
        except Exception as e:
            self.logger.error("transport socket bind/connect fail")
            self.sock.close()
            self.logger.info("transport socket close")
            return

        self.fileno = self.sock.get(zmq.FD)
        return

if __name__ == "__main__":
    trans = Transport("ipc:///tmp/test1", zmq.PUSH)
