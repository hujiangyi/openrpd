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
import tftpy
import argparse

def setup_tftp_server(rootpath=None, server=None, port=None):
    if rootpath is None or not isinstance(rootpath, str):
        rootpath = '/tmp'
    if server is None:
        server = '127.0.0.1'
    if port is None:
        port = 69
    print "=" * 40 + 'setup_tftp_server' + "=" * 40
    print "=" * 40 + 'rootpath:' + str(rootpath) + "=" * 40
    print "=" * 40 + 'server:' + str(server) + "=" * 40
    print "=" * 40 + 'port:' + str(port) + "=" * 40
    s = tftpy.TftpServer(rootpath)
    s.listen(server, int(port))

if __name__ == "__main__":
    parser = argparse.ArgumentParser("tftp server args parser")
    parser.add_argument(
        "--root", metavar='R', type=str, help="tftp root path")
    parser.add_argument(
        "--port", metavar='P', type=int, help="port num")
    parser.add_argument(
        "--server", metavar='S', type=str, help="ip address")
    args = parser.parse_args()
    setup_tftp_server(rootpath=args.root, server=args.server, port=args.port)