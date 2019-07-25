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

import unittest

from rpd.dispatcher.dispatcher import Dispatcher


class TestDispatcher(unittest.TestCase):

    def test_essential(self):
        self.assertIsNotNone(Dispatcher(), 'Failed to initialize dispatcher')

    def test_fd_reg(self):
        d = Dispatcher()
        d.fd_register(0, Dispatcher.EV_FD_ALL, None)
        d.fd_modify(0, 0)
        d.fd_unregister(0)
        del d

    def _test_fd_sock_helper(self, fd, eventmask):
        self.disp.fd_unregister(fd)
        self.disp.end_loop()
        self.got_fd = fd
        self.got_eventmask = eventmask

    def test_fd_sock(self):
        d = Dispatcher()
        self.disp = d  # for _test_fd_sock_helper()

        import socket
        s = socket.socket()
        s.setblocking(0)
        s.bind(('', 65000))
        s.listen(10)

        d.fd_register(s.fileno(), d.EV_FD_IN, self._test_fd_sock_helper)
        d.fd_modify(s.fileno(), 0)
        d.fd_unregister(s.fileno())

        c = socket.socket()
        c.setblocking(0)
        ret = c.connect_ex(('localhost', 65000))
        self.assertEqual(ret, 115, 'async connect failed')

        d.fd_register(s.fileno(), d.EV_FD_IN, self._test_fd_sock_helper)
        d.loop()
        self.assertEqual(self.got_fd, s.fileno())
        self.assertEqual(self.got_eventmask, Dispatcher.EV_FD_IN)

        del d
        del s
        del c

    def test_pylint(self):
        """Tests for pylint errors."""
        from subprocess import Popen, PIPE
        import inspect
        fn = inspect.getfile(inspect.currentframe())  # script filename
        pylint_proc = Popen(["pylint", fn], stdout=PIPE, stderr=PIPE)
        grep_proc = Popen(["grep", "^E:"], stdin=pylint_proc.stdout,
                          stdout=PIPE)
        pylint_proc.stdout.close()
        output = grep_proc.communicate()[0]
        self.assertEqual('', output)
        del pylint_proc
        del grep_proc


if __name__ == '__main__':
    unittest.main()
