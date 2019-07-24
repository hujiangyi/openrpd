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
import threading
import errno
from os import EX_DATAERR
from rpd.rcp.rcp_sessions import RCPSlaveSession, RCPMasterCapabilities,RCPMasterDescriptor, RCPMaster
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.rcp.rcp_lib import rcp_tlv_def, rcp
from rpd.rcp.rcp_packet_director import RCPMasterScenario
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib.rcp import RCPSequence
from rpd.rcp.rcp_process import RcpProcess, RcpHalProcess
from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.proto import GcpMsgType
from rpd.rcp.gcp.gcp_sessions import GCPSlaveDescriptor, GCPSession

def fake_cb(data):
    print "fake cb handled"


class RcpSessionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dispatcher = Dispatcher()
        cls.desc = GCPSlaveDescriptor(addr_master='localhost', interface_local='local')
        cls.session = RCPSlaveSession(cls.desc, cls.dispatcher,
                                      fake_cb, fake_cb, fake_cb)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def setUp(self):
        self.process = RcpHalProcess("ipc:///tmp/_test_rcp.tmp",
                                     notify_mgr_cb=fake_cb)

    def tearDown(self):
        self.process.cleanup()

    def test_RCPSlaveSession(self):

        try:
            RCPSlaveSession(self.desc, None,
                        fake_cb, fake_cb, fake_cb)
        except Exception as e:
            self.assertIsInstance(e, AttributeError)

        try:
            RCPSlaveSession(None, self.dispatcher,
                            fake_cb, fake_cb, fake_cb)
        except Exception as e:
            self.assertIsInstance(e, AttributeError)

        try:
            RCPSlaveSession(self.desc, self.dispatcher,
                            None, fake_cb, fake_cb)
        except Exception as e:
            self.assertIsInstance(e, AttributeError)


        self.assertIsNotNone(self.session)

        self.session.reconnect_cnt = 0
        ret = self.session.is_reconnect_timeout()
        self.assertTrue(ret)

        self.session.reconnect_cnt = -1
        ret = self.session.is_reconnect_timeout()
        self.assertFalse(ret)

        self.session.reconnect_cnt = 0
        self.session.update_reconnect_cnt()
        self.assertEqual(self.session.reconnect_cnt, 1)

        self.session.reconnect_cnt = 1
        self.session.clear_reconnect_cnt()
        self.assertEqual(self.session.reconnect_cnt, 0)

        self.session._sequence_id = 1
        ret = self.session.get_next_seq_id()
        self.assertEqual(ret, 2)

        self.session._sequence_id = self.session.RCP_SEQUENCE_ID_END - 1
        ret = self.session.get_next_seq_id()
        self.assertEqual(ret, 0)

        self.session._transaction_id = 1
        ret = self.session.get_next_trans_id()
        self.assertEqual(ret, 2)

        self.session._transaction_id = self.session.RCP_TRANSACTION_ID_END - 1
        ret = self.session.get_next_trans_id()
        self.assertEqual(ret, 0)

        self.session.session_state = 0
        self.assertFalse(self.session.is_initiated())
        self.session.session_state = RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED
        self.assertTrue(self.session.is_initiated())

        self.session.session_state = GCPSession.SESSION_STATE_FAILED
        self.session.initiate()
        self.assertFalse(self.session.is_initiated())

        self.session.session_state = RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATION_FAILED
        self.session.initiate()
        self.assertFalse(self.session.is_initiated())

        self.session.session_state = GCPSession.SESSION_STATE_OPEN
        self.session.initiate()
        self.assertFalse(self.session.is_initiated())

        self.session.session_state =GCPSession.SESSION_STATE_INPROCESS
        self.session.initiate()
        self.assertFalse(self.session.is_initiated())

        self.session.session_state = RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED
        self.session.io_ctx.close()
        self.session.io_ctx = None
        self.session.close()

        self.session.initiate_timer = self.dispatcher.timer_register(
                self.session.CORE_CONNECT_TIMEOUT, self.session.connecting_timeout_cb, arg=self)
        self.session.timeout_timer = self.dispatcher.timer_register(
            self.session.CORE_CONNECT_TIMEOUT, self.session.connecting_timeout_cb, arg=self)
        self.session.close()

        self.session.dispatcher = None
        self.session.timeout_timer = "test"
        self.session.close()
        self.session.dispatcher = self.dispatcher

    def test_RCPMasterCapabilities(self):
        try:
            ret = RCPMasterCapabilities(index =None)
        except Exception as e:
            self.assertIsInstance(e, AttributeError)
        ret  = RCPMasterCapabilities(index=1,core_id="CORE_12312ds",
                              core_ip_addr="1.1.1.1",
                              is_principal=True,
                              core_name="CBR",
                              vendor_id=9,
                              is_active=True)
        self.assertIsInstance(ret, RCPMasterCapabilities)

    def test_RCPMasterDescriptor(self):
        try:
            ret = RCPMasterDescriptor(capabilities=None, addr=None)
        except Exception as e:
            self.assertIsInstance(e, TypeError)

        cap = RCPMasterCapabilities(index=1, core_id="CORE_12312ds",
                                    core_ip_addr="1.1.1.1",
                                    is_principal=True,
                                    core_name="CBR",
                                    vendor_id=9,
                                    is_active=True)
        test = "test"
        try:
            ret = RCPMasterDescriptor(capabilities=cap,addr=None, scenario=test)
        except Exception as e:
            self.assertIsInstance(e, TypeError)

        ret = RCPMasterDescriptor(capabilities=cap,addr="1.1.1.1")
        self.assertIsInstance(ret,RCPMasterDescriptor)

    def test_RCPMasterConnectionContext(self):
        ctx = RCPMaster.RCPMasterConnectionContext(socket=None)
        self.assertIsInstance(ctx, RCPMaster.RCPMasterConnectionContext)

        ctx._sequence_id = 1
        ret = ctx.get_next_seq_id()
        self.assertEqual(ret, 2)

        ctx._transaction_id = 1
        ret = ctx.get_next_trans_id()
        self.assertEqual(ret, 2)

        ret = ctx.get_responses_list()
        self.assertEqual(ret,ctx._responses_list)

        ret = ctx.get_last_response()
        self.assertIsNone(ret)

        test = "test"
        ctx.add_response(test)
        self.assertEqual(0,ctx.get_responses_count())

        pkt = rcp.RCPPacket()
        pkt_1 = rcp.RCPPacket()
        ctx.add_response(pkt)
        self.assertEqual(1,ctx.get_responses_count())
        for i in range(0,ctx.max_rsp_list_size):
            ctx.add_response(pkt_1)
        self.assertEqual(ctx.get_responses_count(), ctx.max_rsp_list_size)
        ret = ctx.get_last_response()
        self.assertEqual(ret, pkt_1)
        self.assertNotEquals(pkt, ctx._responses_list[0])

    def __slave_worker(self):
        self.slave_work_run = True
        if not self.session.is_initiated():
            self.session.reinit()
            self.session.initiate()
        while self.slave_work_run:
            while self.session.is_session_connecting():
                ret = self.session.start_and_check_connect()
                if ret in [0, errno.EINPROGRESS, errno.EALREADY]:
                    continue
                elif ret in [errno.EISCONN, ]:
                    self.session.session_state = RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED
                    return

    def test_RCPMaster(self):
        try:
            RCPMaster(session_descriptor=None, dispatcher=self.dispatcher)
        except Exception as e:
            self.assertIsInstance(e, TypeError)


        cap = RCPMasterCapabilities(index=1, core_id="CORE_12312ds",
                                    core_ip_addr="1.1.1.1",
                                    is_principal=True,
                                    core_name="CBR",
                                    vendor_id=9,
                                    is_active=True)
        scena = RCPMasterScenario()

        desc = RCPMasterDescriptor(capabilities=cap, addr="localhost", scenario=scena)
        master = RCPMaster(session_descriptor=desc, dispatcher=self.dispatcher, scenario=scena)
        self.assertIsInstance(master, RCPMaster)
        master.initiate()
        self.assertTrue(master.is_initiated())

        # start slave working thread
        t = threading.Thread(target=self.__slave_worker())
        t.start()
        fd = master.accept_connection()
        self.assertIsNotNone(fd)

        rsp_list = master.get_responses_list(fd)
        self.assertIsNotNone(rsp_list)

        test = "test"
        master.add_response(pkt=test,fd=fd)
        self.assertEqual(0,master.get_responses_count(fd=fd))

        pkt = rcp.RCPPacket()
        master.add_response(pkt=pkt, fd=fd)
        self.assertEqual(1,master.get_responses_count(fd=fd))
        ret_pkt = master.get_last_response(fd)
        self.assertEqual(pkt,ret_pkt)

        master.close()
        master.remove_connection(fd)
        # wait for the thread
        self.slave_work_run = False
        t.join()
        master.close()
        self.session.close()
        master.dispatcher = None
        master.remove_connection(fd=fd)
        master.close()

if __name__ == '__main__':
    unittest.main()

