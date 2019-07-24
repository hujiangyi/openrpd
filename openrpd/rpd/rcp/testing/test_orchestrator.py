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
from rpd.rcp.rcp_orchestrator import *
from rpd.rcp.rcp_master_orchestrator import RCPMasterOrchestrator
from rpd.rcp.gcp.gcp_sessions import GCPSessionDescriptor, GCPSlaveDescriptor
from rpd.rcp.rcp_msg_handling import RCPMSGHandlingError
from rpd.rcp.simulator.start_rpd_alone import *
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.rcp.rcp_lib.testing import test_rcp
from rpd.rcp.gcp.gcp_lib import gcp_msg_def
from rpd.rcp.rcp_lib import rcp_tlv_def
from rpd.gpb.GeneralNotification_pb2 import t_GeneralNotification

addr_family = socket.AF_INET
local_interface = 'lo'
local_port = GCPSessionDescriptor.DEFAULT_PORT_MASTER
local_ip = "127.0.0.1"
core_ip = "127.0.0.1"


class TestRCPSlavePacketHandlerError(unittest.TestCase):

    def test_init_error(self):
        # callback is None
        try:
            RCPSlavePacketHandler(None, None)
        except Exception as e:
            self.assertEqual(AttributeError, type(e))

        # callback is not RCPSlavePacketHandlerCallbackSet
        try:
            RCPSlavePacketHandler(1, None)
        except Exception as e:
            self.assertEqual(TypeError, type(e))


class TestOrchestrator(unittest.TestCase):
    __metaclass__ = AddLoggerToClass

    class RcpProcessChannel(object):

        def notify_mgr_cb(self, seq, args=None):
            print "notify mgr msg: " + str(args)

        def send_ipc_msg(self, msg):
            print "send ipc msg: " + str(msg)

    @classmethod
    def setUpClass(cls):
        cls.master_thread = None
        cls.slave_thread = None
        cls.master_disp = dispatcher.Dispatcher()
        cls.slave_disp = dispatcher.Dispatcher()
        cls.master_orchestrator = None
        cls.slave_orchestrator = None
        cls.setup_master()
        time.sleep(3)
        cls.setup_slave()

    @classmethod
    def tearDownClass(cls):
        cls.master_disp.end_loop()
        cls.slave_disp.end_loop()
        cls.master_thread.join()
        cls.slave_thread.join()

    def setUp(self):
        setup_logging("orchestrator", filename="test_rcp_orchestrator.log")
        self.slave_orchestrator.__init__(disp=self.slave_disp,
                                         cfg_ipc_channel=self.RcpProcessChannel(),
                                         reboot_cb=None)

    def tearDown(self):
        self.slave_orchestrator.remove_sessions_all()
        for s_id, ses in self.slave_orchestrator.sessions_active.items():
            desc = ses.get_descriptor()
            try:
                del self.slave_orchestrator.sessions_active_fd[ses.get_socket_fd()]
            except Exception:
                pass
            ses.close()
            del self.slave_orchestrator.sessions_active[desc.get_uniq_id()]
        for session in self.master_orchestrator.sessions_active.values():
            session.close()

    @classmethod
    def setup_master(cls):
        print "setup master"
        caps = RCPMasterCapabilities(index=1,
                                     core_id="SIM",
                                     core_ip_addr=local_ip,
                                     is_principal=True,
                                     core_name="Master_SIM",
                                     vendor_id=0,
                                     is_active=True,
                                     initial_configuration_complete=True,
                                     move_to_operational=True,
                                     core_function=1,
                                     resource_set_index=2
                                     )
        cls.master_desc = RCPMasterDescriptor(
            caps,
            addr=local_ip,
            port=local_port,
            addr_family=addr_family,
            interface_name=local_interface)
        cls.master_orchestrator = RCPMasterOrchestrator(cls.master_disp)
        cls.master_thread = threading.Thread(target=cls.master_disp.loop)
        cls.master_thread.start()
        time.sleep(1)

    @classmethod
    def setup_slave(cls):
        print "setup slave"
        cls.slave_orchestrator = RCPSlaveOrchestrator(disp=cls.slave_disp,
                                                 cfg_ipc_channel=cls.RcpProcessChannel(),
                                                 reboot_cb=None)
        cls.slave_desc = GCPSlaveDescriptor(
            core_ip, port_master=local_port, addr_local=local_ip,
            interface_local=local_interface,
            addr_family=addr_family)
        cls.slave_thread = threading.Thread(target=cls.slave_disp.loop)
        cls.slave_thread.start()

    def test_add_session(self):
        self.master_orchestrator.add_sessions([self.master_desc])
        time.sleep(2)
        self.slave_orchestrator.add_sessions([self.slave_desc])
        while len(self.slave_orchestrator.sessions_active_fd) < 1:
            print 'active session:', self.slave_orchestrator.sessions_active
            print 'failed session:', self.slave_orchestrator.sessions_failed
            print self.slave_orchestrator.sessions_active_fd
            # test gdm handler
            if len(self.slave_orchestrator.sessions_active):
                session = self.slave_orchestrator.sessions_active.values()[0]
                if session.session_state == session.SESSION_STATE_FAILED:
                    print 'Session failed in test add session...'
                    return
                ret = GdmMsgHandler.ka_msg_hanlder(session, None)
                self.assertEqual(ret, 0)

                self.slave_orchestrator.session_initiate_cb(session)
                ret = self.slave_orchestrator.session_is_active_fd(100)
                self.assertFalse(ret)

                # handle none pkt
                try:
                    self.slave_orchestrator.pkt_handler.handle_pkt(None, session)
                except Exception as e:
                    pass
                if len(self.slave_orchestrator.sessions_active_fd) == 0:
                    session.session_state = RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED
                    fd = session.get_socket_fd()
                    # add it into the sessions_active_fd
                    if fd != -1:
                        self.slave_orchestrator.sessions_active_fd[fd] = session
            time.sleep(1)

        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        # redirect, session in active fd
        session = self.slave_orchestrator.sessions_active.values()[0]
        self.slave_orchestrator.redirect_received(session, [('127.0.0.1', socket.AF_INET)])

        # session_ev_cb, event is error
        self.slave_orchestrator.session_ev_cb(session.get_socket_fd(),
                                              self.slave_orchestrator.dispatcher.EV_FD_ERR)

        try:
            session.session_state = RCPSlaveSession.SESSION_STATE_FAILED
            self.slave_orchestrator.pkt_handler.handle_pkt('pkt', session)
        except Exception as e:
            self.assertEqual(RCPMSGHandlingError, type(e))

        session.session_state = RCPSlaveSession.SESSION_STATE_INIT
        # RCPMSGHandlingError
        self.slave_orchestrator.pkt_handler.handle_msg_notify_rsp('msg', session, 'pkt')

        # connection timeout cb
        self.slave_orchestrator.session_connecting_timeout_cb(session)

        session.connecting_retry = session.CORE_CONNECT_RETRY_COUNT
        self.slave_orchestrator.session_connecting_timeout_cb(session)

    def test_device_management_handler(self):
        self.slave_orchestrator.add_sessions([self.slave_desc])
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]
        self.slave_orchestrator.device_management_handler(slave, 100)

    def test_configuration_to_rcp_wrapper(self):
        self.slave_orchestrator.add_sessions([self.slave_desc])
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]
        seq = test_rcp.TestRCPSpecifics.create_testing_ds_cfg_sequence(
            gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.slave_orchestrator.configuration_to_rcp_wrapper(slave,
                                                             seq, 'transaction_identifier', 'trans_id')
        # remvoe session
        self.slave_orchestrator.remove_sessions_by_core('lo', '127.0.0.1')

    def test_ex_cb(self):
        self.slave_orchestrator.ex_cb(10)

    def test_session_ev_cb_abnormal_case(self):
        # eventmask is 0
        self.slave_orchestrator.session_ev_cb(100, 0)

        # eventmask isn't 0, but fd invalid
        self.slave_orchestrator.session_ev_cb(100, 1)

    def test_configuration_operation(self):
        self.slave_orchestrator.add_sessions([self.slave_desc])
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]
        # None block
        try:
            self.slave_orchestrator.configuration_operation(None, None, None, None)
        except Exception as e:
            self.assertEqual(AttributeError, type(e))

        # rcp_sequence_list is empty
        try:
            self.slave_orchestrator.configuration_operation(slave,
                                                        [], 'pkt_req', None)
        except Exception as e:
            self.assertEqual(AttributeError, type(e))

        # rcp_sequence_list is not empty, but info type is wrong
        try:
            self.slave_orchestrator.configuration_operation(slave,
                                                            [1, ], 'pkt_req', None)
        except Exception as e:
            self.assertEqual(TypeError, type(e))

        # rcp_sequence_list info type is right
        seq = test_rcp.TestRCPSpecifics.create_testing_ds_cfg_sequence(
            gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX)
        self.slave_orchestrator.configuration_operation(slave,
                                                            [seq, ], 'pkt_req', None)
        self.assertEqual(len(self.slave_orchestrator.req_msg_db['pkt_req']["sent_msg"]),1)

    def test_RCPSlaveOrchestrator_init_error(self):
        # dispatcher is None
        try:
            RCPSlaveOrchestrator.__init__(None, None, None)
        except Exception as e:
            self.assertEqual(TypeError, type(e))

        # cfg_ipc_channel is None
        try:
            RCPSlaveOrchestrator.__init__(1, None, None)
        except Exception as e:
            self.assertEqual(TypeError, type(e))

    def test_set_active_principal_core(self):
        self.slave_orchestrator.add_sessions([self.slave_desc])
        # caps is None
        self.slave_orchestrator.set_active_principal_core('eth0', '127.0.0.1')

        # caps is not None, interface is eth0
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]
        slave.ccap_capabilities = self.master_desc.capabilities
        self.slave_orchestrator.set_active_principal_core('eth0', '127.0.0.1')

        # caps not None, interface is lo, mode is standby
        slave.ccap_capabilities.is_active = False
        self.slave_orchestrator.set_active_principal_core('lo', '127.0.0.1')

    def test_set_system_operational(self):
        self.slave_orchestrator.set_system_operational(True)
        self.assertTrue(self.slave_orchestrator.operational)

    def test_notification_process_cb(self):
        # not supported msg type
        self.slave_orchestrator.notification_process_cb(1, 'not supported msg type')

        # support msg type
        self.slave_orchestrator.notification_process_cb(MsgTypeRoutePtpStatus, 'LOSS OF SYNC')
        # support General notification msg
        gen_ntf_msg = t_GeneralNotification()
        gen_ntf_msg.NotificationType = \
            t_GeneralNotification.PTPRESULTNOTIFICATION
        gen_ntf_msg.PtpResult = t_GeneralNotification.PTPHOOUTOFSPEC
        self.slave_orchestrator.notification_process_cb(\
            MsgTypeGeneralNtf, gen_ntf_msg.SerializeToString())
        # active session add, active fd
        self.slave_orchestrator.add_sessions([self.slave_desc])

        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]

        self.slave_orchestrator.session_initiate_cb(slave)
        self.slave_orchestrator.notification_process_cb(MsgTypeRoutePtpStatus, 'ALIGNED')
        #support I07 general notification msg
        gen_ntf_msg.PtpResult = t_GeneralNotification.PTPSYNCHRONIZED
        self.slave_orchestrator.notification_process_cb(\
            MsgTypeGeneralNtf, gen_ntf_msg.SerializeToString())
        # MsgTypeRpdIpv6Info, MsgTypeFaultManagement
        ipv6_msg = t_VendorSpecificExtension()
        sub_tlv_ipv6_addr = ipv6_msg.Ipv6Address.add()
        sub_tlv_ipv6_addr.EnetPortIndex = 0
        sub_tlv_ipv6_addr.IpAddress = "2001:93:3:1::0"
        sub_tlv_ipv6_addr.AddrType = 1
        sub_tlv_ipv6_addr.PrefixLen = 128
        payload = ipv6_msg.SerializeToString()
        self.slave_orchestrator.notification_process_cb(MsgTypeRpdIpv6Info, payload)

        grp_msg = t_VendorSpecificExtension()
        groupinfo = grp_msg.RpdGroupInfo
        groupinfo.ShelfId = "12:34:56:78:90:ab"
        groupinfo.Master = 1
        groupinfo.ShelfSn = "CAT123456"
        payload = grp_msg.SerializeToString()
        self.slave_orchestrator.notification_process_cb(MsgTypeRpdGroupInfo, payload)

        try:
            self.slave_orchestrator.notification_process_cb(MsgTypeFaultManagement,
                                                            json.dumps((1, 'test', {})))
        except Exception as e:
            self.assertEqual(KeyError, type(e))

        slave.ccap_capabilities = self.master_desc.capabilities
        event_dict = rpd_event_def.RpdEventOrderedBuffer.new_dict(
                        str(rpd_event_def.RPD_EVENT_CONNECTIVITY_208[0]), 'test', 0) 
        self.assertIsInstance(event_dict[0],str)
        try:
            self.slave_orchestrator.notification_process_cb(
                MsgTypeFaultManagement, json.dumps((1, 'test', event_dict[1])))
        except:
            self.fail("notification process fail")

    def test_pkt_timeout(self):
        self.slave_orchestrator.PKT_HANDLE_TIMEOUT = 1
        seq = test_rcp.TestRCPSpecifics.create_testing_ds_cfg_sequence(
            gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_REX)
        data = self.master_orchestrator.RCPDataForSlave(
            None,
            seq.parent_gpb)
        self.master_orchestrator.add_data_to_send(data)
        time.sleep(2)
        print "test pkt timeout here"

    @staticmethod
    def construct_gdm_packet(cmd):
        builder = TestOrchestrator.slave_orchestrator.pkt_director.builder
        builder.clear()
        builder.add_packet(transaction_id=0xffff)
        builder.add_gcp_msg(gcp_msg_def.ManagementREQ, 0xffff)
        # Fill GCP message fields
        builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        builder.last_gcp_msg.msg_fields.Port.set_val(0)
        builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        builder.last_gcp_msg.msg_fields.Command.set_val(cmd)
        pkts = builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    @staticmethod
    def construct_eds_pkt_read_rpdcap():
        builder = TestOrchestrator.slave_orchestrator.pkt_director.builder
        builder.clear()
        builder.add_packet(transaction_id=0xffff)
        builder.add_gcp_msg(gcp_msg_def.DataStructREQ, 0xffff)
        builder.add_rcp_msg(rcp_tlv_def.RCP_MSG_TYPE_IRA)
        builder.add_rcp_seq(0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ, gpb_config=None)

        # Fill GCP message fields
        builder.last_gcp_msg.msg_fields.Mode.set_val(0)
        builder.last_gcp_msg.msg_fields.Port.set_val(0)
        builder.last_gcp_msg.msg_fields.Channel.set_val(0)
        builder.last_gcp_msg.msg_fields.VendorID.set_val(0)
        builder.last_gcp_msg.msg_fields.VendorIndex.set_val(0)

        # Set RCP sequence
        builder.last_rcp_sequence.RpdCapabilities.set_is_used()

        seq = builder.last_rcp_sequence
        seq.RpdCapabilities.NumBdirPorts.set_is_used()
        seq.RpdCapabilities.NumDsRfPorts.set_is_used()
        seq.RpdCapabilities.NumUsRfPorts.set_is_used()

        pkts = builder.get_packets()
        if len(pkts) != 1:
            raise RCPPacketBuildError(
                "Unexpected resulting number of packets: {}, "
                "expected: 1".format(len(pkts)))
        return pkts[0]

    @staticmethod
    def construct_eds_pkt_write_ssd():
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ)

        # Set RCP sequence
        seq.parent_gpb.Ssd.SsdServerAddress = '1.1.1.1'

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    @staticmethod
    def construct_eds_pkt_redirect():
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ)

        # Set RCP sequence
        red = seq.parent_gpb.RpdRedirect.add()
        red.RedirectIpAddress = '1.1.1.1'

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    @staticmethod
    def construct_eds_pkt_CcapCoreIdentification(need_info=False,
                                                 op=rcp_tlv_def.RCP_OPERATION_TYPE_READ):
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, op)

        # Set RCP sequence
        ccap = seq.parent_gpb.CcapCoreIdentification.add()
        ccap.Index = 1
        if need_info:
            ccap.IsPrincipal = True
            ccap.CoreMode = 1
            ccap.CoreId = 'CoreId'
            ccap.CoreIpAddress = '1.1.1.1'
            ccap.CoreName = 'CoreName'
            ccap.VendorId = 12

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    @staticmethod
    def construct_eds_pkt_RpdConfigurationDone():
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ)

        # Set RCP sequence
        seq.parent_gpb.RpdConfigurationDone = 1

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    @staticmethod
    def construct_eds_pkt_RpdGlobal():
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ)

        # Set RCP sequence
        ctrl = seq.parent_gpb.RpdGlobal.EvCfg.EvControl.add()
        ctrl.EvPriority = 1
        ctrl.EvReporting = 1

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    @staticmethod
    def construct_eds_pkt_ConfiguredCoreTable():
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ)

        # Set RCP sequence
        tab = seq.parent_gpb.ConfiguredCoreTable.add()
        tab.ConfiguredCoreIp = '1.1.1.1'
        tab.Operation = 1

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    @staticmethod
    def construct_eds_pkt_ActivePrincipalCore():
        seq = rcp.RCPSequence(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA,
                              0xffff, rcp_tlv_def.RCP_OPERATION_TYPE_READ)

        # Set RCP sequence
        seq.parent_gpb.ActivePrincipalCore = '1.1.1.1'

        rcp_msg = rcp.RCPMessage(gcp_msg_def.DataStructREQ, rcp_tlv_def.RCP_MSG_TYPE_IRA)
        rcp_msg.sequences.append(seq)

        gcp_msg = rcp.Message(gcp_msg_def.DataStructREQ)
        # TODO implement correct setting of message fields
        transaction_id = 0xffff
        gcp_msg.msg_fields.TransactionID.set_val(transaction_id)
        gcp_msg.msg_fields.Mode.set_val(0)
        gcp_msg.msg_fields.Port.set_val(11)
        gcp_msg.msg_fields.Channel.set_val(111)
        gcp_msg.msg_fields.VendorID.set_val(1111)
        gcp_msg.msg_fields.VendorIndex.set_val(254)

        gcp_msg.tlv_data.rcp_msgs.append(rcp_msg)

        pkt = rcp.RCPPacket()
        pkt.transaction_identifier = transaction_id
        pkt.protocol_identifier = rcp.RCP_PROTOCOL_ID
        pkt.unit_id = 0
        pkt.msgs.append(gcp_msg)

        return [pkt, gcp_msg]

    def test_handle_eds_pkt(self):
        self.slave_orchestrator.add_sessions([self.slave_desc])
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]
        pkt_handler = self.slave_orchestrator.pkt_handler.handle_msg_eds_req

        # read rpd capability
        pkt, msg = self.construct_eds_pkt_redirect()
        pkt_handler(msg, slave, pkt)

        # write ssd
        slave.ccap_capabilities = self.master_desc.capabilities
        slave.ccap_capabilities.is_active = False
        pkt, msg = self.construct_eds_pkt_write_ssd()
        pkt_handler(msg, slave, pkt)

        # Global, not active
        pkt, msg = self.construct_eds_pkt_RpdGlobal()
        pkt_handler(msg, slave, pkt)

        #CcapCoreIdentification
        pkt, msg = self.construct_eds_pkt_CcapCoreIdentification()
        pkt_handler(msg, slave, pkt)

        pkt, msg = self.construct_eds_pkt_CcapCoreIdentification(True)
        pkt_handler(msg, slave, pkt)

        # configuration done
        pkt, msg = self.construct_eds_pkt_RpdConfigurationDone()
        pkt_handler(msg, slave, pkt)

        # Global, principal and active
        pkt, msg = self.construct_eds_pkt_RpdGlobal()
        pkt_handler(msg, slave, pkt)

        # Configured core table
        pkt, msg = self.construct_eds_pkt_ConfiguredCoreTable()
        pkt_handler(msg, slave, pkt)

        # Active principal core get request
        pkt, msg = self.construct_eds_pkt_ActivePrincipalCore()
        pkt_handler(msg, slave, pkt)

    def test_handle_eds_pkt_AW(self):
        aw_type = rcp_tlv_def.RCP_OPERATION_TYPE_ALLOCATE_WRITE
        wr_type = rcp_tlv_def.RCP_OPERATION_TYPE_WRITE
        self.slave_orchestrator.add_sessions([self.slave_desc])
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return
        slave = self.slave_orchestrator.sessions_active.values()[0]
        pkt_handler = self.slave_orchestrator.pkt_handler.handle_msg_eds_req

        #CcapCoreIdentification
        pkt, msg = self.construct_eds_pkt_CcapCoreIdentification(False, aw_type)
        pkt_handler(msg, slave, pkt)

        pkt, msg = self.construct_eds_pkt_CcapCoreIdentification(True, wr_type)
        pkt_handler(msg, slave, pkt)

        # configuration done
        pkt, msg = self.construct_eds_pkt_RpdConfigurationDone()
        pkt_handler(msg, slave, pkt)

        # Global, principal and active
        pkt, msg = self.construct_eds_pkt_RpdGlobal()
        pkt_handler(msg, slave, pkt)

        # Configured core table
        pkt, msg = self.construct_eds_pkt_ConfiguredCoreTable()
        pkt_handler(msg, slave, pkt)

        # Active principal core get request
        pkt, msg = self.construct_eds_pkt_ActivePrincipalCore()
        pkt_handler(msg, slave, pkt)
        self.assertTrue(slave.is_ira_recv)

    def test_handle_gdm(self):
        self.slave_orchestrator.add_sessions([self.slave_desc])
        if not len(self.slave_orchestrator.sessions_active):
            print 'session init fail'
            return

        Cold_Reset  = 1
        Warm_Reset  = 2
        Standby     = 3
        Wakeup  = 4
        Power_Down  = 5
        Power_Up = 6
        try:
            slave = self.slave_orchestrator.sessions_active.values()[0]
            pkt_handler = self.slave_orchestrator.pkt_handler.handle_pkt
            pkt = self.construct_gdm_packet(Cold_Reset)
            pkt_handler(pkt, slave)
            pkt = self.construct_gdm_packet(Warm_Reset)
            pkt_handler(pkt, slave)
            pkt = self.construct_gdm_packet(Standby)
            pkt_handler(pkt, slave)
            pkt = self.construct_gdm_packet(Power_Down)
            pkt_handler(pkt, slave)
            pkt = self.construct_gdm_packet(Power_Up)
            pkt_handler(pkt, slave)
            pkt = self.construct_gdm_packet(Wakeup)
            pkt_handler(pkt, slave)
        except Exception as e:
            pass

if __name__ == '__main__':
    setup_logging("GCP", filename="rcp.log")
    unittest.main()
