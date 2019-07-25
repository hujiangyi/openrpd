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

import socket

from rpd.rcp.gcp import gcp_sessions
from rpd.rcp.rcp_lib import rcp
from rpd.rcp.rcp_packet_director import RCPMasterScenario
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.rcp.rcp_lib import rcp_master
from rpd.confdb.rpd_redis_db import RPDAllocateWriteRecord
from rpd.gpb.CcapCoreIdentification_pb2 import t_CcapCoreIdentification
from rpd.confdb.rpd_redis_db import RCPDB
from rpd.common.utils import Convert


class RCPSlaveSession(gcp_sessions.GCPSlaveSession):
    """Extends GCP slave session with the RCP specifics."""
    __metaclass__ = AddLoggerToClass
    SESSION_STATE_RCP_SLAVE_INITIATED = 20
    SESSION_STATE_RCP_SLAVE_INITIATION_FAILED = 21

    RCP_SEQUENCE_ID_START = 0
    RCP_SEQUENCE_ID_END = 65000
    RCP_TRANSACTION_ID_START = 0
    RCP_TRANSACTION_ID_END = 65000

    PacketClass = rcp.RCPPacket

    MAX_RECONNECT_CNT = 0
    TIMEOUT_TIME = 15

    CORE_CONNECT_TIMEOUT = 5
    CORE_CONNECT_RETRY_COUNT = 3

    RCP_STOP_SYNC = 0
    RCP_WAIT_FOR_SYNC = 1
    RCP_RCV_SYNC = 2

    def __init__(self, session_descriptor, disp, initiated_cb, timeout_cb, connecting_cb):
        """Adds dispatcher object parameter and initiated_cb which will be
        called when session is initiated or when the initiation failed.
        The initiated_cb uses parameter session" what is a object of the
        GCPSession class.

        :param session_descriptor: The session descriptor of the slave session
        :type session_descriptor: GCPSlaveDescriptor
        :param disp: The instance of dispatcher
        :param initiated_cb: Callback function which is called when the
        session is initiated. This instance (self) is passed as argument of the
        callback.

        """
        if ((None is disp) or (None is initiated_cb) or
                (None is session_descriptor)):
            raise AttributeError()

        super(RCPSlaveSession, self).__init__(session_descriptor)
        self.dispatcher = disp

        # Is called after the initiation was successful and this session
        # is in the SESSION_STATE_RCP_SLAVE_INITIATED state
        self.initiated_cb = initiated_cb
        self.timeout_cb = timeout_cb
        self.is_ira_recv = False
        self.is_rex_recv = False

        # initiated may cost random time when connected to core which not exist.
        self.connecting_timer = None
        self.connecting_timeout_cb = connecting_cb
        self.connecting_retry = 0

        self.initiate_retries = 0
        self.ccap_identification = None
        self.initiate_timer = None
        self.timeout_timer = None
        self.keep_alive = self.RCP_STOP_SYNC
        self.reconnect_cnt = 0

        # These items must be accessed by getters only !
        self._transaction_id = self.RCP_TRANSACTION_ID_START
        self._sequence_id = self.RCP_SEQUENCE_ID_START

    def is_reconnect_timeout(self):
        self.logger.debug("Check reconnect cnt: %d", self.reconnect_cnt)
        return self.reconnect_cnt >= self.MAX_RECONNECT_CNT

    def update_reconnect_cnt(self):
        self.reconnect_cnt += 1

    def clear_reconnect_cnt(self):
        self.logger.debug("Clear reconnect cnt")
        self.reconnect_cnt = 0

    def get_next_seq_id(self):
        self._sequence_id += 1
        self._sequence_id %= self.RCP_SEQUENCE_ID_END
        return self._sequence_id

    def get_next_trans_id(self):
        self._transaction_id += 1
        self._transaction_id %= self.RCP_TRANSACTION_ID_END
        return self._transaction_id

    def is_initiated(self):
        return self.session_state == \
            RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED

    def close(self):
        """Closes the session and unregisters file descriptors and timers from
        the dispatcher."""
        try:
            self.dispatcher.fd_unregister(self.get_socket_fd())
        except Exception:
            # socket was not registered
            self.logger.warning("Slave:Socket already removed")
        try:
            if None is not self.initiate_timer:
                self.dispatcher.timer_unregister(self.initiate_timer)
                self.initiate_timer = None
            if None is not self.timeout_timer:
                self.dispatcher.timer_unregister(self.timeout_timer)
                self.timeout_timer = None
            if None is not self.connecting_timer:
                self.dispatcher.timer_unregister(self.connecting_timer)
                self.connecting_timer = None
            self.is_ira_recv = False
            self.is_rex_recv = False

        except Exception:
            self.logger.warning("Slave:timer already unregistered")

        self.keep_alive = self.RCP_STOP_SYNC
        self.initiate_retries = 0
        self.ccap_identification = None
        try:
            super(RCPSlaveSession, self).close()
        except Exception as e:
            self.logger.warning("Slave:Exception happened when close %s", str(e))

        self.logger.info("RCP Slave session closed: %s",
                         self.get_descriptor())

    def initiate(self):
        """Starts the sessions initiation."""
        if self.is_session_failed():
            self.logger.error("Session already failed, can't continue.")
            return

        if self.connecting_timer is None:
            self.connecting_timer = self.dispatcher.timer_register(
                self.CORE_CONNECT_TIMEOUT, self.connecting_timeout_cb, arg=self)
        try:
            super(RCPSlaveSession, self).initiate()
        except Exception as e:
            self.logger.warning("Session already opened: %s", str(e))

        if super(RCPSlaveSession, self).is_session_connecting():
            self.logger.debug("GCP slave session is in connect process, "
                              "please wait for the result.")
            return

        # try to initiate GCPSlaveSession (try to connect to the server)
        if not super(RCPSlaveSession, self).is_initiated():
            self.logger.debug("Failed to initiate GCP slave session, "
                              "can't continue with RCP")
            self.session_state = RCPSlaveSession.SESSION_STATE_FAILED
            return

        # Call the initiated callback
        self.logger.info("RCP Slave session %s has been initiated", self.get_descriptor())
        self.session_state =\
            RCPSlaveSession.SESSION_STATE_RCP_SLAVE_INITIATED

        # call the initiated_cb()
        self.initiated_cb(self)

    def is_session_failed(self):
        """Returns True if the session is in failed state, False is returned
        otherwise."""
        if ((super(RCPSlaveSession, self).is_session_failed()) or
                (self.session_state == RCPSlaveSession
                 .SESSION_STATE_RCP_SLAVE_INITIATION_FAILED)):
            return True
        return False


class CcapCoreIdentification(RPDAllocateWriteRecord):

    """Describes capabilities of the CCAP core."""

    __metaclass__ = AddLoggerToClass
    MAX_INDEX = 0xF

    def __init__(self, index=1, core_id="NA", core_ip_addr="0.0.0.0",
                 is_principal=True, core_name="NA", vendor_id=9,
                 core_mode=t_CcapCoreIdentification.COREMODEACTIVE, initial_configuration_complete=False,
                 move_to_operational=False, core_function=1,
                 resource_set_index=2, data=None):
        super(CcapCoreIdentification, self).__init__(self.MAX_INDEX)

        self.index = index
        self.core_id = core_id
        self.core_ip_addr = core_ip_addr
        self.is_principal = is_principal
        self.core_name = core_name
        self.vendor_id = vendor_id
        self.is_active = core_mode is t_CcapCoreIdentification.COREMODEACTIVE
        self.initial_configuration_complete = initial_configuration_complete
        self.move_to_operational = move_to_operational
        self.core_function = core_function
        self.resource_set_index = resource_set_index
        self.core_mode = core_mode
        self.data = data

    def allocateIndex(self, core_ip_addr="0.0.0.0"):
        """
        when allocate the index with operate allocate write type, we should search the table if
        this ipaddress with a existing a mapping index or not.
        if exsit, return the mapping index. Otherwise, return a new index from the pool
        :param ip_addr:
        :param index:
        :return:
        """
        self.logger.debug("CcapCoreIdentification allocate index ip=%s ", core_ip_addr)
        self.core_ip_addr = core_ip_addr
        db = RCPDB()
        for key in db.get_keys(pattern=self.poolName + ":*"):
            self.index = key.split(':')[1]
            self.read()
            if self.core_ip_addr == core_ip_addr:
                self.logger.debug("find a exist record index=%d with ip=%s",
                                  self.index, core_ip_addr)
                return
        self.__init__()
        super(CcapCoreIdentification, self).allocateIndex()

    def __str__(self):
        return "\n{\n  InitialConfigurationComplete: %s" \
               "\n  MoveToOperational: %s" \
               "\n  CoreFunction: %s" \
               "\n  ResourceSetIndex: %s" \
               "\n  CoreID: %s" \
               "\n  CoreName: %s" \
               "\n  IsPrincipal: %s" \
               "\n}" % (self.initial_configuration_complete, self.move_to_operational, self.core_function,
                        self.resource_set_index, self.core_id, self.core_name, self.is_principal)
    __repr__ = __str__


class RCPMasterDescriptor(gcp_sessions.GCPMasterDescriptor):
    """Adds capabilities into the Master descriptor."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, capabilities, addr,
                 port=gcp_sessions.GCPSessionDescriptor.DEFAULT_PORT_MASTER,
                 addr_family=socket.AF_INET,
                 interface_name=None,
                 scenario=None):
        """

        :param capabilities: The capabilities of the Master
        :type capabilities: RCPMasterCapabilities
        :param addr: IP address of the Master
        :param port:  TCP port on which the Master is listening
        :param addr_family: The address family (AF_INET or AF_INET6)
        :param interface_name: A name of the local interface. Is needed for
        IPv6 link local addresses.
        :raises TypeError: If some of parameters has invalid type.

        """
        if not isinstance(capabilities, CcapCoreIdentification):
            raise TypeError("Invalid capabilities type")

        if ((None is not scenario) and
                (not isinstance(scenario, RCPMasterScenario))):
            raise TypeError("Invalid scenario type")

        super(RCPMasterDescriptor, self).__init__(addr, port, addr_family,
                                                  interface_name)
        self.capabilities = capabilities
        self.scenario = scenario


class RCPMaster(gcp_sessions.GCPMaster):
    """Extends GCP master session with the RCP specifics."""
    __metaclass__ = AddLoggerToClass
    PacketClass = rcp_master.RCPMasterPacket

    class RCPMasterConnectionContext(gcp_sessions.GCPSession.GCP_IO_CTX):
        """Class extends the connection context with transaction_id,
        session_id and scenario_steps."""
        RCP_SEQUENCE_ID_START = 0
        RCP_SEQUENCE_ID_END = 65000
        RCP_TRANSACTION_ID_START = 0
        RCP_TRANSACTION_ID_END = 65000

        def __init__(self, socket,
                     transaction_id_start=RCP_TRANSACTION_ID_START,
                     sequence_id_start=RCP_SEQUENCE_ID_START,
                     scenario_steps=None):
            super(RCPMaster.RCPMasterConnectionContext, self).__init__(socket)
            self.scenario_steps = scenario_steps
            self._sequence_id = sequence_id_start
            self._transaction_id = transaction_id_start
            self._responses_list = []
            self.max_rsp_list_size = 5

        def get_next_seq_id(self):
            self._sequence_id += 1
            self._sequence_id %= self.RCP_SEQUENCE_ID_END
            return self._sequence_id

        def get_next_trans_id(self):
            self._transaction_id += 1
            self._transaction_id %= self.RCP_TRANSACTION_ID_END
            return self._transaction_id

        def get_responses_list(self):
            return self._responses_list

        def add_response(self, pkt):
            if not isinstance(pkt, rcp.RCPPacket):
                self.logger.warning("Unexpected response type")
                return
            self._responses_list.append(pkt)
            if len(self._responses_list) > self.max_rsp_list_size:
                self._responses_list.remove(self._responses_list[0])

        def get_responses_count(self):
            return len(self._responses_list)

        def get_last_response(self):
            if not self.get_responses_count():
                return None
            return self._responses_list[len(self._responses_list) - 1]

    def __init__(self, session_descriptor, dispatcher,
                 scenario=None):
        """

        :param session_descriptor: The descriptor of the RCP Master session
        :type session_descriptor: RCPMasterDescriptor
        :param dispatcher: The instances of dispatcher

        """
        if not isinstance(session_descriptor, RCPMasterDescriptor):
            raise TypeError()
        super(RCPMaster, self).__init__(session_descriptor)
        self.dispatcher = dispatcher

        self.scenario = scenario

    def accept_connection(self):
        """Accepts new connection on the socket and returns file descriptor
        of the new connection."""
        connection, addr = self.io_ctx.socket.accept()
        connection.setblocking(0)
        p_name = connection.getpeername()
        slave_id = "{}:{}".format(p_name[0], p_name[1])
        slave_ip = "{}".format(p_name[0])
        if None is not self.scenario:
            steps_default = self.scenario.get_steps(None)
            steps_id = self.scenario.get_steps(slave_id)
            steps_ip = self.scenario.get_steps(slave_ip)

            if steps_default == steps_id:
                steps = steps_ip
            else:
                steps = steps_id
        else:
            steps = None

        self.slave_cons[connection.fileno()] =\
            RCPMaster.RCPMasterConnectionContext(socket=connection,
                                                 scenario_steps=steps)

        self.logger.info("%s:: Accepted connection (%s)", self.descr,
                         gcp_sessions.GCPSession.get_sock_string(connection))
        return connection.fileno()

    def close(self):
        """Closes the session and unregisters all timers and file descriptors
        from the dispatcher."""
        try:
            self.dispatcher.fd_unregister(self.get_socket_fd())
        except Exception:
            self.logger.debug("Master:Socket already removed")

        # unregister all slaves
        for fd, ctx in self.slave_cons.items():
            ctx.close()
            try:
                self.dispatcher.fd_unregister(fd)
            except (IOError, KeyError):
                self.logger.debug("Slave socket already unregistered")

        super(RCPMaster, self).close()
        self.logger.info("RCPMaster closed: %s", self.get_descriptor())

    def remove_connection(self, fd):
        """Removes connection specified by the connection's file descriptor."""
        try:
            self.dispatcher.fd_unregister(fd)
        except Exception:
            self.logger.debug("File descriptor already unregistered")
        super(RCPMaster, self).remove_connection(fd)

    #
    # Methods for access a response cache (for testing purposes)
    #

    def get_responses_list(self, fd):
        return self.slave_cons[fd].get_responses_list()

    def add_response(self, pkt, fd):
        if not isinstance(pkt, rcp.RCPPacket):
            self.logger.warning("Unexpected response type")
            return
        self.slave_cons[fd].add_response(pkt)

    def get_responses_count(self, fd):
        return self.slave_cons[fd].get_responses_count()

    def get_last_response(self, fd):
        return self.slave_cons[fd].get_last_response()
