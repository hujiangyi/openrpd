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

import rpd.provision.process_agent.agent.agent as agent
import rpd.provision.proto.process_agent_pb2 as protoDef
from rpd.dispatcher.dispatcher import Dispatcher
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.proto import Ikev2MsgType
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.rpd_event_def import RPD_EVENT_MUTUAL_AUTH_ERROR

import zmq
import vici
import socket
import json
import struct
import sys

class IkeAgent(agent.ProcessAgent):
    UP = "UP"
    DOWN = "DOWN"
    IKE_UP = "ESTABLISHED"
    CERT = '/etc/ipsec.d/certs/nodeCert.pem'
    VICI = "/var/run/charon.vici"
    CLI_ZMQ = "/tmp/zmq-ikev2.ipc"

    __metaclass__ = AddLoggerToClass
    def __init__(self):

        super(IkeAgent, self).__init__(agent.ProcessAgent.AGENTTYPE_IPSEC)
        self.ike = {}
        self.vici_sock = socket.socket(socket.AF_UNIX)
        self.vici_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.vici_sock.setblocking(0)
        try:
            self.vici_sock.connect(self.VICI)
        except socket.error as e:
            self.logger.error(
                "Cannot connect to the ike server, reason:%s" % str(e))
            self.vici_sock.close()
            sys.exit(0)

        try:
            self.cert = open(self.CERT)
            self.mycert = self.cert.read()
        except IOError:
            self.logger.error("Cannot open the certificate:%s", self.CERT)
            self.vici_sock.close()
            sys.exit(0)

        try:
            self.vici_ses = vici.Session(self.vici_sock)
            # Get all ike conns and stop them
            self.stop_legacy_ike_conn()

            self.vici_ses.register("ike-updown")
        except Exception, e:
            self.logger.error("Cannot initiate the vici session: %s" % e)
            self.vici_sock.close()
            sys.exit(0)

        self.dispatcher.fd_register(self.vici_sock.fileno(), \
                    Dispatcher.EV_FD_IN | Dispatcher.EV_FD_ERR, \
                    self.ike_event_callback)

        self.CliMsgsHandler = {
            Ikev2MsgType.ShowIkev2Session: self.show_ikev2_session,
            Ikev2MsgType.ShowIkev2SessionDetail: self.show_ikev2_session_detail,
        }

    def stop_legacy_ike_conn(self):
        """Clean up the legacy IKE sessions in strongswan."""
        ike_conns = []
        # get the detailed info by blocked operation
        try:
            for conn in self.vici_ses.list_conns():
                ike_conns.append(conn)
        except Exception, e:
            self.logger.error("Cannot get the ike sa info: %s" % e)

        for ike_conn in ike_conns:
            for conn_name in ike_conn.keys():
                self.unload_ike_conn_and_sas(conn_name)


    def ike_event_callback(self, fd, eventmask):
        """Receive an event notification from strongswan.

        :param args: active socket and events
        :type dict
        :return:

        """
        local_ip = None
        remote_ip = None
        ike_status = None

        # Receive the msg from the remote
        if eventmask == 0 or self.vici_sock.fileno() != fd:
            self.logger.warn("Got a fake process event, ignore it")
            return

        if Dispatcher.EV_FD_IN & eventmask == 0:
            self.logger.debug("Got a fake event, the receive is not ready!")
            return

        try:
            event = self.vici_ses.listen_status()

            for k, v in event.iteritems():
                if k in self.ccap_cores:
                    local_ip = v.get('local-host')
                    remote_ip = v.get('remote-host')
                    ike_status = v.get('state')
                    break
        # Fixme: should we exit the process?
        except socket.error, msg:
            self.logger.error("Cannot process the event, reason:%s" % str(msg))
            self.dispatcher.fd_unregister(self.vici_sock)
            self.vici_sock.close()
            sys.exit(0)
        except struct.error:
            self.logger.error(
                "Unpack error when try to get the status notification!")
            self.dispatcher.fd_unregister(self.vici_sock)
            self.vici_sock.close()
            sys.exit(0)
        else:
            # Update the status if no exception
            self.logger.debug(
                "Local IP:%s, remote IP:%s, status:%s" %
                (local_ip, remote_ip, ike_status))
            if not local_ip or not remote_ip:
                # ignore this event since it's not meaningful
                self.logger.debug("Cannot process the event, no ip address")
                return

            if local_ip in self.ike and remote_ip in self.ike[local_ip]:
                old_status = self.ike[local_ip][remote_ip]['status']
                if ike_status == self.IKE_UP:
                    self.ike[local_ip][remote_ip]["status"] = self.UP
                else:
                    self.ike[local_ip][remote_ip]["status"] = self.DOWN

                # fault management notify
                if ike_status == self.DOWN:
                    self.notify.error(RPD_EVENT_MUTUAL_AUTH_ERROR[0],
                                      "Certificate Failed(%s %s)" % (local_ip, remote_ip), "")
                # Notify Mgr FSM
                if old_status != self.ike[local_ip][remote_ip]["status"]:
                    id = self.ike[local_ip][remote_ip]["id"]
                    event_request_rsp = protoDef.msg_event_notification()
                    event_request_rsp.core_event.id = id
                    event_request_rsp.core_event.ccap_core_id = id
                    event_request_rsp.core_event.status = protoDef.msg_core_event_notification.OK
                    event_request_rsp.core_event.reason = "Status changed"
                    event_request_rsp.core_event.event_id = self.id
                    event_request_rsp.core_event.result = \
                    self.ike[local_ip][remote_ip]["status"]
                    ccap_core = self.ccap_cores[id]
                    transport = self.mgrs[ccap_core["mgr"]]['transport']

                    try:
                        transport.sock.send(
                            event_request_rsp.SerializeToString(),
                            flags=zmq.NOBLOCK)
                        self.logger.debug(
                            "Send status change to id %s, msg:%s" %
                            (id, event_request_rsp))
                    except zmq.Again as e:
                        pass
                    except Exception as e:
                        self.logger.warn(
                            "Cannot send the event, reason:%s" % str(e))

    def start_ike(self, conn, local_ip, remote_ip):
        """Try to build up a new IKE session.

        :param conn: ike connection name
        :param local_ip: ip address of the local interface
        :type str
        :param remote_ip: ip address of the ccap core
        :type str
        :return: bool

        """
        # fixme: need further improvement
        gcp_sa = conn + "-gcp"
        l2tp_sa = conn + "-l2tp"
        local_ip_str = local_ip + "/" + "32"
        remote_ip_str = remote_ip + "/" + "32"

        local_gcp_ts = local_ip_str + "[tcp]"
        remote_gcp_ts = remote_ip_str + "[tcp/8190]"
        local_l2tp_ts = local_ip_str + "[l2tp]"
        remote_l2tp_ts = remote_ip_str + "[l2tp]"
        proposals = "aes128-sha1-modp768"
        esp_proposals = ['aes128-sha1-modp768','aes128-null-modp768','null-sha1-modp768']

        ses = {
               conn: {'local_addrs': [local_ip], 'remote_addrs': [remote_ip], 'version': '2',
                      'local-2': {'auth': 'pubkey', 'certs': [self.mycert]},
                      'remote-2': {'auth': 'pubkey'},
                      'proposals': [proposals],
                      'children':
                          {
                           gcp_sa: {'mode': 'TRANSPORT', 'start_action': 'start',
                                 'local_ts':[local_gcp_ts], 'remote_ts':[remote_gcp_ts],
                                    'esp_proposals':esp_proposals},
                           l2tp_sa: {'mode': 'TRANSPORT', 'start_action': 'start',
                               'local_ts': [local_l2tp_ts], 'remote_ts': [remote_l2tp_ts]}
                           }
                      }
               }

        rst = True
        self.unregister_vici_notification()
        try:
            self.vici_ses.load_conn(ses)
        except Exception,e:
            self.logger.error("Cannot load the IKE connection: %s"%e)
            rst = False

        self.register_vici_notification()
        return rst

    def unload_ike_conn_and_sas(self, conn):
        """Try to stop the IKE connection.

        :param conn:  connection name
        :type: str
        :return: bool

        """

        conn_name = {"name": conn}
        ike_sa = {"ike":conn, "loglevel":0}
        gcp_child = {"child":conn+"-gcp", "loglevel":0}
        l2tp_child = {"child":conn+"-l2tp", "loglevel":0}

        # Try to terminate all SAs one by one!
        try:
            # termnate all sas
            for log in self.vici_ses.terminate(gcp_child):
                print log
        except Exception, e:
            self.logger.error("Cannot terminate the gcp sa: %s" % e)

        try:
            for log in self.vici_ses.terminate(l2tp_child):
                print log
        except Exception, e:
            self.logger.error("Cannot terminate the l2tp sa: %s" % e)

        try:
            for log in self.vici_ses.terminate(ike_sa):
                print log
        except Exception, e:
            self.logger.error("Cannot terminate the IKE sa: %s" % e)

        try:
            # unload the connection
            self.vici_ses.unload_conn(conn_name)
        except Exception, e:
            self.logger.error("Cannot unload the IKE connection: %s" % e)

    def stop_ike(self, conn):
        """Try to stop the IKE connection.

        :param conn:  connection name
        :type str
        :return: bool

        """
        name = {"name": conn}
        rst = True

        self.unregister_vici_notification()
        rst = self.unload_ike_conn_and_sas(conn)

        self.register_vici_notification()
        return rst

    def process_event_action(self, action):
        """Process the request from the client. TODO params dont match

        :param action: START, STOP or CHECKSTATUS
        :type msg_event
        :return:

        """
        id = action.ccap_core_id
        event_action = action.action

        self.logger.debug("Receive an event action:%s", action)

        if id not in self.ccap_cores:
            self.logger.warn(
                "Cannot process the event action for id %s, reason: id is not registered" % id)
            self._send_event_notification(id, protoDef.msg_core_event_notification.FAIL,
                                          "CCAP core ID is not registered")
            return

        # Get the transport
        ccap_core = self.ccap_cores[id]
        transport = self.mgrs[ccap_core["mgr"]]['transport']
        if not action.HasField("parameter"):
            self.logger.warn("Cannot process the event action for id %s, "
                              "reason:Parameter is not set" % id)
            # return error
            self._send_event_notification(id, protoDef.msg_core_event_notification.FAIL, "Parameter is not set")
            return

        parameter = action.parameter
        # parameter = "12.0.0.1;27.0.0.1"
        # parameter's format is "local_ip;core_ip"
        local_ip, core_ip = parameter.split(";")

        if event_action == protoDef.msg_event.START or \
            event_action == protoDef.msg_event.CHECKSTATUS:
            # check if we are in the requester list, if yes,
            # we just send a current status to it

            rst = True
            if local_ip not in self.ike:
                # this is a new IKE session
                self.ike[local_ip] = {core_ip:{"id":id, "status": self.DOWN}}
                rst = self.start_ike(id, local_ip, core_ip)
            elif core_ip not in self.ike[local_ip]:
                self.ike[local_ip][core_ip] = {"id":id, "status": self.DOWN}
                rst = self.start_ike(id, local_ip, core_ip)

            self.ike[local_ip][core_ip]["id"] = id

            if rst == True:
                status = protoDef.msg_core_event_notification.OK
            else:
                status = protoDef.msg_core_event_notification.FAIL
            self._send_event_notification(
                id, status=status,
                reason="Id has been issue this action, send current status to you",
                result=self.ike[local_ip][core_ip]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            if local_ip not in self.ike or \
                            core_ip not in self.ike[local_ip]:
                status = protoDef.msg_core_event_notification.FAIL
                reason = "Cannot stop event since can not find it."
            else:
                self.ike[local_ip].pop(core_ip)

                if len(self.ike[local_ip]) == 0:
                    self.ike.pop(local_ip)
                rst = self.stop_ike(id)

                if rst == True:
                    status = protoDef.msg_core_event_notification.OK
                else:
                    status = protoDef.msg_core_event_notification.FAIL
                reason = "Executed stop event."

            self._send_event_notification(id, status=status, reason=reason)
            return

    def show_ikev2_session(self):
        """Process the request from the CLI module.

        :type: t_CliMessage
        :return: ret, value

        """

        # just get the simple ike status from local db
        ike_session = []
        for local in self.ike:
            for remote in self.ike[local]:
                id = self.ike[local][remote]["id"]
                status = self.ike[local][remote]["status"]
                value = {"Core-id":id,"Local":local,"Remote":remote,"Status":status}
                ike_session.append(value)

        return True, ike_session

    def unregister_vici_notification(self):
        # unregister the vici_sock at first
        self.dispatcher.fd_unregister(self.vici_sock.fileno())

        # unregister IKE-UPDOWN
        try:
            self.vici_ses.unregister("ike-updown")
        except Exception, e:
            self.logger.error("Cannot unregister the ike event: %s" % e)

    def register_vici_notification(self):
        # register to the poller
        self.dispatcher.fd_register(
            self.vici_sock.fileno(),
            Dispatcher.EV_FD_IN | Dispatcher.EV_FD_ERR,
            self.ike_event_callback)
        # register IKE-UPDOWN again
        try:
            self.vici_ses.register("ike-updown")
        except Exception, e:
            self.logger.error("Cannot register the ike event: %s" % e)

    def show_ikev2_session_detail(self):
        """Process the request from the CLI module.

        :type: t_CliMessage
        :return: ret, value

        """
        # get the detailed ike status from strongswan
        ike_session = []
        rst = True

        self.unregister_vici_notification()

        # get the detailed info by blocked operation
        try:
            for sa in self.vici_ses.list_sas():
                ike_session.append(sa)
        except Exception, e:
            self.logger.error("Cannot get the ike sa info: %s" % e)
            rst = False

        self.register_vici_notification()

        return rst, ike_session

    def process_cli_action(self, msg):
        """Process the request from the CLI module.

        :param msg: message from CLI module
        :type: t_CliMessage
        :return:

        """
        self.logger.debug("Receive an CLI message:%s", msg)

        rsp_msg = t_CliMessage()
        rsp_msg.CliMsgType = msg.CliMsgType
        rsp_msg.CliDataOperation = msg.CliDataOperation

        if msg.CliMsgType in self.CliMsgsHandler:
            handler = self.CliMsgsHandler[msg.CliMsgType]
            ret, value = handler()

            if ret:
                rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_OK
            else:
                rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_FAIL
            rsp_msg.CliIkev2.ShowIkev2Status.status = json.dumps(value)
        else:
            self.logger.debug("Receive a fake CLI message:%s" % str(msg))
            rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_NONE

        self.send_cli_rsp(rsp_msg)

if __name__ == "__main__":
    setup_logging("PROVISION", filename="provision_ike.log")
    ike_agent = IkeAgent()
    ike_agent.start()
