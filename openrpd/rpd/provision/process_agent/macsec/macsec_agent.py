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
from rpd.gpb.provisionapi_pb2 import t_PrivisionApiMessage as t_CliMessage
from rpd.provision.proto import MacsecMsgType
from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.common.rpd_event_def import RPD_EVENT_NET_AUTH_ERROR
from subprocess import call
import os
import json
import commands
from time import time


class MacsecAgent(agent.ProcessAgent):

    """This class defines a 802.1x process agent.

    the main logic is to start the 802.1x feature. Also it is
    responsible for handling the event from mgr.

    """
    UP = "UP"
    DOWN = "DOWN"
    NA = "NA"
    EAP_REQ_TIMEOUT = 10
    EAPOL_START_RETRIES = 3
    __metaclass__ = AddLoggerToClass

    def __init__(self, agent_id=agent.ProcessAgent.AGENTTYPE_8021X):

        super(MacsecAgent, self).__init__(agent_id)

        # the 802.1x status which will be checked, the schema is as follows:
        # interface_name: {
        #   "status" : UP/DOWN
        #   "lastChangeTime": time()
        # }
        self.status_8021x = dict()

        self.CliMsgsHandler = {
            MacsecMsgType.Show8021xSummary: self.show_8021x_summary,
            MacsecMsgType.Show8021xDetail: self.show_8021x_detail,
        }

        # try generate supplicant.conf
        self.generate_wpa_config_file()

        self.register_poll_timer(
            self.EAP_REQ_TIMEOUT, self._check_status_8021x_callback, None)

    def get_mac_address(self):
        """
        @summary: return the MAC address of the first interface
        """
        mac = ""
        try:
            for line in os.popen("/sbin/ifconfig"):
                if 'Ether' in line:
                    mac = line.split()[4]
                    break
        except:
            self.logger.warn("Cannot get the mac address!")

        return mac

    def generate_wpa_config_file(self):
        """Try to generate supplicant.conf.

        :return:

        """
        if os.path.exists('/etc/supplicant.conf') == True:
            return

        mac = self.get_mac_address()

        # fixme: remove when released
        RSA_KEY_FNAME = '/tmp/rpd-rsa.pem'
        RSA_CERT_FNAME = '/tmp/rpd-rsa.cert'
        CL_ROOT_CA_FNAME = '/tmp/CableLabs-Root-CA.cert'
        CL_DEV_CA_FNAME = '/tmp/CableLabs-Device-CA.cert'
        CL_ROOT_CLT_FNAME = '/tmp/CableLabs-Root-CA-Clt.cert'
        ca_cert = CL_ROOT_CLT_FNAME
        client_cert = RSA_CERT_FNAME
        private_key = RSA_KEY_FNAME
        try:
            if (os.path.exists(CL_ROOT_CA_FNAME) and
                    os.path.exists(CL_DEV_CA_FNAME) and
                    os.path.exists(RSA_KEY_FNAME) and
                    os.path.exists(RSA_CERT_FNAME)):
                os.system("cat " + CL_DEV_CA_FNAME + " " + CL_ROOT_CA_FNAME + " > " + CL_ROOT_CLT_FNAME)
                for filepath in [CL_ROOT_CLT_FNAME, RSA_KEY_FNAME, RSA_CERT_FNAME]:
                    with open(filepath, 'r') as fp:
                        if fp.read().strip() != '':
                            break
                else:
                    ca_cert = '/etc/ipsec.d/cacerts/ca_root_clt.pem'
                    client_cert = '/etc/ipsec.d/certs/rpdCert.pem'
                    private_key = '/etc/ipsec.d/private/rpd.key'
            else:
                ca_cert = '/etc/ipsec.d/cacerts/ca_root_clt.pem'
                client_cert = '/etc/ipsec.d/certs/rpdCert.pem'
                private_key = '/etc/ipsec.d/private/rpd.key'

            # if the file doesn't exist, create it
            f = open('/etc/supplicant.conf', 'w')
            f.write("ctrl_interface=/var/run/wpa_supplicant\n")
            f.write("eapol_version=2\n")
            f.write("ap_scan=0\n")
            f.write("fast_reauth=1\n")

            f.write("network={\n")
            f.write("       key_mgmt=IEEE8021X\n")
            f.write("       eap=TLS\n")
            f.write("       identity=" + "\"" + mac + "\"\n")
            f.write("       ca_cert=" + "\"" + ca_cert + "\"\n")
            f.write("       client_cert=" + "\"" + client_cert + "\"\n")
            f.write("       private_key=" + "\"" + private_key + "\"\n")
            f.write("       eapol_flags=0\n")
            f.write("}\n")
            f.close()
        except Exception as e:
            self.logger.error("Cannot generate supplicant.conf:" + str(e))

    def process_event_action(self, action):
        """Process the request from the client. Currently, we will support the
        following event: start/check status/stop.

        :param action: the protobuf object, which contains the event information.
        :return: the function will return an message to remote, success or fail.

        """
        ccap_id = action.ccap_core_id
        event_action = action.action

        self.logger.debug(
            "CCAP core[%s] issued an event action:%s", ccap_id, action)
        if ccap_id not in self.ccap_cores:
            self.logger.warn(
                "Cannot process the event action for id %s, reason: id is not registered" % ccap_id)
            self._send_event_notification(
                ccap_id,
                protoDef.msg_core_event_notification.FAIL,
                "CCAP core ID is not registered")
            return

        if not action.HasField("parameter"):
            self.logger.warn(
                "Cannot process the event action for id %s, reason:Parameter is not set" % ccap_id)
            # return error
            self._send_event_notification(
                ccap_id,
                protoDef.msg_core_event_notification.FAIL,
                "Parameter is not set")
            return

        ifname = action.parameter

        if event_action == protoDef.msg_event.START or event_action == protoDef.msg_event.CHECKSTATUS:
            # check if we are in the requester list, if yes, we just send a current status to it
            if ifname in self.status_8021x:
                if ccap_id not in self.status_8021x[ifname]["ccap_core_id"]:
                    self.status_8021x[ifname]["ccap_core_id"].append(ccap_id)
   	
            else:
                # create a interface in self interfaces
                self.status_8021x[ifname] = {
                    "status": self.DOWN,
                    "lastChangeTime": time(),
                    "ccap_core_id": [ccap_id],
                    "count": 0,
                    "eap_received": False,
                }

                # wpa_supplicant is always running as a daemon, the start just triggers a wpa_cli command
                # wpa_cli -g /var/run/wpa_suppliant-global interface_add eth1 "./test.conf" wired
                wpa_cli = "wpa_cli"
                option = "-g"
                ctrlintf = "/var/run/wpa_supplicant-global"
                cmd = "interface_add"
                confname = "/etc/supplicant.conf"
                driver = "wired"

                stop_cmd = "interface_remove"

                # redirect output to /dev/null
                with open(os.devnull, "w") as dev_null:
                    self.logger.info("Start 8021.x for interface %s" % ifname)

                    try:
                        # try to stop is at first
                        call([wpa_cli, option, ctrlintf, stop_cmd, ifname],
                             stdout=dev_null)
                        # start it again
                        call([wpa_cli, option, ctrlintf, cmd, ifname, confname, driver],
                             stdout=dev_null)
                    except OSError:
                        self.logger.exception(
                            "Failed to add new 8021x interface")

            self._send_event_notification(
                ccap_id, protoDef.msg_core_event_notification.OK,
                reason="Id has been issue this action, send current status to you",
                result=self.status_8021x[ifname]["status"])
            return

        if event_action == protoDef.msg_event.STOP:
            interface_exist = ifname in self.status_8021x
            if interface_exist == True:
                if ccap_id in self.status_8021x[ifname]["ccap_core_id"]:
                    self.status_8021x[ifname]["ccap_core_id"].remove(ccap_id)
            else:
                self._send_event_notification(
                    ccap_id, protoDef.msg_core_event_notification.FAIL,
                    reason="Cannot stop event since can not find it.")
                return

            if len(self.status_8021x[ifname]["ccap_core_id"]) == 0 and \
                            self.status_8021x[ifname]['status'] == self.DOWN:
                # Remove the interface from 802.1x
                self.status_8021x.pop(ifname)

                # wpa_supplicant is always running as a daemon, the stop
                # just triggers a wpa_cli command
                # wpa_cli -g /var/run/wpa_supplicant-global interface_remove
                # eth1
                wpa_cli = "wpa_cli"
                option = "-g"
                ctrlintf = "/var/run/wpa_supplicant-global"
                cmd = "interface_remove"

                with open(os.devnull, "w") as dev_null:
                    self.logger.info("Remove 8021.x for interface %s" % ifname)

                    try:
                        call([wpa_cli, option, ctrlintf, cmd, ifname],
                             stdout=dev_null)
                    except OSError:
                        self.logger.exception(
                            "Failed to remove new 8021x interface")

            self._send_event_notification(
                ccap_id, protoDef.msg_core_event_notification.OK,
                reason="Successful stop event.")

            return

    def _check_status_8021x_callback(self, arg):
        """This function will poll the 802.1x status, and update the interface
        802.1x status.

        :param arg: Not used by this function.
        :return: None

        """
        self.logger.debug("Check the 802.1x status...")
        if len(self.status_8021x) == 0:
            return

        for ifname in self.status_8021x:
            self.logger.debug("Check the 8021x(%s) status..." % (ifname))
            status_8021x = self.status_8021x[ifname]['status']
            self.status_8021x[ifname]['count'] += 1

            # check the 802.1x status
            # wpa_supplicant is always running as a daemon, the check
            # just triggers a wpa_cli command
            # wpa_cli -i eth0 status
            wpa_cli = "wpa_cli"
            option = "-i " + ifname
            cmd = "status"
            wpa_cmd = wpa_cli + " " + option + " " + cmd

            self.logger.debug("Get the status of 8021.x for interface %s" % ifname)

            status, output = commands.getstatusoutput(wpa_cmd)

            if status != 0:
                self.logger.info(
                    "Can't get the status of 8021.x for interface %s, reason: %s" % (ifname, output))
                continue
            else:
                # \nsuppPortStatus=Unauthorized\nEAP state=FAILURE
                status_list = output.split("\n")
                port_status = None
                eap_state = None
                pae_state = None
                for str in status_list:
                    if str.find("suppPortStatus=") != -1:
                        # get the 802.1x state
                        port_status = str.split("=")[1]
                    elif str.find("EAP state=") != -1:
                        # get the EAP state
                        eap_state = str.split("=")[1]
                    elif str.find("Supplicant PAE state=") != -1:
                        # get the EAP state
                        pae_state = str.split("=")[1]
                    else:
                        pass

                if port_status == "Authorized":
                    status_8021x = self.UP
                    self.status_8021x[ifname]['count'] = 0
                    self.status_8021x[ifname]['eap_received'] = True
                elif pae_state == "CONNECTING":
                    # RESET eap_received
                    self.status_8021x[ifname]['eap_received'] = False
                    status_8021x = self.DOWN
                elif pae_state == "AUTHENTICATING":
                    # EAP_REQ has been received
                    self.status_8021x[ifname]['eap_received'] = True
                    status_8021x = self.DOWN
                else:
                    status_8021x = self.DOWN
                    pass

            if self.status_8021x[ifname]['count'] > self.EAPOL_START_RETRIES:
                if not self.status_8021x[ifname]['eap_received']:
                    # means no authentication in network, set the status to UP
                    status_8021x = self.UP
                    if status_8021x != self.status_8021x[ifname]['status']:
                        self.logger.debug(
                            "No authentication in network, ccap (%s) status is changed to UP" % (ifname))
                elif status_8021x != self.UP:
                    self.notify.error(RPD_EVENT_NET_AUTH_ERROR[0],
                                      "pae state is %s, eap state is %s" % (pae_state, eap_state), "")

            if self.status_8021x[ifname]['status'] != status_8021x:
                self.logger.info(
                    "Inteface (%s) 8021x status is changed to %s" % (ifname, status_8021x))
                # Need notify all ccap cores
                for ccap_id in self.status_8021x[ifname]['ccap_core_id']:
                    self._send_event_notification(
                        ccap_id, protoDef.msg_core_event_notification.OK,
                        reason="Status changed",
                        result=status_8021x)

                self.status_8021x[ifname]['status'] = status_8021x

    def show_8021x_summary(self):
        """Process the request from the CLI module.

        :type: t_CliMessage
        :return: ret, value

        """
        # just get the simple 8021x status from local db
        macsec_status = []
        for ifname in self.status_8021x:
            status = self.status_8021x[ifname]["status"]
            eap_received = self.status_8021x[ifname]["eap_received"]
            value = {"Interface": ifname, "Status": status, "eap": eap_received}
            macsec_status.append(value)

        return True, macsec_status

    def show_8021x_detail(self):
        """Process the request from the CLI module.

        :type: t_CliMessage
        :return: ret, value

        """
        # get the detailed 8021x status from wpa_supplicant
        macsec_detail = []
        rst = True

        for ifname in self.status_8021x:

            # check the 802.1x status
            # wpa_supplicant is always running as a daemon, the check
            # just triggers a wpa_cli command
            # wpa_cli -i eth0 status
            wpa_cli = "wpa_cli"
            option = "-i " + ifname
            cmd = "status"
            wpa_cmd = wpa_cli + " " + option + " " + cmd

            status, output = commands.getstatusoutput(wpa_cmd)

            if status != 0:
                self.logger.info(
                    "Can't get the status of 8021.x for interface %s, reason: %s" % (ifname, output))
                continue
            else:
                status = self.status_8021x[ifname]["status"]
                eap_received = self.status_8021x[ifname]["eap_received"]
                value = {"Interface": ifname, "Status": status, "eap": eap_received, "Details": output}
                macsec_detail.append(value)

        return rst, macsec_detail

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
            rsp_msg.Cli8021x.Show8021xStatus.status = json.dumps(value)
        else:
            self.logger.debug("Receive a fake CLI message:%s" % str(msg))
            rsp_msg.CliDataResult = rsp_msg.CLI_RESULT_NONE

        self.send_cli_rsp(rsp_msg)


if __name__ == "__main__":  # pragma: no cover
    setup_logging("PROVISION", filename="provision_8021x.log")
    mac_agent = MacsecAgent()
    mac_agent.start()
