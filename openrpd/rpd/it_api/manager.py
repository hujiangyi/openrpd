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

#
# Implements testing version of manager.py
#

from rpd.common.rpd_logging import setup_logging, AddLoggerToClass
from rpd.gpb.it_api_msgs_pb2 import t_ItApiRpdMessage
from rpd.it_api.it_api import ItApiServerOpenRpd
from rpd.dispatcher.dispatcher import Dispatcher
from os.path import exists
from commands import getstatusoutput


class RpdITManager(object):
    """Class extends Manager process with Integration Testing API socket."""

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.disp = Dispatcher()
        self.it_api_server = ItApiServerOpenRpd(rx_cb=self._it_api_rx_cb,
                                                disp=self.disp)

    def start(self):
        self.disp.loop()

    def _it_api_rx_cb(self, gpb_msg):
        if not isinstance(gpb_msg, t_ItApiRpdMessage):
            raise TypeError("Invalid GPB message passed")

        self.logger.debug("Received IT API message: %s",
                          gpb_msg.t_ItApiRpdMessageType.Name(gpb_msg.ItApiRpdMessageType))

        response = t_ItApiRpdMessage()
        response.ItApiRpdMessageType = gpb_msg.ItApiRpdMessageType
        response.result = response.IT_API_RESULT_OK

        if gpb_msg.ItApiRpdMessageType == gpb_msg.IT_API_RPD_GET:
            # return the latest provision state
            try:
                cmd = "grep 'Entering state ' /tmp/provision_mgr_process.log | sed -n '$p'"
                (status, state_str) = getstatusoutput(cmd)
                if status == 0:
                    response.ItMsgPayload = state_str.\
                        split("Entering state")[
                            1].split(' ')[1]
                    self.logger.info("Get latest provision state:%s",
                                     response.ItMsgPayload)
                else:
                    response.result = response.IT_API_RESULT_FAIL
            except Exception as e:
                self.logger.info("Can't get provision state")
                response.result = response.IT_API_RESULT_FAIL
        elif gpb_msg.ItApiRpdMessageType == gpb_msg.IT_API_RPD_GET_RCP_CFG:
            if exists("/tmp/fakedriver-rcp.db"):
                try:
                    with open("/tmp/fakedriver-rcp.db") as f:
                        data = f.read()
                        response.ItMsgPayload = data
                        f.close()
                except Exception as e:
                    self.logger.error("open file fakedriver-rcp.db error")
                    response.result = response.IT_API_RESULT_FAIL
            else:
                self.logger.info("No Rcp db file")
                response.result = response.IT_API_RESULT_FAIL
        elif gpb_msg.ItApiRpdMessageType == gpb_msg.IT_API_RPD_GET_L2TP_CFG:
            if exists("/tmp/fakedriver-l2tp.db"):
                try:
                    with open("/tmp/fakedriver-l2tp.db") as f:
                        data = f.read()
                        response.ItMsgPayload = data
                        f.close()
                except Exception as e:
                    self.logger.error("open file fakedriver-l2tp.db error")
                    response.result = response.IT_API_RESULT_FAIL
            else:
                self.logger.info("No L2tp db file")
                response.result = response.IT_API_RESULT_FAIL
        else:
            self.logger.error(
                "Received unexpected testing message type: %s(%u)",
                gpb_msg.t_ItApiRpdMessageType.Name(
                    gpb_msg.ItApiRpdMessageType),
                gpb_msg.ItApiRpdMessageType)
            response.result = response.IT_API_RESULT_FAIL

        self.logger.debug("Msg %s Response prepared, result:%d",
                          gpb_msg.t_ItApiRpdMessageType.Name(
                              response.ItApiRpdMessageType),
                          response.result)
        self.it_api_server.it_api_send_msg(response)

    def testing_cleanup(self):
        """Extends testing_cleanup() with a cleanup of IT API socket."""
        self.it_api_server.cleanup()


if __name__ == "__main__":
    setup_logging("ItManager", filename="it_mgr.log")
    try:
        RpdITManager().start()
    except Exception as ex:
        RpdITManager.logger.exception("Unexpected failure: %s", ex.message)
