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
import time
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hal.src.msg import HalCommon_pb2
from rpd.hal.src.HalGlobal import HalGlobal
from rpd.hal.src.HalAgent import HalAgent
from rpd.hal.src.HalDispatcher import HalDispatcher


class TestHalAgent(unittest.TestCase):

    def setUp(self):
        # Setup the Dispatcher for invoke dispatcher
        HalGlobal.gDispatcher = HalDispatcher()

        # Instance of class
        self.halAgent = HalAgent()

        # Setup some necessary value
        # Init some value
        self.msgCache = self.halAgent.msgCache

        self.runtimeTimeoutList = self.halAgent.runtimeTimeoutList
        self.resendList = self.halAgent.resendList

    def tearDown(self):
        self.halAgent.removeFromAgentDB()

        # Create a tmp cb  for
    def tmpCb(self, int):
        pass

    def test_HalAgent(self):
        """
        1.Exception
        2.Add events and remove events(timeout list)
        3.Process timeout(<timeout and =>timeout)
        4.Add to resend list and process resend list(time = time() + 5)
        """

        self.halAgent.processTimeoutObjs()
        # runtimeTimeoutList is Null(len==0)
        self.assertIsNone(self.halAgent.processTimeoutObjs())
        self.assertEqual(len(self.runtimeTimeoutList), 0)

        # Initial values
        seqNumb = 123
        tmpCb = self.tmpCb
        timeout = 2

        # Test type
        try:
            self.assertFalse(
                self.halAgent.addToRuntimeObjList("123", timeout, (tmpCb, 1)))
            print "Error"
        except Exception as e:
            pass

        try:
            self.assertFalse(
                self.halAgent.addToRuntimeObjList(seqNumb, "999", (tmpCb, 1)))
            print "Error"
        except Exception as e:
            pass

        # Add events to RuntimeObjList and remove it to RuntimeObjList
        # runtimeTimeoutList is Not Null and msgCache is not null
        self.halAgent.addToRuntimeObjList(seqNumb, timeout, (tmpCb, 1))
        self.halAgent.addToRuntimeObjList(seqNumb, timeout, (tmpCb, 1))
        self.assertEqual(len(self.msgCache), 1)
        self.assertEqual(len(self.runtimeTimeoutList), 1)
        self.halAgent.save_cfg_rsp_msg(seqNumb, "test message:number 1")
        self.halAgent.save_cfg_rsp_msg(seqNumb, "test message:number 2")
        self.halAgent.save_cfg_rsp_msg(seqNumb, "test message:number 2")

        # Add events to RuntimeObjList(1--->2) again
        # seq = 22
        self.halAgent.addToRuntimeObjList(22, 3, (tmpCb, 1))
        self.assertEqual(len(self.msgCache), 2)
        self.assertEqual(len(self.runtimeTimeoutList), 2)
        self.halAgent.save_cfg_rsp_msg(22, "test message:number 2")

        # Remove(2--->0) events(seqNumb==123 and seq==22) from
        # The RuntimeObjList meanwhile msgCache
        ref_count, msg = self.halAgent.removeFromRuntimeObjList(seqNumb)
        self.assertEqual(ref_count, 1)
        self.assertEqual(msg, None)

        ref_count, msg = self.halAgent.removeFromRuntimeObjList(seqNumb)
        self.assertEqual(ref_count, 0)
        self.assertEqual(len(msg), 2)

        self.assertEqual(len(self.runtimeTimeoutList), 1)
        self.halAgent.removeFromRuntimeObjList(seq=22)
        self.assertEqual(len(self.runtimeTimeoutList), 0)
        self.assertEqual(len(self.msgCache), 0)
        self.halAgent.removeFromRuntimeObjList(seq=22)
        self.assertEqual(len(self.msgCache), 0)

        # Test processTimeoutObjs
        # Add events to RuntimeObjList for test timeout value(<timeout ||
        # =timeout==2 Sec)
        self.halAgent.addToRuntimeObjList(seqNumb, timeout, (tmpCb, 101))
        # Confirm add success
        self.assertEqual(len(self.runtimeTimeoutList), 1)

        # Sleep 1 Sec(<timeout) and no timeout and not pop/remove
        time.sleep(1)
        self.halAgent.processTimeoutObjs()
        # Not pop and not remove && msgCache && confirm
        self.assertEqual(len(self.runtimeTimeoutList), 1)
        self.assertEqual(len(self.msgCache), 1)

        # Sleep 3 Sec(triger it) and timeout(as:timeout==2 Sec)
        # Execute timeout and pop(0)/remove it  && msgCache
        time.sleep(3)
        self.halAgent.processTimeoutObjs()
        # Confirm it
        self.assertEqual(len(self.runtimeTimeoutList), 0)
        self.assertEqual(len(self.msgCache), 0)

        # Test isMsgTimeout
        # Seq is not in msgCache(is NULL)
        self.assertTrue(self.halAgent.isMsgTimeout(seqNumb))

        # Add to RuntimeObjList and seq is in msgCache
        self.halAgent.addToRuntimeObjList(seqNumb, timeout, (tmpCb, 101))
        self.halAgent.save_cfg_rsp_msg(seqNumb, "test message:number 2")
        # Confirm it
        self.assertFalse(self.halAgent.isMsgTimeout(seqNumb))

        # Seq is in msgCache and remove it
        self.halAgent.removeFromRuntimeObjList(seqNumb)

        # Then, seq is not in msgCache
        self.assertTrue(self.halAgent.isMsgTimeout(seqNumb))

        # Create msg for addToResendList
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="435qwert22",
                                 SeqNum=322,
                                 CfgMsgType=100,
                                 CfgMsgPayload="test HalAgent")

        # Test resendList is null
        self.halAgent.processResendList()
        self.assertEqual(len(self.resendList), 0)

        # ResendList is not null
        # Add msg to  ResendList
        self.halAgent.addToResendList(
            seq=88, sendagent=self.halAgent, msg=self.cfgMsg)

        # Success added
        self.assertEqual(len(self.resendList), 1)
        # ResendList is not null
        # Not timeout 5s and  removeList(local variable) is null
        self.halAgent.processResendList(True)

        # Test timeout 5 Sec(--->"time": time() + 5) and
        # RemoveList is not NULL(as:method--->append)
        time.sleep(5)
        self.halAgent.processResendList(True)
        # Confirm it 1--->0
        self.assertEqual(len(self.resendList), 0)

    # Test exception
    def test_disconnectHandler(self):
        try:
            self.halAgent.disconnectHandler(transport=3)
        except Exception as e:
            pass


if __name__ == '__main__':
    unittest.main()
