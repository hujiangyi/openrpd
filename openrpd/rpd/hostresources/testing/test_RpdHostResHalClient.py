import unittest

from rpd.gpb.rcp_pb2 import t_RcpMessage
from rpd.hal.src.HalConfigMsg import MsgTypeHostResources
from rpd.hal.src.msg.HalMessage import HalMessage
from rpd.hostresources.src.RpdHostResHalClient import RpdHostResHalClient


class testRpdInfoHalClient(unittest.TestCase):
    def setUp(self):
        self.rpdhostres = RpdHostResHalClient("RpdHostRes_hal",
                                              "This is RPD HostRes hal client",
                                              "1.0.0", (MsgTypeHostResources,), ())

    # @unittest.skip("This is broken and fails Jenkins unit testing.")
    def test_recvCfgMsgCb(self):
        cfg = t_RcpMessage()
        cfg.RcpMessageType = t_RcpMessage.RPD_CONFIGURATION
        payload = cfg.SerializeToString()
        print payload
        self.cfgMsg = HalMessage("HalConfig",
                                 SrcClientID="testRpdHostResources",
                                 SeqNum=322,
                                 CfgMsgType=MsgTypeHostResources,
                                 CfgMsgPayload=payload)
        self.assertEqual(None, self.rpdhostres.recvCfgMsgCb(self.cfgMsg))

if __name__ == '__main__':
    unittest.main()

