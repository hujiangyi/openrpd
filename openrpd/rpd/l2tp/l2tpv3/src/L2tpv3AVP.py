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
"""

::
	
  +---------------------------------------------------------------+
  |0                   1                   2                   3  |
  |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1|
  +-+-+-------+-------------------+-------------------------------+
  |M|H| rsvd  |      Length       |           Vendor ID           |
  +-+-+-------+-------------------+-------------------------------+
  |         Attribute Type        |        Attribute Value ...    |
  +-------------------------------+-------------------------------+
  |                   (until Length is reached)                   |
  +---------------------------------------------------------------+
"""
import copy
import struct
from json import JSONEncoder
from rpd.common.rpd_logging import AddLoggerToClass


class l2tpv3AVPerror(Exception):
    pass


class AvpEncoder(JSONEncoder):
    """Encode the control packet to string using json facility.

    The excludedFields is used to tell the encoder that don't encode
    these fields.

    """
    Excludefields = (
        "logger", "data", "attrValue", "tieBreaker")

    def __init__(self):
        super(AvpEncoder, self).__init__(indent=4)

    def default(self, o):
        """Get out some fields."""
        retDict = copy.copy(o.__dict__)

        for field in self.Excludefields:
            if field in retDict:
                retDict.pop(field)

        return retDict


class l2tpv3AVP(object):
    """The base class for l2tp AVP, the main function of this class is to
    define some AVP number and provide a framework for AVP specific
    definition."""
    ControlMessage = 0
    ResultCode = 1
    ProtocolVersion = 2
    FrameCapabilities = 3
    TieBreaker = 5
    FirmwareRevision = 6
    HostName = 7
    VendorName = 8
    ReceivedWindowSize = 10
    RouterID = 60
    AssignedControlConnectionID = 61
    PseudowireCapabilityList = 62
    CallSerialNumber = 15
    SequenceRequired = 39
    LocalSession = 63
    RemoteSession = 64
    RemoteEndID = 66
    PseudowireType = 68
    Layer2SpecificSublayer = 69
    DataSequence = 70
    CircuitStatus = 71
    SbfdVccv = 96
    SbfdDiscriminator = 102
    AssignedControlConnectionIDCisco = 1
    PseudowireCapabilityListCisco = 2
    DraftAvpVersionCisco = 10
    LocalSessionCisco = 3
    RemoteSessionCisco = 4
    PseudowireTypeCisco = 7
    SessionTieBreakerCisco = 9
    DepiMcmtsSimplificationCisco = 115

    # new AVPs in RFC4951
    FailoverCapability = 76
    TunnelRecovery = 77
    SuggestedControlSequence = 78
    FailoverSessionState = 79

    # AVP supported vendors
    CiscoVendor = 9
    CableLabsVendor = 4491
    ItefVendor = 0

    MinAvpLength = 6

    # All AVP implementation should register to this dict.
    SubclassMapping = dict()
    __metaclass__ = AddLoggerToClass

    def __init__(self, AttrType=0, AttrValue="", VendorID=0, MustAvp=True, HidenAVP=True):
        """Assume the Attribute value is a string type, also we will use the
        string length as the length of the Length of AVP control field."""
        if not isinstance(AttrType, int) or not isinstance(AttrValue, str) or not isinstance(VendorID, int) \
                or not isinstance(MustAvp, bool) or not isinstance(HidenAVP, bool):
            self.logger.warn(
                "Args type error, AttrType[%s],  AttrValue [%s], VendorID[%s], MustAvp[%s], HidenAVP[%s]",
                type(AttrType), type(AttrValue), type(VendorID), type(MustAvp), type(HidenAVP))
            raise l2tpv3AVPerror("Args type error")

        self.attrType = AttrType
        self.attrValue = AttrValue
        self.vendorID = VendorID
        self.length = 6 + len(AttrValue)
        self.mustAvp = MustAvp
        self.hiddenAvp = HidenAVP

        self.avpName = self.__class__.__name__

    def __str__(self):
        """Provide a string method for AVP, this is for debug or logging
        usage."""
        return AvpEncoder().encode(self)

    def encode(self):
        """Generate a buf which hold all the AVP elem values."""
        # processing the Must hand Hiden
        flags = 0

        if self.mustAvp:
            flags |= 0x8000

        if self.hiddenAvp:
            flags |= 0x4000

        flags |= self.length

        formatStr = "!HHH" + str(len(self.attrValue)) + "s"
        return struct.pack(formatStr, flags, self.vendorID, self.attrType, self.attrValue)

    def decode(self, buf):
        """Return a AVP from a string buffer."""
        if len(buf) < 6:
            msg = "Cannot decode the buffer since the buf is too low, buf:%s" % str(buf)
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        # decdoe the length
        flags, = struct.unpack("!H", buf[:2])

        length = flags & 0x03ff
        if len(buf) < length:
            msg = "Cannot decode the buffer since the buf is too low, buf:%s" % str(buf)
            self.logger.warn(msg)
            raise l2tpv3AVPerror(msg)

        self.length = length
        self.mustAvp = True if flags & 0x8000 else False
        self.hiddenAvp = True if flags & 0x4000 else False

        # extract others
        formatStr = "!HH" + str(length - 6) + "s"
        self.vendorID, self.attrType, self.attrValue = struct.unpack(
            formatStr, buf[2:])

        return

    def handleAvp(self, pkt, retPak):
        """The SVP handlers."""
        self.logger.debug("Receive a AVP:%d, vendor:%d" %
                          (self.attrType, self.vendorID))
        return True
        # raise NotImplementedError

    def SetFlags(self, mustAvp, hiddenAvp):
        """Set the must bit ad hidden bit."""
        raise NotImplementedError

    @staticmethod
    def decodeAll(buf):
        """Return a AVP from a string buffer."""
        offset = 0
        retAVPs = list()
        while offset < len(buf):
            if len(buf[offset:]) < l2tpv3AVP.MinAvpLength:
                msg = "Cannot decode the buffer since the buf is too low."
                raise l2tpv3AVPerror(msg)
            # decode the length field
            flags, = struct.unpack("!H", buf[offset:offset + 2])
            length = flags & 0x03ff
            offset += 2
            if length < l2tpv3AVP.MinAvpLength:
                msg = "Cannot decode the buffer avp length must larger than %d, got %d" % \
                      (l2tpv3AVP.MinAvpLength, length)
                raise l2tpv3AVPerror(msg)

            if len(buf) < length:
                msg = "Cannot decode the buffer since the buf is too low"
                raise l2tpv3AVPerror(msg)

            mustAvp = True if flags & 0x8000 else False
            hiddenAvp = True if flags & 0x4000 else False

            # extract AttrType and the Vendor
            formatStr = "!HH"
            vendorID, attrType = struct.unpack(
                formatStr, buf[offset:offset + 4])
            offset += 4
            # Get the subclass
            if (vendorID, attrType) in l2tpv3AVP.SubclassMapping:
                cls = l2tpv3AVP.SubclassMapping[(vendorID, attrType)]

                if not cls.ValidateFlags(mustAvp, hiddenAvp):
                    pass  # Should do sth?
                try:
                    avp = cls.decode(buf[offset:offset + length - 6])
                    avp.SetFlags(mustAvp, hiddenAvp)
                except Exception as e:
                    continue
            else:
                # FIXME, do we should check the must bit here and drop the connection here? or we can process it later?
                # using the general AVP tp decode it
                avp = GeneralL2tpv3AVP(
                    AttrType=attrType, AttrValue=buf[
                        offset:offset + length - 6],
                    VendorID=vendorID, MustAvp=mustAvp, HidenAVP=hiddenAvp)

            retAVPs.append(avp)
            offset += length - 6

        return retAVPs

    @staticmethod
    def validateAvps(avps):
        if not (isinstance(avps, tuple) or isinstance(avps, list)):
            return False


class GeneralL2tpv3AVP(l2tpv3AVP):
    """If a AVP not implemented, will fall into this class, we should add some
    error code to here."""
    AttrType = -1


# Add debug log
def addDebugLogToHandle(func):
    """A decorator to add some debug code.

    :param func: func to be decorated
    :return: new function.

    """

    def handle(self, pkt, retPak):
        return func(self, pkt, retPak)

    return handle
