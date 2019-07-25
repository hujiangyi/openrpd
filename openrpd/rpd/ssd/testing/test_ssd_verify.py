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

import os
import unittest
import datetime
from rpd.ssd.codeFileVerify import CodeFileVerify as CFV
from rpd.ssd.codeFileVerify import SsdVerifyResult as RST
from rpd.common.rpd_logging import setup_logging


class TestSsdVerify(unittest.TestCase):

    def setUp(self):
        currentPath = os.path.dirname(os.path.realpath(__file__))
        dirs = currentPath.split("/")
        rpd_index = dirs.index("testing")
        self.rootpath = "/".join(dirs[:rpd_index])

        self.rootca = self.rootpath + '/testing/CABLELABS_ROOT_CA_PEM.CRT'

        # Test GCP CVC TLV
        self.mfr_cvc = open(self.rootpath + '/testing/mfr_cvc.der', 'r').read()
        self.mso_cvc = open(self.rootpath + '/testing/mso_cvc.der', 'r').read()
        self.codefile = self.rootpath + '/testing/codefile'

        # one signer case:
        self.one_codefile = self.rootpath + '/testing/codefile.one'

        # one CA codefile case:
        self.noca_codefile = self.rootpath + '/testing/codefile.noca'

        # wrong formated codefile case:
        self.wrong_codefile = self.rootpath + '/testing/codefile.wrong'

        # sha1 codefile case:
        self.sha1_codefile = self.rootpath + '/testing/codefile.sha1'

        # no extended key in codefile case:
        self.nokey_codefile = self.rootpath + '/testing/codefile.noextkey'

        self.wrong_rootca = self.rootpath + '/testing/caRoot_wrong.pem'

        # Test GCP CVC TLV
        self.wrong_mfr_cvc = open(self.rootpath + '/testing/mfr_cvc_wrong.der', 'r').read()
        self.wrong_mso_cvc = open(self.rootpath + '/testing/mso_cvc_wrong.der', 'r').read()
        self.single_mfr_cvc = open(self.rootpath + '/testing/mfr_cvc_single.der', 'r').read()

    def test_verify(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test the normal verification process....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # Test codefile
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # Get the image
        ret = test.get_image('/tmp/testsvae', self.codefile)
        self.assertTrue(ret)

        ret = test.get_image('/tmp/', self.codefile)
        self.assertFalse(ret)

    def test_verify_mfr_name_mismatch(self):
        print "\n==================================================="
        print "Begin to test Manufacture's name mismatch in GCP CVC....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco2", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

    def test_verify_mso_name_mismatch(self):
        print "\n==================================================="
        print "Begin to test MSO's name mismatch in GCP CVC....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast2", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_less_starttime(self):
        print "\n==================================================="
        print "Begin to test MFR's validity start time in CVC is less than RPD..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160911122430Z",
                                     "cvcAccessStart": "20160911122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mso_less_starttime(self):
        print "\n==================================================="
        print "Begin to test MSO's validity start time in CVC is less than RPD..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160911122430Z",
                                  "cvcAccessStart": "20160911122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_no_issuer(self):
        print "\n==================================================="
        print "Begin to test MFR's issuer CA is missing or incorrect..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.single_mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_no_exkey(self):
        print "\n==================================================="
        print "Begin to test MFR's extended key usage is missing or incorrect..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.wrong_mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mso_no_exkey(self):
        print "\n==================================================="
        print "Begin to test MSO's extended key usage is missing or incorrect..."
        print "==================================================="

        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "Comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.wrong_mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_bad_chain(self):
        print "\n==================================================="
        print "Begin to test MFR CVC is not chained to root CA..."
        print "==================================================="

        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.wrong_rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mso_bad_chain(self):
        print "\n==================================================="
        print "Begin to test Mso CVC is not chained to root CA..."
        print "==================================================="

        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.wrong_rootca)

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_miss_cvc(self):
        print "\n==================================================="
        print "Begin to test MFR CVC is missing..."
        print "==================================================="

        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc("", True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mso_miss_cvc(self):
        print "\n==================================================="
        print "Begin to test Mso CVC is missing..."
        print "==================================================="

        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MSO CVC
        rst = test.verify_cvc("", False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_signing_time(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test MFR's Signing time in codefile is less than RPD.."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # re-configure the wrong initcode
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160911122430Z",
                                     "cvcAccessStart": "20160911122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}
        # Test codefile

        test.set_initcode(initcode)
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mso_signing_time(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test MSO's Signing time in codefile is less than RPD.."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # re-configure the wrong initcode
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160911122430Z",
                                  "cvcAccessStart": "20160911122430Z"}}
        # Test codefile

        test.set_initcode(initcode)
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_signing_time_cvc(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test MFR's Signing time in codefile is less than CVC.."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # re-configure the wrong initcode
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160911122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}
        # Test codefile

        test.set_initcode(initcode)
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mso_signing_time_cvc(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test MSO's Signing time in codefile is less than CVC.."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # re-configure the wrong initcode
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160911122430Z"}}
        # Test codefile

        test.set_initcode(initcode)
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_bad_chain(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test MFR's cert in codefile is not chained to the root CA.."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # Reconfig the bad root CA
        test.set_rootca(self.wrong_rootca)
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_mfr_bad_signature(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test MFR's bad signature in codefile.."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        rst = test.verify_file(self.codefile + "abcd")
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_co_mismatch(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test  co-signer mismatch for GCP and codefile..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_no_co_initcode(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test no co-signer information in initcode..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_invalid_period_mfr_cvc(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test invalid period in GCP MFR CVC..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Reset the linux date
        save_date = datetime.datetime.now().date()
        os.system("date -s 2011-08-03")

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        # recover the date
        os.system("date -s " + str(save_date))
        if rst[0] == False:
            return

    def test_verify_invalid_period_mso_cvc(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test invalid period in GCP MSO CVC..."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Reset the linux date
        save_date = datetime.datetime.now().date()
        os.system("date -s 2011-08-03")

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        # recover the date
        os.system("date -s " + str(save_date))
        return

    def test_verify_invalid_period_in_codefile(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test invalid period in codefile MFR CVC....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Get the new parameters
        print "\nGet the new initcode:"
        initcode = test.get_initcode()
        print initcode

        # Reset the linux date
        save_date = datetime.datetime.now().date()
        os.system("date -s 2011-08-03")

        # Test codefile
        rst = test.verify_file(self.codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        # recover the date
        os.system("date -s " + str(save_date))

        if rst[0] == False:
            return

    def test_verify_no_rootca(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test no root ca....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, "")

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_one_signer(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test the one signer case....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Test codefile
        rst = test.verify_file(self.one_codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_noca_codefile(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test no CA in codefile....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Test codefile
        rst = test.verify_file(self.noca_codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_noext_codefile(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test no extened key in codefile....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Test codefile
        rst = test.verify_file(self.nokey_codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_wrong_codefile(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test wrong codefile....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Verify MSO CVC
        rst = test.verify_cvc(self.mso_cvc, False)
        print "mso CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Test codefile
        rst = test.verify_file(self.wrong_codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_sha1_sign(self):
        # {"manufacturer": {"organizationName":, "codeAccessStart":, "cvcAccessStart":},
        # "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        # Format: YYYYMMDDHH[MM[SS[.fff]]]Z
        print "\n==================================================="
        print "Begin to test the wrong sha1 signature....."
        print "==================================================="
        # Case 1. Normal Case
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)

        # Verify MFR CVC at first
        rst = test.verify_cvc(self.mfr_cvc, True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

        # Test codefile
        rst = test.verify_file(self.sha1_codefile)
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        if rst[0] == False:
            return

    def test_verify_negative(self):
        print "\n==================================================="
        print "Begin to test the negative value verify....."
        print "==================================================="
        initcode = {"manufacturer": {"organizationName": "cisco", "codeAccessStart": "20160311122430Z",
                                     "cvcAccessStart": "20160311122430Z"},
                    "co-signer": {"organizationName": "comcast", "codeAccessStart": "20160311122430Z",
                                  "cvcAccessStart": "20160311122430Z"}}

        test = CFV(initcode, self.rootca)
        rst = test.verify_cvc('0000000000000000000000000000000', True)
        print "manufacturer CVC verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]

        rst = test.verify_file('000000000000000000000000000000')
        print "codefile verification result: " + str(rst[0]) + ", " + RST.ssdErrorMessage[rst[1]]


if __name__ == '__main__':
    setup_logging('HAL', filename="codefile_verifying.log")
    unittest.main()
