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

import time
import datetime
import hashlib
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2315
from OpenSSL import crypto as c

from rpd.common.rpd_logging import setup_logging, AddLoggerToClass


class Asn1Decoder(object):

    @classmethod
    def __asn1_read_length(cls, der, ix):
        """Get a ASN1 node.

        :param ix: ix points to the first byte of the asn1 structure
        :return: Returns first byte pointer, first content byte pointer and last

        """
        first = ord(der[ix + 1])
        if (ord(der[ix + 1]) & 0x80) == 0:
            length = first
            ix_first_content_byte = ix + 2
            ix_last_content_byte = ix_first_content_byte + length - 1
        else:
            lengthbytes = first & 0x7F
            length = cls.__bytestr_to_int(der[ix + 2:ix + 2 + lengthbytes])
            ix_first_content_byte = ix + 2 + lengthbytes
            ix_last_content_byte = ix_first_content_byte + length - 1

        return (ix, ix_first_content_byte, ix_last_content_byte)

    @classmethod
    def __bytestr_to_int(cls, s):
        """Convert a byte string to int.

        :return:

        """
        # converts bytestring to integer
        i = 0
        for char in s:
            i <<= 8
            i |= ord(char)
        return i

    @classmethod
    def asn1_node_root(cls, der):
        """Gets the first ASN1 structure in der.

        :return:

        """
        return cls.__asn1_read_length(der, 0)

    @classmethod
    def asn1_node_next(cls, der, (ixs, ixf, ixl)):
        """Gets the next ASN1 structure following (ixs,ixf,ixl).

        :return:

        """
        return cls.__asn1_read_length(der, ixl + 1)

    @classmethod
    def asn1_node_first_child(cls, der, (ixs, ixf, ixl)):
        """Get returns the first child ASN1 inside der.

        :return:

        """
        if ord(der[ixs]) & 0x20 != 0x20:
            raise ValueError('Error: can only open constructed types. '
                             + 'Found type: 0x' + der[ixs].encode("hex"))
        return cls.__asn1_read_length(der, ixf)


class SsdVerifyResult(object):
    SUCCESS = 0
    ERROR_CVC_MFR_NAME_MISMATCH = 1
    ERROR_CVC_CO_NAME_MISMATCH = 2
    ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_RPD = 3
    ERROR_PKCS_MFR_VALIDITY_TIME_LESS_THAN_RPD = 4
    ERROR_CVC_MFR_VALIDITY_TIME_LESS_THAN_RPD = 5
    ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_CVC = 6
    ERROR_CVC_MFR_MISS_OR_IMPROPER_KEY_USAGE = 7
    ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_RPD = 8
    ERROR_PKCS_CO_VALIDITY_TIME_LESS_THAN_RPD = 9
    ERROR_CVC_CO_VALIDITY_TIME_LESS_THAN_RPD = 10
    ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_CVC = 11
    ERROR_CVC_CO_MISS_OR_IMPROPER_KEY_USAGE = 12

    ERROR_FILE_MFR_CVC_ROOT_CA_MISMATCH_GCP = 30
    ERROR_FILE_MFR_CVS_VALIDATION = 31
    ERROR_FILE_CO_CVC_ROOT_CA_MISMATCH_GCP = 32
    ERROR_FILE_CO_CVS_VALIDATION = 33
    ERROR_FILE_DOWNLOAD = 34
    ERROR_MISS_PARAMETR = 35

    ERROR_GCP_CVC_MISS_OR_IMPROPER_KEY_USAGE = 40
    ERROR_GCP_CVC_VALIDATION = 41

    ERROR_GCP_MISS_MFR_CVC = 42
    ERROR_GCP_MISS_CO_CVC = 43
    ERROR_GCP_MISS_ISSUER_CVC = 44

    ERROR_GCP_INVALIDITY_PERIOD_MFR_CVC = 45
    ERROR_GCP_INVALIDITY_PERIOD_CO_CVC = 46

    ERROR_FILE_INVALIDITY_PERIOD_MFR_CVC = 47
    ERROR_FILE_INVALIDITY_PERIOD_CO_CVC = 48

    ERROR_FILE_WRONG_FORMAT = 49
    ERROR_FILE_CO_MISMATCH_WITH_GCP = 50

    ERROR_MISS_ROOT_CA = 51
    ERROR_SW_FILE_CORRUPTION = 52

    WARN_SAME_IMAGE = 90

    ssdErrorMessage = {
        SUCCESS:
            "The verification is successful",
        ERROR_CVC_MFR_NAME_MISMATCH:
            "CVC subject organizationName for manufacturer "
            "does not match the RPD's manufacturer name",
        ERROR_CVC_CO_NAME_MISMATCH:
            "CVC subject organizationName for code co-signing "
            "agent does not match the RPD's current code co-signing agent",
        ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_RPD:
            "The manufacturer [PKCS#7] signingTime value is less-than "
            "the codeAccessStart value currently held in the RPD",
        ERROR_PKCS_MFR_VALIDITY_TIME_LESS_THAN_RPD:
            "The manufacturer [PKCS#7] validity start time value is "
            "less-than the cvcAccessStart value currently held in the RPD",
        ERROR_CVC_MFR_VALIDITY_TIME_LESS_THAN_RPD:
            "The manufacturer CVC validity start time is less-than "
            "the cvcAccessStart value currently held in the RPD",
        ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_CVC:
            "The manufacturer [PKCS#7] signingTime value is "
            "less-than the CVC validity start time",
        ERROR_CVC_MFR_MISS_OR_IMPROPER_KEY_USAGE:
            "Missing or improper extended key-usage extension "
            "in the manufacturer CVC",
        ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_RPD:
            "The co-signer [PKCS#7] signingTime value is less-than "
            "the codeAccessStart value currently held in the RPD",
        ERROR_PKCS_CO_VALIDITY_TIME_LESS_THAN_RPD:
            "The co-signer [PKCS#7] validity start time value is "
            "less-than the cvcAccessStart value currently held in the RPD",
        ERROR_CVC_CO_VALIDITY_TIME_LESS_THAN_RPD:
            "The co-signer CVC validity start time is less-than the "
            "cvcAccessStart value currently held in the RPD",
        ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_CVC:
            "The co-signer [PKCS#7] signingTime value is less-than "
            "the CVC validity start time",
        ERROR_CVC_CO_MISS_OR_IMPROPER_KEY_USAGE:
            "Missing or improper extended key-usage extension in "
            "the co-signer CVC",
        ERROR_FILE_MFR_CVC_ROOT_CA_MISMATCH_GCP:
            "The manufacturer CVC in the code file does not chain to "
            "the same root CA as the manufacturer CVC received via GCP",
        ERROR_FILE_MFR_CVS_VALIDATION:
            "Code file manufacturer CVS validation failure ",
        ERROR_FILE_CO_CVC_ROOT_CA_MISMATCH_GCP:
            "The co-signer CVC in the code file does not chain to the "
            "same root CA as the co-signer CVC received via GCP ",
        ERROR_FILE_CO_CVS_VALIDATION:
            "Code file co-signer CVS validation failure ",
        ERROR_FILE_DOWNLOAD: "can't download the specific file",
        ERROR_MISS_PARAMETR: "miss required parameters",
        ERROR_GCP_CVC_MISS_OR_IMPROPER_KEY_USAGE:
            "Missing or improper key usage attribute in GCP CVC",
        ERROR_GCP_CVC_VALIDATION:
            "Validation failure of CVC received via GCP",
        ERROR_GCP_MISS_MFR_CVC:
            "No manufacturer's CVC in GCP",
        ERROR_GCP_MISS_ISSUER_CVC:
            "No issuing CA CVC in GCP",
        ERROR_GCP_MISS_CO_CVC:
            "No co-signer's CVC in GCP",
        ERROR_GCP_INVALIDITY_PERIOD_MFR_CVC:
            "The validity period of MFR CVC in GCP is not valid",
        ERROR_GCP_INVALIDITY_PERIOD_CO_CVC:
            "The validity period of co-signer CVC in GCP is not valid",
        ERROR_FILE_INVALIDITY_PERIOD_MFR_CVC:
            "The validity period of MFR CVC in codefile is not valid",
        ERROR_FILE_INVALIDITY_PERIOD_CO_CVC:
            "The validity period of co-signer CVC in codefile is not valid",
        ERROR_FILE_WRONG_FORMAT:
            "The codefile can't be correctly parsed",
        ERROR_FILE_CO_MISMATCH_WITH_GCP:
            "The co-signer info doesn't exist in GCP, yet exist in codefile",
        ERROR_MISS_ROOT_CA:
            "No Root CA found",
        ERROR_SW_FILE_CORRUPTION:
            "The SW file is corrupted, hash digest is not same with signature",
        WARN_SAME_IMAGE:
            "Skip the same image file upgrade",
    }


class CodeFileVerify(object):

    __metaclass__ = AddLoggerToClass

    CODE_SIGN_OID = "1.3.6.1.5.5.7.3.3"
    SIGNINGTIME_OID = "1.2.840.113549.1.9.5"
    SHA256_OID = "2.16.840.1.101.3.4.2.1"
    MESSAGEDIGEST_OID = "1.2.840.113549.1.9.4"

    def __init__(self, initcode, rootca='/etc/ipsec.d/cacerts/CABLELABS_ROOT_CA_PEM.CRT'):
        """Update the initcode, local parameters of manufacture and co-signer.

        :initcode:
         {"manufacturer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":},
          "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        :rootca: root certificate
        :return: SUCCESS or ERROR list

        """
        self.file = None
        self.initcode = initcode
        self.current_time = None
        self.mfr_org_name = self.initcode['manufacturer']['organizationName']
        self.mfr_codeAccessStart = self.initcode['manufacturer']['codeAccessStart']
        self.mfr_cvcAccessStart = self.initcode['manufacturer']['cvcAccessStart']
        if 'co-signer' in self.initcode:
            self.mso_org_name = self.initcode['co-signer']['organizationName']
            self.mso_codeAccessStart = self.initcode['co-signer']['codeAccessStart']
            self.mso_cvcAccessStart = self.initcode['co-signer']['cvcAccessStart']
        else:
            self.mso_org_name = None
            self.mso_codeAccessStart = None
            self.mso_cvcAccessStart = None

        self.new_mfr_cvcAccessStart = self.mfr_cvcAccessStart
        self.new_mfr_codeAccessStart = self.mfr_codeAccessStart
        self.new_mso_cvcAccessStart = self.mso_cvcAccessStart
        self.new_mso_codeAccessStart = self.mso_codeAccessStart

        self.mfr_signing_time = None
        self.mso_signing_time = None
        self.mfr_signerInfo = None
        self.mso_signerInfo = None
        self.mfr_signer_attrs = None
        self.mso_signer_attrs = None
        self.mfr_message_digest = None
        self.mso_message_digest = None

        self.mfr_cvc = None
        self.mfr_cvc_ca = None
        self.mso_cvc = None
        self.mso_cvc_ca = None
        self.co_signed_gcp = False
        self.co_signed_codefile = False

        self.signedContentOffset = 0
        self.limit_block = 1024 * 1024

        self.root_cert = None

        self.verify_result = SsdVerifyResult.SUCCESS

        # fixme: use /bootflash/rootca currently
        if rootca is None:
            rootca = '/bootflash/CABLELABS_ROOT_CA_PEM.CRT'
        try:
            with open(rootca, 'r') as root_cert_file:
                self.root_cert = c.load_certificate(c.FILETYPE_PEM,
                                                    root_cert_file.read())
        except:
            self.logger.error("Can't load root certificate!")

    def __get_generalized_time(self, timeValue):
        """Parses date string and returns a generalized date string."""
        # YYMMDDHHMMSSZ format
        # UTCTime has only short year format (last two digits), so add
        # 19 or 20 to make it "full" year; by RFC 5280 it's range 1950..2049

        shortyear = int(timeValue[:2])
        return (shortyear >= 50 and "19" or "20") + timeValue

    def __parse_datetime(self, date):
        """Parses date string and returns a datetime object."""
        year = int(date[:4])
        month = int(date[4:6])
        day = int(date[6:8])
        hour = int(date[8:10])
        minute = int(date[10:12])
        try:
            # seconds must be present per RFC 5280, but some braindead certs
            # omit it
            second = int(date[12:14])
        except (ValueError, IndexError):
            second = 0
        return datetime.datetime(year, month, day, hour, minute, second)

    def __verify_extended_key_usage(self, is_mfr):
        """Verify the extended key usage in CVC.

        :is_mfr:
        :return: True or False

        """
        if is_mfr == True:
            cert = self.mfr_cvc
        else:
            cert = self.mso_cvc

        if cert == None:
            return False

        DeData = None
        for index in range(0, cert.get_extension_count()):
            if cert.get_extension(index).get_short_name() == 'extendedKeyUsage':
                KeyData = cert.get_extension(index).get_data()  # ASN1 encoded string
                DeData = decode(KeyData)  # Returns tuple containing instance
                if str(DeData[0][0]) == self.CODE_SIGN_OID:
                    return True
                break

        return False

    def __verify_mfr_starttime_orgname(self, is_gcp):
        """Verify the validity start time and organization name in Mfr CVC.

        :is_gcp:
        :return: True or False

        """
        if self.mfr_cvc == None:  # pragma: no cover
            self.verify_result = SsdVerifyResult.ERROR_GCP_MISS_MFR_CVC
            return False

        notBefore = self.mfr_cvc.get_notBefore()

        # Check the organization name
        ou = c.X509Name(self.mfr_cvc.get_subject())
        org_name = ou.organizationName

        if self.mfr_org_name != org_name:
            self.verify_result = SsdVerifyResult.ERROR_CVC_MFR_NAME_MISMATCH
            return False

        # AssumecvcAccessStart as ASN.1 GENERALIZEDTIME, YYYYMMDDHH[MM[SS[.fff]]]Z
        if self.__parse_datetime(self.mfr_cvcAccessStart) > self.__parse_datetime(notBefore):
            if is_gcp == True:
                self.verify_result = SsdVerifyResult.ERROR_CVC_MFR_VALIDITY_TIME_LESS_THAN_RPD
            else:
                self.verify_result = SsdVerifyResult.ERROR_PKCS_MFR_VALIDITY_TIME_LESS_THAN_RPD
            return False

        return True

    def __verify_mso_starttime_orgname(self, is_gcp):
        """Verify the validity start time and organization name in co-signer
        CVC.

        :is_gcp:
        :return: True or False

        """
        if self.mso_cvc == None:  # pragma: no cover
            self.verify_result = SsdVerifyResult.ERROR_GCP_MISS_CO_CVC
            return False

        notBefore = self.mso_cvc.get_notBefore()

        # Check the organization name
        ou = c.X509Name(self.mso_cvc.get_subject())
        org_name = ou.organizationName

        # should we return false if the mso_org_name doesn't exist
        if self.mso_org_name != None and self.mso_org_name != org_name:
            self.verify_result = SsdVerifyResult.ERROR_CVC_CO_NAME_MISMATCH
            return False
        else:
            # Give an initial value
            self.mso_org_name = org_name

        # AssumecvcAccessStart as ASN.1 GENERALIZEDTIME
        if self.mso_cvcAccessStart != None:
            if self.__parse_datetime(self.mso_cvcAccessStart) > self.__parse_datetime(notBefore):
                if is_gcp == True:
                    self.verify_result = SsdVerifyResult.ERROR_CVC_CO_VALIDITY_TIME_LESS_THAN_RPD
                else:
                    self.verify_result = SsdVerifyResult.ERROR_PKCS_CO_VALIDITY_TIME_LESS_THAN_RPD
                return False
        else:
            # Give an initial vaue
            self.mso_cvcAccessStart = notBefore
            self.mso_codeAccessStart = notBefore
            self.new_mso_codeAccessStart = notBefore
            self.new_mso_cvcAccessStart = notBefore

        return True

    def __verify_chain_of_trust(self, is_mfr):
        """Verify the CVC chain.

        :is_mfr:
        :return: True or False.

        """
        # Create and fill a X509Sore with trusted certs
        store = c.X509Store()

        if is_mfr == True:
            cert = self.mfr_cvc
            cert_ca = self.mfr_cvc_ca
        else:
            cert = self.mso_cvc
            cert_ca = self.mso_cvc_ca

        store.add_cert(cert_ca)
        store.add_cert(self.root_cert)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = c.X509StoreContext(store, cert)
        # Returns None if certificate can be validated
        result = store_ctx.verify_certificate()

        if result is None:
            return True
        else:
            return False

    def __verify_cvc_and_signature_chain(self, is_mfr):
        """Verify the CVC and CVC CA certificate signatures chain up to the
        Root CA.

        :is_mfr:
        :return: True or False

        """

        if self.root_cert == None:
            self.logger.error("No root certificate found when verifying cvc chain!")
            return False

        try:
            verified = self.__verify_chain_of_trust(is_mfr)
        except Exception as e:
            self.logger.error("Failed to verify cvc chain, reason:" + str(e))
            return False

        if verified == False:
            self.logger.error("Failed to verify cvc chain!")
            return False

        return True

    def __verify_cvc_period(self, is_mfr):
        """Verify the validity periods for CVC and the issuing CA certificate
        has not expired.

        :is_mfr:
        :return: True or False

        """
        if is_mfr == True:
            cert = self.mfr_cvc
        else:
            cert = self.mso_cvc

        if cert == None:
            return False

        notBefore = cert.get_notBefore()
        notAfter = cert.get_notAfter()

        datetime_notBefore = self.__parse_datetime(notBefore)
        datetime_notAfter = self.__parse_datetime(notAfter)
        self.current_time = datetime.datetime.now()

        if self.current_time < datetime_notBefore:
            return False

        if self.current_time > datetime_notAfter:
            return False

        # Save temporarily
        if is_mfr == True:
            self.new_mfr_cvcAccessStart = notBefore
            cur_codeAccessStart = self.__parse_datetime(self.mfr_codeAccessStart)
            if datetime_notBefore > cur_codeAccessStart:
                self.new_mfr_codeAccessStart = notBefore
        else:
            self.new_mso_cvcAccessStart = notBefore
            cur_codeAccessStart = self.__parse_datetime(self.mso_codeAccessStart)
            if datetime_notBefore > cur_codeAccessStart:
                self.new_mso_codeAccessStart = notBefore

        return True

    def __split_cvc_chain(self, cvc):
        """Split the bundle to cvc and cvc CA.

        :cvc: bundle of CVC and CVC CA
        :return: SUCCESS or ERROR list

        """
        cvc_node = Asn1Decoder.asn1_node_root(cvc)

        # Points to the last value Byte which is the last Byte of the chunk.
        cvc_length = cvc_node[2]

        child_cvc = cvc[0:cvc_length + 1]  # double check this later!!!!!!
        cvc_ca = None
        if len(cvc) > cvc_length + 1:
            cvc_ca = cvc[cvc_length + 1:]

        return(child_cvc, cvc_ca)

    def verify_cvc(self, cvc, is_mfr):
        """Verify the CVC received via GCP.

        :cvc: CVC received via GCP, include CVC + CVC_CA
        :return: SUCCESS or ERROR list

        """
        self.logger.debug("Begin to verify CVC..." + (is_mfr and "manufacturer" or "co-signer"))

        if is_mfr == False:
            self.co_signed_gcp = True

        # At first, seperate CVC to mfr/mso CVC and CVC CA
        try:
            child_cvc, cvc_ca = self.__split_cvc_chain(cvc)

            if is_mfr == True:
                period_error = SsdVerifyResult.ERROR_GCP_INVALIDITY_PERIOD_MFR_CVC
                self.mfr_cvc = c.load_certificate(c.FILETYPE_ASN1, child_cvc)

                if cvc_ca == None:
                    self.verify_result = SsdVerifyResult.ERROR_GCP_MISS_ISSUER_CVC
                    return (False, self.verify_result)

                self.mfr_cvc_ca = c.load_certificate(c.FILETYPE_ASN1, cvc_ca)
            else:
                period_error = SsdVerifyResult.ERROR_GCP_INVALIDITY_PERIOD_CO_CVC
                self.mso_cvc = c.load_certificate(c.FILETYPE_ASN1, child_cvc)

                if cvc_ca == None:
                    self.verify_result = SsdVerifyResult.ERROR_GCP_MISS_ISSUER_CVC
                    return (False, self.verify_result)

                self.mso_cvc_ca = c.load_certificate(c.FILETYPE_ASN1, cvc_ca)
                self.co_signed = True
        except:
            self.verify_result = is_mfr == True and SsdVerifyResult.ERROR_GCP_MISS_MFR_CVC or SsdVerifyResult.ERROR_GCP_MISS_CO_CVC
            return (False, self.verify_result)

        try:
            # Verify extended key usage
            if self.__verify_extended_key_usage(is_mfr) == False:
                self.verify_result = SsdVerifyResult.ERROR_GCP_CVC_MISS_OR_IMPROPER_KEY_USAGE
                return (False, self.verify_result)

            # Verify start time and organization name
            if is_mfr == True:
                if self.__verify_mfr_starttime_orgname(True) == False:
                    return (False, self.verify_result)
            else:
                if self.__verify_mso_starttime_orgname(True) == False:
                    return (False, self.verify_result)

            # Verify the CVC and signature chain
            if self.__verify_cvc_and_signature_chain(is_mfr) == False:
                self.verify_result = SsdVerifyResult.ERROR_GCP_CVC_VALIDATION
                return (False, self.verify_result)

            # Verify the validity period and  Update cvcAccessStart and codeAccessStart
            if self.__verify_cvc_period(is_mfr) == False:
                self.verify_result = period_error
                return (False, self.verify_result)
        except Exception as e:
            self.logger.warn("cvc chain parse fail:" + str(e))
            self.verify_result = period_error
            return (False, self.verify_result)

        # Update time
        self.mfr_cvcAccessStart = self.new_mfr_cvcAccessStart
        self.mfr_codeAccessStart = self.new_mfr_codeAccessStart
        self.mso_cvcAccessStart = self.new_mso_cvcAccessStart
        self.mso_codeAccessStart = self.new_mso_codeAccessStart

        self.logger.debug("Succeed in verifying CVC..." + (is_mfr and "manufacturer" or "co-signer"))
        self.verify_result = SsdVerifyResult.SUCCESS
        return (True, self.verify_result)

    def __verify_signing_time(self, is_mfr):
        """verify the signintTime.

        :is_mfr:
        :return: SUCCESS or ERROR list

        """
        # get signing time from signinfo
        if is_mfr == True:
            signerInfo = self.mfr_signerInfo
        else:
            signerInfo = self.mso_signerInfo

        if signerInfo == None:
            self.logger.error("No signer info found when verifying signing time!")
            return False

        signing_time = None
        message_digest = None
        try:
            attrs = signerInfo['authenticatedAttributes']

            for x in attrs:
                type = x.getComponentByName("type")
                if str(type) == self.SIGNINGTIME_OID:
                    values = x.getComponentByName("values")
                    for v in values:
                        signing_time = decode(v)[0]
                elif str(type) == self.MESSAGEDIGEST_OID:
                    values = x.getComponentByName("values")
                    for v in values:
                        message_digest = decode(v)[0]
        except:
            return False

        if signing_time == None:
            self.logger.error("No signing time found in certificate!")
            return False

        signing_time = self.__get_generalized_time(signing_time)

        if is_mfr == True:
            self.mfr_signing_time = signing_time
            self.mfr_message_digest = message_digest
            cert = self.mfr_cvc
            cur_codeAccessStart = self.__parse_datetime(self.mfr_codeAccessStart)
        else:
            self.mso_signing_time = signing_time
            self.mso_message_digest = message_digest
            cert = self.mso_cvc
            cur_codeAccessStart = self.__parse_datetime(self.mso_codeAccessStart)

        if cert == None:
            self.logger.error("No certificate found when verifying signing time!")
            return False

        # print "\nTry to parse datetime:%s" % str(signing_time)
        datetime_signing = self.__parse_datetime(signing_time)

        notBefore = cert.get_notBefore()
        notAfter = cert.get_notAfter()

        datetime_notBefore = self.__parse_datetime(notBefore)
        datetime_notAfter = self.__parse_datetime(notAfter)

        # Bypass signing time check due to downgrade mis-functioned.

        # Normally if we need support downgrade, we would assign
        # the codefile signing time to cvc start time.
        # But if we assin the signing time to cvc start time, then the
        # signing time become meaningless, since SSD also check the cvc
        # validity. So we just skip checking the signing time validity.

        return True

        # The value of signingTime is equal to or greater than the manufacturer codeAccessStart value currently held in the RPD;
        # The value of signingTime is equal to or greater than the manufacturer CVC validity start time;
        # The value of signingTime is less than or equal to the manufacturer CVC validity end time.
        if datetime_signing < cur_codeAccessStart:
            self.logger.error("The signing time is less than codeAccessStart in RPD!")
            return False

        if datetime_signing < datetime_notBefore:
            self.logger.error("The signing time is less than the validity start time!")
            return False

        if datetime_signing > datetime_notAfter:
            self.logger.error("The signing time is greater than the validity end time!")
            return False

        return True

    def __get_codefile_cvc(self, signedData):
        """get cvc from codefile.

        :signedData:
        :return: SUCCESS or ERROR list

        """
        try:
            sign_node = Asn1Decoder.asn1_node_root(signedData)
            sign_node = Asn1Decoder.asn1_node_first_child(signedData, sign_node)  # Version
            sign_node = Asn1Decoder.asn1_node_next(signedData, sign_node)  # DisgestAlgorithmIdentifier
            sign_node = Asn1Decoder.asn1_node_next(signedData, sign_node)  # ContentInfo header
            sign_node = Asn1Decoder.asn1_node_next(signedData, sign_node)  # Certificates
            CVCs = signedData[sign_node[0] + 4: sign_node[2] + 1]  # Get the real CVCs
            sign_node = Asn1Decoder.asn1_node_next(signedData, sign_node)  # SignerInfo
            signerInfos = signedData[sign_node[0] + 4: sign_node[2] + 1]  # Get the real signerInfos

            # Get the CVCs
            try:
                cert_node = Asn1Decoder.asn1_node_root(CVCs)  # Mfr CVC
                mfr_cvc = CVCs[cert_node[0]:cert_node[2] + 1]
                self.mfr_cvc = c.load_certificate(c.FILETYPE_ASN1, str(mfr_cvc))
                cert_node = Asn1Decoder.asn1_node_next(CVCs, cert_node)  # Mfr CVC CA
                mfr_cvc_ca = CVCs[cert_node[0]:cert_node[2] + 1]
                self.mfr_cvc_ca = c.load_certificate(c.FILETYPE_ASN1, str(mfr_cvc_ca))
            except:
                self.logger.error("Can't get the manufacturer's CVC or CVC CA from codefile!")
                return

            try:
                cert_node = Asn1Decoder.asn1_node_next(CVCs, cert_node)  # optional Mso CVC
                mso_cvc = CVCs[cert_node[0]:cert_node[2] + 1]
                self.mso_cvc = c.load_certificate(c.FILETYPE_ASN1, str(mso_cvc))
                cert_node = Asn1Decoder.asn1_node_next(CVCs, cert_node)  # optional Mso CVC CA
                mso_cvc_ca = CVCs[cert_node[0]:cert_node[2] + 1]
                self.mso_cvc_ca = c.load_certificate(c.FILETYPE_ASN1, str(mso_cvc_ca))
            except:
                pass

            # Get the attributes
            signer_node = Asn1Decoder.asn1_node_root(signerInfos)  # Mfr SignerInfo
            mfr_signerInfo = signerInfos[signer_node[0]:signer_node[2] + 1]

            mso_signerInfo = None
            if self.mso_cvc != None:
                signer_node = Asn1Decoder.asn1_node_next(signerInfos, signer_node)  # mso SignerInfo
                mso_signerInfo = signerInfos[signer_node[0]:signer_node[2] + 1]

            if self.mfr_cvc != None:
                root_node = Asn1Decoder.asn1_node_root(mfr_signerInfo)
                child_node = Asn1Decoder.asn1_node_first_child(mfr_signerInfo, root_node)  # Version
                child_node = Asn1Decoder.asn1_node_next(mfr_signerInfo, child_node)  # issuer info
                child_node = Asn1Decoder.asn1_node_next(mfr_signerInfo, child_node)  # digest Algorithm
                child_node = Asn1Decoder.asn1_node_next(mfr_signerInfo, child_node)  # authenticateAttributes
                signer_attrs = mfr_signerInfo[child_node[0]:child_node[2] + 1]
                # Change the first byte to 0x31
                self.mfr_signer_attrs = '\x31' + signer_attrs[1:]

            if mso_signerInfo != None:
                root_node = Asn1Decoder.asn1_node_root(mso_signerInfo)
                child_node = Asn1Decoder.asn1_node_first_child(mso_signerInfo, root_node)  # Version
                child_node = Asn1Decoder.asn1_node_next(mso_signerInfo, child_node)  # issuer info
                child_node = Asn1Decoder.asn1_node_next(mso_signerInfo, child_node)  # digest Algorithm
                child_node = Asn1Decoder.asn1_node_next(mso_signerInfo, child_node)  # authenticateAttributes
                signer_attrs = mso_signerInfo[child_node[0]:child_node[2] + 1]
                # Change the first byte to 0x31
                self.mso_signer_attrs = '\x31' + signer_attrs[1:]

        except Exception, e:
            self.logger.info("Can't get CVC or signer attribute from codefile, reason: " + str(e))
            pass

        if self.mso_cvc != None:
            self.co_signed_codefile = True

        if self.mso_cvc != None and self.mso_cvc_ca == None:
            # share the same CVC CA
            self.mso_cvc_ca = self.mfr_cvc_ca

        return

    def __split_parse_codefile(self, codefile):
        """Split the bundle to signadata and signcontent.

        :codefile:
        :return: SUCCESS or ERROR list

        """

        try:
            with open(codefile, 'r') as f:
                head = f.read(256)
                sign_node = Asn1Decoder.asn1_node_root(head)
                sign_length = sign_node[2]
                f.seek(0, 0)
                sign_data = f.read(sign_length + 1)
                self.signedContentOffset = sign_length + 1

            decoded, rest = decode(sign_data, asn1Spec=rfc2315.ContentInfo())
            signedData_der = decoded['content']
            self.__get_codefile_cvc(signedData_der)

            sign, rest = decode(signedData_der, asn1Spec=rfc2315.SignedData())
            self.mfr_signerInfo = sign['signerInfos'][0]

            if self.mso_cvc != None:
                # get the co-signer signature
                self.mso_signerInfo = sign['signerInfos'][1]
        except Exception, e:
            self.logger.info("Exception when parsing codefile, reason: " + str(e))
            pass

        return

    def __verify_codefile_signature(self, is_mfr, codefile):
        """Verify the signature in codefile.

        :is_mfr:
        :return: SUCCESS or ERROR list

        """
        digest_verified_failed = False
        if is_mfr == True:
            signerInfo = self.mfr_signerInfo
            cert = self.mfr_cvc
            attrs = self.mfr_signer_attrs
            message_digest = self.mfr_message_digest
        else:
            signerInfo = self.mso_signerInfo
            cert = self.mso_cvc
            attrs = self.mso_signer_attrs
            message_digest = self.mso_message_digest

        if signerInfo == None or attrs == None:
            self.logger.error("No signer info or attributes in codefile when try to verify signature!")
            return False, digest_verified_failed

        try:
            # Get the encrypted digest
            encryptedDigest = str(signerInfo['encryptedDigest'])

            # Get the digest type, sha1, sha256...
            hash_algo = str(signerInfo['digestAlgorithm']['algorithm'])
            if hash_algo != self.SHA256_OID:
                # Only sha256 is used in CM/RPD certificate/signature
                self.logger.error("The hash algorithm in CVC is not sha256!")
                return False, digest_verified_failed

            # With the attributes in PKCS7, the encryptedDigest is for attributes (no -noattr in openssl)
            # So, here signedContent should not be used
            try:
                c.verify(cert, encryptedDigest, str(attrs), "sha256")
            except Exception as e:
                self.logger.error("Failed to verify encrypted digest, reason: " + str(e))
                return False, digest_verified_failed

            # Continue to verify the message digest, sha256(signedContent) == messagedigest
            hash_sha = hashlib.sha256()
            with open(codefile, 'r') as f:
                f.seek(self.signedContentOffset, 0)
                buf = f.read(self.limit_block)
                while buf:
                    hash_sha.update(buf)
                    buf = f.read(self.limit_block)
            digest = hash_sha.hexdigest()
            if digest != message_digest.prettyPrint()[2:]:  # remove the "0x"
                self.logger.error("Failed to verify the message digest!")
                digest_verified_failed = True
                return False, digest_verified_failed

        except Exception, e:
            self.logger.error("Failed to verify signature, reason: " + str(e))
            return False, digest_verified_failed

        return True, digest_verified_failed

    def __verify_code_steps(self, is_mfr, codefile):
        """Verify the mfr or mso codefile.

        :is_mfr:
        :return: SUCCESS or ERROR list

        """
        if is_mfr == True:
            signing_time_error = SsdVerifyResult.ERROR_PKCS_MFR_SIGNING_TIME_LESS_THAN_RPD
        else:
            signing_time_error = SsdVerifyResult.ERROR_PKCS_CO_SIGNING_TIME_LESS_THAN_RPD

        # Verify mfr/mso signingTime
        if self.__verify_signing_time(is_mfr) == False:
            self.verify_result = signing_time_error
            return False

        # Verify mfr/mso organization name and start time
        if is_mfr == True:
            cvc_mismatch = SsdVerifyResult.ERROR_FILE_MFR_CVC_ROOT_CA_MISMATCH_GCP
            exkey_error = SsdVerifyResult.ERROR_CVC_MFR_MISS_OR_IMPROPER_KEY_USAGE
            period_error = SsdVerifyResult.ERROR_FILE_INVALIDITY_PERIOD_MFR_CVC
            cvs_error = SsdVerifyResult.ERROR_FILE_MFR_CVS_VALIDATION
            if self.__verify_mfr_starttime_orgname(False) == False:
                return False
        else:
            cvc_mismatch = SsdVerifyResult.ERROR_FILE_CO_CVC_ROOT_CA_MISMATCH_GCP
            exkey_error = SsdVerifyResult.ERROR_CVC_CO_MISS_OR_IMPROPER_KEY_USAGE
            period_error = SsdVerifyResult.ERROR_FILE_INVALIDITY_PERIOD_CO_CVC
            cvs_error = SsdVerifyResult.ERROR_FILE_CO_CVS_VALIDATION
            if self.__verify_mso_starttime_orgname(False) == False:
                return False

        # Verify mfr/mso extended key usage
        if self.__verify_extended_key_usage(is_mfr) == False:
            self.verify_result = exkey_error
            return False

        # Verify mfr/mso CVC chains up to Root CA
        if self.__verify_cvc_and_signature_chain(is_mfr) == False:
            self.verify_result = cvc_mismatch
            return False

        # Verify mfr/mso validity periods
        if self.__verify_cvc_period(is_mfr) == False:
            self.verify_result = period_error
            return False

        # Verify mfr/mso code file signature
        status, digest_verify_failed = self.__verify_codefile_signature(is_mfr, codefile)
        if status is False:
            self.verify_result = \
                cvs_error if digest_verify_failed is False else SsdVerifyResult.ERROR_SW_FILE_CORRUPTION
            return False

        return True

    def verify_file(self, codefile):
        """Verify the codefile.

        :codefile:
        :return: SUCCESS or ERROR list

        """
        # Drop the previous CVC from GCP
        self.mfr_cvc = None
        self.mfr_cvc_ca = None
        self.mso_cvc = None
        self.mso_cvc_ca = None

        self.logger.debug("Begin to verify codefile...")

        # Split and parse the codefile
        try:
            self.__split_parse_codefile(codefile)
        except Exception, e:
            self.logger.error("Failed to parse codefile, reason: " + str(e))
            self.verify_result = SsdVerifyResult.ERROR_FILE_WRONG_FORMAT
            return (False, self.verify_result)

        if self.mfr_cvc == None or self.mfr_cvc_ca == None:
            self.verify_result = SsdVerifyResult.ERROR_FILE_WRONG_FORMAT
            return (False, self.verify_result)

        try:
            # Verify Manufacturer
            if self.__verify_code_steps(True, codefile) == False:
                self.logger.error("failed to verify manufacturer's info!")
                return (False, self.verify_result)

            if self.co_signed_codefile == True:
                if self.co_signed_gcp == False:
                    # Mismatch here, reject it
                    self.verify_result = SsdVerifyResult.ERROR_FILE_CO_MISMATCH_WITH_GCP
                    return (False, self.verify_result)

                # Verify co-signer, i.e. MSO
                if self.__verify_code_steps(False, codefile) == False:
                    self.logger.error("failed to verify co-signer's info!")
                    return (False, self.verify_result)
        except Exception as e:
            self.logger.warn("codefile parse fail:" + str(e))
            self.verify_result = SsdVerifyResult.ERROR_FILE_WRONG_FORMAT
            return (False, self.verify_result)

        # Update codeAccessStart time
        self.new_mfr_codeAccessStart = str(self.mfr_signing_time)
        self.new_mso_codeAccessStart = str(self.mso_signing_time)

        self.logger.debug("Succeed in verifying codefile!")
        self.verify_result = SsdVerifyResult.SUCCESS
        return (True, self.verify_result)

    def get_initcode(self):
        """Get the varying time from code file.

        :return: latest initcode dict()
         {"manufacturer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":},
          "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
         or None

        """
        new_parameters = {"manufacturer": {"organizationName": self.mfr_org_name,
                                           "codeAccessStart": self.new_mfr_codeAccessStart,
                                           "cvcAccessStart": self.new_mfr_cvcAccessStart},
                          "co-signer": {"organizationName": self.mso_org_name,
                                        "codeAccessStart": self.new_mso_codeAccessStart,
                                        "cvcAccessStart": self.new_mso_cvcAccessStart}}
        return new_parameters

    def set_initcode(self, initcode):
        """Set the initcode, local parameters of manufacture and co-signer,
        for unit-test only.

        :initcode: dict()
         {"manufacturer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":},
          "co-signer":{"organizationName":, "codeAccessStart":, "cvcAccessStart":}}
        :return: None

        """
        self.initcode = initcode
        self.mfr_org_name = self.initcode['manufacturer']['organizationName']
        self.mfr_codeAccessStart = self.initcode['manufacturer']['codeAccessStart']
        self.mfr_cvcAccessStart = self.initcode['manufacturer']['cvcAccessStart']

        self.mso_org_name = self.initcode['co-signer']['organizationName']
        self.mso_codeAccessStart = self.initcode['co-signer']['codeAccessStart']
        self.mso_cvcAccessStart = self.initcode['co-signer']['cvcAccessStart']

    def set_rootca(self, rootca):
        """ Only for unit test."""
        with open(rootca, 'r') as root_cert_file:
            self.root_cert = c.load_certificate(c.FILETYPE_PEM, root_cert_file.read())

    def get_image(self, path, codefile):
        """save the RPD image from code file to fixed path.

        return: True
                False
        """

        ret = False
        try:
            with open(path, 'w') as f1:
                with open(codefile, 'r') as f2:
                    f2.seek(self.signedContentOffset + 3, 0)
                    buf = f2.read(self.limit_block)
                    while buf:
                        f1.write(buf)
                        buf = f2.read(self.limit_block)
                    ret = True
        except Exception as e:
            self.logger.error("save image fail:%s", str(e))

        return ret
