#
# Copyright (c) 2018 Cisco and/or its affiliates, and
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

import multiprocessing
import urllib2
import signal
import tftpy
import os
from rpd.common.utils import Convert
from tftpy.TftpShared import TftpTimeout, TftpException
from rpd.confdb.rpd_redis_db import RPDAllocateWriteRecord, DBRecord
from rpd.common.rpd_logging import AddLoggerToClass
from HttpMultiDataForm import MultiDataForm
from rpd.rcp.rcp_lib import rcp_tlv_def


class CrashFileStatusInfo(RPDAllocateWriteRecord):
    """
    It is used to save crash files status info
    """
    MAX_IDX = 255

    def __init__(self, index=None):
        super(CrashFileStatusInfo, self).__init__(CrashFileStatusInfo.MAX_IDX)
        self.fileName = None
        self.index = index
        self.fileControl = CrashFileCtrlHandler.CONTROL_OTHER
        self.fileStatus = CrashFileCtrlHandler.STATUS_AVAILFORUPLOAD


class CrashDataServerInfo(DBRecord):
    """
    It is used to save the server information
    """

    def __init__(self, index=None):
        super(CrashDataServerInfo, self).__init__()
        self.index = 0
        self.destIpAddress = ""
        self.destPath = ""
        self.protocol = CrashFileCtrlHandler.PROTOCOL_TFTP


class CrashFileUploadProcess(multiprocessing.Process):

    TFTP_PORT = 69
    HTTP_PORT = 80

    __metaclass__ = AddLoggerToClass

    def __init__(self, uploadIdx):
        super(CrashFileUploadProcess, self).__init__()
        self.uploadingFileIdx = uploadIdx

    def run(self):
        """
        crash file upload function
        :return:
        """
        uploadingFileIdx = self.uploadingFileIdx
        if uploadingFileIdx is None:
            return
        self.logger.debug("The current uploading file index is %d" % uploadingFileIdx)
        crashFileStatusInfo = CrashFileStatusInfo(uploadingFileIdx)
        crashFileStatusInfo.read()
        if not crashFileStatusInfo.fileName:
            crashFileStatusInfo.delete()
            self.logger.warn(
                "Upload fail due to no mapping index %d" % crashFileStatusInfo.index)
            return
        if not os.path.exists(CrashFileCtrlHandler.CORE_FILE_PATH + crashFileStatusInfo.fileName):
            crashFileStatusInfo.delete()
            return
        if crashFileStatusInfo.fileStatus == CrashFileCtrlHandler.STATUS_UPLOADCANCELLED:
            self.logger.debug(
                "Cancel file %s upload" % crashFileStatusInfo.fileName)
            return
        if crashFileStatusInfo.fileStatus == CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS:
            self.logger.debug("crash file %s is in uploading progress" %
                              crashFileStatusInfo.fileName)
            return
        self.logger.debug("Begin to start file %s upload" % crashFileStatusInfo.fileName)
        self.upload_crash_file(crashFileStatusInfo)

    def update_crash_file_status(self, status, crashFileCtrlInfo):
        crashFileCtrlInfo.fileStatus = status
        crashFileCtrlInfo.write()

    def upload_with_tftp(self, crashFileCtrlInfo, crashDataServerInfo):
        """
        upload the crash file in tftp mode
        :param tftp_options:
        :param crashFileCtrlInfo:
        :return:
        """
        tftp_options = {}
        if Convert.is_valid_ipv4_address(str(crashDataServerInfo.destIpAddress)):
            blksize = 1042
            tftp_options['blksize'] = int(blksize)
        elif Convert.is_valid_ipv6_address(str(crashDataServerInfo.destIpAddress)):
            blksize = 1048
            tftp_options['blksize'] = int(blksize)
        fileName = crashFileCtrlInfo.fileName
        if crashDataServerInfo.destPath.endswith('/'):
            destFileName = crashDataServerInfo.destPath + fileName
        else:
            destFileName = crashDataServerInfo.destPath + '/' + fileName
        srcFileName = CrashFileCtrlHandler.CORE_FILE_PATH + fileName
        self.logger.debug("Tftp upload destFileName:%s srcFileName:%s destIpAddress:%s" %
                          (destFileName, srcFileName, crashDataServerInfo.destIpAddress))
        try:

            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS,
                                          crashFileCtrlInfo)
            tclient = tftpy.TftpClient(crashDataServerInfo.destIpAddress, int(self.TFTP_PORT),
                                       tftp_options)
            tclient.upload(str(destFileName), str(srcFileName))
            self.logger.debug("tftp upload %s complete", srcFileName)
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADCOMPLETED,
                                          crashFileCtrlInfo)
        except TftpTimeout as err:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR,
                                          crashFileCtrlInfo)
            self.logger.warn(
                "Error: File {0:s} fail to upload with TftpException {1:s}"
                .format(fileName, str(err)))
        except TftpException as err:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR,
                                          crashFileCtrlInfo)
            self.logger.warn("Error: File %s fail to upload with TftpException %s" %
                             (fileName, str(err)))
        except Exception as err:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR,
                                          crashFileCtrlInfo)
            self.logger.warn("Error: File %s fail to upload with TftpException %s" %
                             (fileName, str(err)))
            if tclient.context is not None:
                tclient.context.end()

    def upload_with_http(self, crashFileCtrlInfo, crashDataServerInfo):
        """
        upload the crash file in http mode
        :param crashFileCtrlInfo:
        :return:
        """
        corefilepath = CrashFileCtrlHandler.CORE_FILE_PATH + crashFileCtrlInfo.fileName
        self.logger.debug("Upload crash file %s in http mode" % corefilepath)
        self.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADINPROGRESS,
                                      crashFileCtrlInfo)
        if Convert.is_valid_ipv6_address(
                str(crashDataServerInfo.destIpAddress)):
            httpServer = "[" + str(crashDataServerInfo.destIpAddress) + "]"
        else:
            httpServer = str(crashDataServerInfo.destIpAddress)
        try:
            dataForm = MultiDataForm()
            with open(corefilepath, 'rb') as uploadFile:
                dataForm.add_file('file', crashFileCtrlInfo.fileName, uploadFile)
                if not str(crashDataServerInfo.destPath):
                    url = 'http://' + httpServer + ':' + str(self.HTTP_PORT)
                else:
                    url = 'http://' + httpServer + ':' + str(self.HTTP_PORT) + \
                          str(crashDataServerInfo.destPath)
                self.logger.info("Http url is %s" % url)
                request = urllib2.Request(url)
                body = str(dataForm)
                request.add_header('Content-type', dataForm.get_content_type())
                request.add_header('Content-length', len(body))
                request.add_data(body)
                urllib2.urlopen(request).read()
                self.logger.debug("Http upload %s compplete" % (crashFileCtrlInfo.fileName))
                self.update_crash_file_status(CrashFileCtrlHandler.STATUS_UPLOADCOMPLETED,
                                              crashFileCtrlInfo)
        except urllib2.HTTPError as e:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR,
                                          crashFileCtrlInfo)
            self.logger.warn("HTTP Error %s fail to upload: %s" % (corefilepath, str(e)))
        except urllib2.URLError as e:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR,
                                          crashFileCtrlInfo)
            self.logger.error("HTTP Error %s fail to upload: %s" % (corefilepath, str(e)))
        except Exception as e:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR,
                                          crashFileCtrlInfo)
            self.logger.error("HTTP Error %s fail to upload: %s" % (corefilepath, str(e)))

    def upload_crash_file(self, crashFileCtrlInfo):
        """
        @:param crashFileCtrlInfo
        :return:
        """
        crashDataServerInfo = CrashFileCtrlHandler.get_server_info()
        if not crashDataServerInfo.destIpAddress or crashDataServerInfo.protocol \
                not in [CrashFileCtrlHandler.PROTOCOL_TFTP, CrashFileCtrlHandler.PROTOCOL_HTTP]:
            self.update_crash_file_status(CrashFileCtrlHandler.STATUS_ERROR, crashFileCtrlInfo)
            self.logger.warn("Crash file didn't support protocol=%d " %
                             crashDataServerInfo.protocol)
            return
        if crashDataServerInfo.protocol == CrashFileCtrlHandler.PROTOCOL_TFTP:
            self.upload_with_tftp(crashFileCtrlInfo, crashDataServerInfo)

        elif crashDataServerInfo.protocol == CrashFileCtrlHandler.PROTOCOL_HTTP:
            self.upload_with_http(crashFileCtrlInfo, crashDataServerInfo)

        if crashFileCtrlInfo.fileStatus == CrashFileCtrlHandler.STATUS_UPLOADCOMPLETED and \
                crashFileCtrlInfo.fileControl == CrashFileCtrlHandler.CONTROL_UPLOADANDDELETE:
            CrashFileCtrlHandler.delete_core_file(crashFileCtrlInfo.fileName)
            crashFileCtrlInfo.delete()
            self.logger.debug("Upload crash file %s and delete " %
                              crashFileCtrlInfo.fileName)


class CrashFileCtrlHandler(object):
    """
    Handle all crashfile control events
    """

    FILE_CTRL_NAME = rcp_tlv_def.FILE_CTRL_NAME

    # Crash data file control for 40.3.2, default value is other
    CONTROL_OTHER = rcp_tlv_def.CONTROL_OTHER[0]
    CONTROL_UPLOAD = rcp_tlv_def.CONTROL_UPLOAD[0]
    CONTROL_CANCELUPLOAD = rcp_tlv_def.CONTROL_CANCELUPLOAD[0]
    CONTROL_DELETEFILE = rcp_tlv_def.CONTROL_DELETEFILE[0]
    CONTROL_UPLOADANDDELETE = rcp_tlv_def.CONTROL_UPLOADANDDELETE[0]

    # Crash file status for 100.20.3
    STATUS_OTHER = rcp_tlv_def.STATUS_OTHER[0]
    STATUS_AVAILFORUPLOAD = rcp_tlv_def.STATUS_AVAILFORUPLOAD[0]
    STATUS_UPLOADINPROGRESS = rcp_tlv_def.STATUS_UPLOADINPROGRESS[0]
    STATUS_UPLOADCOMPLETED = rcp_tlv_def.STATUS_UPLOADCOMPLETED[0]
    STATUS_UPLOADPENDING = rcp_tlv_def.STATUS_UPLOADPENDING[0]
    STATUS_UPLOADCANCELLED = rcp_tlv_def.STATUS_UPLOADCANCELLED[0]
    STATUS_ERROR = rcp_tlv_def.STATUS_ERROR[0]

    FILE_STATUS_NAME = rcp_tlv_def.FILE_STATUS_NAME

    # Crash data server control for 40.4.4
    PROTOCOL_TFTP = rcp_tlv_def.PROTOCOL_TFTP[0]
    PROTOCOL_HTTP = rcp_tlv_def.PROTOCOL_HTTP[0]

    PROTOCOL_NAME = rcp_tlv_def.PROTOCOL_NAME

    CORE_FILE_PATH = "/bootflash/corefiles/"

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self.uploadProcess = None
        self.waitingUploadList = []

    @staticmethod
    def delete_core_file(fileName):
        if not fileName.strip():
            return
        path = CrashFileCtrlHandler.CORE_FILE_PATH + fileName
        if os.path.isdir(path):
            os.removedirs(path)
        elif os.path.isfile(path):
            os.remove(path)

    @staticmethod
    def get_server_info():
        crashDataServerInfo = CrashDataServerInfo()
        crashDataServerInfo.index = 0
        crashDataServerInfo.read()
        return crashDataServerInfo

    def set_server_info(self, crashDataServerInfo):
        crashDataServerInfo.index = 0
        crashDataServerInfo.write()

    def check_file_valid(self, fileName):
        if ".core.gz" not in fileName:
            return False
        return True

    def update_crash_file_table(self, _):
        """
        Update the crash file status table in every 10s
        :param _:
        :return:
        """
        self.start_upload_process()
        file_list = []
        if os.path.exists(CrashFileCtrlHandler.CORE_FILE_PATH):
            file_list = os.listdir(CrashFileCtrlHandler.CORE_FILE_PATH)
        num = len(file_list)
        if num > CrashFileStatusInfo.MAX_IDX:
            del_num = (len(file_list) - CrashFileStatusInfo.MAX_IDX)
            cmd = "ls -tr %s | grep '.core.gz' | head -%d " % \
                  (CrashFileCtrlHandler.CORE_FILE_PATH, del_num)
            del_files = os.popen(cmd)
            for file_name in del_files:
                file_name = file_name.split("\n")[0]
                self.delete_core_file(file_name)
                file_list.remove(file_name)

        db_file_list = list()
        for key in CrashFileStatusInfo.get_keys():
            crashFileStatusInfo = CrashFileStatusInfo(key)
            crashFileStatusInfo.read()
            db_file_list.append(crashFileStatusInfo.fileName)
            if crashFileStatusInfo.fileName is None or \
                    crashFileStatusInfo.fileName not in file_list:
                crashFileStatusInfo.delete()

        for coreFileName in file_list:
            if '.core.gz' not in coreFileName:
                self.delete_core_file(coreFileName)
                continue
            if coreFileName not in db_file_list:
                crashFileInfo = CrashFileStatusInfo()
                crashFileInfo.allocateIndex()
                crashFileInfo.fileName = coreFileName.strip()
                self.logger.debug("Crash file table new record index=%d "
                                  "fileName=%s" %
                                  (crashFileInfo.index, crashFileInfo.fileName))
                crashFileInfo.write()
        return

    def save_crash_data_server(self, crashDataServerCtrl):
        """
        Update crash data server configuration
        :param crashDataServerCtrl:
        :return:
        """
        crashDataServerInfo = self.get_server_info()
        if crashDataServerCtrl.HasField("DestPath"):
            destPath = crashDataServerCtrl.DestPath
            crashDataServerInfo.destPath = destPath.strip()
        if crashDataServerCtrl.HasField("Protocol"):
            crashDataServerInfo.protocol = crashDataServerCtrl.Protocol
        if crashDataServerCtrl.HasField("DestIpAddress"):
            crashDataServerInfo.destIpAddress = crashDataServerCtrl.DestIpAddress
            if not crashDataServerCtrl.DestIpAddress:
                crashDataServerCtrl.DestIpAddress = "0.0.0.0"
        self.set_server_info(crashDataServerInfo)
        self.logger.debug("Crash data server DestIpAddress=%s DestPath=%s Protocol=%d" %
                          (crashDataServerInfo.destIpAddress,
                           crashDataServerInfo.destPath,
                           crashDataServerInfo.protocol))
        return True

    def get_crash_data_server(self, crashDataServerCtrl):
        """
        Update crash data server configuration
        :param crashDataServerCtrl:
        :return:
        """
        crashDataServerInfo = self.get_server_info()
        crashDataServerCtrl.DestPath = crashDataServerInfo.destPath
        crashDataServerCtrl.Protocol = crashDataServerInfo.protocol
        if crashDataServerInfo.destIpAddress:
            crashDataServerCtrl.DestIpAddress = crashDataServerInfo.destIpAddress
        return True

    def stop_upload_process(self):
        """
        Stop the uploading thread when receive a cancel command
        :return:
        """
        try:
            if self.is_upload_process_alive():
                self.logger.info("Stop the pid %d" % self.uploadProcess.pid)
                os.kill(self.uploadProcess.pid, signal.SIGKILL)
                self.uploadProcess = None
        except Exception as e:
            self.logger.warn("stop upload process failed due to %s" % str(e))

    def is_upload_process_alive(self):
        if self.uploadProcess and self.uploadProcess.is_alive():
            return True
        else:
            self.uploadProcess = None
            return False

    def start_upload_process(self):
        """
        Start the upload thread
        :return:
        """
        try:
            if not self.waitingUploadList:
                return
            if not self.is_upload_process_alive():
                index = self.waitingUploadList.pop(0)
                self.uploadProcess = CrashFileUploadProcess(index)
                self.uploadProcess.daemon = True
                self.uploadProcess.start()
        except Exception as e:
            self.logger.warn("start upload process failed due to %s" % str(e))

    def update_waiting_upload_list(self, op, index):
        try:
            if op and index not in self.waitingUploadList:
                self.waitingUploadList.append(index)
                return True
            if not op and index in self.waitingUploadList:
                self.waitingUploadList.remove(index)
                return True
        except Exception as e:
            self.logger.warn("Upload waiting List failed due to %s" % str(e))
            return False
        return False

    def update_pending_file_idx_list(self, index, fileCtrl):
        """
        Handle the crash file control command
        :param index:
        :param fileCtrl:
        :return:
        """
        crashFileCtrlInfo = CrashFileStatusInfo(index)
        crashFileCtrlInfo.read()

        crashFileCtrlInfo.fileControl = fileCtrl
        self.logger.debug("Recv new crash file control index:%d fileName:%s"
                          " fileControl:%d" % (index, crashFileCtrlInfo.fileName,
                                               crashFileCtrlInfo.fileControl))

        if fileCtrl == self.CONTROL_UPLOAD or fileCtrl == self.CONTROL_UPLOADANDDELETE:
            if crashFileCtrlInfo.fileStatus != self.STATUS_UPLOADINPROGRESS and \
                    self.update_waiting_upload_list(True, crashFileCtrlInfo.index):
                crashFileCtrlInfo.fileStatus = self.STATUS_UPLOADPENDING
                crashFileCtrlInfo.write()
            else:
                self.logger.debug("The index %d is in the uploading waiting"
                                  " list" % index)
            self.start_upload_process()
        elif fileCtrl == self.CONTROL_CANCELUPLOAD:
            if crashFileCtrlInfo.fileStatus == self.STATUS_UPLOADINPROGRESS:
                self.stop_upload_process()
                self.start_upload_process()
            else:
                self.update_waiting_upload_list(False, crashFileCtrlInfo.index)
            crashFileCtrlInfo.fileStatus = self.STATUS_UPLOADCANCELLED
            crashFileCtrlInfo.write()
        elif fileCtrl == self.CONTROL_DELETEFILE:
            if crashFileCtrlInfo.fileStatus == self.STATUS_UPLOADINPROGRESS:
                self.stop_upload_process()
                self.start_upload_process()
            self.update_waiting_upload_list(False, crashFileCtrlInfo.index)
            self.delete_core_file(crashFileCtrlInfo.fileName)
            crashFileCtrlInfo.delete()
        else:
            return False
        return True
