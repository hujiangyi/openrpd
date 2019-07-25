#
# Copyright (c) 2017-2018 Cisco and/or its affiliates, and
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

from rpd.common.rpd_logging import AddLoggerToClass
import psutil
import commands
import os

# hrStorage type dict
STORAGE_TYPE = {
    "Other": 1,
    "Ram": 2,
    "VirtualMemory": 3,
    "FixedDisk": 4,
    "RemovableDisk": 5,
    "FloppyDisk": 6,
    "CompactDisc": 7,
    "RamDisk": 8,
    "FlashMemory": 9,
    "NetworkDisk": 10,
}

# hrProcess type and status dict
PROCESS_TYPE = {
    'unknown': 1,
    'system': 2,
    'driver': 3,
    'application': 4,
}

PROCESS_STATUS = {
    'running': 1,
    'runnable': 2,
    'notrunnable': 3,
    'invalid': 4,
}


class HostResourceHandler(object):
    __metaclass__ = AddLoggerToClass

    def getMemorySize(self):
        f = open("/proc/meminfo")
        lines = f.readlines()
        f.close()
        memsize = 0

        for line in lines:
            if line.find("MemTotal") != -1:
                memsize = line.split(':')[1].split()[0]
                self.logger.debug("Get memory size: %s" % memsize)

        return int(memsize)

    def getProcessorLoad(self):
        f = open("/proc/loadavg")
        loadinfo = f.read().split()
        f.close()
        # get load with percent rate
        cpuload = float(loadinfo[0]) * 100
        self.logger.debug("Get process load: %f" % cpuload)

        return int(cpuload)

    def getStorages(self, hrstorages):
        # storage allocation units (KByte)
        unit = 1024
        # get system memory info
        st = hrstorages.add()
        f = open("/proc/meminfo")
        lines = f.readlines()
        f.close()
        for line in lines:
            if line.find("MemTotal") != -1:
                st.hrStorageSize = int(line.split()[1])
                continue
            if line.find("MemFree") != -1:
                st.hrStorageUsed = st.hrStorageSize - int(line.split()[1])
                continue

        st.hrStorageIndex = 1
        st.hrStorageType = STORAGE_TYPE["Ram"]
        st.hrStorageAllocationFailures = 0
        st.hrStorageAllocationUnits = unit
        self.logger.debug("Get storage info: index=%s, size=%sKB, type=%s, "
                          "used=%sKB, allocfail=%s, allocunit=%sByte"
                          % (st.hrStorageIndex, st.hrStorageSize,
                             st.hrStorageType, st.hrStorageUsed,
                             st.hrStorageAllocationFailures,
                             st.hrStorageAllocationUnits))

        # get disk and flash memory info
        rtn, stinfo = commands.getstatusoutput('df -h')
        # get disk info list
        stlist = list()
        for line in stinfo.split('\n'):
            if line.split()[-1].startswith('/'):
                stlist.append(line)

        # add disk info into hrstorage
        for line in stlist:
            st = hrstorages.add()

            linestat = line.split()
            stdir = linestat[5]
            sttype = linestat[0]
            disk = os.statvfs(stdir)
            st.hrStorageIndex = stlist.index(line) + 2
            st.hrStorageSize = disk.f_bsize * disk.f_blocks / unit
            if stdir == '/':
                st.hrStorageType = STORAGE_TYPE["FixedDisk"]
            elif stdir == '/bootflash':
                st.hrStorageType = STORAGE_TYPE["FlashMemory"]
            elif sttype == 'tmpfs':
                st.hrStorageType = STORAGE_TYPE['VirtualMemory']
            elif sttype.find('dev/mmcblk'):
                st.hrStorageType = STORAGE_TYPE['RemovableDisk']
            else:
                st.hrStorageType = STORAGE_TYPE['Other']
            st.hrStorageUsed = st.hrStorageSize - disk.f_bsize * disk.f_bfree / unit
            st.hrStorageAllocationFailures = 0
            st.hrStorageAllocationUnits = unit

            self.logger.debug("Get storage info: index=%s, size=%sKB, type=%s, "
                              "used=%sKB, allocfail=%s, allocunit=%sByte"
                              % (st.hrStorageIndex,
                                 st.hrStorageSize,
                                 st.hrStorageType,
                                 st.hrStorageUsed,
                                 st.hrStorageAllocationFailures,
                                 st.hrStorageAllocationUnits))

    def getProcesses(self, hrprocesses):
        # TODO: specify the processes to send back,
        # return the top 10 processes sorted by memory percent
        pdict = {}
        for i in psutil.pids():
            try:
                pdict[i] = int(psutil.Process(i).memory_info()[0])
            except psutil.NoSuchProcess:
                continue
        # sort the dict according to memory percent
        plist = sorted(pdict.items(), key=lambda d: d[1], reverse=True)

        # if length of plist is longer than 10, return the top 10 processes
        # if length is shorter than 10, return what we have
        listLen = 0
        if plist is not None:
            self.logger.debug("Current system process number is %d" % len(plist))
            if len(plist) < 10:
                listLen = len(plist)
            else:
                listLen = 10

        for i in range(listLen):
            p = psutil.Process(plist[i][0])
            # load the process info into list
            procinfo = hrprocesses.add()
            procinfo.hrSWRunIndex = p.pid
            procinfo.hrSWRunPerfCPU = int(p.cpu_percent())
            procinfo.hrSWRunPerfMem = int(p.memory_info()[0] / (2 ** 10))
            procinfo.hrSWRunType = PROCESS_TYPE['application']

            if p.status() in PROCESS_STATUS.keys():
                procinfo.hrSWRunStatus = PROCESS_STATUS[p.status()]
            else:
                procinfo.hrSWRunStatus = PROCESS_STATUS['runnable']

            self.logger.debug("Get process info: index=%s, cpupercent=%s,"
                              "meminfo=%sKB, status=%s, type=%s"
                              % (procinfo.hrSWRunIndex,
                                 procinfo.hrSWRunPerfCPU,
                                 procinfo.hrSWRunPerfMem,
                                 procinfo.hrSWRunStatus,
                                 procinfo.hrSWRunType))
