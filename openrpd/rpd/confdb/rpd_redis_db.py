#
# Copyright (c) 2017 Cisco and/or its affiliates, and
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

import pickle
import redis
import json
import os
from sortedcontainers import SortedList
from rpd.common.utils import singleton
from rpd.common.rpd_logging import AddLoggerToClass


@singleton
class RCPDB(object):
    """
    Connection the resource database, provide a basic redis db operational.
    Each operational should be a object, not a serializable data

    """
    __metaclass__ = AddLoggerToClass

    DB_CFG_FILE = "/etc/config/rpd_res_db.conf"

    def __init__(self):
        cfg_file = RCPDB.DB_CFG_FILE
        try:
            with open(cfg_file, 'rt') as fp:
                db_cfg = json.load(fp)
            self.redis_db = redis.StrictRedis(db=db_cfg["RES_DB_NUM"],
                                              unix_socket_path=db_cfg[
                                                  "DB_SOCKET_PATH"])
        except Exception as e:
            self.logger.error("Resource db connection failure: %s", str(e))

    def write(self, key, record):
        value = pickle.dumps(record)
        self.redis_db.set(key, value)

    def read(self, key):
        value = self.redis_db.get(key)
        if value is None:
            return None
        d = pickle.loads(value)
        return d

    def delete(self, key):
        self.redis_db.delete(key)

    def get_keys(self, pattern="*"):
        return self.redis_db.keys(pattern)


class DBRecord(object):

    """
    Prepares and stores some permanent data like configure tlv which is
    needed to support both write and read. Performs the permanent data into
    a redis database.
    It should be provider delete, add and search function for each table.
    We should inherit this basic record if you want to save it in rpd resource
    db.

    """

    def _get_key(self):
        return '%s:%s' % (self.__class__.__name__, str(self.get_index()))

    def write(self):
        """
        Save an specified record into this table
        :param key
        :param record
        """
        db = RCPDB()
        db.write(self._get_key(), self)

    def read(self):
        """
        Search the record by key form all resource database
        Return the entry by index identified which has already saved in
        database.
        :param index
        :return DBRecord
        """
        db = RCPDB()
        key = self._get_key()
        d = db.read(key)
        if d is None:
            return
        assert(isinstance(d, DBRecord))
        for k, v in d.__dict__.items():
            self.__dict__[k] = v

    def delete(self):
        """
        delete this record by key index
        """
        db = RCPDB()
        db.delete(self._get_key())

    def get_index(self):
        return self.index

    @classmethod
    def decode_index(cls, init_str):
        return int(init_str)

    @classmethod
    def get_keys(cls):
        db = RCPDB()
        pattern = cls.__name__ + ":*"
        keys = db.get_keys(pattern)
        for key in keys:
            index = key[(key.find(':') + 1):]
            yield cls.decode_index(index)

    @classmethod
    def get_sorted_key_list(cls):
        index_list = SortedList()
        for dbindex in cls.get_keys():
            index_list.add(dbindex)
        return index_list

    @classmethod
    def get_all(cls):
        for dbindex in cls.get_keys():
            ses = cls(dbindex)
            ses.read()
            yield ses

    @classmethod
    def get_next_n(cls, key=None, count=0):
        index_list = cls.get_sorted_key_list()
        ret_count = 0
        for index in index_list.irange(minimum=key):
            if ret_count >= count:
                break
            ret_count += 1
            ses = cls(index)
            ses.read()
            yield ses


class RPDAllocateWriteRecord(DBRecord):

    """
    Prepares and stores some permanent data like allocate write support, which
    need maintains a index pool for the special Table.
    Please call this init function before you use it

    """

    indexDBPool = {}

    def __init__(self, rangeIdx):
        """
        rangeIdx is used to limit the range of index pool in the special table
        different table has different index pool
        """
        self.poolName = self.__class__.__name__
        self.range_max = rangeIdx
        if RPDAllocateWriteRecord.indexDBPool.get(self.poolName):
            return
        else:
            indexPool = [num for num in range(0, rangeIdx)]
            RPDAllocateWriteRecord.indexDBPool[self.poolName] = indexPool
            db = RCPDB()
            for key in db.get_keys(pattern=self.poolName + ":*"):
                '''sync with current db, will extension the key type'''
                index = key[(key.find(':') + 1):]
                assert(index)
                RPDAllocateWriteRecord.indexDBPool[self.poolName].remove(
                    int(index))

    def allocateIndex(self, index=None):
        """
        allocate the index, used for allocatewrite operation type
        :return:
        """
        if not index:
            self.index = RPDAllocateWriteRecord.indexDBPool.get(self.poolName).pop(0)
        else:
            self.index = index

    def write(self):
        """
        save the record
        :return:
        """
        if self.index in RPDAllocateWriteRecord.indexDBPool.get(self.poolName):
            RPDAllocateWriteRecord.indexDBPool.get(self.poolName).remove(self.index)
        super(RPDAllocateWriteRecord, self).write()

    def delete(self):
        """
        delete the record and reuse the index
        :return:
        """

        if self.index is None:
            return
        if self.index >= self.range_max:
            return
        if self.poolName not in RPDAllocateWriteRecord.indexDBPool.keys():
            return
        if self.index in RPDAllocateWriteRecord.indexDBPool.get(self.poolName):
            return

        RPDAllocateWriteRecord.indexDBPool.get(self.poolName).append(self.index)
        super(RPDAllocateWriteRecord, self).delete()

    def getIndexPool(self):
        """
        get the left unused index list of the pool
        :return:
        """
        return RPDAllocateWriteRecord.indexDBPool.get(self.poolName)
