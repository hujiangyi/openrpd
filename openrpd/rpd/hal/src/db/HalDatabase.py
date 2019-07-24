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
import redis
from rpd.common.rpd_logging import AddLoggerToClass


class HalDatabase(object):

    """HalDatabase class provides the basic operation to redis server.

    All the message will be set with a specific timeout value.
    When the time expires, the message will be cleared by the redis
    automatically.

    Limitations:
    * HalDatabase is a single threaded design.

    """
    __metaclass__ = AddLoggerToClass

    def __init__(self, address, timeout, db=12):

        tcpConnection = False
        if isinstance(address, tuple) or isinstance(address, list):
            tcpAddr = address[0]
            tcpPort = address[1]
            tcpConnection = True
        else:  # unix domain socket case
            path = address

        # connect with Tcp
        if tcpConnection:
            self.redisConnection = redis.StrictRedis(
                host=tcpAddr, port=tcpPort, db=db)
        else:
            self.redisConnection = redis.StrictRedis(
                db=db, unix_socket_path=address)

        # set the expire info
        self.timeout = timeout

    def addMsgtoDB(self, msgKey, msg, expired=True):
        """Every msg will be stored in a hash table in redis. The msg here is a
        dict, which contain some information about the msg, such as the
        transaction info, the client info. Also, all the key info will stored
        in a list named "MsgInProcessSet".

        :param msgKey: the key of the message, constructed by the clientID+seq
        :param msg: basically the msg will contain the following info::
                    {
                        clientID: the client ID,
                        msg: the gpb encoded msg, the msg will resend to HAL for further process.
                    }
        :return:

        """
        if self.redisConnection.exists(msgKey):  # enlarge the timeout
            if expired:
                self.redisConnection.expire(msgKey, self.timeout)

        self.redisConnection.hmset(msgKey, msg)
        if expired:
            self.redisConnection.expire(msgKey, self.timeout)
        return

    def removeMsgFromDB(self, msgKey):
        """The reverse function for addMsgtoDB, first remove the key from
        MsgInProcessSet, and then remove the message.

        :param msgKey:
        :return:

        """
        self.redisConnection.delete(msgKey)

    def listAllMsgs(self, msgKey=None):
        """Get all the messages from the redis.

        :return:

        """
        if msgKey is None:
            keys = self.redisConnection.keys(pattern="*")

            if keys is None or len(keys) <= 0:
                self.logger.warn(
                    "Cannot find the keys in DB, do you have a valid connection to the DB?")
                return None

            ret = list()
            for key in keys:
                hkey = self.redisConnection.hgetall(key)
                if len(hkey) == 0:
                    continue
                hkey["Key"] = key
                ret.append(hkey)

            return ret
        else:
            keys = self.redisConnection.hgetall(msgKey)
            return keys

    def updateKeyExpire(self, msgKey):
        """Update a message expire time.

        :param msgKey: the key of the message, constructed by the cliendID+seq
        :return:

        """
        if self.redisConnection.exists(msgKey):  # enlarge the timeout
            self.redisConnection.expire(msgKey, self.timeout)

    def isDatabaseEmpty(self, msgKey=None):
        """Check if the database has contents for either a given msgKey or any
        key.

        :param: msgKey
        :return: boolean

        """
        if msgKey is None:
            keys = self.redisConnection.keys(pattern="*")
            if keys is None or len(keys) == 0:
                return True
        else:
            keysLen = self.redisConnection.hlen(msgKey)
            if keysLen <= 0:
                return True

        return False
