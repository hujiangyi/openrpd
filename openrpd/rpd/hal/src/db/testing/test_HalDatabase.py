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
from rpd.hal.src.db.HalDatabase import HalDatabase
import uuid
import redis
import subprocess
import time
import os

timeStampSock = "/tmp/testHalDbRedis" + \
    time.strftime("%d%H%M%S", time.localtime()) + ".sock"


def setupDB():
    global timeStampSock
    cmd = "redis-server --version"
    output = subprocess.check_output(cmd.split(" "))
    if output.find("Redis") < 0:
        raise Exception("Cannot find redis installation")

    # start a redis server
    configurefileContent = "daemonize  yes \nport 0 \nunixsocket " + \
        timeStampSock + " \nunixsocketperm 700\n"
    configurefileContentLocal = "daemonize  yes \nport 6379 \nbind 127.0.0.1 \n"
    filename = "/tmp/test_haldb.conf"
    with open(filename, "w") as f:
        f.write(configurefileContent)

    subprocess.call(["redis-server", filename])
    with open(filename, "w") as f:
        f.write(configurefileContentLocal)

    subprocess.call(["redis-server", filename])

    timeOut = time.time() + 5
    while time.time() < timeOut:
        if os.path.exists(timeStampSock):
            break
        time.sleep(1)

    if time.time() > timeOut:
        raise Exception("Cannot setup the redis")


class TestHalDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setupDB()

    @classmethod
    def tearDownClass(cls):
        subprocess.call(["killall", "redis-server"])
        time.sleep(2)

    def setUp(self):
        global timeStampSock
        # start the redes
        self.halDb = HalDatabase(timeStampSock, 1, 0)
        self.r = redis.StrictRedis(db=0, unix_socket_path=timeStampSock)

    def tearDown(self):
        self.r.flushdb()

    def test_tcpSetup(self):
        """test clear up DB.

        :keyword:
        :exception:
        :parameter:
        :return:

        """
        self.halTcpDb = HalDatabase(["127.0.0.1", "6379"], 1, 0)
        self.r2 = redis.StrictRedis(host="127.0.0.1", port=6379, db=0)
        time.sleep(1)
        self.r2.flushdb()

    def test_addMsgtoDB(self):
        """test HalDatabase#addMsgtoDB.

        check whether the message can be added
        to the DB, if not case fail

        check whether the message clear up after
        timeout, if not case fail.

        :keyword:HalDatabase#addMsgtoDB
        :exception:assertEqual(val, msg),
                   assertEqual(len(val), 0)
        :parameter:
        :return:

        """
        msgKey = str(uuid.uuid4())
        msg = {
            "ClientID": msgKey,
            "msg": "hello, world"
        }

        self.halDb.addMsgtoDB(msgKey, msg)

        # Get from the redis and check the result

        val = self.r.hgetall(msgKey)

        self.assertEqual(val, msg)

        self.halDb.addMsgtoDB(msgKey=msgKey, msg=msg, expired=True)
        import time

        time.sleep(self.halDb.timeout + 0.1)

        val = self.r.hgetall(msgKey)

        self.assertEqual(len(val), 0)

        self.r.flushdb()  # remove all the data

    def test_removeMsgFromDB(self):
        """test HalDatabase#removeMsgFromDB, check whether the message can be
        removed from the DB, if not case fail.

        :keyword:HalDatabase#removeMsgFromDB
        :exception:assertFalse(self.r.exists(msgKey))
        :parameter:
        :return:

        """
        msgKey = str(uuid.uuid4())
        msg = {
            "ClientID": msgKey,
            "Msg": "hello, world"
        }

        self.halDb.addMsgtoDB(msgKey, msg)

        # remove it
        self.halDb.removeMsgFromDB(msgKey)

        # check the keys
        self.assertFalse(self.r.exists(msgKey))

    def test_isDatabaseEmpty(self):
        """test HalDatabase#isDatabaseEmpty, check whether the DB message
        exists after add to DB or remove from DB, if not case fail.

        :keyword:HalDatabase#isDatabaseEmpty
        :exception:assertTrue(self.halDb.isDatabaseEmpty(msgKey)),
                   assertTrue(self.halDb.isDatabaseEmpty())
        :parameter:
        :return:

        """
        msgKey = str(uuid.uuid4())
        msg = {
            "ClientID": msgKey,
            "msg": "hello, world"
        }

        self.assertTrue(self.halDb.isDatabaseEmpty(msgKey))

        self.halDb.addMsgtoDB(msgKey, msg)

        self.assertFalse(self.halDb.isDatabaseEmpty(msgKey))
        self.assertFalse(self.halDb.isDatabaseEmpty())

        self.halDb.removeMsgFromDB(msgKey)
        self.assertTrue(self.halDb.isDatabaseEmpty())

    def test_listAllkeys(self):
        """test HalDatabase#listAllkeys, check whether the DB message key
        exists after add to DB or clear up from DB, if not case fail.

        :keyword:HalDatabase#listAllkeys
        :exception:assertEqual(all[key], msg),
                   assertIsNone(msg)
        :parameter:
        :return:

        """
        self.r.flushdb()
        msgKey1 = str(uuid.uuid4())
        msg1 = {
            "ClientID": msgKey1,
            "msg": "hello, world"
        }

        msgKey2 = str(uuid.uuid4())
        msg2 = {
            "ClientID": msgKey2,
            "msg": "hello, world"
        }
        self.halDb.addMsgtoDB(msgKey1, msg1)
        self.halDb.addMsgtoDB(msgKey2, msg2)

        all = self.halDb.listAllMsgs()

        for key in all:
            if key == msgKey1:
                self.assertEqual(all[key], msg1)
            if key == msgKey2:
                self.assertEqual(all[key], msg2)

        msg = self.halDb.listAllMsgs(msgKey1)

        self.assertEqual(msg, msg1)
        self.r.flushdb()

        msg = self.halDb.listAllMsgs()

        self.assertIsNone(msg)

    def test_updateKey(self):
        """test HalDatabase#updateKeyExpire, Update a message expire time, if
        throw exception case fail.

        :keyword:HalDatabase#updateKeyExpire
        :exception:assertIsNone(str(e))
        :parameter:
        :return:

        """
        msgKey1 = str(uuid.uuid4())
        msg1 = {
            "ClientID": msgKey1,
            "msg": "hello, world"
        }

        self.halDb.addMsgtoDB(msgKey1, msg1)
        try:
            self.halDb.updateKeyExpire(msgKey1 * 2)
            self.halDb.updateKeyExpire(msgKey1)
        except Exception as e:
            self.assertIsNone(str(e))

if __name__ == '__main__':
    unittest.main()
