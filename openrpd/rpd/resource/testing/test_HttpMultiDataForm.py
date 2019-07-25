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
import unittest
from rpd.common.rpd_logging import AddLoggerToClass
from rpd.resource.src.HttpMultiDataForm import MultiDataForm


class testRpdInfoHalClient(unittest.TestCase):

    __metaclass__ = AddLoggerToClass

    def setUp(self):
        self.multiDataForm = MultiDataForm()
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_get_content_type(self):
        self.logger.info("test_get_content_type")
        type = self.multiDataForm.get_content_type()
        self.assertTrue(len(type) > 0)

    def test_add_field(self):
        self.logger.info("test_add_field")
        self.multiDataForm.add_field("value", "value1")
        self.assertTrue(len(self.multiDataForm.form_fields) > 0)

    def test_add_file(self):
        self.logger.info("test_add_file")
        file_object = open('/tmp/111.log', 'a+')
        file_object.write("test11")
        self.multiDataForm.add_file('file', '111.log', file_object)
        body = str(self.multiDataForm)
        self.assertTrue(len(body) > 0)


if __name__ == '__main__':
    unittest.main()
