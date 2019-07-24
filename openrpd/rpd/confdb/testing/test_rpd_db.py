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

from google.protobuf.descriptor import FieldDescriptor
from protobuf_to_dict import Message
from rpd.gpb import cfg_pb2
from rpd.confdb.rpd_db import RPD_DB, DBKeyError, GPBHelpers
from rpd.gpb.db_pb2 import db
from rpd.gpb.RfChannel_pb2 import t_RfChannel
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities


@unittest.skip("FIXME skip testing the confdb, since it will replaced by redis db")
class TestDatabase(unittest.TestCase):

    def test_write_leaf(self):
        """Use set_val to write value to one leaf."""
        data = RPD_DB()
        path = ['oper', 'HwVersion']
        data.set_val(path, 'ver1.2.3')
        self.assertEqual(data.get_val(path), 'ver1.2.3')
        str1 = data.data.SerializeToString()

        db2 = RPD_DB(init_file=RPD_DB.DB_FNAME, load_all=True)
        str2 = db2.data.SerializeToString()
        self.assertEqual(str1, str2)

    def test_write_obj(self):
        """Fill GPB, set it to correct position and check value in DB."""
        data = RPD_DB()
        core = db.operational.t_CCAPCapabilities()
        core.is_principal = True
        core.ip_addr = '2.2.2.2'
        core.is_active = True
        data.set_val(['oper', 'CCAPCapabilities'], core)
        self.assertTrue(data.get_val(
            ['oper', 'CCAPCapabilities', '2.2.2.2', 'is_principal']))

    def test_write_invalid(self):
        """Set invalid value to valid path."""
        data = RPD_DB()
        with self.assertRaises(TypeError):
            data.set_val(['oper', 'CCAPCapabilities', 'is_active'], None)

    def test_db_reload(self):
        """Fill some data to DB, save, load DB content from file."""
        self.test_write_obj()

        # Create another DB instance to load values filled (& saved to file)
        db2 = RPD_DB(load_all=True, init_file=RPD_DB.DB_FNAME)
        path_to_bools = ['oper', 'CCAPCapabilities', '2.2.2.2']
        self.assertTrue(db2.get_val(path_to_bools + ['is_active']))

        # By default operational data are dropped during DB init
        db3 = RPD_DB(init_file=RPD_DB.DB_FNAME)
        self.assertIsNone(db3.get_val(path_to_bools + ['is_active']))

    def test_read_unset_leaf(self):
        """Read unset leaves, expected value is default."""
        data = RPD_DB()
        self.assertIsNone(data.get_val(['oper', 'HwVersion']))
        self.assertIsNone(data.get_val(['oper', 'CCAPCapabilities']))

    def test_del_valid(self):
        # Write on value and delete it
        data = RPD_DB()
        core = db.operational.t_CCAPCapabilities()
        core.is_principal = True
        core.ip_addr = '2.2.2.2'
        core.is_active = True
        data.set_val(['oper', 'CCAPCapabilities'], core)
        data.del_val(['oper', 'CCAPCapabilities', '2.2.2.2', 'is_active'])
        self.assertIsNone(
            data.get_val(['oper', 'CCAPCapabilities', 'is_active']))

    def test_del_unset(self):
        # Create one value and delete another value, which was not set
        data = RPD_DB()
        core = db.operational.t_CCAPCapabilities()
        core.is_principal = True
        core.ip_addr = '2.2.2.2'
        data.set_val(['oper', 'CCAPCapabilities'], core)
        data.del_val(['oper', 'CCAPCapabilities', '2.2.2.2', 'is_active'])
        self.assertIsNone(data.get_val(
            ['oper', 'CCAPCapabilities', '2.2.2.2', 'is_active']))
        self.assertTrue(data.get_val(
            ['oper', 'CCAPCapabilities', '2.2.2.2', 'is_principal']))

    def test_path_invalid(self):
        # Delete with wrong path
        data = RPD_DB()
        # If parent (oper) has no children, then exception is not raised,
        # because parent exists and we don't have reason to check children
        data.del_val(['oper', 'CCAPCapabilities', 'test'])
        self.assertIsNone(data.get_val(['oper', 'CCAPCapabilities', 'test']))
        core = db.operational.t_CCAPCapabilities()
        core.is_active = True
        core.ip_addr = '2.2.2.2'
        data.set_val(['oper', 'CCAPCapabilities'], core)
        # Deleting from repeated list, element, which does not exist
        data.del_val(['oper', 'CCAPCapabilities', 'test'])
        # Deleting from path, which is invalid
        with self.assertRaises(DBKeyError):
            data.del_val(['oper', 'test'])
        # Getting value from repeated list, path is valid
        data.del_val(['oper', 'CCAPCapabilities', 'test'])
        # Getting value from invalid path
        with self.assertRaises(DBKeyError):
            data.get_val(['oper', 'test'])
        with self.assertRaises(DBKeyError):
            data.set_val(['oper', 'CCAPCapabilities', 'test'], True)

    def test_db_malformed(self):
        """Create DB file, remove mandatory data and try to parse again."""
        data = RPD_DB()
        core = db.operational.t_CCAPCapabilities()
        core.is_active = True
        core.is_principal = True
        core.ip_addr = "1.1.1.1"
        data.set_val(['oper', 'CCAPCapabilities'], core)
        data.set_val(['cfg', 'RpdCapabilities', 'NumBdirPorts'], 5)
        # DB file is now ready with values filled

        # Remove oper keyword
        with open(data.DB_FNAME, 'r+') as db_file:
            lines = db_file.readlines()
            db_file.seek(0)
            for line in lines:
                if not line.strip().startswith('"oper"'):
                    db_file.write(line)
            db_file.truncate()
        # Try to parse malformed file -> load default values
        db2 = RPD_DB(load_all=True, init_file=data.DB_FNAME)

        # Check if malformed classes were removed
        self.assertIsNone(db2.get_val(
            ['oper', 'CCAPCapabilities', '1.1.1.1', 'is_active']))
        # Check if also other values (valid) values were dropped
        self.assertIsNone(
            db2.get_val(['cfg', 'RpdCapabilities', 'NumBdirPorts']))

    def test_db_file_update(self):
        """Insert/delete CCAPCores and check if DB file was updated."""
        data = RPD_DB()

        self.assertNotIn('is_active', open(data.DB_FNAME).read())
        core = db.operational.t_CCAPCapabilities()
        core.is_active = True
        core.ip_addr = "1.1.1.1"
        data.set_val(['oper', 'CCAPCapabilities'], core)
        self.assertIn('is_active', open(data.DB_FNAME).read())
        data.del_val(['oper', 'CCAPCapabilities', '1.1.1.1'])
        self.assertNotIn('is_active', open(data.DB_FNAME).read())

    def test_get_gpb_keys(self):
        """Check if function returns correct number of keys in GPB message."""
        data = db()
        data.cfg.RpdCapabilities.LcceChannelReachability.add()
        keys_cnt = len(GPBHelpers.get_child_keys(data.cfg.RpdCapabilities,
                                                 'LcceChannelReachability'))
        self.assertEqual(keys_cnt, 3)

    def test_repeated_check(self):
        data = db()
        self.assertTrue(GPBHelpers.is_child_repeated(data.cfg.RpdCapabilities,
                                                     'LcceChannelReachability'))
        self.assertFalse(GPBHelpers.is_child_repeated(data.cfg.RpdCapabilities,
                                                      'NumOneGeNsPorts'))

    def test_get_elm_from_repeated(self):
        """Get one element from repeated object by both - numeric, string idx"""
        data = RPD_DB()
        t = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t.EnetPortIndex = 5
        t.ChannelType = 2
        t.RfPortIndex = 7
        # Get element by numeric indices
        t2 = data.get_val(
            ['cfg', 'RpdCapabilities', 'LcceChannelReachability', 5, 2, 7])
        self.assertIs(t, t2)
        # Get element by string indices
        t3 = data.get_val(
            ['cfg', 'RpdCapabilities', 'LcceChannelReachability',
             '5', '2', '7'])
        self.assertIs(t, t3)

    def test_get_elm_from_repeated_list(self):
        """Get one element from repeated object list."""
        data = RPD_DB()
        t = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t.EnetPortIndex = 5
        t.ChannelType = 2
        t.RfPortIndex = 7

        # Completely different values
        t2 = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t2.EnetPortIndex = 4
        t2.ChannelType = 3
        t2.RfPortIndex = 5

        # One value difference
        t3 = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t3.EnetPortIndex = 5
        t3.ChannelType = 2
        t3.RfPortIndex = 6

        # Get element by numeric indices
        t_copy = data.get_val(
            ['cfg', 'RpdCapabilities', 'LcceChannelReachability', 5, 2, 7])
        self.assertIs(t, t_copy)
        t2_copy = data.get_val(
            ['cfg', 'RpdCapabilities', 'LcceChannelReachability', 4, 3, 5])
        self.assertIs(t2, t2_copy)
        t3_copy = data.get_val(
            ['cfg', 'RpdCapabilities', 'LcceChannelReachability', 5, 2, 6])
        self.assertIs(t3, t3_copy)

    def test_add_elm_to_repeated_list(self):
        """Add element to empty list and read it back."""
        data = RPD_DB()
        rep_obj = t_RpdCapabilities.t_LcceChannelReachability()
        rep_obj.EnetPortIndex = 5
        rep_obj.ChannelType = 4
        rep_obj.RfPortIndex = 3
        rep_obj.StartChannelIndex = 15

        data.set_val(['cfg', 'RpdCapabilities', 'LcceChannelReachability'],
                     [rep_obj])

        clone = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 4, 3])
        # Set val is doing deep copy, so object should not be same
        self.assertIsNot(rep_obj, clone)
        self.assertEqual(clone.StartChannelIndex, 15)
        self.assertEqual(
            len(data.data.cfg.RpdCapabilities.LcceChannelReachability), 1)

    def test_add_elm_to_not_empty_list(self):
        data = RPD_DB()
        t = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t.EnetPortIndex = 5
        t.ChannelType = 2
        t.RfPortIndex = 7

        t2 = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t2.EnetPortIndex = 4
        t2.ChannelType = 3
        t2.RfPortIndex = 5

        rep_obj = t_RpdCapabilities.t_LcceChannelReachability()
        rep_obj.EnetPortIndex = 5
        rep_obj.ChannelType = 4
        rep_obj.RfPortIndex = 3
        rep_obj.StartChannelIndex = 15

        data.set_val(['cfg', 'RpdCapabilities', 'LcceChannelReachability'],
                     [rep_obj])

        clone = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 4, 3])

        self.assertEqual(clone.StartChannelIndex, 15)
        self.assertEqual(clone.EnetPortIndex, 5)
        self.assertEqual(
            len(data.data.cfg.RpdCapabilities.LcceChannelReachability), 3)

    def test_add_more_elms_to_not_empty_list(self):
        data = RPD_DB()
        t = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t.EnetPortIndex = 5
        t.ChannelType = 2
        t.RfPortIndex = 7

        rep = t_RpdCapabilities.t_LcceChannelReachability()
        rep.EnetPortIndex = 5
        rep.ChannelType = 4
        rep.RfPortIndex = 3
        rep.StartChannelIndex = 15

        rep2 = t_RpdCapabilities.t_LcceChannelReachability()
        rep2.EnetPortIndex = 5
        rep2.ChannelType = 4
        rep2.RfPortIndex = 2

        data.set_val(['cfg', 'RpdCapabilities', 'LcceChannelReachability'],
                     [rep, rep2])

        clone = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 4, 3])
        self.assertEqual(clone.EnetPortIndex, 5)
        self.assertEqual(
            len(data.data.cfg.RpdCapabilities.LcceChannelReachability), 3)

    def test_update_repeated_elm(self):
        """Update element in repeated list."""
        data = RPD_DB()
        t = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t.EnetPortIndex = 5
        t.ChannelType = 2
        t.RfPortIndex = 7
        t.StartChannelIndex = 14
        t.EndChannelIndex = 20

        rep = t_RpdCapabilities.t_LcceChannelReachability()
        rep.EnetPortIndex = 5
        rep.ChannelType = 2
        rep.RfPortIndex = 7
        rep.StartChannelIndex = 15

        data.set_val(
            ['cfg', 'RpdCapabilities', 'LcceChannelReachability'], rep)

        value = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 2, 7,
                              'StartChannelIndex'])
        self.assertEqual(value, 15)
        # Repeated element is replaced, not merged => value should be dropped
        value = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 2, 7,
                              'EndChannelIndex'])
        self.assertIsNone(value)
        self.assertEqual(
            len(data.data.cfg.RpdCapabilities.LcceChannelReachability), 1)

    def test_get_repeated_invalid(self):
        data = RPD_DB()
        t = data.data.cfg.RpdCapabilities.LcceChannelReachability.add()
        t.EnetPortIndex = 5
        t.ChannelType = 2
        t.RfPortIndex = 7
        t.StartChannelIndex = 14

        value = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 2, 8,
                              'StartChannelIndex'])

        self.assertIsNone(value)

        with self.assertRaises(DBKeyError):
            data.get_val(['cfg', 'RpdCapabilities',
                          'LcceChannelReachability', 5, 2, 7,
                          'test'])

        value = data.get_val(['cfg', 'RpdCapabilities',
                              'LcceChannelReachability', 5, 2, 8])

        self.assertIsNone(value)

    def _create_repeated_list(self, data):
        d1 = data.data.cfg.DsOfdmProfile.add()
        d1.ProfileId = 1
        d11 = d1.DsOfdmSubcarrierModulation.add()
        d11.StartSubcarrierId = 11
        d11.EndSubcarrierId = 11
        d11.Modulation = 1
        d2 = data.data.cfg.DsOfdmProfile.add()
        d2.ProfileId = 2
        d21 = d2.DsOfdmSubcarrierModulation.add()
        d21.StartSubcarrierId = 21
        d21.EndSubcarrierId = 21
        d21.Modulation = 2
        d22 = d2.DsOfdmSubcarrierModulation.add()
        d22.StartSubcarrierId = 22
        d22.EndSubcarrierId = 22
        d22.Modulation = 3

    def test_two_repeated_in_path(self):
        """Check functionality with path + key + path + key + path."""
        data = RPD_DB()
        self._create_repeated_list(data)

        # Check if values are really here
        value = data.get_val(['cfg', 'DsOfdmProfile', 1,
                              'DsOfdmSubcarrierModulation', 11, 'Modulation'])
        self.assertEqual(value, 1)
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation', 21])
        self.assertEqual(value.Modulation, 2)

        # Add next value to second level repeated list
        rep = cfg_pb2.config.t_DsOfdmProfile. \
            t_DsOfdmSubcarrierModulation()
        rep.StartSubcarrierId = 23
        rep.EndSubcarrierId = 23
        rep.Modulation = 4
        data.set_val(['cfg', 'DsOfdmProfile', 2, 'DsOfdmSubcarrierModulation'],
                     [rep])
        # Check if value was inserted to right place
        self.assertEqual(len(data.data.cfg.DsOfdmProfile), 2)
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'])
        self.assertEqual(len(value), 3)

        # Update one from original values
        rep = cfg_pb2.config.t_DsOfdmProfile. \
            t_DsOfdmSubcarrierModulation()
        rep.StartSubcarrierId = 21
        rep.EndSubcarrierId = 21
        rep.Modulation = 5
        data.set_val(['cfg', 'DsOfdmProfile', 2, 'DsOfdmSubcarrierModulation'],
                     [rep])

        # Check if update was successful
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'])
        self.assertEqual(len(value), 3)

        # Update changed values from 2,3,4 to 3,4,5, because first element was
        # deleted and new one was appended to end of the list
        self.assertListEqual([x.Modulation for x in value], [3, 4, 5])

    def test_delete_repeated(self):
        """Delete repeated object & leaves in it."""
        data = RPD_DB()
        self._create_repeated_list(data)

        # Delete leaf
        data.del_val(['cfg', 'DsOfdmProfile', 2,
                      'DsOfdmSubcarrierModulation', 21, 'Modulation'])

        self.assertIsNone(data.get_val(
            ['cfg', 'DsOfdmProfile', 2, 'DsOfdmSubcarrierModulation',
             21, 'Modulation']))
        self.assertIsNotNone(data.get_val(
            ['cfg', 'DsOfdmProfile', 2, 'DsOfdmSubcarrierModulation', 21]))

        # Delete key leaf => forbidden
        with self.assertRaises(DBKeyError):
            data.del_val(['cfg', 'DsOfdmProfile', 1,
                          'DsOfdmSubcarrierModulation', 11, 'StartSubcarrierId'])

        # Delete last (one) element from repeated list
        data.del_val(['cfg', 'DsOfdmProfile', 1,
                      'DsOfdmSubcarrierModulation', 11])
        value = data.get_val(['cfg', 'DsOfdmProfile', 1,
                              'DsOfdmSubcarrierModulation'])
        self.assertIsNone(value)

        # Delete list of elements
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'])
        self.assertEqual(len(value), 2)
        data.del_val(['cfg', 'DsOfdmProfile', 2,
                      'DsOfdmSubcarrierModulation'])
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'])
        self.assertIsNone(value)

        # Delete config
        data.del_val(['cfg'])
        value = data.get_val(['cfg'])
        self.assertIsNone(value)

    def _create_filled_cfg(self):
        c = cfg_pb2.config()
        d1 = c.DsOfdmProfile.add()
        d1.ProfileId = 1
        d11 = d1.DsOfdmSubcarrierModulation.add()
        d11.StartSubcarrierId = 11
        d11.EndSubcarrierId = 11
        d11.Modulation = 1
        d2 = c.DsOfdmProfile.add()
        d2.ProfileId = 2
        d21 = d2.DsOfdmSubcarrierModulation.add()
        d21.StartSubcarrierId = 21
        d21.EndSubcarrierId = 21
        d21.Modulation = 2
        d22 = d2.DsOfdmSubcarrierModulation.add()
        d22.StartSubcarrierId = 22
        d22.EndSubcarrierId = 22
        d22.Modulation = 3
        return c

    def test_trees_merge_to_empty(self):
        data = RPD_DB()
        data.data.Clear()
        c = self._create_filled_cfg()

        # Merge and check if DB content is same as inserted object
        data.merge_from_tree(['cfg'], c)
        str1 = data.data.cfg.SerializeToString()
        str2 = c.SerializeToString()
        self.assertEqual(str1, str2)

    def test_trees_merge_no_conflicts(self):
        data = RPD_DB()
        data.data.Clear()
        c = self._create_filled_cfg()

        # Add one element, merge again and check if value was not overwritten
        data.data.cfg.RpdCapabilities.NumBdirPorts = 5
        data.merge_from_tree(['cfg'], c)
        str1 = data.data.cfg.SerializeToString()
        str2 = c.SerializeToString()
        self.assertNotEqual(str1, str2)
        self.assertEqual(
            data.get_val(['cfg', 'RpdCapabilities', 'NumBdirPorts']), 5)
        # Delete additional item, check if buffers are same now
        data.del_val(['cfg', 'RpdCapabilities', 'NumBdirPorts'])
        str1 = data.data.cfg.SerializeToString()
        self.assertEqual(str1, str2)

    def test_trees_merge_conflict(self):
        data = RPD_DB()

        caps = t_RpdCapabilities()
        caps.NumBdirPorts = 5
        caps.NumDsRfPorts = 6

        data.set_val(['cfg', 'RpdCapabilities'], caps)

        # Create second instance with conflict
        caps2 = t_RpdCapabilities()
        caps2.NumDsRfPorts = 7
        caps2.NumTenGeNsPorts = 8

        # Merge tree to DB
        data.merge_from_tree(['cfg', 'RpdCapabilities'], caps2)

        value = data.get_val(['cfg', 'RpdCapabilities'])
        self.assertEqual(value.NumBdirPorts, 5)
        self.assertEqual(value.NumDsRfPorts, 7)
        self.assertEqual(value.NumTenGeNsPorts, 8)
        self.assertEqual(len(value.ListFields()), 3)

    def test_trees_merge_repeated_no_conflict(self):
        data = RPD_DB()
        c = self._create_filled_cfg()
        data.set_val(['cfg'], c)

        # DB is prepared, create another copy with added element on level 1
        c2 = self._create_filled_cfg()
        d3 = c2.DsOfdmProfile.add()
        d3.ProfileId = 4
        d11 = d3.DsOfdmSubcarrierModulation.add()
        d11.StartSubcarrierId = 15
        d11.EndSubcarrierId = 15
        d11.Modulation = 6

        data.merge_from_tree(['cfg'], c2)

        value = data.get_val(['cfg', 'DsOfdmProfile'])
        self.assertEqual(len(value), 3)
        self.assertListEqual([x.ProfileId for x in value], [1, 2, 4])

    def test_trees_merge_two_levels(self):
        data = RPD_DB()
        c = self._create_filled_cfg()
        data.set_val(['cfg'], c)

        c2 = cfg_pb2.config()
        d1 = c2.DsOfdmProfile.add()
        d1.ProfileId = 1
        # Add another subcarrier under existing profileId
        d11 = d1.DsOfdmSubcarrierModulation.add()
        d11.StartSubcarrierId = 12
        d11.EndSubcarrierId = 12
        d11.Modulation = 1
        # Change leaf which is not leaf
        d2 = c2.DsOfdmProfile.add()
        d2.ProfileId = 2
        d21 = d2.DsOfdmSubcarrierModulation.add()
        d21.StartSubcarrierId = 21
        d21.EndSubcarrierId = 21
        d21.Modulation = 3

        data.merge_from_tree(['cfg'], c2)
        value = data.get_val(['cfg', 'DsOfdmProfile'])
        self.assertEqual(len(value), 2)
        value = data.get_val(['cfg', 'DsOfdmProfile', 1,
                              'DsOfdmSubcarrierModulation'])
        self.assertListEqual([x.StartSubcarrierId for x in value], [11, 12])
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'])
        # One from two subcarriers specified - check if second was not removed
        self.assertEqual(len(value), 2)
        self.assertListEqual([x.Modulation for x in value], [3, 3])

    def test_tree_del_leaf(self):
        data = RPD_DB()
        data.data.Clear()
        data.data.cfg.RpdCapabilities.NumBdirPorts = 5
        data.data.cfg.RpdCapabilities.NumDsRfPorts = 2

        data.del_tree({'cfg': {'RpdCapabilities': {'NumBdirPorts': None}}})
        value = data.get_val(['cfg', 'RpdCapabilities'])
        self.assertEqual(len(value.ListFields()), 1)
        self.assertIsNone(
            data.get_val(['cfg', 'RpdCapabilities', 'NumBdirPorts']))
        self.assertEqual(
            data.get_val(['cfg', 'RpdCapabilities', 'NumDsRfPorts']), 2)

    def test_tree_del_container(self):
        data = RPD_DB()
        data.data.cfg.RpdCapabilities.NumBdirPorts = 5
        data.data.cfg.DsScQamChannelConfig.PowerAdjust = 2

        data.del_tree({'cfg': {'DsScQamChannelConfig': None}})
        value = data.get_val(['cfg', 'DsScQamChannelConfig'])
        self.assertIsNone(value)
        value = data.get_val(['cfg'])
        # RpdCapabilities subtree should stay here
        self.assertEqual(len(value.ListFields()), 1)

    def test_tree_del_more_values(self):
        data = RPD_DB()
        data.data.Clear()
        data.data.cfg.RpdCapabilities.NumBdirPorts = 5
        data.data.cfg.DsScQamChannelConfig.PowerAdjust = 2
        data.data.cfg.RpdCapabilities.NumDsRfPorts = 4
        data.del_tree({
            'cfg': {
                'DsScQamChannelConfig': {
                    'PowerAdjust': None
                },
                'RpdCapabilities': {
                    'NumDsRfPorts': None
                }
            }
        })
        value = data.get_val(['cfg'])
        self.assertEqual(len(value.ListFields()), 1)
        value = data.get_val(['cfg', 'RpdCapabilities'])
        self.assertEqual(len(value.ListFields()), 1)

    def test_tree_del_repeated_one_key(self):
        data = RPD_DB()
        data.data.Clear()
        self._create_repeated_list(data)
        data.del_tree({
            'cfg': {
                'DsOfdmProfile': {
                    2: {
                        'DsOfdmSubcarrierModulation': {
                            21: None
                        }
                    }
                }
            }
        })
        value = data.get_val(['cfg'])
        self.assertEqual(len(value.ListFields()), 1)
        value = data.get_val(['cfg', 'DsOfdmProfile'])
        self.assertEqual(len(value), 2)
        value = data.get_val(['cfg', 'DsOfdmProfile', 1,
                              'DsOfdmSubcarrierModulation'])
        self.assertEqual(len(value), 1)
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'])
        self.assertListEqual([x.StartSubcarrierId for x in value], [22])

    def test_tree_del_repeated_all_elms(self):
        data = RPD_DB()
        data.data.Clear()
        self._create_repeated_list(data)
        data.del_tree({
            'cfg': {
                'DsOfdmProfile': {
                    2: None,
                    1: None
                }
            }
        })
        value = data.get_val(['cfg'])
        self.assertIsNone(value)

    def test_fill_trees_one_repeated(self):
        data = RPD_DB()
        self._create_repeated_list(data)
        ret = data.fill_tree({
            'cfg': {
                'DsOfdmProfile': {
                    2: None
                }
            }
        })
        self.assertIsInstance(ret, db)
        # Use get_val to extract profiles from returned object
        value = data.get_val(['cfg', 'DsOfdmProfile'], ret)
        self.assertEqual(len(value), 1)
        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'], ret)
        self.assertEqual(len(value), 2)

    def test_fill_trees_list_and_leaf(self):
        data = RPD_DB()
        self._create_repeated_list(data)
        data.data.cfg.RpdCapabilities.NumBdirPorts = 5
        data.data.cfg.RpdCapabilities.NumTenGeNsPorts = 14
        ret = data.fill_tree({
            'cfg': {
                'DsOfdmProfile': None,
                'RpdCapabilities': {
                    'NumTenGeNsPorts': None
                }
            }
        })
        # Reuse get_val to extract profiles from returned object
        value = data.get_val(['cfg', 'DsOfdmProfile'], ret)
        self.assertEqual(len(value), 2)
        self.assertListEqual([x.ProfileId for x in value], [1, 2])

        value = data.get_val(['cfg', 'DsOfdmProfile', 2,
                              'DsOfdmSubcarrierModulation'], ret)
        self.assertEqual(len(value), 2)
        value = data.get_val(['cfg', 'RpdCapabilities'], ret)
        self.assertEqual(len(value.ListFields()), 1)
        self.assertEqual(value.NumTenGeNsPorts, 14)

    def test_fill_trees_from_empty_db(self):
        data = RPD_DB()
        data.data.Clear()
        ret = data.fill_tree({
            'cfg': {
                'DsOfdmProfile': None,
                'RpdCapabilities': {
                    'NumTenGeNsPorts': None
                }
            }
        })
        self.assertEqual(len(ret.ListFields()), 0)

    def test_fill_trees_invalid_path(self):
        data = RPD_DB()
        # If DB is empty, we will return before detecting invalid path
        self._create_repeated_list(data)
        # Get value from 'test' path
        with self.assertRaises(DBKeyError):
            data.fill_tree({
                'cfg': {
                    'test': None,
                    'RpdCapabilities': {
                        'NumTenGeNsPorts': None
                    }
                }
            })

    def test_fill_trees_unset_obj_from_filled_db(self):
        data = RPD_DB()
        self._create_repeated_list(data)
        ret = data.fill_tree({
            'cfg': {
                'RpdCapabilities': {
                    'NumTenGeNsPorts': None
                }
            }
        })
        self.assertEqual(len(ret.ListFields()), 0)

    @staticmethod
    def _walk_obj_and_fill_leafs(obj, string_val, int_val, uint_val, enum_idx,
                                 bool_val, elements_count):
        type_to_val_map = {FieldDescriptor.TYPE_STRING: string_val,
                           FieldDescriptor.TYPE_BOOL: bool_val,
                           FieldDescriptor.TYPE_INT32: int_val,
                           FieldDescriptor.TYPE_INT64: int_val,
                           FieldDescriptor.TYPE_UINT32: uint_val,
                           FieldDescriptor.TYPE_UINT64: uint_val}
        special_values = {'DeviceMacAddress': '11:11:22:22:33:33',
                          'SyncMacAddress': '11:11:22:22:33:33',
                          'CcapCoreOwner': '11:11:22:22:33:33',
                          'RpdMacAddress': '11:11:22:22:33:33',
                          'PhysAddress': '11:11:22:22:33:33',
                          'ifPhysAddress': '11:11:22:22:33:33',
                          'SsdServerAddress':
                          'ABAA:CDAA:AAAA:AAAA:AAAA:AAAA:AAAA:AA01',
                          'CoreIpAddress': '1.2.3.4',
                          'SerialNumber': '1234567890',
                          'FecCodewordLength': 20,
                          'MinislotPilotPattern': 5,
                          'NumSymbolsPerFrame': 10,
                          'Code': 10,
                          'TimeInterleaverDepth': 10,
                          'NumSubcarriers': 10,
                          'SyncInterval': 10,
                          'UsBurstReceiverModelNumber': 'Model:A',
                          'UsBurstReceiverDriverVersion': 'Driver:B',
                          'UsBurstReceiverSerialNumber': 'SN:123',
                          'RpdRcpProtocolVersion': 'Proto:RCP',
                          'RpdRcpSchemaVersion': 'Schema:1.0',
                          'UsBurstReceiverVendorId': 'AB',
                          'GeoLocationLatitude': '-750015.1',
                          'GeoLocationLongitude': '-0100015.1',
                          'RedirectIpAddress': '1.2.3.4',
                          'ControlAddress': '1.2.3.4',
                          'RpdLcceIpAddress': '1.2.3.4',
                          'RemoteLcceIpAddr': '1.2.3.4',
                          'RouterIpAddress': '1.2.3.4',
                          'NetAddress': '1.2.3.4'
                          }

        if isinstance(obj, Message):
            for field in obj.DESCRIPTOR.fields:
                # Message + repeated
                if field.type == field.TYPE_MESSAGE:
                    if field.name == "RpdRedirect":
                        continue
                    if field.name == "CcapCoreIdentification":
                        continue
                    TestDatabase._walk_obj_and_fill_leafs(
                        getattr(
                            obj, field.name), string_val, int_val, uint_val,
                        enum_idx, bool_val, elements_count)
                # Fill leafs
                elif field.type in type_to_val_map:
                    # Hack to fill special values
                    if field.name in special_values:
                        setattr(obj, field.name, special_values[field.name])
                    elif field.name == 'VendorId' and\
                            field.type == field.TYPE_STRING:
                        setattr(obj, field.name, 'FF')
                    elif field.name == 'Index':
                        # The Index in CCAP ID will be 1, so
                        # it will overwrite the CCAP ID from the session
                        # initiation
                        setattr(obj, field.name, 1)
                    else:
                        setattr(obj, field.name, type_to_val_map[field.type])

                elif field.type == field.TYPE_ENUM:
                    enum_idx %= len(field.enum_type.values)
                    setattr(obj, field.name,
                            field.enum_type.values[enum_idx].number)
        # Is it repeated object?
        elif hasattr(obj, 'add'):
            for i in xrange(elements_count):
                added_elm = obj.add()
                TestDatabase._walk_obj_and_fill_leafs(added_elm, string_val,
                                                      int_val +
                                                      i, uint_val + i,
                                                      enum_idx + i, bool_val,
                                                      elements_count)

    @staticmethod
    def _generate_full_cfg(element_count, str_len):
        from random import choice
        from string import lowercase

        long_string = "".join(choice(lowercase) for _ in range(str_len))
        # These values will be modified for repeated elements
        int_val = 0
        uint_val = 0
        enum_val_idx = 0  # first item
        bool_val = True
        # Element count can be max 7 -> we are not able to generate more unique
        # IDs for UsOfdmaDataRangingIuc (index is enum)
        if element_count > 7:
            raise ValueError("Max count of repeated elements is 7")

        conf = cfg_pb2.config()
        TestDatabase._walk_obj_and_fill_leafs(conf, long_string, int_val,
                                              uint_val, enum_val_idx, bool_val,
                                              element_count)
        return conf

    def test_get_val_on_path(self):
        testing_cfg = TestDatabase._generate_full_cfg(3, 5)
        val_cfg = GPBHelpers.get_val_on_path(['cfg'], testing_cfg)
        self.assertIsNotNone(val_cfg)

        val_cfg = GPBHelpers.get_val_on_path(
            ['cfg', 'RpdCapabilities'],
            testing_cfg)
        self.assertIsNotNone(val_cfg)

        val_cfg = GPBHelpers.get_val_on_path(
            ['cfg', 'RpdCapabilities', 'AllocDsChanResources'],
            testing_cfg)
        self.assertIsNotNone(val_cfg)

        val_cfg = GPBHelpers.get_val_on_path(
            ['cfg', 'RpdCapabilities', 'AllocDsChanResources', '6'],
            testing_cfg)
        self.assertIsNotNone(val_cfg)
        self.assertEqual(val_cfg.DsPortIndex, 6)

        val_cfg = GPBHelpers.get_val_on_path(
            ['cfg', 'RpdCapabilities', 'AllocDsChanResources',
             '6', 'AllocatedDsOfdmChannels'],
            testing_cfg)
        self.assertIsNotNone(val_cfg)
        self.assertEqual(val_cfg, 6)


if __name__ == "__main__":
    unittest.main()
