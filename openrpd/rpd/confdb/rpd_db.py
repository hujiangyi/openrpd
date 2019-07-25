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

#
# DB for the RPD manager process
#
import json
from os.path import exists
from os import access, R_OK
from collections import Iterable
from types import NoneType

from protobuf_to_dict import protobuf_to_dict, dict_to_protobuf, Message
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.text_format import MessageToString

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.gpb.db_pb2 import db
from rpd.common.proto_generator import ProtoGenerator


class DBKeyError(KeyError):
    pass


class DBSerializer(json.JSONEncoder):
    """JSON encoder/decoder extensions to allow serialization of GPB
    classes."""

    def default(self, obj):
        # All classes should be instances of GPB message
        if isinstance(obj, Message):
            return protobuf_to_dict(obj)
        return json.JSONEncoder.default(self, obj)


class RPD_DB(object):
    """Database to store config and operational data."""
    DB_FNAME = '/tmp/rpd.db'
    DB_INIT_FNAME = '/etc/config/rpd_init.conf'

    __metaclass__ = AddLoggerToClass

    def __init__(self, load_all=False, init_file=DB_INIT_FNAME):
        init_data = None
        if exists(init_file) and access(init_file, R_OK):
            try:
                with open(init_file) as f:
                    tmp = json.load(f)
                    if tmp is not None and 'data' in tmp:
                        init_data = dict_to_protobuf(db, tmp['data'])
            except EnvironmentError:
                self.logger.debug("DB file does not exist, creating new ...")
            except (ValueError, KeyError):
                self.logger.warning("Wrong format of DB file, ignoring ...")
        if init_data:
            self.data = init_data
            if not load_all:
                self.data.oper.Clear()
        else:
            self.data = db()
        self.dump()

    def dump(self, db_file=DB_FNAME):
        """Dump DB content to "configuration" file in JSON format.

        :param string db_file: Absolute path to output file
        :return:

        """
        try:
            f = open(db_file, 'w')
        except (OSError, IOError) as e:
            self.logger.error("Failed to open DB file: %s", e.strerror)
            return

        json.dump(self.__dict__, f, indent=4, sort_keys=True, cls=DBSerializer)
        f.close()

    def get_val(self, paths, src_gpb=None):
        """Get message or value from specific path in GPB message.

        :param paths: path to object to be extracted, for example:

         ['oper', 'HwVersion'], if multiple instances of same message can be
         stored, then instance is identified by one or more keys,
         key value can be string or integer,
         all required fields in GPB message are keys, for example:

         ['oper', 'CCAPCapabilities', '1.1.1.1', 'is_principal'], where '1.1.1.1'
         is key for CCAPCapabilities (required field)
        :type paths: list of strings
        :param src_gpb: optional argument, if not provided database
         GPB structure is used
        :type src_gpb: google.protobuf.message.Message
        :return: object (GPB message, string, int) found on specified path
         or None, when object is not filled
        :raises DBKeyError: path does not exist (missing keys,
         invalid attribute name, unexpected attribute names,..)
        :raises TypeError: type of arguments is incorrect

        """
        if type(paths) is not list or len(paths) == 0:
            raise TypeError("Path to object in invalid format")
        if not isinstance(src_gpb, (Message, NoneType)):
            raise TypeError("Src object must be GPBmessage or None, but is %s" %
                            type(src_gpb))
        obj = self.data if src_gpb is None else src_gpb
        path_iter = iter(paths)
        for path in path_iter:
            # Path does not exist
            if not hasattr(obj, path):
                raise DBKeyError("Key not found: %s" % path)
            if GPBHelpers.is_child_repeated(obj, path):
                # Need to match keys in path with keys in elements
                rep_list = getattr(obj, path)
                # Getting all elements from repeated list
                if path == paths[-1]:
                    return rep_list if len(rep_list) > 0 else None
                keys = GPBHelpers.get_child_keys(obj, path)
                # Get keys from path
                key_vals = []
                try:
                    for key in keys:
                        key_vals.append(next(path_iter))
                        # Update path to store last processed path element
                        if key == keys[-1]:
                            path = key_vals[-1]
                except StopIteration:
                    raise DBKeyError("Keys missing in path")
                child = GPBHelpers.get_child_from_repeated(rep_list, keys,
                                                           key_vals)
                # No element was found matching keys passed in path
                if None is child:
                    return None
            else:
                # Object is not filled
                if not obj.HasField(path):
                    return None
                child = getattr(obj, path)
            # Leaf found
            if not isinstance(child, Message):
                if path != paths[-1]:
                    raise DBKeyError("Unexpected elements in path found")
                return child
            obj = child
        return obj

    def set_val(self, paths, value, merge=False):
        """Set message or value to specific path to DB.

        :param paths: path to object to be set, for more info see get_val
        :type paths: list of strings
        :param value: value to be set to location specified by path
        :type value: GPB message, string or int
        :param bool merge:
         False = if value on path already exists, then it's replaced by new value

         True = value is merged with original value, in case of conflicts old
         value is replaced

         Repeated object elements are always appended to existing list, remove of
         existing values is possible only using delete operation
        :return:
        :raises DBKeyError: path does not exist (missing keys,
         invalid attribute name, unexpected attribute names,..)
        :raises TypeError: type of arguments is incorrect
        :raises ValueError: invalid operation - setting key value,
         mandatory fields are not set (keys)

        """
        if type(paths) is not list or len(paths) == 0 or value is None:
            raise TypeError("Invalid argument")
        path = None
        obj = self.data
        setting_leaf = False
        path_iter = iter(paths)
        for path in path_iter:
            if not hasattr(obj, path):
                raise DBKeyError("Key not found: %s" % path)
            if GPBHelpers.is_child_repeated(obj, path):
                # Need to match keys in path with keys in elements
                rep_list = getattr(obj, path)
                keys = GPBHelpers.get_child_keys(obj, path)
                # Setting to repeated list => append values to existing list
                if path == paths[-1]:
                    if not isinstance(value, Iterable):
                        value = [value]
                    # Replace operation -> delete conflicts, add new values
                    conflicts = GPBHelpers.find_repeated_conflicts(rep_list,
                                                                   value, keys)
                    for orig, insert in conflicts:
                        rep_list.remove(orig)
                    rep_list.extend(value)
                    self.dump()
                    return
                # Get keys from path
                key_vals = []
                try:
                    for key in keys:
                        key_vals.append(next(path_iter))
                        # Update path to store last processed path element
                        if key == keys[-1]:
                            path = key_vals[-1]
                except StopIteration:
                    raise DBKeyError("Keys missing in path")
                child = GPBHelpers.get_child_from_repeated(rep_list, keys,
                                                           key_vals)
                if None is child:
                    raise DBKeyError("Child specified in path does not "
                                     "exist - key values %s" % key_vals)
            else:
                child = getattr(obj, path)
            if not isinstance(child, Message):
                if path != paths[-1]:
                    raise DBKeyError("Unexpected elements in path found")
                setting_leaf = True
                break
            obj = child
        if setting_leaf:
            # Leaf assignment
            if GPBHelpers.is_child_key(obj, path):
                raise ValueError(
                    "Setting keys directly is forbiden: %s" % path)
            setattr(obj, path, value)
        else:
            # Message assignment
            if not value.IsInitialized():
                raise ValueError(
                    "Value does not have all mandatory fields set")
            if merge:
                RPD_DB._merge_trees(obj, value)
            else:
                obj.CopyFrom(value)
        self.dump()

    @staticmethod
    def _del_helper(paths, obj):
        if len(paths) == 0:
            return
        path = paths[0]
        path_elm_used = 1
        # If root has no children, then we are done
        if len(obj.ListFields()) == 0:
            return
        # Find referenced child
        if not hasattr(obj, path):
            raise DBKeyError("Key not found: %s" % path)
        if GPBHelpers.is_child_repeated(obj, path):
            # Need to match keys in path with keys in elements
            rep_list = getattr(obj, path)
            # Deleting all elements from list
            if path == paths[-1]:
                obj.ClearField(path)
                return
            keys = GPBHelpers.get_child_keys(obj, path)
            # Get keys from path
            if len(paths) < 1 + len(keys):
                raise DBKeyError("Keys missing in path: rem %d, exp: %d" %
                                 (len(paths), 1 + len(keys)))
            key_vals = paths[1:1 + len(keys)]
            path = key_vals[-1]
            path_elm_used += len(keys)

            child = GPBHelpers.get_child_from_repeated(
                rep_list, keys, key_vals)
            # No element was found matching keys passed in path
            if None is child:
                return
            # Deleting this one element from list
            if path == paths[-1]:
                rep_list.remove(child)
                return
        else:
            if GPBHelpers.is_child_key(obj, path):
                raise DBKeyError("Key value delete is forbidden: %s" % path)
            child = getattr(obj, path)

        # Not last element in path, step into next GPB message
        if path != paths[-1]:
            # Leaf, but not last element in path
            if not isinstance(child, Message):
                raise DBKeyError("Unexpected elements in path found")

            RPD_DB._del_helper(paths[path_elm_used:], child)
            # Child->child was probably cleared, maybe need to clear our child
            if len(child.ListFields()) == 0:
                obj.ClearField(path)
            return
        # Leaf/Message to be cleared
        if obj.HasField(path):
            obj.ClearField(path)

    def del_val(self, paths):
        """Delete message or value from specific path from DB.

        :param paths: path to object to be set, for more info see get_val
        :type paths: list of strings
        :return:
        :raises DBKeyError: path does not exist (missing keys,
         invalid attribute name, unexpected attribute names,..)
        :raises TypeError: type of arguments is incorrect

        """
        if type(paths) is not list or len(paths) == 0:
            raise TypeError("Path to object in invalid format")
        obj = self.data
        RPD_DB._del_helper(paths, obj)
        self.dump()

    @staticmethod
    def _fill_tree_helper(path_tree, message, gpb_to_fill, keys=None):
        # if we are working with list, keys list must be specified
        if keys is None:
            if not isinstance(message, Message):
                raise TypeError("GBP message type expected, has: %s" %
                                type(message))
            # If parent has no children, then we are done
            if len(message.ListFields()) == 0:
                return False
        for path, path_val in path_tree.iteritems():
            child_keys = None
            # Walking elements in repeated list
            if keys is not None:
                # Need to match keys in path with keys in elements
                key_vals = path
                if not isinstance(key_vals, Iterable):
                    key_vals = [key_vals]

                if len(key_vals) != len(keys):
                    raise DBKeyError(
                        "Keys missing in path: found %d, exp: %d" %
                        (len(key_vals), len(keys)))
                child = GPBHelpers.get_child_from_repeated(message, keys,
                                                           key_vals)
                # No element was found matching keys passed in path
                if None is child:
                    continue
                gpb_child = gpb_to_fill.add()
                # Deleting this one element from list
                if path_val is None:
                    gpb_child.CopyFrom(child)
                    continue
            # If child is not elm in repeated list, then it should be attribute
            elif not hasattr(message, path):
                raise DBKeyError("Key not found: %s" % path)
            # Walking repeated list
            elif GPBHelpers.is_child_repeated(message, path):
                child = getattr(message, path)
                gpb_child = getattr(gpb_to_fill, path)
                # Reading all elements from list
                if path_val is None:
                    gpb_child.MergeFrom(child)
                    continue
                if not isinstance(path_val, dict):
                    raise TypeError("Path value is not dict: %s" %
                                    type(path_val))
                child_keys = GPBHelpers.get_child_keys(message, path)
            # Walking simple leaf/container
            else:
                if GPBHelpers.is_child_key(message, path):
                    raise DBKeyError(
                        "Key value delete is forbidden: %s" % path)
                child = getattr(message, path)
                gpb_child = getattr(gpb_to_fill, path)

            # Not last element in path, step into next GPB message
            if path_val is not None:
                # Leaf, but not last element in path
                if isinstance(child, (basestring, int, NoneType)):
                    raise DBKeyError("Unexpected elements in path found")

                RPD_DB._fill_tree_helper(
                    path_val, child, gpb_child, child_keys)
                # cleanup
                if isinstance(gpb_child, Message):
                    if not gpb_child.IsInitialized():
                        if len(gpb_child.ListFields()) == 0:
                            # Nothing was filled, we can safely remove this
                            # node
                            gpb_to_fill.ClearField(path)
                        else:
                            # Some value was set, keys are missing-> fill them
                            GPBHelpers.copy_key_values(gpb_child, child,
                                                       child_keys)

                continue
            # Leaf/Message to be cleared
            if message.HasField(path):
                if isinstance(child, Message):
                    gpb_child.CopyFrom(child)
                else:
                    setattr(gpb_to_fill, path, child)

    def fill_tree(self, path_tree):
        """Read one or more leaves/messages from DB specified by tree of paths.

        :param path_tree: hierarchy of paths to objects to be returned from DB,
         None value is used to mark object to be read from DB, example::

           {'cfg':
               {'RpdCapabilities':
                   {'NumBdirPorts':None}},
            'oper':
               {'HwVersion': None}}

        :type path_tree: nested dictionaries
        :return:
        :raises DBKeyError: path does not exist (missing keys,
         invalid attribute name, unexpected attribute names,..)
        :raises TypeError: type of arguments is incorrect

        """
        if not isinstance(path_tree, dict):
            raise TypeError("Path tree is not dictionary")
        if path_tree is None:
            raise TypeError("Whole DB cannot be returned")
        message = self.data
        gpb_to_return = db()
        RPD_DB._fill_tree_helper(path_tree, message, gpb_to_return)
        return gpb_to_return

    @staticmethod
    def _del_tree(path_tree, message, keys=None):
        # if we are working with list, keys list must be specified
        if keys is None:
            if not isinstance(message, Message):
                raise TypeError("GBP message type expected, has: %s" %
                                type(message))
            # If parent has no children, then we are done
            if len(message.ListFields()) == 0:
                return
        for path, path_val in path_tree.iteritems():
            child_keys = None
            # Walking elements in repeated list
            if keys is not None:
                # Need to match keys in path with keys in elements
                key_vals = path
                if not isinstance(key_vals, Iterable):
                    key_vals = [key_vals]

                if len(key_vals) != len(keys):
                    raise DBKeyError(
                        "Keys missing in path: found %d, exp: %d" %
                        (len(key_vals), len(keys)))
                child = GPBHelpers.get_child_from_repeated(message, keys,
                                                           key_vals)
                # No element was found matching keys passed in path
                if None is child:
                    raise DBKeyError("Element does not exist in repeated list")
                # Deleting this one element from list
                if path_val is None:
                    message.remove(child)
                    continue
            # If child is not elm in repeated list, then it should be attribute
            elif not hasattr(message, path):
                raise DBKeyError("Key not found: %s" % path)
            # Walking repeated list
            elif GPBHelpers.is_child_repeated(message, path):
                child = getattr(message, path)
                # Deleting all elements from list
                if path_val is None:
                    message.ClearField(path)
                    continue
                if not isinstance(path_val, dict):
                    raise ValueError("Path value is not dict: %s" %
                                     type(path_val))
                child_keys = GPBHelpers.get_child_keys(message, path)
            # Walking simple leaf/container
            else:
                if GPBHelpers.is_child_key(message, path):
                    raise DBKeyError(
                        "Key value delete is forbidden: %s" % path)
                child = getattr(message, path)

            # Not last element in path, step into next GPB message
            if path_val is not None:
                # Leaf, but not last element in path
                if isinstance(child, (basestring, int, NoneType)):
                    raise DBKeyError("Unexpected elements in path found")

                RPD_DB._del_tree(path_val, child, child_keys)
                # Child->child was probably removed,
                # maybe we need to clear our child
                if isinstance(child, Message):
                    if len(child.ListFields()) == 0:
                        message.ClearField(path)
                continue
            # Leaf/Message to be cleared
            if message.HasField(path):
                message.ClearField(path)

    def del_tree(self, path_tree):
        """Delete one or more leaves/messages from DB specified by tree of
        paths.

        :param path_tree: hierarchy of paths to objects to be removed from DB,
         None value is used to mark object to be removed from DB, example::

           {'cfg':
               {'RpdCapabilities':
                   {'NumBdirPorts':None}},
            'oper':
               {'HwVersion': None}}
        :type path_tree: nested dictionaries
        :return:
        :raises DBKeyError: path does not exist (missing keys,
         invalid attribute name, unexpected attribute names,..)
        :raises TypeError: type of arguments is incorrect

        """
        if not isinstance(path_tree, dict):
            raise TypeError("Path tree is not iterable")
        if path_tree is None:
            raise TypeError("Whole DB cannot be cleared")
        message = self.data
        RPD_DB._del_tree(path_tree, message)
        self.dump()

    @staticmethod
    def _merge_trees_helper(dst_tree, src_tree):
        """GPB does not know about indices in repeated objects, so we need to
        merge them manually.

        """
        for descr, value in dst_tree.ListFields():
            if descr.type != descr.TYPE_MESSAGE:
                continue
            src_val = getattr(src_tree, descr.name)
            if descr.label == FieldDescriptor.LABEL_REPEATED:
                keys = GPBHelpers.get_child_keys(dst_tree, descr.name)
                confs = GPBHelpers.find_repeated_conflicts(
                    value, src_val, keys)
                for dst, src in confs:
                    RPD_DB._merge_trees_helper(dst, src)
                    dst.MergeFrom(src)
                    src_val.remove(src)
            else:
                RPD_DB._merge_trees_helper(value, src_val)

    @staticmethod
    def _merge_trees(dst_tree, src_tree):
        """Merge tree to DB tree."""
        if type(dst_tree) is not type(src_tree):
            raise TypeError("Different type of src and dst tree")
        # Type of both objects is same, check for one value is sufficient
        if not isinstance(dst_tree, Message):
            raise TypeError("Only GBP messages can be merged")

        RPD_DB._merge_trees_helper(dst_tree, src_tree)

        # Conflicts in repeated lists are merged now, we can do automatic merge
        dst_tree.MergeFrom(src_tree)

    def merge_from_tree(self, path, value):
        """Merge one or more leaves/messages to DB specified by tree of paths.

        :param path: hierarchy of paths to objects to be returned from DB,
         None value is used to mark object to be read from DB, example::

           {'cfg':
               {'RpdCapabilities':
                   {'NumBdirPorts':None}},
            'oper':
               {'HwVersion': None}}

        :type path: nested dictionaries
        :param value: message to be merged to GPB message in DB
        :type value: GPB message, string or int
        :return:
        :raises DBKeyError: path does not exist (missing keys,
         invalid attribute name, unexpected attribute names,..)
        :raises TypeError: type of arguments is incorrect

        """
        self.set_val(path, value, True)
        self.dump()


class GPBHelpers(object):

    @staticmethod
    def get_child_description(parent, path):
        """Get GPB child field description from parent message object.

        :param parent: parent of message from which, we want extract
         specified child
        :type parent: google.protobuf.message.Message
        :param string path: name of child to be returned
        :return: extracted child field description
        :rtype: google.protobuf.descriptor.FieldDescriptor
        :raises TypeError: if parent is not GPB message
        :raises KeyError: when field specified by path does not exist

        """
        if not isinstance(parent, Message):
            raise TypeError("GPB object expected, received: %s" % type(parent))
        return parent.DESCRIPTOR.fields_by_name[path]

    @staticmethod
    def get_child_keys(parent, name):
        """Get required field names from child GPB message.

        :param parent: parent of message from which, we need key names
        :type parent: google.protobuf.message.Message
        :param string name: name of child from which key names will be extracted
        :return: list of key names
        :rtype: list of strings
        :raises TypeError: if parent is not GPB message

        """
        if not isinstance(parent, Message):
            raise TypeError(
                "GPB object expected, received: %s" % type(parent))
        type_name = ProtoGenerator.TYPE_PREFIX + name
        if type_name not in parent.DESCRIPTOR.nested_types_by_name:
            return []
        fields = parent.DESCRIPTOR.nested_types_by_name[type_name].fields
        return [key.name for key in fields if
                key.label == FieldDescriptor.LABEL_REQUIRED]

    @staticmethod
    def get_child_from_repeated(rep_list, key_names, key_vals):
        """Get child specified by key values from repeated list.

        :param rep_list: repeated list to be iterated
        :type rep_list:
         google.protobuf.internal.containers.RepeatedCompositeFieldContainer
        :param key_names: names of attributes used to comparison
        :type key_names: list of strings
        :param key_vals: key values of wanted element
        :type key_vals: list of strings
        :return: found element or None if nothing was found
        :rtype: google.protobuf.message.Message or None
        :raises DBKeyError: Key values does not have expected format

        """
        if len(key_names) != len(key_vals):
            raise DBKeyError("Number of key values (%d) does not match expected"
                             " count (%d)" % (len(key_vals), len(key_names)))
        for rep_elm in rep_list:
            for key, key_val in zip(key_names, key_vals):
                # Numeric key needed, but we have string path
                if isinstance(getattr(rep_elm, key), int) and\
                        isinstance(key_val, basestring):
                    try:
                        key_val = int(key_val)
                    except ValueError:
                        raise DBKeyError("Int key value expected for key %s" %
                                         key)
                if getattr(rep_elm, key) != key_val:
                    break
                if key == key_names[-1]:
                    return rep_elm
        return None

    @ staticmethod
    def copy_key_values(dst, src, keys):
        """Copy required fields specified by key list from src to dst.

        :param dst: destination GPB message
        :type dst: google.protobuf.message.Message
        :param src: source GPB message
        :type src: google.protobuf.message.Message
        :param keys: key names to be copied
        :type keys: list of strings
        :return:

        """
        if type(dst) is not type(src):
            raise TypeError(
                "Types of objects are not same: dst: %s, src: %s" %
                type(dst), type(src))
        # Types are same -> it's safe to check type of one value
        if not isinstance(dst, Message):
            raise TypeError("Provided objects are not GPB messages: %s" %
                            type(dst))
        for path in keys:
            # It's expected that keys are provided from get_child_keys method
            # so we can skip path validation checks, all keys are leaves, so we
            # can do easy getattr/setattr copy
            setattr(dst, path, getattr(src, path))

    @staticmethod
    def is_child_repeated(parent, name):
        """Checks whether child of GPB message is repeated.

        :param parent: parent of message about which, we need type information
        :type parent: google.protobuf.message.Message
        :param string name: name of child
        :return: whether parents child is repeated
        :rtype: bool

        """
        descr = GPBHelpers.get_child_description(parent, name)
        return descr.label == FieldDescriptor.LABEL_REPEATED

    @staticmethod
    def is_child_key(parent, name):
        """Checks whether child of GPB message is used as a key.

        :param parent: parent of message about which, we need type information
        :type parent: google.protobuf.message.Message
        :param string name: name of child
        :return: whether parents child is mandatory
        :rtype: bool

        """
        descr = GPBHelpers.get_child_description(parent, name)
        return descr.label == FieldDescriptor.LABEL_REQUIRED

    @staticmethod
    def print_gpb_content(message):
        """Prints content of GPB message to console.

        :param message: GPB message to be recursively walked and printed
        :type message: google.protobuf.message.Message
        :return:
        :raises TypeError: if parent is not GPB message

        """
        if not isinstance(message, Message):
            raise TypeError("message arg is not instance of GPB message %s" %
                            type(message))
        for line in MessageToString(message).splitlines():
            GPBHelpers.logger.info(line)

    @staticmethod
    def find_repeated_conflicts(rep_list, values, key_names):
        """Find objects from values list, which are alredy in repeated list.

        :param rep_list: repeated list to be iterated
        :type rep_list:
         google.protobuf.internal.containers.RepeatedCompositeFieldContainer
        :param values: seconf list of elements, to be compared to rep_list
        :type values:
         google.protobuf.internal.containers.RepeatedCompositeFieldContainer
        :param key_names: attributes specified by name to be used in comparison
        :type key_names: list of strings
        :return: list of elements found in both lists (rep_list and values)
        :rtype: list of tuples(google.protobuf.message.Message,
                              google.protobuf.message.Message)
        :raises DBKeyError: Key values does not have expected format

        """
        conflicts = []
        for val in values:
            key_vals = []
            for key in key_names:
                key_vals.append(getattr(val, key))
            child = GPBHelpers.get_child_from_repeated(rep_list, key_names,
                                                       key_vals)
            if None is not child:
                conflicts.append((child, val))
        return conflicts

    @staticmethod
    def get_val_on_path(path, parent):
        """Returns a value from the GPB parent. The value is identified by
        path. The path must have at least one directory (a parent's directory).

        :param path: Path to the value. First directory on the path is not
         used, it's deemed as name of the parent.
        :type path: List of strings
        :param parent: GPB message.

        """
        if None in (path, parent):
            raise AttributeError("Some mandatory attribute not passed")

        if len(path) < 1:
            raise AttributeError("Too short path passed: %s".format(path))

        result = parent

        # the first directory on a path is a parent
        i = 1
        while i < len(path):
            directory = path[i]
            if GPBHelpers.is_child_repeated(result, directory):
                i += 1
                if len(path) <= i:
                    result = getattr(result, directory)
                    return result

                key_names_list = GPBHelpers.get_child_keys(result, directory)

                if len(key_names_list) > (len(path) - i):
                    # no all required keys are specified
                    GPBHelpers.logger.error("Invalid path, "
                                            "no all required keys specified: %s",
                                            path)
                    return None

                key_val_list = []
                for key_name in key_names_list:
                    key_val_list.append(path[i])
                    i += 1

                repeated_parent = getattr(result, directory)
                result = GPBHelpers.get_child_from_repeated(repeated_parent,
                                                            key_names_list,
                                                            key_val_list)
                if None is result:
                    GPBHelpers.logger.error(
                        "No such repeated object with keys: %s",
                        zip(key_names_list, key_val_list))
                    return None

                continue
            else:
                result = getattr(result, directory)
                if None is result and (i < len(path)):
                    GPBHelpers.logger.error("No such directory with name: %s, "
                                            "invalid path: %s",
                                            directory, path)
                    return None

            i += 1

        return result
