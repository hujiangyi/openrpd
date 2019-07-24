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


ROOT_DIRECTORY_NAME = "root"


class PathBuilder(object):

    """Implement a builder for GPB message representing configuration paths in
    IPC messages.

    All configuration path GPB messages must have the first directory
    set to root (ROOT_DIRECTORY_NAME).

    """

    def __init__(self):
        self.root = None

    def get_result(self):
        """Returns resulting path and clears context of the builder.

        :return t_Path

        """
        result = self.root
        self.root = None
        return result

    @staticmethod
    def init_root(path_root):
        """Initialize a root of path."""
        if not path_root.Name:
            path_root.Name = ROOT_DIRECTORY_NAME

    def set_root(self, path_root):
        """Sets the path_root attribute as current root."""
        self.init_root(path_root)
        self.root = path_root

    def add_subpath_sequence(self, path_as_sequence):
        """Adds subpath specified by sequence of directories (strings)"""
        if None is path_as_sequence:
            raise AttributeError()

        curr_subdir = self.root
        for sub_dir in path_as_sequence:

            already_there = False
            for curr_sub_subdir in curr_subdir.Value:
                if curr_sub_subdir.Name == sub_dir:
                    already_there = True
                    curr_subdir = curr_sub_subdir
                    break

            if not already_there:
                # add new subdir
                curr_subdir = curr_subdir.Value.add()
                curr_subdir.Name = "{}".format(sub_dir)

    @staticmethod
    def __add_subpath_to_dir(dir, subpath_dict):
        for subdir_name, sub_subdirs in subpath_dict.iteritems():

            next_dir = None
            for subdir in dir.Value:
                if subdir.Name == subdir_name:
                    next_dir = subdir
                    break

            if None is next_dir:
                next_dir = dir.Value.add()
                next_dir.Name = "{}".format(subdir_name)

            if sub_subdirs is not None:
                PathBuilder.__add_subpath_to_dir(next_dir, sub_subdirs)

    def add_subpath_dict(self, path_as_dict):
        """Adds subpath(s) specified by dictionary in this format which allows
        to specify a tree of paths::

          { "directory_name" : { subdirectory_name: None }}

        Example::

          path_as_dict = {
              "cfg" : {
                  "RpdCapabilities": None
              }
              "oper" : None
          }

        """
        if None is path_as_dict:
            raise AttributeError()

        PathBuilder.__add_subpath_to_dir(self.root, path_as_dict)


class PathConverter(object):

    """Implements static methods which converting one format of path to another
    one."""

    @staticmethod
    def __check_path_gpb(path_gpb):
        if path_gpb.Name != ROOT_DIRECTORY_NAME:
            raise AttributeError(
                "Invalid path GPB, without {} directory".format(
                    ROOT_DIRECTORY_NAME))

    @staticmethod
    def __add_next_list(seq_list, curr_path_list, subpath_gpb):
        for sub_gpb in subpath_gpb.Value:
            new_path_list = curr_path_list + [str(sub_gpb.Name), ]
            if not sub_gpb.Value:
                seq_list.append(new_path_list)
            else:
                PathConverter.__add_next_list(seq_list, new_path_list,
                                              sub_gpb)

    @staticmethod
    def path_gpb_to_list_of_lists(path_gpb):
        """Converts path from GPB message format to the list of lists."""
        if None is path_gpb:
            return []

        PathConverter.__check_path_gpb(path_gpb)

        result = []
        PathConverter.__add_next_list(result, [], path_gpb)
        return result

    @staticmethod
    def __add_next_dict(sub_dict, subpath_gpb):
        for sub_gpb in subpath_gpb.Value:
            if not sub_gpb.Value:
                sub_dict[str(sub_gpb.Name)] = None
            else:
                new_sub_dict = {}
                sub_dict[sub_gpb.Name] = new_sub_dict
                PathConverter.__add_next_dict(new_sub_dict, sub_gpb)

    @staticmethod
    def path_gpb_to_dict(path_gpb):
        """Converts path from GPB message format to the dictionary of
        dictionaries."""
        if None is path_gpb:
            return []

        PathConverter.__check_path_gpb(path_gpb)
        result = {}
        PathConverter.__add_next_dict(result, path_gpb)
        return result

    @staticmethod
    def path_sequence_to_gpb(path_sequence, gpb_path):
        """Converts a sequence of directory names into the GPB message.

        :param path_sequence: List of directory names.
        :param gpb_path: A GPB path root where the path will be expanded
         according to the path_sequence.

        """
        PathBuilder.init_root(gpb_path)
        curr_subpath = gpb_path
        for sub_path in path_sequence:
            curr_subpath = curr_subpath.Value.add()
            curr_subpath.Name = "{}".format(sub_path)
        return gpb_path

    @staticmethod
    def __add_next_gpb_from_dict(gpb_parent, sub_dict):
        if None is gpb_parent or None is sub_dict:
            return
        for name, sub_subdict in sub_dict.iteritems():
            new_subdir = gpb_parent.Value.add()
            new_subdir.Name = "{}".format(name)
            if None is not sub_subdict:
                PathConverter.__add_next_gpb_from_dict(new_subdir, sub_subdict)

    @staticmethod
    def path_dict_to_gpb(path_dict, gpb_path):
        """Converts dictionary of dictionaries ... of directories into the GPB
        message.

        :param path_dict: Dictionary of directory names.
        :param gpb_path: A GPB path root where the path will be expanded
         according to the path_dict.

        """
        PathBuilder.init_root(gpb_path)
        PathConverter.__add_next_gpb_from_dict(gpb_path, path_dict)
        return gpb_path


class PathDirector(object):

    """Implements building of the most common paths."""
    _BUILDER = PathBuilder()

    PATH_CFG = ['cfg']
    PATH_OPER = ['oper']
    PATH_RPD_CAPS = PATH_CFG + ['RpdCapabilities']

    def get_cfg_path(self, gpb_path, sub_paths_dict=None):
        self._BUILDER.set_root(gpb_path)
        if None is sub_paths_dict:
            self._BUILDER.add_subpath_sequence(self.PATH_CFG)
        else:
            cfg_dict = {'cfg': sub_paths_dict}
            self._BUILDER.add_subpath_dict(cfg_dict)

        return self._BUILDER.get_result()

    def get_oper_path(self, gpb_path):
        self._BUILDER.set_root(gpb_path)
        self._BUILDER.add_subpath_sequence(self.PATH_OPER)
        return self._BUILDER.get_result()

    def get_rpd_capabilities_path(self, gpb_path):
        self._BUILDER.set_root(gpb_path)
        self._BUILDER.add_subpath_sequence(self.PATH_RPD_CAPS)
        return self._BUILDER.get_result()
