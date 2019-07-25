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


import google
from protobuf_to_dict import Message
import google.protobuf.internal.containers

from rpd.common.rpd_logging import AddLoggerToClass
from rpd.confdb.rpd_db import RPD_DB
from rpd.gpb.rcp_pb2 import t_RpdDataMessage
from rpd.common.ipc_gpb_utils import PathConverter
from rpd.gpb.RpdCapabilities_pb2 import t_RpdCapabilities


class CfgDbAdapterError(Exception):
    pass


class DataObj(object):
    """Stores data prepared for DB operations."""
    __metaclass__ = AddLoggerToClass

    def __init__(self, cfg_data, operation, path, is_bulk=False):
        if operation in CfgDbAdapter.RPD_DATA_OPER_WR_OR_AW \
                and cfg_data is None:
            raise AttributeError("Missing data to write")
        elif operation in [CfgDbAdapter.RPD_DATA_OPER_RD,
                           CfgDbAdapter.RPD_DATA_OPER_DEL] and path is None:
            raise AttributeError("Missing path for read/delete")

        self.cfg_data = cfg_data
        self.operation = operation
        self.path = path
        self.is_bulk = is_bulk


class CfgDbAdapter(object):
    """Prepares and stores RPD specific data for particular operation.

    Performs operations with prepared data with the database. Operations
    are performed in the same order in which they have been prepared by
    the prepare_data() method.

    """
    RPD_DATA_OPER_RD = t_RpdDataMessage.RPD_CFG_READ
    RPD_DATA_OPER_WR = t_RpdDataMessage.RPD_CFG_WRITE
    RPD_DATA_OPER_DEL = t_RpdDataMessage.RPD_CFG_DELETE
    RPD_DATA_OPER_AW = t_RpdDataMessage.RPD_CFG_ALLOCATE_WRITE
    RPD_DATA_OPER = (RPD_DATA_OPER_RD,
                     RPD_DATA_OPER_WR,
                     RPD_DATA_OPER_DEL,
                     RPD_DATA_OPER_AW)
    RPD_DATA_OPER_WR_OR_AW = (RPD_DATA_OPER_WR, RPD_DATA_OPER_AW)

    __metaclass__ = AddLoggerToClass

    def __init__(self, database):
        """
        :param database: DB on which a configuration operations will be
         processed
        :type databse: RPD_DB
        """
        if None is database:
            raise AttributeError("Database is mandatory attribute")

        if not isinstance(database, RPD_DB):
            raise TypeError()

        self.database = database
        self.oper_data = None

    def prepare_data(self, cfg_data, data_path=None, operation=None,
                     is_bulk=False):
        """Converts RCP specific data into the representation in DB and creates
        object(s) of DataObj class and sets their attributes.

        :param cfg_data: Data to be configured.
        :param data_path: A configuration path in form of list of strings or
         dictionary. See common/ipc_gpb_utils.py for more details about format.
        :param operation: action to be made on data read/write/delete
        :param is_bulk: If the operation is for one value or for set of values.

        """
        if isinstance(cfg_data, t_RpdDataMessage):
            # We are passing list of RCPSequence instances only
            operation = cfg_data.RpdDataOperation

            if operation in self.RPD_DATA_OPER_WR_OR_AW:
                path = PathConverter.path_gpb_to_list_of_lists(cfg_data.Path)
                if 1 != len(path):
                    # TODO DB doesn't have implemented support for multiple
                    # TODO partial writes according to path defined as dict
                    self.logger.error(
                        "Handling of multiple writes is not implemented")
                    return
                path = path[0]
            else:
                path = PathConverter.path_gpb_to_dict(cfg_data.Path)

            is_bulk = True

            if operation == self.RPD_DATA_OPER_RD:
                self.logger.warning("There's not implemented support for partial"
                                    "reads")
                path = {'cfg': None}

            data = DataObj(cfg_data.RpdData, operation, path, is_bulk)
            self.oper_data = data
            self.logger.debug("Data prepared for operation: %s, path: %s",
                              operation, path)
            return
        elif isinstance(cfg_data, t_RpdCapabilities):
            operation = self.RPD_DATA_OPER_WR
            is_bulk = True
            path = ['cfg', 'RpdCapabilities']
            data = DataObj(cfg_data, operation, path, is_bulk)
            self.oper_data = data
            self.logger.debug("RpdCapabilities prepared for write to DB")
            return
        else:
            #
            # Processing dependent on RCP operation
            #
            if None is operation:
                raise AttributeError("rcp_oper not passed")
            if operation not in self.RPD_DATA_OPER:
                raise AttributeError("rcp_oper unknown")
            if None is data_path:
                raise AttributeError("data_path not passed")
            if len(data_path) < 1:
                raise AttributeError("data_path length is less than 1")

            # read/del specific
            if (self.RPD_DATA_OPER_RD == operation) \
                    or (self.RPD_DATA_OPER_DEL == operation):
                self.oper_data = DataObj(None, operation, data_path, is_bulk)
                return

            # write specific
            elif operation in self.RPD_DATA_OPER_WR_OR_AW:

                if None is cfg_data:
                    raise AttributeError("rcp_data not passed")

                # process the rcp_data and store them in the oper_data list
                self.oper_data = []

                if isinstance(cfg_data, (basestring, int, Message, tuple, list,
                                         google.protobuf.internal.containers.
                                         RepeatedScalarFieldContainer)):
                    self.oper_data = DataObj(cfg_data, operation, data_path,
                                             is_bulk)
                else:
                    raise AttributeError("Unknown rcp_data type passed")
                return
            else:
                raise NotImplementedError()

        # this should never happen
        raise AttributeError("Invalid attributes")

    def set_leaf(self, db_path_to_leaf, val_to_db, is_bulk=False):
        """Set one or more values to specified path in DB.

        :param db_path_to_leaf: List of names where the value should be set.
         For example:

         path = ['cfg', 'interface']: this will set value directly to
         'interface' attribute of 'cfg' (if it's type is valid for this
         location). If is_bulk is set to False, then provided value will
         replace original value on this location. Else values in this provided
         subtree will be merged will original value.

         More details can be found in database docstrings.

        :param val_to_db: value(s) to be set to path in DB
        :type val_to_db: (google.protobuf.message.Message, int, string)
        :param bool is_bulk: setting one value (False) or more (True)?
        :return: Result of operation (True = success)
        :rtype: bool

        """
        if not isinstance(db_path_to_leaf, list):
            self.logger.error("Failed to SET value from path '%s' "
                              "- expected path type 'list' passed type '%s'",
                              str(db_path_to_leaf), type(db_path_to_leaf))
            return False

        # TODO: do path validation

        try:
            self.prepare_data(cfg_data=val_to_db,
                              data_path=db_path_to_leaf,
                              operation=CfgDbAdapter.RPD_DATA_OPER_WR,
                              is_bulk=is_bulk)
            ret = self.process_all()
        except Exception, e:
            self.logger.error("Failed to SET value '%s' into path %s - database "
                              "exception '%s'", str(val_to_db), str(db_path_to_leaf), e)
            return False

        if ret is None:
            self.logger.error(
                "Failed to SET value '%s' into path %s - database NOK",
                str(val_to_db), str(db_path_to_leaf))
            return False
        else:
            return True

    def _get_common(self, db_path_to_leaf, operation_bulk, log_err=False):
        try:
            self.prepare_data(cfg_data=None,
                              data_path=db_path_to_leaf,
                              operation=CfgDbAdapter.RPD_DATA_OPER_RD,
                              is_bulk=operation_bulk)
            ret = self.process_all()
        except Exception, e:
            self.logger.error("Failed to GET value from path %s - database "
                              "exception '%s'", str(db_path_to_leaf), e)
            return None
        if None is ret:
            if log_err:
                self.logger.error("Failed to GET value from path %s",
                                  str(db_path_to_leaf))
        return ret

    def get_leaf(self, db_path_to_leaf):
        """Get value (leaf or subtree) from specified path in DB.

        :param db_path_to_leaf: List of strings to object to be deleted
          For example:

          ['cfg', 'interface'] this will delete whatever, what is on stored
          in variable interface inside of 'cfg' GPB message, but all other
          variables under 'cfg' will stay untouched

        :return: Object in specified location in DB or None if not set
        :rtype: None, int, string, list, google.protobuf.message.Message

        """
        if not isinstance(db_path_to_leaf, list):
            self.logger.error("Failed to GET value from path '%s' "
                              "- expected path type 'list' passed type '%s'",
                              str(db_path_to_leaf), type(db_path_to_leaf))
            return None

        return self._get_common(db_path_to_leaf, False)

    def _del_common(self, db_path_to_leaf, operation_bulk, log_err=False):
        try:
            self.prepare_data(cfg_data=None,
                              data_path=db_path_to_leaf,
                              operation=CfgDbAdapter.RPD_DATA_OPER_DEL,
                              is_bulk=operation_bulk)
            ret = self.process_all()
        except Exception, e:
            self.logger.error("Failed to DEL value from path '%s' - database"
                              " exception '%s'", str(db_path_to_leaf), e)
            return False

        if ret is None:
            if log_err:
                self.logger.error("Failed to DEL value from path '%s'",
                                  str(db_path_to_leaf))
            return False

        else:
            return ret

    def del_leaf(self, db_path_to_leaf):
        """Delete value from DB specified by list of names of objects in path.

        :param db_path_to_leaf: List of names to object to be deleted.
         For example:

         ['cfg', 'interface'] this will delete whatever, what is on stored
         in variable interface inside of 'cfg' GPB message, but all other
         variables under 'cfg' will stay untouched

        :return: Result of operation (True = success)
        :rtype: bool

        """
        if not isinstance(db_path_to_leaf, list):
            self.logger.error("Failed to DEL value from path '%s' "
                              "- expected path type 'list' passed type '%s'",
                              str(db_path_to_leaf), type(db_path_to_leaf))
            return False

        return self._del_common(db_path_to_leaf, False)

    def del_tree(self, db_path_dict):
        """Delete more values from DB specified by tree of paths.

        For example::

          {test: {
                  test2: None}}  --this will delete whatever, what is on stored
                  in test2 variable (GPB message, int, string, ...),
                  but all other branches under test will stay untouched

        :param db_path_dict: Tree of paths to objects to be deleted.
        :return: Result of operation (True = success)
        :rtype bool

        """
        if not isinstance(db_path_dict, dict):
            self.logger.error("Failed to DEL_TREE value from path '%s' "
                              "- expected path type 'dict' passed type '%s'",
                              str(db_path_dict), type(db_path_dict))
            return False

        return self._del_common(db_path_dict, True)

    #
    # Perform operations
    #
    @staticmethod
    def read(database, data):
        """Performs read operation with data prepared for read.

        :param database: DB on which read operation will be executed
        :param data: Request specification - path(s) to data to be read,
         ID of operation, ...
        :type data: DataObj
        :return: Requested data from DB
        :rtype: object (GPB message, string, int) found on specified path
                or None, when object is not filled

        """
        try:
            if data.is_bulk:
                ret_data = database.fill_tree(data.path)
                if None is not ret_data:
                    # db GPB message is returned, we need only cfg part
                    ret_data = ret_data.cfg
            else:
                ret_data = database.get_val(data.path)
        except Exception as ex:
            CfgDbAdapter.logger.error("Failed to read data from DB "
                                      "(path: %s): %s",
                                      data.path, ex)
            return None

        return ret_data

    @staticmethod
    def write(database, data):
        """Performs read operation with data prepared for read.

        :param database: DB on which write operation will be executed
        :param data: Request specification - path, where data will be written,
                     values to be written to this path, ID of operation, ...
        :type data: DataObj
        :return: Result of operation (True = success)
        :rtype: bool

        """
        try:
            if data.is_bulk and isinstance(data.path, dict):
                database.merge_from_tree(data.path, data.cfg_data)
            else:
                database.set_val(data.path, data.cfg_data, data.is_bulk)
        except Exception as ex:
            CfgDbAdapter.logger.error("Failed to write data into DB "
                                      "(path: %s): %s",
                                      data.path, ex)
            return False
        return True

    @staticmethod
    def delete(database, data):
        """Performs only delete operation with data prepared for delete.

        :param database: DB on which delete operation will be executed
        :param data: Request specification - path(s) to data to be deleted,
                     ID of operation, ...
        :type data: DataObj
        :return: Result of operation (True = success)
        :rtype: bool

        """
        try:
            if data.is_bulk:
                database.del_tree(data.path)
            else:
                database.del_val(data.path)
        except Exception as ex:
            CfgDbAdapter.logger.error("Failed to delete data into DB "
                                      "(path: %s): %s",
                                      data.path, ex)
            return False

        return True

    def process_all(self):
        """Performs operation prepared, returns rpd.gpb.cfg_pb2.config for read
        operations, bool for others.

        :return: Returns True / False / DataObj
                 True or DataObj is set when the operation was successful,
                 False otherwise.
        :rtype: rpd.gpb.cfg_pb2.config or bool

        """
        if self.oper_data is None:
            self.logger.debug("Nothing to be processed")
            return
        operation = self.oper_data.operation
        if self.RPD_DATA_OPER_RD == operation:
            r_data = self.read(self.database,
                               self.oper_data)  # return None or Object
            return r_data

        elif operation in self.RPD_DATA_OPER_WR_OR_AW:
            result = self.write(self.database,
                                self.oper_data)  # return False or True
            if not result:
                self.logger.error("Failed to process write operation"
                                  "path: %s", self.oper_data.path)
                # TODO handle rollback
            return result

        elif self.RPD_DATA_OPER_DEL == operation:
            result = self.delete(self.database, self.oper_data)
            if not result:
                self.logger.error("Failed to process delete operation with "
                                  "path: %s", self.oper_data.path)
                # TODO handle rollback

            return result
            # undefined operation
        else:
            raise CfgDbAdapterError("Undefined data operation: {}".format(
                operation))
