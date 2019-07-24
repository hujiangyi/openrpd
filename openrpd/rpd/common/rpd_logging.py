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
import json
import logging
import logging.config
import os

from rpd.common.rpd_event_def import EventCommonOperation

DEFAULT_LOGGING_CONFIGURATION_FILE_PATH = '/etc/config/rpd_logging.conf'


def setup_logging(module,
                  filename=None,
                  configfile_path=DEFAULT_LOGGING_CONFIGURATION_FILE_PATH,
                  logging_level=logging.INFO,
                  env_key='LOG_CFG'):
    """Setup the logging configuration from the configuration file, if the
    loggingCfg is ``None``, will use the default.

    :param configfile_path: the location of the total RPD logging configure file.
    :param module: which indicate a module name, such as GCP. L2TP...
    :param filename: which is the logging file name
    :param logging_level: this is the default logging level, if we can not parse the
     configuration file correctly, we can use this level.
    :param env_key: when search the configuration file, we will use the ENV key first, and
     then use the configuration path.
    :return:

    """
    path = configfile_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if not os.path.exists(path):
        # we will try to search the files directory
        current_path = os.path.dirname(os.path.realpath(__file__))
        dirs = current_path.split("/")
        rpd_index = dirs.index('rpd')
        if rpd_index == 0:  # pragma: no cover
            logging.basicConfig(level=logging_level)
            return

        path = '/'.join(dirs[:rpd_index]) + '/rpd/files/rpd_logging.conf'

    if not os.path.exists(path):
        logging.basicConfig(level=logging_level)
        return

    with open(path, 'rt') as f:
        config = json.load(f)

    # we should give a separate file name for every module
    if "file_handler" in config["handlers"] and filename:
        config["handlers"]["file_handler"]["filename"] = filename

    loggers = dict()
    if isinstance(module, tuple) or isinstance(module, list):
        for mod in module:
            if mod in config["loggers"]:
                loggers.update(config['loggers'][mod])
    else:
        if module in config["loggers"]:
            loggers.update(config['loggers'][module])

    if len(loggers):
        config['loggers'] = loggers
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=logging_level)


class FaultManagementLogger(object):
    """For Fault management logging
    1: will logger system information
    2: send to CCAP CORE

    """

    def __init__(self, logger):
        self.logger = logger

    def critical(self, event_id, *args):
        msg = EventCommonOperation.construct_event_msg(event_id, *args)
        self.logger.critical(msg)

    def error(self, event_id, *args):
        msg = EventCommonOperation.construct_event_msg(event_id, *args)
        self.logger.error(msg)

    def warn(self, event_id, *args):
        msg = EventCommonOperation.construct_event_msg(event_id, *args)
        self.logger.warn(msg)

    def info(self, event_id, *args):
        msg = EventCommonOperation.construct_event_msg(event_id, *args)
        self.logger.info(msg)

    warning = warn


class AddLoggerToClass(type):
    """This meta class will add a logger class variable to every class that
    sets it's meta class to it.

    """
    moduleMapping = dict()

    def __new__(cls, name, base, dct):
        dct["logger"] = logging.getLogger(name)
        cls.moduleMapping[name] = dct["logger"]
        dct["notify"] = FaultManagementLogger(dct["logger"])
        return super(AddLoggerToClass, cls).__new__(cls, name, base, dct)
