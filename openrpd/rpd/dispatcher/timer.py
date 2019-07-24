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

import time
from rpd.common.rpd_logging import AddLoggerToClass


class Timer(object):
    """Timer object that is used to identify given timer."""
    pass


class DpTimerManager(object):
    """Timer for Dispatcher.

    This object holds sorted list of timers, sorted ascendenting by time
    left.

    """
    TIMER_ONESHOT = 0
    TIMER_REPEATED = 1

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        # {seconds : {Timer : (), Timer : (), ...}}
        self._timers = {}

    def add(self, secs, cb, arg=None, timer_type=None):
        """Add timer to list of timers. Secs parameter is seconds from now
        format.

        Warning: this function does not check your parameter correctness,
        multiple inserts of the same timer is possible - take care.

        :param secs: Time in seconds
        :type secs: int or float
        :param cb: Pointer to callback function
        :param arg: An argument which is passed to callback function
        :returns: Timer instance
        :rtype: Timer

        """
        if timer_type is None:
            timer_type = self.TIMER_ONESHOT

        if cb is None:
            return None
        original_secs = secs
        secs = time.time() + secs  # Timers are stored in epoch time
        t = Timer()

        if secs not in self._timers:
            self._timers[secs] = {}
        self._timers[secs][t] = (cb, arg, timer_type, original_secs)

        return t

    def delete(self, timer):
        """Delete the timer from list of timers. Delete will also delete the
        one_shot and repeated timer.

        :param timer: Timer instance
        :type timer: Timer

        """
        if timer is None:
            return

        for t in self._timers.keys():
            val = self._timers[t]  # val = {Timer : (cb, arg), ...}
            if timer in val:
                del val[timer]
                # If this was the last Timer : {} t
                if len(val) == 0:
                    del self._timers[t]

    def update_timers(self, delta):
        """Update timestamps for all running timers, when system time is
        changed.

        :param delta: Time difference in seconds
        :type delta: float
        :return:

        """
        new_timers = {}
        for t in self._timers.keys():
            new_timers[t + delta] = self._timers[t]
        self._timers.clear()
        self._timers = new_timers

    def get_next_timeout(self):
        """Returns time until next timeout.

        Returns -1 when there are no timers

        The return value is used as argument "timeout" of the
        select.epoll().poll() method.

        :returns: Time to the next timeout in seconds
        :rtype: int or float

        """
        if len(self._timers) == 0:
            return -1

        # "for all dict keys, get the lowest
        ret = min(self._timers) - time.time()
        if ret < 0:
            # return zero when the timer has already been timeouted
            ret = 0

        return ret

    def _get_timeouted(self):
        """get_timeouted() -> {Timer : {cb, arg}], ...}
        Returns list of timeouted timers, and deletes the timers from local
        list."""
        t = time.time()
        res = {}
        system_time_change = False
        for k, t_dict in self._timers.items():
            offset = k - t
            max_timeout = 0
            for cb, arg, timer_type, original_secs, in t_dict.values():
                if original_secs > max_timeout:
                    max_timeout = original_secs
            if offset > max_timeout:
                # system time change, will mark all timer timeout
                system_time_change = True
            if t >= k or system_time_change:
                res.update(t_dict)
                del self._timers[k]
        return res

    def fire_timeouted(self):
        """For all timeouted timers, call their appropriate callbacks."""
        fired = self._get_timeouted()
        for timer in fired.keys():
            if fired[timer][0] is None:
                del fired[timer]
                continue
            try:
                cb, arg, _, _ = fired[timer]
                cb(arg)
            except Exception, e:
                # TODO for debugging purposes
                self.logger.exception('Timer handler raised: %s' % e)
                raise e

            # Update the timer
            timer_type = fired[timer][2]
            if timer_type == self.TIMER_REPEATED:
                # delete it from the timers
                self.delete(timer)

                # Add it again
                cb, arg, _, secs = fired[timer]
                self.add(secs=secs, cb=cb, arg=arg, timer_type=timer_type)
            else:
                self.delete(timer)
