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

import exceptions

import zmq

from rpd.dispatcher.timer import DpTimerManager
from rpd.common.rpd_logging import AddLoggerToClass


class DispatcherTimeoutError(Exception):
    pass


class Dispatcher(object):
    """Dispatcher is mainloop implementation in python.

    Add your file descriptors to it, and execute loop() function. To end
    the mainloop, call end_loop() function.

    """
    EV_FD_NONE = 0
    EV_FD_IN = zmq.POLLIN
    EV_FD_OUT = zmq.POLLOUT
    EV_FD_ERR = zmq.POLLERR
    EV_FD_ALL = EV_FD_IN | EV_FD_OUT | EV_FD_ERR

    MASK_RD_ERR = (EV_FD_ERR | EV_FD_IN)
    MASK_WR_ERR = (EV_FD_ERR | EV_FD_OUT)
    MASK_ERR = EV_FD_ERR
    MASK_ALL = EV_FD_ALL

    __metaclass__ = AddLoggerToClass

    def __init__(self):
        self._poll = zmq.Poller()
        self._fds = {}
        # Dictionary of registered file descriptors, or zmq sockets
        self._tm = DpTimerManager()
        self._end_loop = False

    def _handle_poll_events(self, events):
        self._tm.fire_timeouted()  # trigger and delete all timeout timers
        events = dict(events) if events else None
        if not isinstance(events, dict):
            # self.logger.error("Got a events which is not a dict type,. The type is
            # %s" % type(events))
            return
        for fd in events:
            try:
                cb = self._fds[fd]
            except KeyError:
                # Poll has an FD registered, but there's no handler registered
                # for it.
                self.fd_unregister(fd)
                continue

            try:
                cb(fd, events[fd])
            except AttributeError, e:
                self.logger.exception(
                    'FD %d has invalid handler "%s"', fd, str(cb))
                self.logger.warning('Removing invalid fd handler from list')
                self.fd_unregister(fd)
                # TODO for debugging purposes
                raise e

    def get_poll(self):
        return self._poll

    def loop(self):
        """Loops over the registered file descriptors, calls callbacks."""
        self._end_loop = False
        while True:
            events = None
            timeout_sec = 0
            try:
                # the reason to limit the max value is, we want to give a chance
                # to the poller handler to run, which can help to check the
                # system time change.
                timeout_sec = self._tm.get_next_timeout()
                if timeout_sec >= 10:
                    timeout_sec = 10
                # the reason to multiply 1000 is that, the zmq unit is
                # different with select poll unit.
                timeout = timeout_sec * 1000
                if timeout <= 10:
                    timeout = 10
                events = self._poll.poll(timeout=long(timeout))

            except exceptions.OverflowError:
                self.logger.error(
                    "Time difference is overflow:%d, error:%s", timeout_sec, exceptions.OverflowError)
                raise DispatcherTimeoutError("Invalid time difference")

            self._handle_poll_events(events)
            if self._end_loop is True:
                self.logger.debug('end_loop mark found, breaking out of loop')
                break

    def fd_register(self, fd, eventmask, callback):
        """Register file descriptor fd for events listed in the eventmask
        bitmask. Use EV_FD_* for eventmask, e.g. EV_FD_IN | EV_FD_OUT. Callback
        parameter expects reference to callable callback(fd, event_mask).

        :param fd: File descriptor
        :type fd: int
        :param eventmask: Bitmask of events
        :type eventmask: int
        :param callback: Pointer to function

        """

        self._poll.register(fd, eventmask)
        self._fds[fd] = callback

    def fd_modify(self, fd, eventmask):
        """Modify the events for which the fd file descriptor should be
        watched.

        :param fd: File descriptor
        :type fd: int
        :param eventmask: Bitmask of events
        :type eventmask: int

        """
        self._poll.modify(fd, eventmask)

    def fd_unregister(self, fd):
        """Unregisters file descriptor from the dispatcher.

        :param fd: File descriptor
        :type fd: int

        """
        try:
            self._poll.unregister(fd)
            del self._fds[fd]
        except KeyError:
            pass

    def timer_register(self, seconds, callback, arg=None, timer_type=DpTimerManager.TIMER_ONESHOT):
        """Register timer with this dispatcher, which should fire after seconds
        has passed. Callback parameter is expected to be callable with
        callback(arg) syntax. This callback is called when the timer triggers.

        Returns timer.Timer object as ID to this added timer. This can be used
        with timer_unregister() to remove the timer.

        :param seconds: Time in seconds
        :type seconds: int or float
        :param callback: Pointer to the function which called when timer fired
        :param arg: An argument passed to the callback function when
         timer fired
        :returns: Timer instance
        :rtype: Timer
        :param timer_type: This is the timer type, currently, we support two types, one shot and repeated.

        """
        return self._tm.add(seconds, callback, arg, timer_type)

    def timer_unregister(self, timer):
        """Removes the timer from the list of registered timers. Parameter
        timer is the one returned from timer_register.

        :param timer: The timer instance returned by timer_register()
        :type timer: Timer

        """
        self._tm.delete(timer)

    def update_all_timers(self, delta):
        """Update timestamps for all running timers, when system time is
        changed.

        :param delta: Time difference in seconds
        :type delta: float
        :return:

        """
        self._tm.update_timers(delta)

    def end_loop(self):
        """Ends the loop."""
        self._end_loop = True
