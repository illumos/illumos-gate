/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

#include <sys/timerfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int
timerfd_create(int clockid, int flags)
{
	int oflags = O_RDWR;
	int fd;

	if (flags & ~(TFD_NONBLOCK | TFD_CLOEXEC)) {
		errno = EINVAL;
		return (-1);
	}

	if (flags & TFD_NONBLOCK)
		oflags |= O_NONBLOCK;

	if (flags & TFD_CLOEXEC)
		oflags |= O_CLOEXEC;

	if ((fd = open("/dev/timerfd", oflags)) < 0)
		return (-1);

	if (ioctl(fd, TIMERFDIOC_CREATE, clockid) != 0) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

int
timerfd_settime(int fd, int flags, const struct itimerspec *new_value,
    struct itimerspec *old_value)
{
	timerfd_settime_t st;
	int rval;

	if (flags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) {
		errno = EINVAL;
		return (-1);
	}

	st.tfd_settime_flags = flags;
	st.tfd_settime_value = (uint64_t)(uintptr_t)new_value;
	st.tfd_settime_ovalue = (uint64_t)(uintptr_t)old_value;

	rval = ioctl(fd, TIMERFDIOC_SETTIME, &st);

	if (rval == -1 && errno == ENOTTY) {
		/*
		 * Linux has us return EINVAL when the file descriptor is valid
		 * but is not a timerfd file descriptor -- and LTP explicitly
		 * checks this case.
		 */
		errno = EINVAL;
	}

	return (rval);
}

int
timerfd_gettime(int fd, struct itimerspec *curr_value)
{
	int rval = ioctl(fd, TIMERFDIOC_GETTIME, curr_value);

	if (rval == -1 && errno == ENOTTY) {
		/*
		 * See comment in timerfd_settime(), above.
		 */
		errno = EINVAL;
	}

	return (rval);
}
