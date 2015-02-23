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
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * Header file to support for the timerfd facility.
 */

#ifndef _SYS_TIMERFD_H
#define	_SYS_TIMERFD_H

#include <sys/types.h>
#include <sys/time_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * To assure binary compatibility with Linux, these values are fixed at their
 * Linux equivalents, not their native ones.
 */
#define	TFD_CLOEXEC		02000000		/* LX_O_CLOEXEC */
#define	TFD_NONBLOCK		04000			/* LX_O_NONBLOCK */
#define	TFD_TIMER_ABSTIME	(1 << 0)
#define	TFD_TIMER_CANCEL_ON_SET	(1 << 1)

/*
 * These ioctl values are specific to the native implementation; applications
 * shouldn't be using them directly, and they should therefore be safe to
 * change without breaking apps.
 */
#define	TIMERFDIOC		(('t' << 24) | ('f' << 16) | ('d' << 8))
#define	TIMERFDIOC_CREATE	(TIMERFDIOC | 1)	/* create timer */
#define	TIMERFDIOC_SETTIME	(TIMERFDIOC | 2)	/* timerfd_settime() */
#define	TIMERFDIOC_GETTIME	(TIMERFDIOC | 3)	/* timerfd_gettime() */

typedef struct timerfd_settime {
	uint64_t tfd_settime_flags;	/* flags (e.g., TFD_TIMER_ABSTIME) */
	uint64_t tfd_settime_value;	/* pointer to value */
	uint64_t tfd_settime_ovalue;	/* pointer to old value, if any */
} timerfd_settime_t;

#ifndef _KERNEL

extern int timerfd_create(int, int);
extern int timerfd_settime(int, int,
    const struct itimerspec *, struct itimerspec *);
extern int timerfd_gettime(int, struct itimerspec *);

#else

#define	TIMERFDMNRN_TIMERFD	0
#define	TIMERFDMNRN_CLONE	1
#define	TIMERFD_VALMAX		(ULLONG_MAX - 1ULL)

/*
 * Fortunately, the values for the Linux clocks that are valid for timerfd
 * (namely, CLOCK_REALTIME and CLOCK_MONOTONIC) don't overlap with our values
 * the same.
 */
#define	TIMERFD_MONOTONIC	1	/* Linux value for CLOCK_MONOTONIC */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIMERFD_H */
