/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Implementation-private.  This header should not be included
 * directly by an application.  The application should instead
 * include <time.h> which includes this header conditionally
 * depending on which feature test macros are defined. By default,
 * this header is included by <time.h>.  X/Open and POSIX
 * standards requirements result in this header being included
 * by <time.h> only under a restricted set of conditions.
 */

#ifndef _SYS_TIME_IMPL_H
#define	_SYS_TIME_IMPL_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#if !defined(_TIME_T) || __cplusplus >= 199711L
#define	_TIME_T
typedef	long	time_t;		/* time of day in seconds */
#endif	/* _TIME_T */

/*
 * Time expressed in seconds and nanoseconds
 */

typedef struct  timespec {		/* definition per POSIX.4 */
	time_t		tv_sec;		/* seconds */
	long		tv_nsec;	/* and nanoseconds */
} timespec_t;

#if defined(_SYSCALL32)

#include <sys/types32.h>

#define	TIMESPEC32_TO_TIMESPEC(ts, ts32)	{	\
	(ts)->tv_sec = (time_t)(ts32)->tv_sec;		\
	(ts)->tv_nsec = (ts32)->tv_nsec;		\
}

#define	TIMESPEC_TO_TIMESPEC32(ts32, ts)	{	\
	(ts32)->tv_sec = (time32_t)(ts)->tv_sec;	\
	(ts32)->tv_nsec = (ts)->tv_nsec;		\
}

#define	TIMESPEC_OVERFLOW(ts)		\
	((ts)->tv_sec < TIME32_MIN || (ts)->tv_sec > TIME32_MAX)

#endif	/* _SYSCALL32 */

typedef struct timespec timestruc_t;	/* definition per SVr4 */

/*
 * The following has been left in for backward compatibility. Portable
 * applications should not use the structure name timestruc.
 */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#define	timestruc	timespec	/* structure name per SVr4 */
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

/*
 * Timer specification
 */
typedef struct itimerspec {		/* definition per POSIX.4 */
	struct timespec	it_interval;	/* timer period */
	struct timespec	it_value;	/* timer expiration */
} itimerspec_t;

#if defined(_SYSCALL32)

#define	ITIMERSPEC32_TO_ITIMERSPEC(it, it32)	{	\
	TIMESPEC32_TO_TIMESPEC(&(it)->it_interval, &(it32)->it_interval); \
	TIMESPEC32_TO_TIMESPEC(&(it)->it_value, &(it32)->it_value);	\
}

#define	ITIMERSPEC_TO_ITIMERSPEC32(it32, it)	{	\
	TIMESPEC_TO_TIMESPEC32(&(it32)->it_interval, &(it)->it_interval); \
	TIMESPEC_TO_TIMESPEC32(&(it32)->it_value, &(it)->it_value);	\
}

#define	ITIMERSPEC_OVERFLOW(it)				\
	(TIMESPEC_OVERFLOW(&(it)->it_interval) &&	\
	TIMESPEC_OVERFLOW(&(it)->it_value))

#endif	/* _SYSCALL32 */

#endif	/* _ASM */

#define	__CLOCK_REALTIME0	0	/* obsolete; same as CLOCK_REALTIME */
#define	CLOCK_VIRTUAL		1	/* thread's user-level CPU clock */
#define	CLOCK_THREAD_CPUTIME_ID	2	/* thread's user+system CPU clock */
#define	CLOCK_REALTIME		3	/* wall clock */
#define	CLOCK_MONOTONIC		4	/* high resolution monotonic clock */
#define	CLOCK_PROCESS_CPUTIME_ID 5	/* process's user+system CPU clock */
#define	CLOCK_HIGHRES		CLOCK_MONOTONIC		/* alternate name */
#define	CLOCK_PROF		CLOCK_THREAD_CPUTIME_ID	/* alternate name */

#ifdef _KERNEL
#define	CLOCK_MAX		6
#endif

#define	TIMER_RELTIME	0x0		/* set timer relative */
#define	TIMER_ABSTIME	0x1		/* set timer absolute */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIME_IMPL_H */
