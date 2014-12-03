/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <lx_signum.h>

/*
 * Translating from the Linux clock types to the Illumos types is a bit of a
 * mess.
 *
 * Linux uses different values for it clock identifiers, so we have to do basic
 * translations between the two.  Thankfully, both Linux and Illumos implement
 * the same POSIX SUSv3 clock types, so the semantics should be identical.
 *
 * However, CLOCK_REALTIME and CLOCK_HIGHRES (CLOCK_MONOTONIC) are the only two
 * clock backends currently implemented on Illumos. Functions in the kernel
 * that use the CLOCK_BACKEND macro will return an error for any clock type
 * that does not exist in the clock_backend array. These functions are
 * clock_settime, clock_gettime, clock_getres and timer_create.
 *
 * For reference, the kernel's clock_backend array looks like this:
 *
 * clock_backend[CLOCK_MAX] (6 entries)
 *    0	__CLOCK_REALTIME0		valid ptr. (obs. same as CLOCK_REALTIME)
 *    1	CLOCK_VIRTUAL			NULL
 *    2	CLOCK_THREAD_CPUTIME_ID		NULL
 *    3	CLOCK_REALTIME			valid ptr.
 *    4	CLOCK_MONOTONIC (CLOCK_HIGHRES)	valid ptr.
 *    5	CLOCK_PROCESS_CPUTIME_ID	NULL
 *
 * See the comment on clock_highres_timer_create for full details but a zone
 * needs the proc_clock_highres privilege to use the CLOCK_HIGHRES clock so it
 * will generally be unusable by lx for timer_create.
 */

static int ltos_clock[] = {
	CLOCK_REALTIME,
	CLOCK_MONOTONIC,
	CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID
};

/*
 * Since the Illumos CLOCK_HIGHRES clock requires elevated privs, which can
 * lead to a DOS, we use the only other option (CLOCK_REALTIME) when given
 * LX_CLOCK_MONOTONIC.
 */
static int ltos_timer[] = {
	CLOCK_REALTIME,
	CLOCK_REALTIME,
	CLOCK_THREAD_CPUTIME_ID,	/* XXX thread, not process but fails */
	CLOCK_THREAD_CPUTIME_ID
};

#define	LX_CLOCK_REALTIME		0
#define	LX_CLOCK_MONOTONIC		1
#define	LX_CLOCK_PROCESS_CPUTIME_ID	2
#define	LX_CLOCK_THREAD_CPUTIME_ID	3

#define	LX_CLOCK_MAX	(sizeof (ltos_clock) / sizeof (ltos_clock[0]))
#define	LX_TIMER_MAX	(sizeof (ltos_timer) / sizeof (ltos_timer[0]))

#define	LX_SIGEV_PAD_SIZE	((64 - \
	(sizeof (int) * 2 + sizeof (union sigval))) / sizeof (int))

typedef struct {
	union sigval	lx_sigev_value;	/* same layout for both */
	int		lx_sigev_signo;
	int		lx_sigev_notify;
	union {
		int	lx_pad[LX_SIGEV_PAD_SIZE];
		int	lx_tid;
		struct {
			void (*lx_notify_function)(union sigval);
			void *lx_notify_attribute;
		} lx_sigev_thread;
	} lx_sigev_un;
} lx_sigevent_t;

/* sigevent sigev_notify conversion table */
static int ltos_sigev[] = {
	SIGEV_SIGNAL,
	SIGEV_NONE,
	SIGEV_THREAD,
	0,		/* Linux skips event 3 */
	SIGEV_THREAD	/* the Linux SIGEV_THREAD_ID */
};

#define	LX_SIGEV_MAX	(sizeof (ltos_sigev) / sizeof (ltos_sigev[0]))

static long
get_cputime(int who, struct timespec *tp)
{
	struct timespec ts;
	struct rusage ru;
	long ns;

	if (getrusage(who, &ru) != 0)
		return (-EINVAL);

	ts.tv_sec = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec;
	ns = (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) * 1000;
	if (ns > NANOSEC) {
		ts.tv_sec += 1;
		ns -= NANOSEC;
	}
	ts.tv_nsec = ns;
	return ((uucopy(&ts, tp, sizeof (struct timespec)) < 0) ?  -EFAULT : 0);
}

long
lx_clock_gettime(int clock, struct timespec *tp)
{
	struct timespec ts;

	if (tp == NULL)
		return (-EFAULT);

	if (clock == LX_CLOCK_PROCESS_CPUTIME_ID) {
		return (get_cputime(RUSAGE_SELF, tp));
	} else if (clock == LX_CLOCK_THREAD_CPUTIME_ID) {
		return (get_cputime(RUSAGE_LWP, tp));
	}

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (clock_gettime(ltos_clock[clock], &ts) < 0)
		return (-errno);

	return ((uucopy(&ts, tp, sizeof (struct timespec)) < 0) ? -EFAULT : 0);
}

long
lx_clock_settime(int clock, struct timespec *tp)
{
	struct timespec ts;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (uucopy(tp, &ts, sizeof (struct timespec)) < 0)
		return (-EFAULT);

	return ((clock_settime(ltos_clock[clock], &ts) < 0) ? -errno : 0);
}

long
lx_clock_getres(int clock, struct timespec *tp)
{
	struct timespec ts;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (clock_getres(ltos_clock[clock], &ts) < 0)
		return (-errno);

	/* the timespec pointer is allowed to be NULL */
	if (tp == NULL)
		return (0);

	return ((uucopy(&ts, tp, sizeof (struct timespec)) < 0) ? -EFAULT : 0);
}

long
lx_clock_nanosleep(int clock, int flags, struct timespec *rqtp,
    struct timespec *rmtp)
{
	int ret = 0;
	int err;
	struct timespec rqt, rmt;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (uucopy(rqtp, &rqt, sizeof (struct timespec)) < 0)
		return (-EFAULT);

	/* the TIMER_RELTIME and TIMER_ABSTIME flags are the same on Linux */
	if ((err = clock_nanosleep(ltos_clock[clock], flags, &rqt, &rmt))
	    != 0) {
		if (err != EINTR)
			return (-err);
		ret = -EINTR;
		/*
		 * We fall through in case we have to pass back the remaining
		 * time.
		 */
	}

	/*
	 * Only copy values to rmtp if the timer is TIMER_RELTIME and rmtp is
	 * non-NULL.
	 */
	if (((flags & TIMER_RELTIME) == TIMER_RELTIME) && (rmtp != NULL) &&
	    (uucopy(&rmt, rmtp, sizeof (struct timespec)) < 0))
		return (-EFAULT);

	return (ret);
}

/*ARGSUSED*/
long
lx_adjtimex(void *tp)
{
	return (-EPERM);
}

/*
 * The Illumos timer_create man page says it accepts the following clocks:
 *   CLOCK_REALTIME (3)	wall clock
 *   CLOCK_VIRTUAL (1)	user CPU usage clock - No Backend
 *   CLOCK_PROF (2)	user and system CPU usage clock - No Backend
 *   CLOCK_HIGHRES (4)	non-adjustable, high-resolution clock
 * However, in reality the Illumos timer_create only accepts CLOCK_REALTIME
 * and CLOCK_HIGHRES, and since we can't use CLOCK_HIGHRES in a zone, we're
 * down to one clock.
 */
long
lx_timer_create(int clock, struct sigevent *lx_sevp, timer_t *tid)
{
	lx_sigevent_t lev;
	struct sigevent sev;

	if (clock < 0 || clock > LX_TIMER_MAX)
		return (-EINVAL);

	/* We have to convert the Linux sigevent layout to the Illumos layout */
	if (uucopy(lx_sevp, &lev, sizeof (lev)) < 0)
		return (-EFAULT);

	if (lev.lx_sigev_notify < 0 || lev.lx_sigev_notify > LX_SIGEV_MAX)
		return (-EINVAL);

	sev.sigev_notify = ltos_sigev[lev.lx_sigev_notify];
	sev.sigev_signo = ltos_signo[lev.lx_sigev_signo];
	sev.sigev_value = lev.lx_sigev_value;

	/*
	 * The sigevent sigev_notify_function and sigev_notify_attributes
	 * members are not used by timer_create, so no conversion is needed.
	 */

	return ((timer_create(ltos_timer[clock], &sev, tid) < 0) ? -errno : 0);
}

long
lx_timer_settime(timer_t tid, int flags, struct itimerspec *new_val,
    struct itimerspec *old_val)
{
	return ((timer_settime(tid, flags, new_val, old_val) < 0) ? -errno : 0);
}

long
lx_timer_gettime(timer_t tid, struct itimerspec *val)
{
	return ((timer_gettime(tid, val) < 0) ? -errno : 0);
}

long
lx_timer_getoverrun(timer_t tid)
{
	int val;

	val = timer_getoverrun(tid);
	return ((val < 0) ? -errno : val);
}

long
lx_timer_delete(timer_t tid)
{
	return ((timer_delete(tid) < 0) ? -errno : 0);
}
