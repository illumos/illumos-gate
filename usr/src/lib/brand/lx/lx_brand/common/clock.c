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
 * Copyright 2016 Joyent, Inc.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <lx_signum.h>

/*
 * Translating from the Linux clock types to the illumos types is a bit of a
 * mess.
 *
 * Linux uses different values for it clock identifiers, so we have to do basic
 * translations between the two.  Thankfully, both Linux and illumos implement
 * the same POSIX SUSv3 clock types, so the semantics should be identical.
 *
 * However, CLOCK_REALTIME and CLOCK_HIGHRES (CLOCK_MONOTONIC) are the only two
 * clock backends currently implemented on illumos. Functions in the kernel
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
 * Although an lx zone has the proc_clock_highres privilege (required to use
 * the CLOCK_HIGHRES clock), it will be unusable by an unprivileged user for
 * timer_create or timerfd_create. See the comment on clock_highres_timer_create
 * for full details. We currently map the Linux CLOCK_MONOTONIC (which
 * corresponds to the illumos CLOCK_HIGHRES) to the illumos CLOCK_REALTIME
 * in the ltos_timer array. This is generally fine since, unlike a standalone
 * system, zone's are not allowed to adjust the sytem's clock.
 */

#define	CLOCK_RT_SLOT	0

#define	LX_CLOCK_REALTIME	0
#define	LX_CLOCK_MONOTONIC	1

static int ltos_clock[] = {
	CLOCK_REALTIME,			/* LX_CLOCK_REALTIME */
	CLOCK_HIGHRES,			/* LX_CLOCK_MONOTONIC */
	CLOCK_PROCESS_CPUTIME_ID,	/* LX_CLOCK_PROCESS_CPUTIME_ID */
	CLOCK_THREAD_CPUTIME_ID,	/* LX_CLOCK_THREAD_CPUTIME_ID */
	CLOCK_HIGHRES,			/* LX_CLOCK_MONOTONIC_RAW */
	CLOCK_REALTIME,			/* LX_CLOCK_REALTIME_COARSE */
	CLOCK_HIGHRES			/* LX_CLOCK_MONOTONIC_COARSE */
};

/*
 * Since the illumos CLOCK_HIGHRES clock requires elevated privs, which can
 * lead to a DOS, we use the only other option (CLOCK_REALTIME) when given
 * LX_CLOCK_MONOTONIC. Note that this thinking is somewhat misguided and should
 * be revisited, since it implies that root in an lx zone can never be
 * compromised or would never DOS the system.
 */
static int ltos_timer[] = {
	CLOCK_REALTIME,
	CLOCK_REALTIME,
	CLOCK_THREAD_CPUTIME_ID,	/* XXX thread, not process but fails */
	CLOCK_THREAD_CPUTIME_ID,
	CLOCK_REALTIME,
	CLOCK_REALTIME,
	CLOCK_REALTIME
};

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
	SIGEV_THREAD	/* Linux SIGEV_THREAD_ID -- see lx_sigev_thread_id() */
};

#define	LX_SIGEV_MAX		(sizeof (ltos_sigev) / sizeof (ltos_sigev[0]))
#define	LX_SIGEV_THREAD_ID	4

long
lx_clock_nanosleep(int clock, int flags, struct timespec *rqtp,
    struct timespec *rmtp)
{
	int ret = 0;
	int err;
	struct timespec rqt, rmt;

	if (clock < 0 || clock >= LX_CLOCK_MAX)
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
 * Notification function for use with native SIGEV_THREAD in order to
 * emulate Linux SIGEV_THREAD_ID. Native SIGEV_THREAD is used as the
 * timer mechanism and B_SIGEV_THREAD_ID performs the actual event
 * delivery to the appropriate lx tid.
 */
static void
lx_sigev_thread_id(union sigval sival)
{
	lx_sigevent_t *lev = (lx_sigevent_t *)sival.sival_ptr;
	syscall(SYS_brand, B_SIGEV_THREAD_ID, lev->lx_sigev_un.lx_tid,
	    lev->lx_sigev_signo, lev->lx_sigev_value.sival_ptr);
	free(lev);
}


/*
 * The illumos timer_create man page says it accepts the following clocks:
 *   CLOCK_REALTIME (3)	wall clock
 *   CLOCK_VIRTUAL (1)	user CPU usage clock - No Backend
 *   CLOCK_PROF (2)	user and system CPU usage clock - No Backend
 *   CLOCK_HIGHRES (4)	non-adjustable, high-resolution clock
 * However, in reality the illumos timer_create only accepts CLOCK_REALTIME
 * and CLOCK_HIGHRES, and since only root could use CLOCK_HIGHRES in an lx zone,
 * we're down to one clock.
 *
 * Linux has complicated support for clock IDs. For example, the
 * clock_getcpuclockid() function can return a negative clock_id. See the Linux
 * source and the comment in include/linux/posix-timers.h (above CLOCKFD) which
 * describes clock file descriptors and shows how they map to a virt. or sched.
 * clock ID. A process can pass one of these negative IDs to timer_create so we
 * need to convert it and we currently only allow CLOCK_PROCESS_CPUTIME_ID
 * against the current process as the input.
 */
long
lx_timer_create(int clock, struct sigevent *lx_sevp, timer_t *tid)
{
	lx_sigevent_t lev;
	struct sigevent sev;

	if (clock < 0) {
		if (clock != 0xfffffffe)
			return (-EINVAL);
		clock = CLOCK_RT_SLOT;	/* force our use of CLOCK_REALTIME */
	}

	if (clock >= LX_TIMER_MAX)
		return (-EINVAL);

	/* We have to convert the Linux sigevent layout to the illumos layout */
	if (uucopy(lx_sevp, &lev, sizeof (lev)) < 0)
		return (-EFAULT);

	if (lev.lx_sigev_notify < 0 || lev.lx_sigev_notify > LX_SIGEV_MAX)
		return (-EINVAL);

	sev.sigev_notify = ltos_sigev[lev.lx_sigev_notify];
	sev.sigev_signo = lx_ltos_signo(lev.lx_sigev_signo, 0);
	sev.sigev_value = lev.lx_sigev_value;

	/*
	 * The signal number is meaningless in SIGEV_NONE, Linux
	 * accepts any value. We convert invalid signals to 0 so other
	 * parts of lx signal handling don't break.
	 */
	if ((sev.sigev_notify != SIGEV_NONE) && (sev.sigev_signo == 0))
		return (-EINVAL);

	/*
	 * Assume all Linux libc implementations map SIGEV_THREAD to
	 * SIGEV_THREAD_ID and ignore passed-in attributes.
	 */
	sev.sigev_notify_attributes = NULL;

	if (lev.lx_sigev_notify == LX_SIGEV_THREAD_ID) {
		pid_t caller_pid = getpid();
		pid_t target_pid;
		lwpid_t ignore;
		lx_sigevent_t *lev_copy;

		if (lx_lpid_to_spair(lev.lx_sigev_un.lx_tid,
		    &target_pid, &ignore) != 0)
			return (-EINVAL);

		/*
		 * The caller of SIGEV_THREAD_ID must be in the same
		 * process as the target thread.
		 */
		if (caller_pid != target_pid)
			return (-EINVAL);

		/*
		 * Pass the original lx sigevent_t to the native
		 * notify function so that it may pass it to the lx
		 * helper thread. It is the responsibility of
		 * lx_sigev_thread_id() to free lev_copy after the
		 * information is relayed to lx.
		 *
		 * If the calling process is forked without an exec
		 * after this copy but before the timer fires then
		 * lev_copy will leak in the child. This is acceptable
		 * given the rarity of this event, the miniscule
		 * amount leaked, and the fact that the memory is
		 * reclaimed when the proc dies. It is firmly in the
		 * land of "good enough".
		 */
		lev_copy = malloc(sizeof (lx_sigevent_t));
		if (lev_copy == NULL)
			return (-ENOMEM);

		if (uucopy(&lev, lev_copy, sizeof (lx_sigevent_t)) < 0) {
			free(lev_copy);
			return (-EFAULT);
		}

		sev.sigev_notify_function = lx_sigev_thread_id;
		sev.sigev_value.sival_ptr = lev_copy;
	}

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

long
lx_timerfd_create(int clockid, int flags)
{
	int r;

	/* These are the only two valid values. LTP tests for this. */
	if (clockid != LX_CLOCK_REALTIME && clockid != LX_CLOCK_MONOTONIC)
		return (-EINVAL);

	r = timerfd_create(ltos_timer[clockid], flags);
	/*
	 * As with the eventfd case, we return a slightly less jarring
	 * error condition if we cannot open /dev/timerfd.
	 */
	if (r == -1 && errno == ENOENT)
		return (-ENOTSUP);

	return (r == -1 ? -errno : r);
}

long
lx_timerfd_settime(int fd, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
	int r = timerfd_settime(fd, flags, value, ovalue);

	return (r == -1 ? -errno : r);
}

long
lx_timerfd_gettime(int fd, struct itimerspec *value)
{
	int r = timerfd_gettime(fd, value);

	return (r == -1 ? -errno : r);
}
