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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "sigev_thread.h"

/*
 * System call wrappers found elsewhere in libc (common/sys/__clock_timer.s).
 */
extern int __clock_getres(clockid_t, timespec_t *);
extern int __clock_gettime(clockid_t, timespec_t *);
extern int __clock_settime(clockid_t, const timespec_t *);
extern hrtime_t __gethrtime(void);
extern int __timer_create(clockid_t, struct sigevent *, timer_t *);
extern int __timer_delete(timer_t);
extern int __timer_getoverrun(timer_t);
extern int __timer_gettime(timer_t, itimerspec_t *);
extern int __timer_settime(timer_t, int, const itimerspec_t *, itimerspec_t *);

/*
 * Array of pointers to tcd's, indexed by timer id.
 * No more than 'timer_max' timers can be created by any process.
 */
int timer_max = 0;
thread_communication_data_t **timer_tcd;
static pthread_once_t timer_once = PTHREAD_ONCE_INIT;

static void
timer_init(void)
{
	timer_max = (int)_sysconf(_SC_TIMER_MAX);
	timer_tcd = malloc(timer_max * sizeof (*timer_tcd));
	(void) memset(timer_tcd, 0, timer_max * sizeof (*timer_tcd));
}

int
clock_getres(clockid_t clock_id, timespec_t *res)
{
	return (__clock_getres(clock_id, res));
}

int
clock_gettime(clockid_t clock_id, timespec_t *tp)
{
	return (__clock_gettime(clock_id, tp));
}

int
clock_settime(clockid_t clock_id, const timespec_t *tp)
{
	return (__clock_settime(clock_id, tp));
}

hrtime_t
gethrtime(void)
{
	return (__gethrtime());
}

int
timer_create(clockid_t clock_id, struct sigevent *sigevp, timer_t *timerid)
{
	struct sigevent sigevent;
	port_notify_t port_notify;
	thread_communication_data_t *tcdp;
	int sigev_thread = 0;
	int rc;

	(void) pthread_once(&timer_once, timer_init);

	if (sigevp != NULL &&
	    sigevp->sigev_notify == SIGEV_THREAD &&
	    sigevp->sigev_notify_function != NULL) {
		sigev_thread = 1;
		tcdp = setup_sigev_handler(sigevp, TIMER);
		if (tcdp == NULL)
			return (-1);
		/* copy the sigevent structure so we can modify it */
		sigevent = *sigevp;
		sigevp = &sigevent;
		port_notify.portnfy_port = tcdp->tcd_port;
		port_notify.portnfy_user = NULL;
		sigevp->sigev_value.sival_ptr = &port_notify;
	}

	rc = __timer_create(clock_id, sigevp, timerid);

	if (sigev_thread) {
		if (rc == 0) {
			if ((rc = launch_spawner(tcdp)) != 0)
				(void) __timer_delete(*timerid);
			else
				timer_tcd[*timerid] = tcdp;
		}
		if (rc != 0)
			free_sigev_handler(tcdp);
	}

	return (rc);
}

int
timer_delete(timer_t timerid)
{
	int rc;

	if ((rc = del_sigev_timer(timerid)) == 0)
		return (__timer_delete(timerid));
	else
		return (rc);
}

int
timer_getoverrun(timer_t timerid)
{
	return (__timer_getoverrun(timerid) + sigev_timer_getoverrun(timerid));
}

int
timer_gettime(timer_t timerid, itimerspec_t *value)
{
	return (__timer_gettime(timerid, value));
}

int
timer_settime(timer_t timerid, int flags, const itimerspec_t *value,
    itimerspec_t *ovalue)
{
	return (__timer_settime(timerid, flags, value, ovalue));
}

/*
 * Cleanup after fork1() in the child process.
 */
void
postfork1_child_sigev_timer(void)
{
	thread_communication_data_t *tcdp;
	int timer;

	for (timer = 0; timer < timer_max; timer++) {
		if ((tcdp = timer_tcd[timer]) != NULL) {
			timer_tcd[timer] = NULL;
			tcd_teardown(tcdp);
		}
	}
}
