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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Implement timeout(9f), untimeout(9f) on top of
 * libc timer_create, timer_settime, etc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <time.h>

typedef void (*sigev_notify_func_t)(union sigval);

/*
 * We never actually reference anything in this array, using it
 * just as a collection of addresses mapped from/to int values.
 * It would be fine to take addresses even beyond the end, but
 * to avoid confusion it's sized larger than _TIMER_MAX (32).
 */
static char timeout_base[100];

timeout_id_t
timeout(void (*func)(void *), void *arg, clock_t delta)
{
	struct sigevent sev;
	struct itimerspec its;
	timer_t tid;
	int err;

	if (delta <= 0)
		return (NULL);

	bzero(&sev, sizeof (sev));
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_value.sival_ptr = arg;
	sev.sigev_notify_function = (sigev_notify_func_t)(uintptr_t)func;
	err = timer_create(CLOCK_REALTIME, &sev, &tid);
	if (err != 0)
		return (NULL);

	bzero(&its, sizeof (its));
	TICK_TO_TIMESTRUC(delta, &its.it_value);
	err = timer_settime(tid, 0, &its, NULL);
	if (err != 0) {
		(void) timer_delete(tid);
		return (NULL);
	}

	/* Convert return to a (sort of) pointer */
	return (timeout_base + tid);
}

clock_t
untimeout(timeout_id_t id_arg)
{
	struct itimerspec its, oits;
	char *id_cp = id_arg;
	clock_t delta;
	timer_t tid;
	int rc;

	if (id_arg == NULL)
		return (-1);

	/* Convert id_arg back to small integer. */
	tid = (int)(id_cp - timeout_base);

	bzero(&its, sizeof (its));
	bzero(&oits, sizeof (oits));
	rc = timer_settime(tid, 0, &its, &oits);
	if (rc != 0) {
		delta = 0;
	} else {
		delta = TIMESTRUC_TO_TICK(&oits.it_value);
		if (delta < 0)
			delta = 0;
	}

	rc = timer_delete(tid);
	if (rc != 0)
		delta = -1;

	return (delta);
}
