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
 * Copyright 2016 Joyent, Inc.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <sys/sysconfig.h>
#include <sys/sysmacros.h>

/* Need direct access to _sysconfig to query NCPU */
extern long _sysconfig(int);


static int
mktimer(timer_t *timer)
{
	struct sigevent sev;
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = timer;

	return (timer_create(CLOCK_MONOTONIC, &sev, timer));
}

int
main()
{
	long ncpu;
	size_t limit;
	timer_t *timers, timer_overage;

	/* Query NCPU with private sysconfig param */
	ncpu = _sysconfig(_CONFIG_NPROC_NCPU);
	assert(ncpu > 0 && ncpu < INT32_MAX);

	/* Current specified limit is 4 * NCPU */
	limit = 4 * ncpu;
	timers = calloc(limit + 1, sizeof (timer_t));
	assert(timers != NULL);

	/* Slowly walk up to the limit doing creations/deletions */
	for (int i = 1; i <= limit; i = MIN(limit, i*2)) {
		for (int j = 0; j < i; j++) {
			assert(mktimer(&timers[j]) == 0);
		}

		/*
		 * Attempt to allocate one additional timer if we've reached
		 * the assumed limit.
		 */
		if (i == limit) {
			assert(mktimer(&timer_overage) == -1);
		}

		for (int j = 0; j < i; j++) {
			assert(timer_delete(timers[j]) == 0);
		}

		/* Bail out if we've finished at the limit */
		if (i == limit)
			break;
	}


	return (0);
}
