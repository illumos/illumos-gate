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



#include "thr_uberdata.h"
#include <cp_defs.h>

extern int __clock_gettime_sys(clockid_t, timespec_t *);

int
__clock_gettime(clockid_t clock_id, timespec_t *tp)
{
	comm_page_t *cp = (comm_page_t *)__uberdata.ub_comm_page;

	if (cp != NULL && __cp_can_gettime(cp) != 0) {
		switch (clock_id) {
		case __CLOCK_REALTIME0:
		case CLOCK_REALTIME:
			return (__cp_clock_gettime_realtime(cp, tp));

		case CLOCK_MONOTONIC:
			return (__cp_clock_gettime_monotonic(cp, tp));

		default:
			/* Fallback */
			break;
		}
	}
	return (__clock_gettime_sys(clock_id, tp));
}
