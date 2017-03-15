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
 * Copyright (c) 2017, Joyent, Inc.
 */


#include "thr_uberdata.h"
#include <cp_defs.h>

#pragma weak _gettimeofday = gettimeofday

extern int __clock_gettime_sys(clockid_t, timespec_t *);

int
gettimeofday(struct timeval *tv, void *tz)
{
	comm_page_t *cp = (comm_page_t *)__uberdata.ub_comm_page;

	/*
	 * Perform a NULL check before attempting to store the result directly.
	 * The old fasttrop logic would perform this same check, but after the
	 * call into hrestime().
	 */
	if (tv == NULL) {
		return (0);
	}

	/*
	 * Since timeval and timespec structs feature the same effective types
	 * and layout of their members, the conversion can be done in-place.
	 */
	if (cp != NULL && __cp_can_gettime(cp) != 0) {
		__cp_clock_gettime_realtime(cp, (struct timespec *)tv);
	} else {
		__clock_gettime_sys(CLOCK_REALTIME, (struct timespec *)tv);
	}
	/* Convert from tv_nsec to tv_usec */
	tv->tv_usec /= 1000;
	return (0);
}
