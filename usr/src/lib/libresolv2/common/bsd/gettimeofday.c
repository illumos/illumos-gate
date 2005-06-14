/*
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef LINT
static const char rcsid[] = "$Id: gettimeofday.c,v 8.4 1999/10/13 16:39:21 vixie Exp $";
#endif


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "port_before.h"
#include "port_after.h"

#if !defined(NEED_GETTIMEOFDAY)
int __bindcompat_gettimeofday;
#else
int
gettimeofday(struct timeval *tvp, struct _TIMEZONE *tzp) {
	time_t clock, time(time_t *);

	if (time(&clock) == (time_t) -1)
		return (-1);
	if (tvp) {
		tvp->tv_sec = clock;
		tvp->tv_usec = 0;
	}
	if (tzp) {
		tzp->tz_minuteswest = 0;
		tzp->tz_dsttime = 0;
	}
	return (0);
}
#endif /*NEED_GETTIMEOFDAY*/
