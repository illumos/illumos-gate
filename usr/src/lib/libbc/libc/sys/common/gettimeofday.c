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
 * Copyright (c) 1995 Sun Microsystems, Inc. All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tzfile.h>
#include <sys/time.h>

static int get_tzp_info(void);
extern long _timezone, _altzone;	/* from the base libc */


/*
 * The second parameter to gettimeofday() did not work correctly on
 * 4.x, and it was documented that localtime() should be used instead.
 * This is an attempt to provide correctly what 4.x meant to do. There
 * are shortcomings, however. See notes for DST_RUM and DST_AUSTALT.
 */

int
gettimeofday(tp, tzp)
struct timeval *tp;
struct timezone *tzp;
{
	int ret = 0;

	if (tp != NULL)
		if ((ret = _gettimeofday(tp)) == -1)
			maperror();

	/*
	 * We should call localtime() with the current time and
	 * set tz_minuteswest to _altzone/SECSPERMIN if tm_isdst
	 * is set. But we want to be bug-for-bug compatible with
	 * 4.x, which would never adjust for DST. Futher comments
	 * are in get_tzp_info().
	 */
	if (tzp != NULL) {
		_tzset();
		tzp->tz_dsttime = get_tzp_info();
		tzp->tz_minuteswest = _timezone/SECSPERMIN;
	}

	return(ret);
}

static int
get_tzp_info()
{
	char	*zonename = getenv("TZ");

	if ((zonename == NULL) || (*zonename == '\0'))
		return (DST_NONE);

	if ((strncmp(zonename, "US/", 3) == 0) ||
	    (strcmp(zonename, "PST8PDT") == 0) ||
	    (strcmp(zonename, "MST7MDT") == 0) ||
	    (strcmp(zonename, "CST6CDT") == 0) ||
	    (strcmp(zonename, "EST5EDT") == 0) ||
	    (strncmp(zonename, "America/", 8) == 0))
		return (DST_USA);

	if (strncmp(zonename, "Australia/", 10) == 0)
		return (DST_AUST);

	if (strcmp(zonename, "WET") == 0)
		return (DST_WET);

	if (strcmp(zonename, "MET") == 0)
		return (DST_MET);

	if (strcmp(zonename, "EET") == 0)
		return (DST_EET);

	if (strncmp(zonename, "Canada/", 7) == 0)
		return (DST_CAN);

	if ((strcmp(zonename, "GB") == 0) ||
	    (strcmp(zonename, "GB-Eire") == 0))
		return (DST_GB);

	/*
	 * what's the corresponding DST_RUM: Rumanian DST?
	 * There was not Rumanian timezone on 4.x.
	 */

	if (strcmp(zonename, "Turkey") == 0)
		return (DST_TUR);

	/*
	 * How do we differentiate between DST_AUST and DST_AUSTALT?
	 * It seems that all of our current Australia timezones do
	 * not have the 1986 shift, so we never will return DST_AUSTALT.
	 */

	return (DST_NONE);
}
