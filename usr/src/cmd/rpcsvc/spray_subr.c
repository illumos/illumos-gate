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
 *
 * Copyright 1985 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <rpcsvc/spray.h>

static spraycumul cumul;
static spraytimeval start_time;

void *
sprayproc_spray_1(argp, clnt)
	sprayarr *argp;
	CLIENT *clnt;
{
	cumul.counter++;
	return ((void *)0);
}

spraycumul *
sprayproc_get_1(argp, clnt)
	void *argp;
	CLIENT *clnt;
{
	gettimeofday((struct timeval *)&cumul.clock, 0);
	if (cumul.clock.usec < start_time.usec) {
		cumul.clock.usec += 1000000;
		cumul.clock.sec -= 1;
	}
	cumul.clock.sec -= start_time.sec;
	cumul.clock.usec -= start_time.usec;
	return (&cumul);
}

void *
sprayproc_clear_1(argp, clnt)
	void *argp;
	CLIENT *clnt;
{
	static char res;

	cumul.counter = 0;
	gettimeofday((struct timeval *)&start_time, 0);
	(void) memset((char *)&res, 0, sizeof(res));
	return ((void *)&res);
}
