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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include "libc.h"

/*
 * Get the time of day information.
 * BSD compatibility on top of SVr4 facilities:
 * u_sec always zero, and don't do anything with timezone pointer.
 */

/*
 * This is defined in sys/gettimeofday.s
 * This extern cannot be in libc.h due to name conflict with port/gen/synonyms.h
 */
extern int _gettimeofday(struct timeval *);

/*ARGSUSED*/
int
gettimeofday(struct timeval *tp, void *tzp)
{
	if (tp == NULL)
		return (0);

	return (_gettimeofday(tp));
}

/*
 * Set the time.
 * Don't do anything with the timezone information.
 */

/*ARGSUSED*/
int
settimeofday(struct timeval *tp, void *tzp)
{
	time_t t;		/* time in seconds */

	if (tp == NULL)
		return (0);

	t = (time_t) tp->tv_sec;
	if (tp->tv_usec >= 500000)
		/* round up */
		t++;

	return (stime(&t));
}
