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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _time = time
#pragma weak _stime = stime

#include "lint.h"
#include <unistd.h>
#include <time.h>

time_t
time(time_t *tloc)
{
	extern time_t __time(void);	/* the raw system call */
	time_t rval;

	rval = __time();
	if (tloc)
		*tloc = rval;
	return (rval);
}

int
stime(const time_t *tp)
{
	extern int __stime(time_t);	/* the raw system call */

	return (__stime(*tp));
}
