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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 32-bit only version of gettimeofday
 */

#include <sys/time.h>
#include <sys/types32.h>
#include <meta.h>

int
meta_gettimeofday(md_timeval32_t *tv32)
{
	struct timeval tv;
	int retval;

	if (tv32 == NULL)
		return (0);

	if ((retval = gettimeofday(&tv, NULL)) == 0) {
	    tv32->tv_sec = (time32_t)tv.tv_sec;
	    tv32->tv_usec = (int32_t)tv.tv_usec;
	    return (0);
	}

	return (retval);
}
