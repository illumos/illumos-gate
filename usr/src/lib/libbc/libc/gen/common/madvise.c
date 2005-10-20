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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

/*
 * Function to provide advise to vm system to optimize it's
 *   characteristics for a particular application
 */

/*LINTLIBRARY*/
int
madvise(caddr_t addr, u_int len, int advice)
{
	if (len == 0) {
		errno = EINVAL;
		return (-1);
	}
	return (mctl(addr, len, MC_ADVISE, advice));
}

/*
 * This is only here so programs that use vadvise will not fail
 * because it is not in the bcp libc.
 */
int
vadvise(int param)
{
	return (0);
}
