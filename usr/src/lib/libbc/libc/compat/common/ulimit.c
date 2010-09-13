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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

long
ulimit(int cmd, long newlimit)
{
	struct rlimit rlimit;

	switch (cmd) {

	case 1:
		if (getrlimit(RLIMIT_FSIZE, &rlimit) < 0)
			return(-1);
		return (rlimit.rlim_cur / 512);

	case 2:
		rlimit.rlim_cur = rlimit.rlim_max = newlimit * 512;
		return (setrlimit(RLIMIT_FSIZE, &rlimit));

	case 3:
		if (getrlimit(RLIMIT_DATA, &rlimit) < 0)
			return(-1);
		return (rlimit.rlim_cur);

	case 4:
		return (getdtablesize());

	default:
		errno = EINVAL;
		return (-1);
	}
}
