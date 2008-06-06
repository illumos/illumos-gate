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

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <limits.h>
/*
 * getdtablesize is implemented on top of getrlimit's
 * RLIMIT_NOFILE feature. The current (Soft) limit is returned.
 */
int
getdtablesize(void)
{
	struct rlimit rip;

	if (getrlimit(RLIMIT_NOFILE, &rip) == -1)
		return (-1);	/* can't happen */
	if (rip.rlim_cur == RLIM_INFINITY)
		return (INT_MAX);
	return ((int)rip.rlim_cur);
}
