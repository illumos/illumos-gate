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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
	  /* from UCB 4.1 83/05/30 */

#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

/*
 * Backwards compatible nice.
 */
int
nice(incr)
	int incr;
{
	register int prio;
	int serrno;

	/* put in brain-damaged upper range checking */
	if ((incr > 40) && (geteuid() != 0)) {
		errno = EPERM;
		return (-1);
	}

	serrno = errno;
	errno = 0;
	prio = getpriority(PRIO_PROCESS, 0);
	if (prio == -1 && errno)
		return (-1);
	prio += incr;
	if (prio < -20)
		prio = -20;
	else if (prio > 19)
		prio = 19;
	if (setpriority(PRIO_PROCESS, 0, prio) == -1) {
		/*
		 * 4.3BSD stupidly returns EACCES on an attempt by a
		 * non-super-user process to lower a priority; map
		 * it to EPERM.
		 */
		if (errno == EACCES)
			errno = EPERM;
		return (-1);
	}
	errno = serrno;
	return (prio);
}
