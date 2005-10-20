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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * POSIX.1 compatible setgroups() routine
 * This is needed while gid_t is not the same size as int (or whatever the
 * syscall is using at the time).
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/syscall.h>

int
setgroups(int ngroups, gid_t grouplist[])
{
	int	glist[NGROUPS];	/* setgroups() syscall expects ints */
	int	i;	/* loop control */

	if (ngroups > NGROUPS) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < ngroups; i++)
		glist[i] = (int)grouplist[i];
	return (_syscall(SYS_setgroups, ngroups, glist));
}
