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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _initgroups = initgroups

#include "lint.h"
#include <stdlib.h>
#include <errno.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>

/* Private interface to the groups code in getgrnam.c */
extern int _getgroupsbymember(const char *, gid_t[], int, int);

int
initgroups(const char *uname, gid_t agroup)
{
	gid_t *groups;
	long ngroups_max;
	int ngroups;
	int errsave, retsave;

	if ((ngroups_max = sysconf(_SC_NGROUPS_MAX)) < 0) {
		/* ==== Hope sysconf() set errno to something sensible */
		return (-1);
	}
	/*
	 * ngroups_max is the maximum number of supplemental groups per
	 * process. if no supplemental groups are allowed, we're done.
	 */
	if (ngroups_max == 0)
		return (0);

	if ((groups = (gid_t *)calloc(ngroups_max, sizeof (gid_t))) == 0) {
		errno = ENOMEM;
		return (-1);
	}
	groups[0] = agroup;

	ngroups = _getgroupsbymember(uname, groups, (int)ngroups_max,
	    (agroup <= MAXUID) ? 1 : 0);
	if (ngroups < 0) {
		/* XXX -- man page does not define a value for errno in */
		/* this case.  Should be looked into sometime.	*/
		free(groups);
		return (-1);
	}

	retsave = setgroups(ngroups, groups);
	errsave = errno;

	free(groups);

	errno = errsave;
	return (retsave);
}
