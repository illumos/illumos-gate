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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013 RackTop Systems.
 */

#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <userdefs.h>
#include <grp.h>
#include <libcmdutils.h>

static int findunusedgid(gid_t start, gid_t stop, gid_t *ret);
static boolean_t isreservedgid(gid_t gid);

/*
 * Find the highest unused uid. If the highest unused gid is "stop",
 * then attempt to find a hole in the range. Returns 0 on success.
 */
int
findnextgid(gid_t start, gid_t stop, gid_t *ret)
{
	gid_t gid = start;
	struct group *grp;
	boolean_t overflow = B_FALSE;

	setgrent();
	for (grp = getgrent(); grp != NULL; grp = getgrent()) {
		if (isreservedgid(grp->gr_gid))		/* Skip reserved IDs */
			continue;
		if (grp->gr_gid >= gid) {
			if (grp->gr_gid == stop) {	/* Overflow check */
				overflow = B_TRUE;
				break;
			}
			gid = grp->gr_gid + 1;
		}
	}
	if (grp == NULL && errno != 0) {
		endgrent();
		return (-1);
	}
	endgrent();
	if (overflow == B_TRUE)				/* Find a hole */
		return (findunusedgid(start, stop, ret));
	while (isreservedgid(gid) && gid < stop)	/* Skip reserved IDs */
		gid++;
	*ret = gid;
	return (0);
}

/*
 * Check to see whether the gid is a reserved gid
 * -- nobody, noaccess or nogroup
 */
static boolean_t
isreservedgid(gid_t gid)
{
	return (gid == 60001 || gid == 60002 || gid == 65534);
}

/*
 * findunusedgid() attempts to return the next valid usable id between the
 * supplied upper and lower limits. Returns 0 on success.
 */
static int
findunusedgid(gid_t start, gid_t stop, gid_t *ret)
{
	gid_t gid;

	for (gid = start; gid <= stop; gid++) {
		if (isreservedgid(gid))
			continue;
		if (getgrgid(gid) == NULL) {
			if (errno != 0)
				return (-1);
			break;
		}
	}
	if (gid > stop)
		return (-1);
	*ret = gid;
	return (0);
}
