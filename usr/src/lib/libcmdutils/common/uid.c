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
 * Copyright (c) 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
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
#include <pwd.h>
#include <libcmdutils.h>

static int findunuseduid(uid_t start, uid_t stop, uid_t *ret);
static boolean_t isreserveduid(uid_t uid);

/*
 * Find the highest unused uid. If the highest unused uid is "stop",
 * then attempt to find a hole in the range. Returns 0 on success.
 */
int
findnextuid(uid_t start, uid_t stop, uid_t *ret)
{
	uid_t uid = start;
	struct passwd *pwd;
	boolean_t overflow = B_FALSE;

	setpwent();
	for (pwd = getpwent(); pwd != NULL; pwd = getpwent()) {
		if (isreserveduid(pwd->pw_uid))		/* Skip reserved IDs */
			continue;
		if (pwd->pw_uid >= uid) {
			if (pwd->pw_uid == stop) {	/* Overflow check */
				overflow = B_TRUE;
				break;
			}
			uid = pwd->pw_uid + 1;
		}
	}
	if (pwd == NULL && errno != 0) {
		endpwent();
		return (-1);
	}
	endpwent();
	if (overflow == B_TRUE)				/* Find a hole */
		return (findunuseduid(start, stop, ret));
	while (isreserveduid(uid) && uid < stop)	/* Skip reserved IDs */
		uid++;
	*ret = uid;
	return (0);
}

/*
 * Check to see whether the uid is a reserved uid
 * -- nobody, noaccess or nobody4
 */
static boolean_t
isreserveduid(uid_t uid)
{
	return (uid == 60001 || uid == 60002 || uid == 65534);
}

/*
 * findunuseduid() attempts to return the next valid usable id between the
 * supplied upper and lower limits. Returns 0 on success.
 */
static int
findunuseduid(uid_t start, uid_t stop, uid_t *ret)
{
	uid_t uid;

	for (uid = start; uid <= stop; uid++) {
		if (isreserveduid(uid))
			continue;
		if (getpwuid(uid) == NULL) {
			if (errno != 0)
				return (-1);
			break;
		}
	}
	if (uid > stop)
		return (-1);
	*ret = uid;
	return (0);
}
