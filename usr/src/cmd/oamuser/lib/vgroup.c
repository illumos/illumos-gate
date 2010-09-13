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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<errno.h>
#include	<limits.h>
#include	<sys/param.h>
#include	<users.h>
#include	<userdefs.h>

extern int valid_gid(gid_t, struct group **);

static int isalldigit(char *);

/*
 *	validate a group name or number and return the appropriate
 *	group structure for it.
 */
int
valid_group(char *group, struct group **gptr, int *warning)
{
	int r, warn;
	long l;
	char *ptr;
	struct group *grp;

	*warning = 0;

	if (!isalldigit(group))
		return (valid_gname(group, gptr, warning));

	/*
	 * There are only digits in group name.
	 * strtol() doesn't return negative number here.
	 */
	errno = 0;
	l = strtol(group, &ptr, 10);
	if ((l == LONG_MAX && errno == ERANGE) || l > MAXUID) {
		r = TOOBIG;
	} else {
		if ((r = valid_gid((gid_t)l, &grp)) == NOTUNIQUE) {
			/* It is a valid existing gid */
			if (gptr != NULL)
				*gptr = grp;
			return (NOTUNIQUE);
		}
	}
	/*
	 * It's all digit, but not a valid gid nor an existing gid.
	 * There might be an existing group name of all digits.
	 */
	if (valid_gname(group, &grp, &warn) == NOTUNIQUE) {
		/* It does exist */
		*warning = warn;
		if (gptr != NULL)
			*gptr = grp;
		return (NOTUNIQUE);
	}
	/*
	 * It isn't either existing gid or group name. We return the
	 * error code from valid_gid() assuming that given string
	 * represents an integer GID.
	 */
	return (r);
}

static int
isalldigit(char *str)
{
	while (*str != '\0') {
		if (!isdigit((unsigned char)*str))
			return (0);
		str++;
	}
	return (1);
}
