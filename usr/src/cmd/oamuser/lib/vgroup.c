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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<users.h>
#include	<userdefs.h>

extern int valid_gid();

/*
 *	validate a group name or number and return the appropriate
 *	group structure for it.
 */
int
valid_group(char *group, struct group **gptr, int *warning)
{
	gid_t gid;
	char *ptr;

	*warning = 0;
	if (isdigit(*group)) {
		gid = (gid_t) strtol(group, &ptr, (int) 10);
		if (! *ptr)
		return (valid_gid(gid, gptr));
	}
	for (ptr = group; *ptr != NULL; ptr++) {
		if (!isprint(*ptr) || (*ptr == ':') || (*ptr == '\n'))
			return (INVALID);
	}

	/* length checking and other warnings are done in valid_gname() */
	return (valid_gname(group, gptr, warning));
}
