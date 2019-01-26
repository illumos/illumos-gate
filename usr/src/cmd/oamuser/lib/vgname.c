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
/*	  All Rights Reserved	*/


/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<stdio.h>
#include	<ctype.h>
#include	<userdefs.h>
#include	<users.h>

/*
 * validate string given as group name.
 */
int
valid_gname(char *group, struct group **gptr, int *warning)
{
	struct group *t_gptr;
	char *ptr = group;
	char c;
	int len = 0;
	int badchar = 0;

	*warning = 0;
	if (!group || !*group)
		return (INVALID);

	for (c = *ptr; c != '\0'; ptr++, c = *ptr) {
		len++;
		if (!isprint(c) || (c == ':') || (c == '\n'))
			return (INVALID);
		if (!(islower(c) || isdigit(c)))
			badchar++;
	}

	/*
	 * XXX constraints causes some operational/compatibility problem.
	 * This has to be revisited in the future as ARC/standards issue.
	 */
	if (len > MAXGLEN - 1)
		*warning = *warning | WARN_NAME_TOO_LONG;
	if (badchar != 0)
		*warning = *warning | WARN_BAD_GROUP_NAME;

	if ((t_gptr = getgrnam(group)) != NULL) {
		if (gptr) *gptr = t_gptr;
		return (NOTUNIQUE);
	}
	return (UNIQUE);
}
