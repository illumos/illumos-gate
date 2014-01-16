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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "errno.h"
#include "string.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** sprintlist() - FLATTEN (char **) LIST INTO (char *) LIST
 **/

char *
#if	defined(__STDC__)
sprintlist (
	char **			list
)
#else
sprintlist (list)
	char			**list;
#endif
{
	register char		**plist,
				*p,
				*q;

	char			*ret;

	int			len	= 0;


	if (!list || !*list)
		return (0);

	for (plist = list; *plist; plist++)
		len += strlen(*plist) + 1;

	if (!(ret = Malloc(len))) {
		errno = ENOMEM;
		return (0);
	}

	q = ret;
	for (plist = list; *plist; plist++) {
		p = *plist;
		while (*q++ = *p++)
			;
		q[-1] = ' ';
	}
	q[-1] = 0;

	return (ret);
}
