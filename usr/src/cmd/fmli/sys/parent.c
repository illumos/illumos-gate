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


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<stdio.h>
#include	"wish.h"
#include	"sizes.h"

char *
parent(path)
register char *path;
{
	register char	*dst;
	register char	*place;
	register bool	slash;
	static char	dirname[PATHSIZ];

	/* first, put a "well-behaved" path into dirname */
	place = NULL;
	slash = FALSE;
	for (dst = dirname; *path; path++)
		if (*path == '/')
			slash = TRUE;
		else {
			if (slash) {
				place = dst;
				*dst++ = '/';
				slash = FALSE;
			}
			*dst++ = *path;
		}
	if (dst == dirname) {
		place = dst;
		*dst++ = '/';
	}
	if (place == NULL) {
		dirname[0] = '.';
		dirname[1] = '\0';
	}
	else if (place == dirname)
		dirname[1] = '\0';
	else
		*place = '\0';
	return dirname;
}
