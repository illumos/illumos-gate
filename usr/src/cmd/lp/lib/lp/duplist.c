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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "errno.h"
#include "string.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** duplist() - DUPLICATE A LIST OF STRINGS
 **/

char **
#if	defined(__STDC__)
duplist (
	char **			src
)
#else
duplist (src)
	register char		**src;
#endif
{
	register char		**dst;

	register int		nitems,
				n;

	if (!src || !*src)
		return (0);

	nitems = lenlist(src);
	if (!(dst = (char **)Malloc((nitems + 1) * sizeof(char *)))) {
		errno = ENOMEM;
		return (0);
	}

	for (n = 0; n < nitems; n++)
		if (!(dst[n] = Strdup(src[n]))) {
			while (n--)
				Free (dst[n]);
			Free ((char *)dst);
			errno = ENOMEM;
			return (0);
		}
	dst[nitems] = 0;

	return (dst);
}

