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

#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** addlist() - ADD ITEM TO (char **) LIST
 **/

int
#if	defined(__STDC__)
addlist (
	char ***		plist,
	char *			item
)
#else
addlist (plist, item)
	register char		***plist,
				*item;
#endif
{
	register char		**pl;

	register int		n;

	if (*plist) {

		n = lenlist(*plist);

		for (pl = *plist; *pl; pl++)
			if (STREQU(*pl, item))
				break;

		if (!*pl) {

			n++;
			*plist = (char **)Realloc(
				(char *)*plist,
				(n + 1) * sizeof(char *)
			);
			if (!*plist) {
				errno = ENOMEM;
				return (-1);
			}
			(*plist)[n - 1] = Strdup(item);
			(*plist)[n] = 0;

		}

	} else {

		*plist = (char **)Malloc(2 * sizeof(char *));
		if (!*plist) {
			errno = ENOMEM;
			return (-1);
		}
		(*plist)[0] = Strdup(item);
		(*plist)[1] = 0;

	}

	return (0);
}
