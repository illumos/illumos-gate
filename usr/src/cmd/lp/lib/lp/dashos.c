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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"

#include "lp.h"

#define issep(X)	strchr(LP_WS, X)

/**
 ** dashos() - PARSE -o OPTIONS, (char *) --> (char **)
 **/

char **
#if	defined(__STDC__)
dashos (
	char *			o
)
#else
dashos (o)
	register char		*o;
#endif
{
	register char		quote,
				c,
				*option;

	char			**list	= 0;

	if (!o)
		return(0);

	while (*o) {

		while (*o && issep(*o))
			o++;

		for (option = o; *o && !issep(*o); o++)
			if (strchr(LP_QUOTES, (quote = *o)))
				for (o++; *o && *o != quote; o++)
					if (*o == '\\' && o[1])
						o++;

		if (option < o) {
			c = *o;
			*o = 0;
			addlist (&list, option);
			*o = c;
		}

	}
	return (list);
}
