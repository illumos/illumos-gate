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

#include "errno.h"
#include "string.h"
#include "stdlib.h"

#include "lp.h"
#include "filters.h"

/**
 ** delfilter() - DELETE A FILTER FROM FILTER TABLE
 **/

int
#if	defined(__STDC__)
delfilter (
	char *			name
)
#else
delfilter (name)
	char			*name;
#endif
{
	register _FILTER	*pf;


	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		trash_filters ();
		goto Done;
	}

	/*
	 * Don't need to check for ENOENT, because if it is set,
	 * well that's what we want to return anyway!
	 */
	if (!filters && get_and_load() == -1 /* && errno != ENOENT */ )
		return (-1);

	if (!(pf = search_filter(name))) {
		errno = ENOENT;
		return (-1);
	}

	free_filter (pf);
	for (; pf->name; pf++)
		*pf = *(pf+1);

	nfilters--;
	filters = (_FILTER *)Realloc(
		(char *)filters, (nfilters + 1) * sizeof(_FILTER)
	);
	if (!filters) {
		errno = ENOMEM;
		return (-1);
	}

/*	filters[nfilters].name = 0; */	/* last for loop above did this */

Done:	return (dumpfilters((char *)0));
}
