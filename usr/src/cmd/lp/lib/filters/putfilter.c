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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "errno.h"
#include "string.h"
#include "stdlib.h"

#include "lp.h"
#include "filters.h"

/**
 ** putfilter() - PUT FILTER INTO FILTER TABLE
 **/

int
#if	defined(__STDC__)
putfilter (
	char *			name,
	FILTER *		flbufp
)
#else
putfilter (name, flbufp)
	char			*name;
	FILTER			*flbufp;
#endif
{
	_FILTER			_flbuf;

	register _FILTER	*pf;


	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		errno = EINVAL;
		return (-1);
	}

	_flbuf.name = Strdup(name);
	_flbuf.command = (flbufp->command? Strdup(flbufp->command) : 0);
	_flbuf.type = flbufp->type;
	_flbuf.printer_types = sl_to_typel(flbufp->printer_types);
	_flbuf.printers = duplist(flbufp->printers);
	_flbuf.input_types = sl_to_typel(flbufp->input_types);
	_flbuf.output_types = sl_to_typel(flbufp->output_types);
	if (!flbufp->templates)
		_flbuf.templates = 0;
	else if (!(_flbuf.templates = sl_to_templatel(flbufp->templates))) {
		free_filter (&_flbuf);
		errno = EBADF;
		return (-1);
	}

	if (!filters && get_and_load() == -1 && errno != ENOENT) {
		free_filter (&_flbuf);
		return (-1);
	}

	if (filters) {

		if ((pf = search_filter(name)))
			free_filter (pf);
		else {
			nfilters++;
			filters = (_FILTER *)Realloc(
				(char *)filters,
				(nfilters + 1) * sizeof(_FILTER)
			);
			if (!filters) {
				free_filter (&_flbuf);
				errno = ENOMEM;
				return (-1);
			}
			filters[nfilters].name = 0;
			pf = filters + nfilters - 1;
		}

	} else {

		nfilters = 1;
		pf = filters = (_FILTER *)Malloc(
			(nfilters + 1) * sizeof(_FILTER)
		);
		if (!filters) {
			free_filter (&_flbuf);
			errno = ENOMEM;
			return (-1);
		}
		filters[nfilters].name = 0;

	}

	*pf = _flbuf;

	return (dumpfilters((char *)0));
}
