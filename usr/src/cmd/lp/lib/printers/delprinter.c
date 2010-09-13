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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "errno.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "printers.h"

#if	defined(__STDC__)
static int		_delprinter ( char * );
#else
static int		_delprinter();
#endif

/**
 ** delprinter()
 **/

int
#if	defined(__STDC__)
delprinter (
	char *			name
)
#else
delprinter (name)
	char			*name;
#endif
{
	long			lastdir;


	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (!Lp_A_Printers || !Lp_A_Interfaces) {
		getadminpaths (LPUSER);
		if (!Lp_A_Printers || !Lp_A_Interfaces)
			return (0);
	}

	if (STREQU(NAME_ALL, name)) {
		lastdir = -1;
		while ((name = next_dir(Lp_A_Printers, &lastdir)))
			if (_delprinter(name) == -1)
				return (-1);
		return (0);
	} else
		return (_delprinter(name));
}

/**
 ** _delprinter()
 **/

static int
#if	defined(__STDC__)
_delprinter (
	char *			name
)
#else
_delprinter (name)
	char			*name;
#endif
{
	register char		*path;
#ifdef LP_USE_PAPI_ATTR
	char			ppdfile[BUFSIZ];
#endif

#define RMFILE(X)	if (!(path = getprinterfile(name, X))) \
				return (-1); \
			if (rmfile(path) == -1) { \
				Free (path); \
				return (-1); \
			} \
			Free (path)
	RMFILE (COMMENTFILE);
	RMFILE (CONFIGFILE);
	RMFILE (FALLOWFILE);
	RMFILE (FDENYFILE);
	RMFILE (UALLOWFILE);
	RMFILE (UDENYFILE);
	RMFILE (STATUSFILE);
	RMFILE (FAULTMESSAGEFILE);

	delalert (Lp_A_Printers, name);

	if (!(path = makepath(Lp_A_Interfaces, name, (char *)0)))
		return (-1);
	if (rmfile(path) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

#ifdef LP_USE_PAPI_ATTR
	/* Check if the printer has a ppd file, if it does delete it */
	(void) snprintf(ppdfile, sizeof (ppdfile), "%s.ppd", name);

	if (!(path = makepath(ETCDIR, "ppd", ppdfile, (char *)0)))
	{
		return (-1);
	}
	if (rmfile(path) == -1)
	{
		Free(path);
		return (-1);
	}
	Free(path);
#endif

	if (!(path = getprinterfile(name, (char *)0)))
		return (-1);
	if (Rmdir(path) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

	return (0);
}
