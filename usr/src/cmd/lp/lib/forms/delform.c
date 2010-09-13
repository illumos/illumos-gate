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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.11	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "errno.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "form.h"

#if	defined(__STDC__)
static int		_delform ( char * );
#else
static int		_delform();
#endif

/**
 ** delform()
 **/

int
#if	defined(__STDC__)
delform (
	char *			name
)
#else
delform (name)
	char			*name;
#endif
{
	long			lastdir;


	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		lastdir = -1;
		while ((name = next_dir(Lp_A_Forms, &lastdir)))
			if (_delform(name) == -1)
				return (-1);
		return (0);
	} else
		return (_delform(name));
}

/**
 ** _delform()
 **/

static int
#if	defined(__STDC__)
_delform (
	char *			name
)
#else
_delform (name)
	char			*name;
#endif
{
	register char		*path;

#define RMFILE(X)	if (!(path = getformfile(name, X))) \
				return (-1); \
			if (rmfile(path) == -1) { \
				Free (path); \
				return (-1); \
			} \
			Free (path)
	RMFILE (DESCRIBE);
	RMFILE (COMMENT);
	RMFILE (ALIGN_PTRN);
	RMFILE (ALLOWFILE);
	RMFILE (DENYFILE);

	delalert (Lp_A_Forms, name);

	if (!(path = getformfile(name, (char *)0)))
		return (-1);
	if (Rmdir(path) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

	return (0);
}
