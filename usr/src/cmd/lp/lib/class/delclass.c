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
/* LINTLIBRARY */

#include "stdio.h"
#include "errno.h"
#include "string.h"
#include "sys/types.h"
#include "string.h"

#include "lp.h"
#include "class.h"

static int		_delclass ( char * );

/**
 ** delclass() - WRITE CLASS OUT TO DISK
 **/

int
delclass(char *name)
{
	long			lastdir;

	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		lastdir = -1;
		while ((name = next_file(Lp_A_Classes, &lastdir)))
			if (_delclass(name) == -1)
				return (-1);
		return (0);
	} else
		return (_delclass(name));
}

/**
 ** _delclass()
 **/

static int
#if	defined(__STDC__)
_delclass (
	char *			name
)
#else
_delclass (name)
	char			*name;
#endif
{
	char			*path;

	if (!(path = getclassfile(name)))
		return (-1);
	if (rmfile(path) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);
	return (0);
}

