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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10	*/
/* LINTLIBRARY */

#include "string.h"
#include "errno.h"

#include "lp.h"

#if	defined(__STDC__)
static int		is ( char *, char *, unsigned int );
#else
static int		is();
#endif

/**
 ** next_x() - GO TO NEXT ENTRY UNDER PARENT DIRECTORY
 **/

char *
#if	defined(__STDC__)
next_x (
	char *			parent,
	long *			lastdirp,
	unsigned int		what
)
#else
next_x (parent, lastdirp, what)
	char			*parent;
	long			*lastdirp;
	unsigned int		what;
#endif
{
	DIR			*dirp;

	register char		*ret = 0;

	struct dirent		*direntp;


	if (!(dirp = Opendir(parent)))
		return (0);

	if (*lastdirp != -1)
		Seekdir (dirp, *lastdirp);

	do
		direntp = Readdir(dirp);
	while (
		direntp
	     && (
			STREQU(direntp->d_name, ".")
		     || STREQU(direntp->d_name, "..")
		     || !is(parent, direntp->d_name, what)
		)
	);

	if (direntp) {
		if (!(ret = Strdup(direntp->d_name)))
			errno = ENOMEM;
		*lastdirp = Telldir(dirp);
	} else {
		errno = ENOENT;
		*lastdirp = -1;
	}

	Closedir (dirp);

	return (ret);
}

static int
#if	defined(__STDC__)
is (
	char *			parent,
	char *			name,
	unsigned int		what
)
#else
is (parent, name, what)
	char			*parent;
	char			*name;
	unsigned int		what;
#endif
{
	char			*path;

	struct stat		statbuf;

	if (!(path = makepath(parent, name, (char *)0)))
		return (0);
	if (Stat(path, &statbuf) == -1) {
		Free (path);
		return (0);
	}
	Free (path);
	return ((statbuf.st_mode & S_IFMT) == what);
}
