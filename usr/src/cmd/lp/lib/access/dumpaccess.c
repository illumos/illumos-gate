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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"
#include "access.h"

#if	defined(__STDC__)
static int		_dumpaccess ( char * , char ** );
#else
static int		_dumpaccess();
#endif

/**
 ** dumpaccess() - DUMP ALLOW OR DENY LISTS
 **/

int
dumpaccess(char *dir, char *name, char *prefix, char ***pallow, char ***pdeny)
{
	register char		*allow_file	= 0,
				*deny_file	= 0;

	int			ret;

	if (
		!(allow_file = getaccessfile(dir, name, prefix, "allow"))
	     || _dumpaccess(allow_file, *pallow) == -1 && errno != ENOENT
	     || !(deny_file = getaccessfile(dir, name, prefix, "deny"))
	     || _dumpaccess(deny_file, *pdeny) == -1 && errno != ENOENT
	)
		ret = -1;
	else
		ret = 0;

	if (allow_file)
		Free (allow_file);
	if (deny_file)
		Free (deny_file);

	return (ret);
}

/**
 ** _dumpaccess() - DUMP ALLOW OR DENY FILE
 **/

static int
_dumpaccess(char *file, char **list)
{
	register char		**pl;

	register int		ret;

	int fd;

	if (list) {
		if ((fd = open_locked(file, "w", MODE_READ)) < 0)
			return (-1);
		errno = 0;
		for (pl = list; *pl; pl++)
			fdprintf (fd, "%s\n", *pl);
		if (errno != 0)
			ret = -1;
		else
			ret = 0;
		close(fd);
	} else
		ret = Unlink(file);

	return (ret);
}
