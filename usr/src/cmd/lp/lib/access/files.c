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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "errno.h"
#include "stdio.h"
#include "string.h"
#include "unistd.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** getaccessfile() - BUILD NAME OF ALLOW OR DENY FILE
 **/

char *
#if	defined(__STDC__)
getaccessfile (
	char *			dir,
	char *			name,
	char *			prefix,
	char *			base
)
#else
getaccessfile (dir, name, prefix, base)
	char			*dir,
				*name,
				*prefix,
				*base;
#endif
{
	register char		*parent,
				*file,
				*f;

	/*
	 * It makes no sense talking about the access files if
	 * the directory for the form or printer doesn't exist.
	 */
	parent = makepath(dir, name, (char *)0);
	if (!parent)
		return (0);
	if (Access(parent, F_OK) == -1) {
		Free(parent);
		return (0);
	}

	if (!(f = makestr(prefix, base, (char *)0))) {
		Free(parent);
		errno = ENOMEM;
		return (0);
	}
	file = makepath(parent, f, (char *)0);
	Free (f);
	Free (parent);

	return (file);
}
