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
/*
 *	getname(name)  --  get logname
 *
 *		getname tries to find the user's logname from:
 *			${LOGNAME}, if set and if it is telling the truth
 *			/etc/passwd, otherwise
 *
 *		The logname is returned as the value of the function.
 *
 *		Getname returns the user's user id converted to ASCII
 *		for unknown lognames.
 *
 */

#include "string.h"
#include "pwd.h"
#include "errno.h"
#include "sys/types.h"
#include "stdlib.h"
#include "unistd.h"

#include "lp.h"

char *
#if	defined(__STDC__)
getname (
	void
)
#else
getname ()
#endif
{
	uid_t			uid;
	struct passwd		*p;
	static char		*logname	= 0;
	char			*l;

	if (logname)
		return (logname);

	uid = getuid();

	setpwent ();
	if (
		!(l = getenv("LOGNAME"))
	     || !(p = getpwnam(l))
	     || p->pw_uid != uid
	)
		if ((p = getpwuid(uid)))
			l = p->pw_name;
		else
			l = 0;
	endpwent ();

	if (l)
		logname = Strdup(l);
	else {
		if (uid > 0) {
			logname = Malloc(10 + 1);
			if (logname)
				sprintf (logname, "%d", uid);
		}
	}

	if (!logname)
	{
		errno = ENOMEM;
	}
	else
	{
		errno = 0;
	}

	return (logname);
}
