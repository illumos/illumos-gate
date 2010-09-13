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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include "uucp.h"

/* copy str into data space -- caller should report errors. */

static char *
strsave(const char *str)
{
	char *rval;

	rval = malloc(strlen(str) + 1);
	if (rval != 0)
		(void) strcpy(rval, str);
	return (rval);
}

/*
 * Determine if the effective user id has the appropriate permission
 *	on a file.  Modeled after access(2).
 *	amode:
 *		00	just checks for file existence.
 *		04	checks read permission.
 *		02	checks write permission.
 *		01	checks execute/search permission.
 *		other bits are ignored quietly.
 */

static int
eaccess(char *path, mode_t amode)
{
	struct stat	s;
	uid_t euid;

	if (stat(path, &s) == -1)
		return (-1);		/* can't stat file */
	amode &= 07;

	if ((euid = geteuid()) == 0)		/* root can do all */
		return (0);
	if (euid == s.st_uid)
	    s.st_mode >>= 6;		/* use owner bits */
	else if (getegid() == s.st_gid)
	    s.st_mode >>= 3;		/* use group bits */

	if ((amode & s.st_mode) == amode)
		return (0);		/* access permitted */
	errno = EACCES;
	return (-1);
}
