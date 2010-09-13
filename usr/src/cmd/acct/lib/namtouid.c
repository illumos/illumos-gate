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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/
/*
 *	namtouid converts login names to uids
 *	maintains ulist for speed only
 */
#include <stdio.h>
#include <sys/types.h>
#include "acctdef.h"
#include <pwd.h>
static int	usize;
static struct ulist {
	char	uname[NSZ];
	uid_t	uuid;
} ul[A_USIZE];
char	ntmp[NSZ+1];

char	*strncpy();

uid_t
namtouid(name)
char	name[NSZ];
{
	register struct ulist *up;
	register uid_t tuid;
	struct passwd *getpwnam(), *pp;

	for (up = ul; up < &ul[usize]; up++)
		if (strncmp(name, up->uname, NSZ) == 0)
			return(up->uuid);
	strncpy(ntmp, name, NSZ);
	(void) setpwent();
	if ((pp = getpwnam(ntmp)) == NULL)
		tuid = -1;
	else {
		tuid = pp->pw_uid;
		if (usize < A_USIZE) {
			CPYN(up->uname, name);
			up->uuid = tuid;
			usize++;
		}
	}
	return(tuid);
}
