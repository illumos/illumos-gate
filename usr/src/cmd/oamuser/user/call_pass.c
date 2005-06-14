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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <userdefs.h>

extern int execvp();

int
call_passmgmt(nargv)
char *nargv[];
{
	int ret, cpid, wpid;

	switch (cpid = fork()) {
	case 0:
		/* CHILD */

		/*
		 * passmgmt should run in same locale as useradd, usermod,
		 * userdel, for locale-sensitive functions like getdate()
		 */
		(void) putenv("LC_ALL=C");

		if (freopen("/dev/null", "w+", stdout) == NULL ||
			freopen("/dev/null", "w+", stderr) == NULL ||
			execvp(nargv[0], nargv) == -1)
			exit(EX_FAILURE);

		break;

	case -1:
		/* ERROR */
		return (EX_FAILURE);

	default:
		/* PARENT */

		while ((wpid = wait(&ret)) != cpid) {
			if (wpid == -1)
				return (EX_FAILURE);
		}

		ret = (ret >> 8) & 0xff;
	}
	return (ret);

}
