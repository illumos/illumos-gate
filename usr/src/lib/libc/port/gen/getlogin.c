/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _getlogin = getlogin
#pragma weak _getlogin_r = getlogin_r

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "utmpx.h"
#include <unistd.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <mtlib.h>
#include "tsd.h"

/*
 * XXX - _POSIX_LOGIN_NAME_MAX limits the length of a login name.  The utmpx
 * interface provides for a 32 character login name, but for the sake of
 * compatibility, we are still using the old utmp-imposed limit.
 */

/*
 * POSIX.1c Draft-6 version of the function getlogin_r.
 * It was implemented by Solaris 2.3.
 */
char *
getlogin_r(char *answer, int namelen)
{
	int		uf;
	off64_t		me;
	struct futmpx	ubuf;

	if (namelen < _POSIX_LOGIN_NAME_MAX) {
		errno = ERANGE;
		return (NULL);
	}

	if ((me = (off64_t)ttyslot()) < 0)
		return (NULL);
	if ((uf = open64(UTMPX_FILE, 0)) < 0)
		return (NULL);
	(void) lseek64(uf, me * sizeof (ubuf), SEEK_SET);
	if (read(uf, &ubuf, sizeof (ubuf)) != sizeof (ubuf)) {
		(void) close(uf);
		return (NULL);
	}
	(void) close(uf);
	if (ubuf.ut_user[0] == '\0')
		return (NULL);
	(void) strncpy(&answer[0], &ubuf.ut_user[0],
	    _POSIX_LOGIN_NAME_MAX - 1);
	answer[_POSIX_LOGIN_NAME_MAX - 1] = '\0';
	return (&answer[0]);
}

/*
 * POSIX.1c standard version of the function getlogin_r.
 * User gets it via static getlogin_r from the header file.
 */
int
__posix_getlogin_r(char *name, int namelen)
{
	int nerrno = 0;
	int oerrno = errno;

	errno = 0;
	if (getlogin_r(name, namelen) == NULL) {
		if (errno == 0)
			nerrno = EINVAL;
		else
			nerrno = errno;
	}
	errno = oerrno;
	return (nerrno);
}

char *
getlogin(void)
{
	char *answer = tsdalloc(_T_LOGIN, _POSIX_LOGIN_NAME_MAX, NULL);

	if (answer == NULL)
		return (NULL);
	return (getlogin_r(answer, _POSIX_LOGIN_NAME_MAX));
}
