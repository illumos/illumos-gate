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

/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

#pragma weak _getlogin = getlogin
#pragma weak _getlogin_r = getlogin_r

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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
 *
 * If you want the full name, use the Consolidation Private getxlogin().
 */

static int
generic_getlogin(char *answer, int namelen, boolean_t truncate)
{
	int		uf;
	off64_t		me;
	struct futmpx	ubuf;

	if ((me = (off64_t)ttyslot()) < 0)
		return (-1);
	if ((uf = open64(UTMPX_FILE, 0)) < 0)
		return (-1);
	(void) lseek64(uf, me * sizeof (ubuf), SEEK_SET);
	if (read(uf, &ubuf, sizeof (ubuf)) != sizeof (ubuf)) {
		(void) close(uf);
		return (-1);
	}
	(void) close(uf);
	if (ubuf.ut_user[0] == '\0')
		return (-1);
	if (strnlen(ubuf.ut_user, sizeof (ubuf.ut_user)) >= namelen &&
	    !truncate) {
		errno = ERANGE;
		return (-1);
	}
	(void) strlcpy(answer, ubuf.ut_user, namelen);

	return (0);
}

/*
 * POSIX.1c Draft-6 version of the function getlogin_r.
 * It was implemented by Solaris 2.3.
 */
char *
getlogin_r(char *answer, int namelen)
{
	if (namelen < _POSIX_LOGIN_NAME_MAX) {
		errno = ERANGE;
		return (NULL);
	}

	if (generic_getlogin(answer, _POSIX_LOGIN_NAME_MAX, B_TRUE) == 0)
		return (answer);

	return (NULL);
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
	if (getlogin_r(name, namelen) != 0) {
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
	struct futmpx fu;
	char *answer = tsdalloc(_T_LOGIN,
	    MAX(sizeof (fu.ut_user), _POSIX_LOGIN_NAME_MAX), NULL);

	if (answer == NULL)
		return (NULL);
	return (getlogin_r(answer, _POSIX_LOGIN_NAME_MAX));
}

char *
getxlogin(void)
{
	struct futmpx fu;
	char *answer = tsdalloc(_T_LOGIN,
	    MAX(sizeof (fu.ut_user), _POSIX_LOGIN_NAME_MAX), NULL);

	if (answer == NULL)
		return (NULL);

	if (generic_getlogin(answer,
	    MAX(sizeof (fu.ut_user), _POSIX_LOGIN_NAME_MAX), B_FALSE) != 0)
		return (NULL);

	return (answer);
}
