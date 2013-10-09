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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak _getlogin = getloginx
#pragma weak _getlogin_r = getloginx_r

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

/* Revert the renames done in unistd.h */
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	getlogint	getlogin
#pragma	redefine_extname	getlogint_r	getlogin_r
#pragma	redefine_extname	__posix_getlogint_r	__posix_getlogin_r
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#ifdef	getlogin
#undef	getlogin
#endif	/* getlogin */
#ifdef	getlogin_r
#undef	getlogin_r
#endif	/* getlogin_r */
#ifdef	__posix_getlogin_r
#undef	__posix_getlogin_r
#endif	/* __posix_getlogin_r */
#define	getlogint	getlogin
#define	getlogint_r	getlogin_r
#define	__posix_getlogint_r	__posix_getlogin_r
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
extern char *getlogint(void);
extern char *getlogint_r(char *, int);
extern int __posix_getlogint_r(char *, int);

/*
 * Use the full length of a login name.
 * The utmpx interface provides for a 32 character login name.
 */
#define	NMAX	(sizeof (((struct utmpx *)0)->ut_user))

/*
 * Common function
 */
static char *
getl_r_common(char *answer, size_t namelen, size_t maxlen)
{
	int		uf;
	off64_t		me;
	struct futmpx	ubuf;

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

	/* Insufficient buffer size */
	if (namelen < strnlen(&ubuf.ut_user[0], maxlen)) {
		errno = ERANGE;
		return (NULL);
	}
	(void) strncpy(&answer[0], &ubuf.ut_user[0], maxlen);
	answer[maxlen] = '\0';
	return (&answer[0]);
}

/*
 * POSIX.1c Draft-6 version of the function getlogin_r.
 * It was implemented by Solaris 2.3.
 */
char *
getlogint_r(char *answer, int namelen)
{
	return (getl_r_common(answer, (size_t)namelen, LOGNAME_MAX_TRAD));
}

/*
 * POSIX.1c standard version of the function getlogin_r.
 * User gets it via static getlogin_r from the header file.
 */
int
__posix_getlogint_r(char *name, int namelen)
{
	int nerrno = 0;
	int oerrno = errno;

	errno = 0;
	if (getl_r_common(name, (size_t)namelen, LOGNAME_MAX_TRAD) == NULL) {
		if (errno == 0)
			nerrno = EINVAL;
		else
			nerrno = errno;
	}
	errno = oerrno;
	return (nerrno);
}

char *
getlogint(void)
{
	char *answer = tsdalloc(_T_LOGIN, LOGIN_NAME_MAX_TRAD, NULL);

	if (answer == NULL)
		return (NULL);
	return (getl_r_common(answer, LOGIN_NAME_MAX_TRAD, LOGNAME_MAX_TRAD));
}

/*
 * POSIX.1c Draft-6 version of the function getlogin_r.
 * It was implemented by Solaris 2.3.
 * For extended login names, selected by redefine_extname in unistd.h.
 */
char *
getloginx_r(char *answer, int namelen)
{
	return (getl_r_common(answer, (size_t)namelen, NMAX));
}

/*
 * POSIX.1c standard version of the function getlogin_r.
 * User gets it via static getlogin_r from the header file.
 * For extended login names, selected by redefine_extname in unistd.h.
 */
int
__posix_getloginx_r(char *name, int namelen)
{
	int nerrno = 0;
	int oerrno = errno;

	errno = 0;
	if (getl_r_common(name, (size_t)namelen, NMAX) == NULL) {
		if (errno == 0)
			nerrno = EINVAL;
		else
			nerrno = errno;
	}
	errno = oerrno;
	return (nerrno);
}

/*
 * For extended login names, selected by redefine_extname in unistd.h.
 */
char *
getloginx(void)
{
	char *answer = tsdalloc(_T_LOGIN, LOGIN_NAME_MAX, NULL);

	if (answer == NULL)
		return (NULL);
	return (getl_r_common(answer, LOGIN_NAME_MAX, NMAX));
}
