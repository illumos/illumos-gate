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


#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:getpwinfo.c 2.8 */

#include "uucp.h"

#include <pwd.h>
extern struct passwd *getpwuid(), *getpwnam();
extern char	*getlogin();


/*
 * get passwd file info for logname or uid
 *	uid	-> uid #
 *	name	-> address of buffer to return ascii user name
 *		This will be set to pw->pw_name.
 *
 * return:
 *	0	-> success
 *	FAIL	-> failure (logname and uid not found)
 */
int
guinfo(uid, name)
uid_t uid;
char *name;
{
	register struct passwd *pwd;
	char	*login_name;

	/* look for this user as logged in utmp */
	if ((login_name = getlogin()) != NULL) {
		pwd = getpwnam(login_name);
		if (pwd != NULL && pwd->pw_uid == uid)
			goto uid_found;
	}

	/* no dice on utmp -- get first from passwd file */
	if ((pwd = getpwuid(uid)) == NULL) {
	    if ((pwd = getpwuid(UUCPUID)) == NULL)
		/* can not find uid in passwd file */
		return(FAIL);
	}

uid_found:
	(void) strcpy(name, pwd->pw_name);
	return(0);
}

/*
 * get passwd file info for name
 *	name	-> ascii user name
 *	uid	-> address of integer to return uid # in
 *	path	-> address of buffer to return working directory in
 * returns:
 *	0	-> success
 *	FAIL	-> failure
 */
int
gninfo(name, uid, path)
char *path, *name;
uid_t *uid;
{
	register struct passwd *pwd;

	if ((pwd = getpwnam(name)) == NULL) {
		/* can not find name in passwd file */
		*path = '\0';
		return(FAIL);
	}

	(void) strcpy(path, pwd->pw_dir);
	*uid = pwd->pw_uid;
	return(0);
}


