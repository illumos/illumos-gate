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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <nss_dbdefs.h>
#include <user_attr.h>
#include <getxby_door.h>
#include <pwd.h>


/* Externs from libnsl */
extern userstr_t *_getusernam(const char *, userstr_t *, char *, int, int *);
extern userstr_t *_getuserattr(userstr_t *, char *, int, int *);
extern userstr_t *_fgetuserattr(FILE *, userstr_t *, char *, int);
extern void _setuserattr(void);
extern void _enduserattr(void);


static userattr_t *userstr2attr(userstr_t *);


userattr_t *
getuserattr()
{
	int		err = 0;
	char		buf[NSS_BUFLEN_USERATTR];
	userstr_t	user;
	userstr_t	*tmp;

	(void) memset(&user, 0, sizeof (userattr_t));
	tmp = _getuserattr(&user, buf, NSS_BUFLEN_USERATTR, &err);
	return (userstr2attr(tmp));
}


userattr_t *
fgetuserattr(FILE *f)
{
	char		buf[NSS_BUFLEN_USERATTR];
	userstr_t	user;
	userstr_t	*tmp;

	(void) memset(&user, 0, sizeof (userattr_t));
	tmp = _fgetuserattr(f, &user, buf, NSS_BUFLEN_USERATTR);
	return (userstr2attr(tmp));
}


userattr_t *
getusernam(const char *name)
{
	int		err = 0;
	char		buf[NSS_BUFLEN_USERATTR];
	userstr_t	user;
	userstr_t	*resptr = (userstr_t *)NULL;

	resptr = _getusernam(name, &user, buf, NSS_BUFLEN_USERATTR, &err);

	return (userstr2attr(resptr));

}


userattr_t *
getuseruid(uid_t u)
{
	struct	passwd pwd;
	char	buf[NSS_BUFLEN_PASSWD];

	if (getpwuid_r(u, &pwd, buf, NSS_BUFLEN_PASSWD) == NULL)
		return ((userattr_t *)NULL);
	return (getusernam(pwd.pw_name));
}


void
setuserattr()
{
	_setuserattr();
}


void
enduserattr()
{
	_enduserattr();
}


void
free_userattr(userattr_t *user)
{
	if (user) {
		free(user->name);
		free(user->qualifier);
		free(user->res1);
		free(user->res2);
		_kva_free(user->attr);
		free(user);
	}
}


static userattr_t *
userstr2attr(userstr_t *user)
{
	userattr_t *newuser;

	if (user == NULL)
		return ((userattr_t *)NULL);

	if ((newuser = (userattr_t *)malloc(sizeof (userattr_t))) == NULL)
		return ((userattr_t *)NULL);

	newuser->name = _do_unescape(user->name);
	newuser->qualifier = _do_unescape(user->qualifier);
	newuser->res1 = _do_unescape(user->res1);
	newuser->res2 = _do_unescape(user->res2);
	newuser->attr = _str2kva(user->attr, KV_ASSIGN, KV_DELIMITER);
	return (newuser);
}


#ifdef DEBUG
void
print_userattr(userattr_t *user)
{
	extern void print_kva(kva_t *);
	char *empty = "empty";

	if (user == NULL) {
		printf("NULL\n");
		return;
	}

	printf("name=%s\n", user->name ? user->name : empty);
	printf("qualifier=%s\n", user->qualifier ? user->qualifier : empty);
	printf("res1=%s\n", user->res1 ? user->res1 : empty);
	printf("res2=%s\n", user->res2 ? user->res2 : empty);
	printf("attr=\n");
	print_kva(user->attr);
	fflush(stdout);
}
#endif  /* DEBUG */
