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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <auth_attr.h>
#include <auth_list.h>

#include "cron.h"

struct stat globstat;
#define	exists(file)	(stat(file, &globstat) == 0)
#define	ROOT	"root"

int per_errno;	/* status info from getuser */
static int within(char *, char *);


char *
getuser(uid_t uid)
{
	struct passwd *nptr;

	if ((nptr = getpwuid(uid)) == NULL) {
		per_errno = 1;
		return (NULL);
	}
	if ((strcmp(nptr->pw_shell, SHELL) != 0) &&
	    (strcmp(nptr->pw_shell, "") != 0)) {
		per_errno = 2;
		/*
		 * return NULL if you want crontab and at to abort
		 * when the users login shell is not /usr/bin/sh otherwise
		 * return pw_name
		 */
		return (nptr->pw_name);
	}
	return (nptr->pw_name);
}

int
allowed(char *user, char *allow, char *deny)
{
	if (exists(allow)) {
		if (within(user, allow)) {
			return (1);
		} else {
			return (0);
		}
	} else if (exists(deny)) {
		if (within(user, deny)) {
			return (0);
		} else {
			return (1);
		}
	} else if (chkauthattr(CRONUSER_AUTH, user)) {
		return (1);
	} else {
		return (0);
	}
}

static int
within(char *username, char *filename)
{
	char line[UNAMESIZE];
	FILE *cap;
	int i;

	if ((cap = fopen(filename, "r")) == NULL)
		return (0);
	while (fgets(line, UNAMESIZE, cap) != NULL) {
		for (i = 0; line[i] != '\0'; i++) {
			if (isspace(line[i])) {
				line[i] = '\0';
				break; }
		}
		if (strcmp(line, username) == 0) {
			fclose(cap);
			return (1);
		}
	}
	fclose(cap);
	return (0);
}

int
cron_admin(const char *name)
{
	return (chkauthattr(CRONADMIN_AUTH, name));
}
