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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <user_attr.h>


#define	EXIT_OK		0
#define	EXIT_FATAL	1

#ifndef	TEXT_DOMAIN			/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

static int show_roles(char *, int);

static char *progname = "roles";

int
main(int argc, char *argv[])
{
	int	print_name = 0;
	int	errs = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc > 2)
		print_name = 1;

	if (argc == 1) {
		errs = show_roles(NULL, 0);
	} else {
		while (*++argv)
			errs += show_roles(*argv, print_name);
	}

	return ((errs == 0) ? EXIT_OK : EXIT_FATAL);
}


static int
show_roles(char *username, int print_name)
{
	register char		*rolelist = NULL;
	register struct passwd	*pw;
	register userattr_t	*user;

	if (username == NULL) {
		if ((pw = getpwuid(getuid())) == NULL) {
			(void) fprintf(stderr, "%s: ", progname);
			(void) fprintf(stderr, gettext("No passwd entry\n"));
			return (1);
		}
		username = pw->pw_name;
	} else if (getpwnam(username) == NULL) {
		(void) fprintf(stderr, "%s: %s : ", progname, username);
		(void) fprintf(stderr, gettext("No such user\n"));
		return (1);
	}

	if ((user = getusernam(username)) != NULL) {
		rolelist = kva_match(user->attr, USERATTR_ROLES_KW);
		if (rolelist == NULL)
			rolelist = gettext("No roles");
		if (print_name && username != NULL)
			(void) printf("%s : ", username);
		(void) printf("%s\n", rolelist);
		free_userattr(user);
	} else {
		if (print_name && username != NULL)
			(void) printf("%s : ", username);
		(void) printf("%s\n", gettext("No roles"));
	}

	return (0);
}
