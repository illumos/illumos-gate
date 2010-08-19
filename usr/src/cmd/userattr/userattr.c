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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <locale.h>
#include <pwd.h>
#include <secdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

boolean_t	verbose = B_FALSE;
char		*attr_name = NULL;

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif	/* !TEXT_DOMAIN */

/*
 *	userattr [-v] attr_name [user]
 */

/* ARGSUSED */
static int
attr(const char *name, kva_t *kva, void *ctxt, void *pres)
{
	char 	*val;

	if ((val = kva_match(kva, attr_name)) != NULL) {
		if (verbose) {
			char *prof_name = "user_attr";

			if (name != NULL) {
				prof_name = (char *)name;
			}
			(void) printf("%s : %s\n", prof_name, val);
		} else {
			(void) printf("%s\n", val);
		}
		exit(0);
	}

	return (0);	/* no match */
}

int
main(int argc, char *argv[])
{
	int	opt = 1;
	char	*user = NULL;
	struct passwd *pwd;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((argc >= 2) &&
	    (strncmp(argv[opt], "-v", sizeof ("-v")) == 0)) {
		verbose = B_TRUE;
		opt++;
		argc--;
	}
	if (argc >= 2) {
		attr_name = argv[opt++];
	}
	if (argc >= 3) {
		user = argv[opt++];
	}

	if ((attr_name == NULL) || (opt < argc)) {
		(void) fprintf(stderr,
		    gettext("Usage: %s [-v] attribute_name [user]\n"), argv[0]);
		exit(1);
	}

	if (user == NULL) {
		uid_t	uid = getuid();

		if ((pwd = getpwuid(uid)) == NULL) {
			(void) fprintf(stderr,
			    gettext("Cannot find user for uid %d\n"), uid);
			exit(1);
		}
		user = pwd->pw_name;
	} else {
		if ((pwd = getpwnam(user)) == NULL) {
			(void) fprintf(stderr,
			    gettext("No such user %s\n"), user);
			exit(1);
		}
	}

	(void) _enum_attrs(user, attr, NULL, NULL);

	if (verbose) {
		(void) fprintf(stderr,
		    gettext("attribute \"%s\" not found for %s\n"), attr_name,
		    user);
	}

	return (1);
}
