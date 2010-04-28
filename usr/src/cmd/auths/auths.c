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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <deflt.h>
#include <libintl.h>
#include <locale.h>
#include <user_attr.h>
#include <prof_attr.h>
#include <auth_attr.h>

#define	EXIT_OK		0
#define	EXIT_FATAL	1
#define	EXIT_NON_FATAL	2

#ifndef	TEXT_DOMAIN			/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	INCRAUTHS	512

typedef struct cbs {
	int	auth_cnt;
	int	auth_max;
	char	**auths;
} cbs_t;

static int show_auths(char *, int);
static int add_auth(const char *, void *, void *);
static void free_auths(cbs_t *);
static void simplify(cbs_t *);

static char *progname = "auths";

int
main(int argc, char *argv[])
{
	int		status = EXIT_OK;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	switch (argc) {
	case 1:
		status = show_auths(NULL, 0);
		break;
	case 2:
		status = show_auths(argv[argc-1], 0);
		break;
	default:
		while (*++argv) {
			status = show_auths(*argv, 1);
			if (status == EXIT_FATAL) {
				break;
			}
		}
		break;
	}

	status = (status == EXIT_OK) ? status : EXIT_FATAL;
	return (status);
}

static int
show_auths(char *username, int print_name)
{
	int		status = EXIT_OK;
	struct passwd	*pw;
	int		i;
	cbs_t		cbs = { 0, 0, NULL };

	if (username == NULL) {
		if ((pw = getpwuid(getuid())) == NULL) {
			status = EXIT_NON_FATAL;
			(void) fprintf(stderr, "%s: ", progname);
			(void) fprintf(stderr, gettext("No passwd entry\n"));
			return (status);
		}
		username = pw->pw_name;
	} else if (getpwnam(username) == NULL) {
		status = EXIT_NON_FATAL;
		(void) fprintf(stderr, "%s: %s : ", progname, username);
		(void) fprintf(stderr, gettext("No such user\n"));
		return (status);
	}

	(void) _enum_auths(username, add_auth, NULL, &cbs);

	if (cbs.auth_cnt == 0)
		status = EXIT_NON_FATAL;

	if (status == EXIT_NON_FATAL) {
		(void) fprintf(stderr, "%s: %s: ", progname, username);
		(void) fprintf(stderr, gettext("No authorizations\n"));
	} else {
		simplify(&cbs);

		if (print_name)
			(void) printf("%s: ", username);

		/* print out the auths */
		for (i = 0; i < cbs.auth_cnt - 1; i++)
			(void) printf("%s,", cbs.auths[i]);

		/* print out the last entry, without the comma */
		(void) printf("%s\n", cbs.auths[cbs.auth_cnt - 1]);

		/* free memory allocated for authorizations */
		free_auths(&cbs);
	}

	return (status);
}

/*ARGSUSED*/
static int
add_auth(const char *authname, void *ctxt, void *res)
{
	cbs_t	*cbs = res;

	if (cbs->auth_cnt >= cbs->auth_max) {
		cbs->auth_max += INCRAUTHS;
		cbs->auths = realloc(cbs->auths,
		    cbs->auth_max * sizeof (char *));

		if (cbs->auths == NULL) {
			(void) fprintf(stderr, "%s: ", progname);
			(void) fprintf(stderr, gettext("Out of memory\n"));
			exit(1);
		}
	}

	cbs->auths[cbs->auth_cnt] = strdup(authname);
	cbs->auth_cnt++;

	return (0);
}

static void
free_auths(cbs_t *cbs)
{
	int i;

	for (i = 0; i < cbs->auth_cnt; i++)
		free(cbs->auths[i]);

	free(cbs->auths);
}

/* We have always ignored .grant in auths(1) */
static boolean_t
auth_match(const char *pattern, const char *auth)
{
	size_t len = strlen(pattern);

	if (pattern[len - 1] != KV_WILDCHAR)
		return (B_FALSE);

	return (strncmp(pattern, auth, len - 1) == 0);
}

static int
mstrptr(const void *a, const void *b)
{
	char *const *ap = a;
	char *const *bp = b;

	return (strcmp(*ap, *bp));
}

/*
 * Simplify the returned authorizations: sort and match wildcards;
 * we're using here that "*" sorts before any other character.
 */
static void
simplify(cbs_t *cbs)
{
	int rem, i;

	/* First we sort */
	qsort(cbs->auths, cbs->auth_cnt, sizeof (cbs->auths[0]), mstrptr);

	/*
	 * Then we remove the entries which match a later entry.
	 * We walk the list, with "i + rem + 1" the cursor for the possible
	 * candidate for removal. With "rem" we count the removed entries
	 * and we copy while we're looking for duplicate/superfluous entries.
	 */
	for (i = 0, rem = 0; i < cbs->auth_cnt - rem - 1; ) {
		if (strcmp(cbs->auths[i], cbs->auths[i + rem + 1]) == 0 ||
		    strchr(cbs->auths[i], KV_WILDCHAR) != NULL &&
		    auth_match(cbs->auths[i], cbs->auths[i + rem + 1])) {
			free(cbs->auths[i + rem + 1]);
			rem++;
		} else {
			i++;
			if (rem > 0)
				cbs->auths[i] = cbs->auths[i + rem];
		}
	}

	cbs->auth_cnt -= rem;
}
