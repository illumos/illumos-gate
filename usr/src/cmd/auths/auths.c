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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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


#define	ALL_AUTHS	"All"
#define	ALL_SUN_AUTHS	"solaris.*"

#define	EXIT_OK		0
#define	EXIT_FATAL	1
#define	EXIT_NON_FATAL	2

#ifndef	TEXT_DOMAIN			/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	PROFLIST_SEP	","
#define	AUTH_SEP	","
#define	MAXAUTHS	4096


static int show_auths(char *, char **, int, int);
static int list_auths(userattr_t *, char **, int *);
static void get_default_auths(char *, char **, int *);
static void getProfiles(char *, char **, int *, char **, int *);
static void add_auths(char *, char **, int *);
static void free_auths(char **, int *);

static char *progname = "auths";


int
main(int argc, char *argv[])
{
	int		status = EXIT_OK;
	char		*defauths[MAXAUTHS];
	int		defauth_cnt = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	switch (argc) {
	case 1:
		get_default_auths(NULL, defauths, &defauth_cnt);
		status = show_auths(NULL, defauths, defauth_cnt, 0);
		break;
	case 2:
		get_default_auths(argv[argc-1], defauths, &defauth_cnt);
		status = show_auths(argv[argc-1], defauths, defauth_cnt, 0);
		break;
	default:
		while (*++argv) {
			get_default_auths(*argv, defauths, &defauth_cnt);
			status = show_auths(*argv, defauths, defauth_cnt, 1);
			if (status == EXIT_FATAL) {
				break;
			}
			/* free memory allocated for default authorizations */
			free_auths(defauths, &defauth_cnt);
		}
		break;
	}

	/* free memory allocated for default authorizations */
	free_auths(defauths, &defauth_cnt);
	status = (status == EXIT_OK) ? status : EXIT_FATAL;

	return (status);
}


static int
show_auths(char *username, char **defauths, int defauth_cnt, int print_name)
{
	int		status = EXIT_OK;
	struct passwd	*pw;
	userattr_t	*user;
	char		*userauths[MAXAUTHS];
	int		userauth_cnt = 0, old_userauth_cnt;
	int		i, j, have_allauths, duplicate;

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

	have_allauths = 0;
	if (username != NULL) {
		/* if ALL_AUTHS is default, don't need to look at other auths */
		for (i = 0; i < defauth_cnt; i++) {
			if (strcmp(defauths[i], ALL_AUTHS) == 0) {
				have_allauths = 1;
				break;
			}
		}
		if (have_allauths) {
			status = EXIT_OK;
		} else if ((user = getusernam(username)) != NULL) {
			status = list_auths(user, userauths, &userauth_cnt);
			/* check if any profiles have ALL_AUTHS */
			for (i = 0; i < userauth_cnt; i++) {
				if (strcmp(userauths[i], ALL_AUTHS) == 0) {
					have_allauths = 1;
					break;
				}
			}
		}
		if ((defauth_cnt + userauth_cnt) == 0) {
			status = EXIT_NON_FATAL;
		}
	}
	if (status == EXIT_NON_FATAL) {
		(void) fprintf(stderr, "%s: %s : ", progname, username);
		(void) fprintf(stderr, gettext("No authorizations\n"));
	} else {
		if (print_name) {
			(void) printf("%s : ", username);
		}

		if (have_allauths) {
			(void) printf("%s\n", ALL_SUN_AUTHS);
		} else {
			/*
			 * combine the user auths and default auths,
			 * and eliminate duplicates from the two
			 */
			old_userauth_cnt = userauth_cnt;
			for (i = 0; i < defauth_cnt; i++) {
				duplicate = 0;
				for (j = 0; j < old_userauth_cnt; j++) {
					if (strcmp(userauths[j], defauths[i]) ==
					    0) {
						duplicate = 1;
						break;
					}
				}
				if (!duplicate) {
					userauths[userauth_cnt] =
					    strdup(defauths[i]);
					userauth_cnt++;
				}
			}

			/* print out the auths */
			for (i = 0; i < (userauth_cnt - 1); i++) {
				(void) printf("%s,", userauths[i]);
			}

			/* print out the last entry, without the comma */
			(void) printf("%s\n", userauths[userauth_cnt - 1]);
		}
	}

	/* free memory allocated for authorizations */
	free_auths(userauths, &userauth_cnt);

	return (status);
}


static int
list_auths(userattr_t *user, char **authArray, int *authcnt)
{
	int		status = EXIT_OK;
	char		*authlist = NULL;
	char		*proflist = NULL;
	char		*profArray[MAXPROFS];
	int		profcnt = 0;

	authlist = kva_match(user->attr, USERATTR_AUTHS_KW);
	if (authlist != NULL) {
		add_auths(authlist, authArray, authcnt);
	}
	if ((proflist = kva_match(user->attr, USERATTR_PROFILES_KW)) == NULL) {
		if (authcnt == 0) {
			status = EXIT_NON_FATAL;
		}
	} else {
		getProfiles(proflist, profArray, &profcnt,
		    authArray, authcnt);
		free_proflist(profArray, profcnt);
	}
	if (authcnt == 0) {
		status = EXIT_NON_FATAL;
	}
	free_userattr(user);

	return (status);
}


static void
get_default_auths(char *user, char **authArray, int *authcnt)
{
	char *auths = NULL;
	char *profs = NULL;
	char *profArray[MAXPROFS];
	int profcnt = 0;

	if (user == NULL) {
		struct passwd *pw;

		if ((pw = getpwuid(getuid())) != NULL) {
			user = pw->pw_name;
		}
	}

	if (_get_user_defs(user, &auths, &profs) == 0) {
		if (auths != NULL) {
			add_auths(auths, authArray, authcnt);
		}

		/* get authorizations from default profiles */
		if (profs != NULL) {
			getProfiles(profs, profArray, &profcnt,
			    authArray, authcnt);
			free_proflist(profArray, profcnt);
		}
		_free_user_defs(auths, profs);
	}
}

void
add_auths(char *auths, char **authArray, int *authcnt)
{
	char	*authname, *lasts, *real_authname;
	int	i;

	for (authname = (char *)strtok_r(auths, AUTH_SEP, &lasts);
	    authname != NULL;
	    authname = (char *)strtok_r(NULL, AUTH_SEP, &lasts)) {

		if ((strcmp(authname, KV_WILDCARD) == 0) ||
		    (strcmp(authname, ALL_SUN_AUTHS) == 0)) {
			real_authname = ALL_AUTHS;
		} else {
			real_authname = authname;
		}

		/* check to see if authorization is already in list */
		for (i = 0; i < *authcnt; i++) {
			if (strcmp(real_authname, authArray[i]) == 0) {
				break;	/* already in list */
			}
		}

		/* not in list, add it in */
		if (i == *authcnt) {
			authArray[i] = strdup(real_authname);
			*authcnt = i + 1;
		}
	}

}

static void
free_auths(char *auths[], int *auth_cnt)
{
	int i;

	for (i = 0; i < *auth_cnt; i++) {
		free(auths[i]);
	}
	*auth_cnt = 0;
}

static void
getProfiles(char *profiles, char **profArray, int *profcnt,
	char **authArray, int *authcnt)
{

	char		*prof;
	char		*lasts;
	profattr_t	*pa;
	char		*auths;
	int		i;

	for (prof = (char *)strtok_r(profiles, PROFLIST_SEP, &lasts);
	    prof != NULL;
	    prof = (char *)strtok_r(NULL, PROFLIST_SEP, &lasts)) {

		getproflist(prof, profArray, profcnt);
	}

	/* get authorizations from list of profiles */
	for (i = 0; i < *profcnt; i++) {

		if ((pa = getprofnam(profArray[i])) == NULL) {
			/*
			 *  this should never happen.
			 *  unless the database has an undefined profile
			 */
			continue;
		}

		/* get auths this profile */
		auths = kva_match(pa->attr, PROFATTR_AUTHS_KW);
		if (auths != NULL) {
			add_auths(auths, authArray, authcnt);
		}

		free_profattr(pa);
	}
}
