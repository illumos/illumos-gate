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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <deflt.h>
#include <user_attr.h>
#include <prof_attr.h>
#include <exec_attr.h>
#include <auth_attr.h>


#define	EXIT_OK		0
#define	EXIT_FATAL	1
#define	EXIT_NON_FATAL	2

#define	TMP_BUF_LEN	2048		/* size of temp string buffer */

#define	PRINT_DEFAULT	0x0000
#define	PRINT_NAME	0x0010
#define	PRINT_LONG	0x0020

#ifndef TEXT_DOMAIN			/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	PROFLIST_SEP	","


static void usage();
static int show_profs(char *, int);
static int list_profs(userattr_t *, int);
static void print_profs_long(execattr_t *);
static void print_profs(char **, int, int);
static void getProfiles(char *, char **, int *);
static void getDefaultProfiles(char *, char **, int *);
static void print_profile_privs(const char *);

static char *progname = "profiles";

int
main(int argc, char *argv[])
{
	extern int	optind;
	int		c;
	int		status = EXIT_OK;
	int		print_flag = PRINT_DEFAULT;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "l")) != EOF) {
		switch (c) {
		case 'l':
			print_flag |= PRINT_LONG;
			break;
		default:
			usage();
			return (EXIT_FATAL);
		}
	}
	argc -= optind;
	argv += optind;

	if (*argv == NULL) {
		status = show_profs(NULL, print_flag);
	} else {
		do {
			(void) printf("%s:\n", *argv);
			status = show_profs((char *)*argv,
			    (print_flag | PRINT_NAME));
			if (status == EXIT_FATAL) {
				break;
			}
			if (argv[1] != NULL) {
				/* seperate users with empty line */
				(void) printf("\n");
			}
		} while (*++argv);
	}
	status = (status == EXIT_OK) ? status : EXIT_FATAL;

	return (status);
}


static int
show_profs(char *username, int print_flag)
{
	int		status = EXIT_OK;
	struct passwd	*pw;
	userattr_t	*user;
	char		*profArray[MAXPROFS];
	int		profcnt = 0;
	execattr_t	*exec;

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
		(void) fprintf(stderr, "%s: %s: ", progname, username);
		(void) fprintf(stderr, gettext("No such user\n"));
		return (status);
	}
	if (username != NULL) {
		if ((user = getusernam(username)) != NULL) {
			status = list_profs(user, print_flag);
		} else {
			getDefaultProfiles(username, profArray, &profcnt);
			if (profcnt == 0) {
				status = EXIT_NON_FATAL;
			} else {
				if (print_flag & PRINT_LONG) {
					exec = getexecuser(username, KV_COMMAND,
					    NULL, GET_ALL|__SEARCH_ALL_POLS);
					print_profs_long(exec);
					free_execattr(exec);
				} else {
					print_profs(profArray, print_flag,
					    profcnt);
				}
			}
		}
	}

	if (status == EXIT_NON_FATAL) {
		(void) fprintf(stderr, "%s: %s: ", progname, username);
		(void) fprintf(stderr, gettext("No profiles\n"));
	}

	return (status);
}


static int
list_profs(userattr_t *user, int print_flag)
{
	int		status = EXIT_OK;
	char		*proflist = (char *)NULL;
	execattr_t	*exec = (execattr_t *)NULL;
	char		*profArray[MAXPROFS];
	int		profcnt = 0;

	if (print_flag & PRINT_LONG) {
		exec = getexecuser(user->name, KV_COMMAND, NULL,
		    GET_ALL|__SEARCH_ALL_POLS);
		if (exec == NULL) {
			status = EXIT_NON_FATAL;
		}
	} else {
		proflist = kva_match(user->attr, USERATTR_PROFILES_KW);
		if (proflist != NULL) {
			getProfiles(proflist, profArray, &profcnt);
		}
		/* Also get any default profiles */
		getDefaultProfiles(user->name, profArray, &profcnt);
		if (profcnt == 0) {
			status = EXIT_NON_FATAL;
		}
	}
	if (status == EXIT_OK) {
		if (print_flag & PRINT_LONG) {
			print_profs_long(exec);
			free_execattr(exec);
		} else {
			print_profs(profArray, print_flag, profcnt);
		}
	}
	free_userattr(user);

	return (status);
}


/*
 * print extended profile information.
 *
 * output is "pretty printed" like
 *   [6spaces]Profile Name1[ possible profile privileges]
 *   [10spaces  ]execname1 [skip to ATTR_COL]exec1 attributes1
 *   [      spaces to ATTR_COL              ]exec1 attributes2
 *   [10spaces  ]execname2 [skip to ATTR_COL]exec2 attributes1
 *   [      spaces to ATTR_COL              ]exec2 attributes2
 *   [6spaces]Profile Name2[ possible profile privileges]
 *   etc
 */
/*
 * ATTR_COL is based on
 *   10 leading spaces +
 *   25 positions for the executable +
 *    1 space seperating the execname from the attributes
 * so attribute printing starts at column 37 (36 whitespaces)
 *
 *  25 spaces for the execname seems reasonable since currently
 *  less than 3% of the shipped exec_attr would overflow this
 */
#define	ATTR_COL	37

static void
print_profs_long(execattr_t *exec)
{
	char	*curprofile;
	int	len;
	kv_t	*kv_pair;
	char	*key;
	char	*val;
	int	i;

	for (curprofile = ""; exec != NULL; exec = exec->next) {
		/* print profile name if it is a new one */
		if (strcmp(curprofile, exec->name) != 0) {
			curprofile = exec->name;
			(void) printf("      %s", curprofile);
			print_profile_privs(curprofile);
			(void) printf("\n");
		}
		len = printf("          %s ", exec->id);

		if ((exec->attr == NULL || exec->attr->data == NULL)) {
			(void) printf("\n");
			continue;
		}

		/*
		 * if printing the name of the executable got us past the
		 * ATTR_COLth column, skip to ATTR_COL on a new line to
		 * print the attribues.
		 * else, just skip to ATTR_COL column.
		 */
		if (len >= ATTR_COL)
			(void) printf("\n%*s", ATTR_COL, " ");
		else
			(void) printf("%*s", ATTR_COL-len, " ");
		len = ATTR_COL;

		/* print all attributes of this profile */
		kv_pair = exec->attr->data;
		for (i = 0; i < exec->attr->length; i++) {
			key = kv_pair[i].key;
			val = kv_pair[i].value;
			if (key == NULL || val == NULL)
				break;
			/* align subsequent attributes on the same column */
			if (i > 0)
				(void) printf("%*s", len, " ");
			(void) printf("%s=%s\n", key, val);
		}
	}
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("  usage: profiles [-l] [user1 user2 ...]\n"));
}

static void
getProfiles(char *profiles, char **profArray, int *profcnt) {

	char		*prof;
	char		*lasts;

	for (prof = (char *)strtok_r(profiles, PROFLIST_SEP, &lasts);
	    prof != NULL;
	    prof = (char *)strtok_r(NULL, PROFLIST_SEP, &lasts)) {

		getproflist(prof, profArray, profcnt);

	}
}

static void
print_profile_privs(const char *profile)
{
	profattr_t *prof_entry = getprofnam(profile);
	char *privs;

	if (prof_entry) {
		privs = kva_match(prof_entry->attr, PROFATTR_PRIVS_KW);
		if (privs)
			(void) printf(" privs=%s", privs);
		free_profattr(prof_entry);
	}
}

static void
print_profs(char **profnames, int print_flag, int profcnt)
{

	int i;
	char *indent = "";

	if (print_flag & PRINT_NAME) {
		indent = "          ";
	}

	for (i = 0; i < profcnt; i++) {
		(void) printf("%s%s", indent, profnames[i]);
		print_profile_privs(profnames[i]);
		(void) printf("\n");
	}

	free_proflist(profnames, profcnt);
}

/*
 * Get the list of default profiles from /etc/security/policy.conf
 */
static void
getDefaultProfiles(char *user, char **profArray, int *profcnt)
{
	char *profs = NULL;

	if (_get_user_defs(user, NULL, &profs) == 0) {
		if (profs != NULL) {
			getProfiles(profs, profArray, profcnt);
			_free_user_defs(NULL, profs);
		}
	}
}
