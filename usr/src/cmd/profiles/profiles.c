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

#define	MAX_LINE_LEN	80		/* max 80 chars per line of output */
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
static void print_profs_long(void *, int);
static void print_profs(char **, int, int);
static void format_attr(int *, int, char *);
static void getProfiles(char *, char **, int *);
static void getDefaultProfiles(char *, char **, int *);

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
			(void) printf("\n%s :\n", *argv);
			status = show_profs((char *)*argv,
			    (print_flag | PRINT_NAME));
			if (status == EXIT_FATAL) {
				break;
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
		(void) fprintf(stderr, "%s: %s : ", progname, username);
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
					    NULL, GET_ALL);
					print_profs_long(exec, print_flag);
					free_execattr(exec);
				} else {
					print_profs(profArray, print_flag,
					    profcnt);
				}
			}
		}
	}

	if (status == EXIT_NON_FATAL) {
		(void) fprintf(stderr, "%s: %s : ", progname, username);
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
		exec = getexecuser(user->name, KV_COMMAND, NULL, GET_ALL);
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
			print_profs_long(exec, print_flag);
			free_execattr(exec);
		} else {
			print_profs(profArray, print_flag, profcnt);
		}
	}
	free_userattr(user);

	return (status);
}


static void
print_profs_long(void *data, int print_flag)
{

	int		i;
	int		len;
	int		outlen;
	char		tmpstr[TMP_BUF_LEN];
	char		*lastname = "";
	char		*key;
	char		*val;
	kv_t		*kv_pair;
	execattr_t	*exec;

	if (!(print_flag & PRINT_NAME)) {
		(void) printf("\n");
	}
	exec = (execattr_t *)data;
	while (exec != (execattr_t *)NULL) {
		if (strcmp(exec->name, lastname) != NULL) {
			(void) snprintf(tmpstr, sizeof (tmpstr),
			    "      %s:", exec->name);
			(void) printf("%s\n", tmpstr);
		}
		(void) snprintf(tmpstr, sizeof (tmpstr),
		    "          %s    ", exec->id);
		outlen = strlen(tmpstr);
		len = outlen;
		(void) printf("%s", tmpstr);
		if ((exec->attr == NULL) ||
		    (kv_pair = exec->attr->data) == NULL) {
			(void) printf("\n");
			lastname = exec->name;
			exec = exec->next;
			continue;
		}
		for (i = 0; i < exec->attr->length; i++) {
			key = kv_pair[i].key;
			val = kv_pair[i].value;
			if ((key == NULL) || (val == NULL)) {
				break;
			}
			if (i > 0) {
				(void) strlcpy(tmpstr, ", ", TMP_BUF_LEN);
				format_attr(&outlen, len, tmpstr);
			}
			(void) snprintf(tmpstr, sizeof (tmpstr), "%s=%s",
			    key, val);
			format_attr(&outlen, len, tmpstr);
		}
		(void) printf("\n");
		lastname = exec->name;
		exec = exec->next;
	}
}


static void
format_attr(int *outlen, int len, char *str)
{
	int newline = 0;

	if ((MAX_LINE_LEN - *outlen) < strlen(str)) {
		newline = 1;
	}
	if (newline) {
		(void) printf("\n");
		len += strlen(str);
		(void) printf("%*s", len, str);
		*outlen = len;
	} else {
		*outlen += strlen(str);
		(void) printf("%s", str);
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
print_profs(char **profnames, int print_flag, int profcnt)
{

	int i;
	char *indent = "";

	if (print_flag & PRINT_NAME) {
		indent = "          ";
	}

	for (i = 0; i < profcnt; i++) {
		(void) printf("%s%s\n", indent, profnames[i]);
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
