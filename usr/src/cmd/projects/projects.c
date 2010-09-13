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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/termio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>
#include <project.h>
#include <locale.h>
#include <libintl.h>

struct projlist {
	void *pl_next;
	char *pl_name;
	char *pl_comm;
};

static struct projlist *projects;
static char *progname;

static void *
safe_malloc(size_t size)
{
	void *buf;

	if ((buf = malloc(size)) == NULL) {
		(void) fprintf(stderr, gettext("%s: not enough memory\n"),
		    progname);
		exit(1);
	}
	return (buf);
}

static int
find_projects(char *name, int default_only)
{
	struct projlist *tail, *prev;
	char *projname, *projcomm;
	struct project proj;
	void *buffer, *tmp;
	int found = 0;

	tmp = safe_malloc(PROJECT_BUFSZ);

	if (default_only) {
		if (getdefaultproj(name, &proj, tmp, PROJECT_BUFSZ) != NULL) {
			projects = safe_malloc(sizeof (struct projlist));
			projname = safe_malloc(strlen(proj.pj_name) + 1);
			projcomm = safe_malloc(strlen(proj.pj_comment) + 1);
			(void) strcpy(projname, proj.pj_name);
			(void) strcpy(projcomm, proj.pj_comment);
			projects->pl_next = NULL;
			projects->pl_name = projname;
			projects->pl_comm = projcomm;
			found = 1;
		}
	} else {
		buffer = safe_malloc(PROJECT_BUFSZ);
		setprojent();
		while (getprojent(&proj, tmp, PROJECT_BUFSZ) != NULL) {
			if (inproj(name, proj.pj_name, buffer, PROJECT_BUFSZ)) {
				tail = safe_malloc(sizeof (struct projlist));
				projname =
				    safe_malloc(strlen(proj.pj_name) + 1);
				projcomm =
				    safe_malloc(strlen(proj.pj_comment) + 1);
				(void) strcpy(projname, proj.pj_name);
				(void) strcpy(projcomm, proj.pj_comment);
				tail->pl_next = NULL;
				tail->pl_name = projname;
				tail->pl_comm = projcomm;
				if (!projects) {
					projects = tail;
					prev = projects;
				} else {
					prev->pl_next = tail;
					prev = tail;
				}
				found = 1;
			}
		}
		endprojent();
		free(buffer);
	}
	free(tmp);
	return (found);
}

/*
 * Get the maximum length of the project name string.
 */
static int
max_projname()
{
	struct projlist *pl;
	int max = 0;
	int len;

	for (pl = projects; pl; pl = pl->pl_next)
		if ((len = strlen(pl->pl_name)) > max)
			max = len;
	return (max);
}

static int
print_projects(char *name, int verbose, int default_only)
{
	struct projlist *pl, *next;
	struct winsize ws;
	int length = 0;
	int smart = isatty(STDOUT_FILENO);
	int columns;

	if (!find_projects(name, default_only)) {
		if (default_only)
			(void) fprintf(stderr,
			    gettext("%s: no default project for user %s\n"),
			    progname, name);
		else
			(void) fprintf(stderr,
			    gettext("%s: no projects for user %s\n"),
			    progname, name);
		return (1);
	}

	if (verbose)
		length = max_projname();

	if (smart) {
		/*
		 * Get the number of columns.
		 */
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1 &&
		    ws.ws_col > 0)
			columns = ws.ws_col;
		else
			columns = 80;
	}

	for (pl = projects; pl; ) {
		/*
		 * Display information about projects.
		 */
		if (verbose) {
			(void) printf("%1-*3$s %s\n",
			    pl->pl_name, pl->pl_comm, length);
		} else {
			if (smart &&
			    length + strlen(pl->pl_name) >= columns) {
				(void) printf("\n");
				length = 0;
			}
			(void) printf("%s ", pl->pl_name);
			length += strlen(pl->pl_name) + 1;
		}
		/*
		 * Free previously allocated buffers.
		 */
		next = pl->pl_next;
		free(pl->pl_name);
		free(pl->pl_comm);
		free(pl);
		pl = next;
	}
	if (!verbose && length != 0)
		(void) printf("\n");

	return (0);
}

void
print_projent(struct project *projent)
{
	char **next;
	char *nextc;
	char *nextsemi;

	(void) fprintf(stdout, "%s\n", projent->pj_name);
	(void) fprintf(stdout, "\tprojid : %d\n", projent->pj_projid);
	(void) fprintf(stdout, "\tcomment: \"%s\"\n", projent->pj_comment);

	(void) fprintf(stdout, "\tusers  : ");
	next = projent->pj_users;
	if (*next == NULL) {
		(void) fprintf(stdout, "(none)\n");
	} else {
		(void) fprintf(stdout, "%s\n", *next);
		for (next++; *next != NULL; next++) {
			(void) fprintf(stdout, "\t         %s\n", *next);
		}
	}

	(void) fprintf(stdout, "\tgroups : ");
	next = projent->pj_groups;
	if (*next == NULL) {
		(void) fprintf(stdout, "(none)\n");
	} else {
		(void) fprintf(stdout, "%s\n", *next);
		for (next++; *next != NULL; next++) {
			(void) fprintf(stdout, "\t         %s\n", *next);
		}
	}

	(void) fprintf(stdout, "\tattribs: ");

	nextc = projent->pj_attr;
	if (nextc == NULL) {
		(void) fprintf(stdout, "(none)\n");
	} else {
		/* print first attribute */
		nextsemi = strchr(nextc, ';');
		if (nextsemi)
			*nextsemi = '\0';
		(void) fprintf(stdout, "%s\n", nextc);

		while (nextsemi) {
			nextc = nextsemi + 1;
			nextsemi = strchr(nextc, ';');
			if (nextsemi)
				*nextsemi = '\0';
			(void) fprintf(stdout, "\t         %s\n", nextc);
		}
	}
}

static int
print_projents(char **projlist)
{
	struct project projent;
	char buf[PROJECT_BUFSZ];

	if (*projlist == NULL) {
		setprojent();

		while (getprojent(&projent, buf, sizeof (buf)) != NULL) {
			print_projent(&projent);
		}
		endprojent();
		return (0);
	}

	while (*projlist != NULL) {

		if (getprojbyname(*projlist, &projent, buf, sizeof (buf))
		    == NULL) {
			(void) fprintf(stderr, "%s: project \"%s\" does "
			    "not exist\n", progname, *projlist);
			exit(1);
		}
		print_projent(&projent);
		projlist++;
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	struct passwd *pwd;
	char *name;
	int c;
	int verbose = 0;
	int default_only = 0;
	int listmode = 0;
	uid_t uid;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	progname = argv[0];
	while ((c = getopt(argc, argv, "dvl")) != EOF) {
		switch (c) {
		case 'd':
			default_only = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'l':
			listmode = 1;
			break;
		default:
			(void) fprintf(stderr, gettext(
			    "Usage: %s [-dv] [user]\n"
			    "       %s -l [project [project...]]\n"),
			    progname, progname);
			return (2);
		}
	}

	/* just list projects if -l is specified */
	if (listmode) {
		if (default_only || verbose) {
			(void) fprintf(stderr, gettext(
			    "%s: -l incompatible with -d and -v\n"),
			    progname);
			(void) fprintf(stderr, gettext(
			    "Usage: %s [-dv] [user]\n"
			    "       %s -l [project [project...]]\n"),
			    progname, progname);
		}
		exit(print_projents(argv + optind));
	}
	if (optind == argc) {
		uid = getuid();
		if ((pwd = getpwuid(uid)) == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: getpwuid failed (%s)\n"),
			    progname, strerror(errno));
			return (1);
		}
		name = pwd->pw_name;
	} else {
		name = argv[optind];
		if (getpwnam(name) == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: user %s does not exist\n"),
			    progname, name);
			return (1);
		}
	}
	return (print_projects(name, verbose, default_only));
}
