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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <locale.h>
#include <limits.h>

#define	BADLINE "Too many/few fields"
#define	TOOLONG "Line too long"
#define	NONAME	"No group name"
#define	BADNAME "Bad character(s) in group name"
#define	BADGID  "Invalid GID"
#define	NULLNAME "Null login name"
#define	NOTFOUND "Logname not found in password file"
#define	DUPNAME "Duplicate logname entry"
#define	DUPNAME2 "Duplicate logname entry (gid first occurs in passwd entry)"
#define	NOMEM	"Out of memory"
#define	NGROUPS	"Maximum groups exceeded for logname "
#define	BLANKLINE "Blank line detected. Please remove line"
#define	LONGNAME  "Group name too long"

int eflag, badchar, baddigit, badlognam, colons, len;
static int longnam = 0;
int code;

#define	MYBUFSIZE (LINE_MAX)	/* max line length including newline and null */
#define	NUM_COLONS	3

char *buf;
char *nptr;
char *cptr;
FILE *fptr;
gid_t gid;
void error(char *msg);

struct group {
	struct group *nxt;
	int cnt;
	gid_t grp;
};

struct node {
	struct node *next;
	int ngroups;
	struct group *groups;
	char user[1];
};

void *
emalloc(size_t size)
{
	void *vp;
	vp = malloc(size);
	if (vp == NULL) {
		fprintf(stderr, "%s\n", gettext(NOMEM));
		exit(1);
	}
	return (vp);
}

int
main(int argc, char *argv[])
{
	struct passwd *pwp;
	struct node *root = NULL;
	struct node *t;
	struct group *gp;
	int ngroups_max;
	int ngroups = 0;
	int listlen;
	int i;
	int lineno = 0;
	char *buf_off, *tmpbuf;
	int delim[NUM_COLONS + 1], buf_len, bufsize;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	code = 0;
	ngroups_max = sysconf(_SC_NGROUPS_MAX);

	if (argc == 1)
		argv[1] = "/etc/group";
	else if (argc != 2) {
		fprintf(stderr, gettext("usage: %s filename\n"), *argv);
		exit(1);
	}

	if ((fptr = fopen(argv[1], "r")) == NULL) {
		fprintf(stderr, gettext("cannot open file %s: %s\n"), argv[1],
		    strerror(errno));
		exit(1);
	}

#ifdef ORIG_SVR4
	while ((pwp = getpwent()) != NULL) {
		t = (struct node *)emalloc(sizeof (*t) + strlen(pwp->pw_name));
		t->next = root;
		root = t;
		strcpy(t->user, pwp->pw_name);
		t->ngroups = 1;
		if (!ngroups_max)
			t->groups = NULL;
		else {
			t->groups = (struct group *)
			    emalloc(sizeof (struct group));
			t->groups->grp = pwp->pw_gid;
			t->groups->cnt = 1;
			t->groups->nxt = NULL;
		}
	}
#endif

	bufsize = MYBUFSIZE;
	if ((buf = malloc(bufsize)) == NULL) {
		(void) fprintf(stderr, gettext(NOMEM));
		exit(1);
	}
	while (!feof(fptr) && !ferror(fptr)) {
		buf_len = 0;
		buf_off = buf;
		while (fgets(buf_off, (bufsize - buf_len), fptr) != NULL) {
			buf_len += strlen(buf_off);
			if (buf[buf_len - 1] == '\n' || feof(fptr))
				break;
			tmpbuf = realloc(buf, (bufsize + MYBUFSIZE));
			if (tmpbuf == NULL) {
				(void) fprintf(stderr, gettext(NOMEM));
				exit(1);
			}
			bufsize += MYBUFSIZE;
			buf = tmpbuf;
			buf_off = buf + buf_len;
		}
		if (buf_len == 0)
			continue;

		/* Report error to be consistent with libc */
		if ((buf_len + 1) > LINE_MAX)
			error(TOOLONG);

		lineno++;
		if (buf[0] == '\n')    /* blank lines are ignored */
		{
			code = 1;		/* exit with error code = 1 */
			eflag = 0;	/* force print of "blank" line */
			fprintf(stderr, "\n%s %d\n", gettext(BLANKLINE),
			    lineno);
			continue;
		}

		if (buf[buf_len - 1] == '\n') {
			if ((tmpbuf = strdup(buf)) == NULL) {
				(void) fprintf(stderr, gettext(NOMEM));
				exit(1);
			}
			tmpbuf[buf_len - 1] = ',';
		} else {
			if ((tmpbuf = malloc(buf_len + 2)) == NULL) {
				(void) fprintf(stderr, gettext(NOMEM));
				exit(1);
			}
			(void) strcpy(tmpbuf, buf);
			tmpbuf[buf_len++] = ',';
			tmpbuf[buf_len] = '\0';
		}

		colons = 0;
		eflag = 0;
		badchar = 0;
		baddigit = 0;
		badlognam = 0;
		gid = 0;

		ngroups++;	/* Increment number of groups found */
		/* Check that entry is not a nameservice redirection */

		if (buf[0] == '+' || buf[0] == '-')  {
			/*
			 * Should set flag here to allow special case checking
			 * in the rest of the code,
			 * but for now, we'll just ignore this entry.
			 */
			free(tmpbuf);
			continue;
		}

		/*	Check number of fields	*/

		for (i = 0; buf[i] != '\0'; i++) {
			if (buf[i] == ':') {
				delim[colons] = i;
				if (++colons > NUM_COLONS)
					break;
			}
		}
		if (colons != NUM_COLONS) {
			error(BADLINE);
			free(tmpbuf);
			continue;
		}

		/* check to see that group name is at least 1 character	*/
		/* and that all characters are lowrcase or digits.	*/

		if (buf[0] == ':')
			error(NONAME);
		else {
			for (i = 0; buf[i] != ':'; i++) {
				if (i >= LOGNAME_MAX)
					longnam++;
				if (!(islower(buf[i]) || isdigit(buf[i])))
					badchar++;
			}
			if (longnam > 0)
				error(LONGNAME);
			if (badchar > 0)
				error(BADNAME);
		}

		/*	check that GID is numeric and <= 31 bits	*/

		len = (delim[2] - delim[1]) - 1;

		if (len > 10 || len < 1)
			error(BADGID);
		else {
			for (i = (delim[1]+1); i < delim[2]; i++) {
				if (! (isdigit(buf[i])))
					baddigit++;
				else if (baddigit == 0)
					gid = gid * 10 + (gid_t)(buf[i] - '0');
				/* converts ascii GID to decimal */
			}
			if (baddigit > 0)
				error(BADGID);
			else if (gid > (gid_t)MAXUID)
				error(BADGID);
		}

		/*  check that logname appears in the passwd file  */

		nptr = &tmpbuf[delim[2]];
		nptr++;

		listlen = strlen(nptr) - 1;

		while ((cptr = strchr(nptr, ',')) != NULL) {
			*cptr = '\0';
			if (*nptr == '\0') {
				if (listlen)
					error(NULLNAME);
				nptr++;
				continue;
			}

			for (t = root; t != NULL; t = t->next) {
				if (strcmp(t->user, nptr) == 0)
					break;
			}
			if (t == NULL) {
#ifndef ORIG_SVR4
				/*
				 * User entry not found, so check if in
				 *  password file
				 */
				struct passwd *pwp;

				if ((pwp = getpwnam(nptr)) == NULL) {
#endif
					badlognam++;
					error(NOTFOUND);
					goto getnext;
#ifndef ORIG_SVR4
				}

				/* Usrname found, so add entry to user-list */
				t = (struct node *)
				    emalloc(sizeof (*t) + strlen(nptr));
				t->next = root;
				root = t;
				strcpy(t->user, nptr);
				t->ngroups = 1;
				if (!ngroups_max)
					t->groups = NULL;
				else {
					t->groups = (struct group *)
					    emalloc(sizeof (struct group));
					t->groups->grp = pwp->pw_gid;
					t->groups->cnt = 1;
					t->groups->nxt = NULL;
				}
			}
#endif
			if (!ngroups_max)
				goto getnext;

			t->ngroups++;

			/*
			 * check for duplicate logname in group
			 */

			for (gp = t->groups; gp != NULL; gp = gp->nxt) {
				if (gid == gp->grp) {
					if (gp->cnt++ == 1) {
						badlognam++;
						if (gp->nxt == NULL)
							error(DUPNAME2);
						else
							error(DUPNAME);
					}
					goto getnext;
				}
			}

			gp = (struct group *)emalloc(sizeof (struct group));
			gp->grp = gid;
			gp->cnt = 1;
			gp->nxt = t->groups;
			t->groups = gp;
getnext:
			nptr = ++cptr;
		}
		free(tmpbuf);
	}

	if (ngroups == 0) {
		fprintf(stderr, gettext("Group file '%s' is empty\n"), argv[1]);
		code = 1;
	}

	if (ngroups_max) {
		for (t = root; t != NULL; t = t->next) {
			if (t->ngroups > ngroups_max) {
				fprintf(stderr, "\n\n%s%s (%d)\n",
				    NGROUPS, t->user, t->ngroups);
				code = 1;
			}
		}
	}
	return (code);
}

/*	Error printing routine	*/

void
error(char *msg)
{
	code = 1;
	if (eflag == 0) {
		fprintf(stderr, "\n\n%s", buf);
		eflag = 1;
	}
	if (longnam != 0) {
		fprintf(stderr, "\t%s\n", gettext(msg));
		longnam = 0;
		return;
	}
	if (badchar != 0) {
		fprintf(stderr, "\t%d %s\n", badchar, gettext(msg));
		badchar = 0;
		return;
	} else if (baddigit != 0) {
		fprintf(stderr, "\t%s\n", gettext(msg));
		baddigit = 0;
		return;
	} else if (badlognam != 0) {
		fprintf(stderr, "\t%s - %s\n", nptr, gettext(msg));
		badlognam = 0;
		return;
	} else {
		fprintf(stderr, "\t%s\n", gettext(msg));
		return;
	}
}
