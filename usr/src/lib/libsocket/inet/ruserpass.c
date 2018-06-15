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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <libintl.h>
#include <limits.h>

#ifdef SYSV
#define	index	strchr
#endif /* SYSV */

static void rnetrc(const char *host, char **aname, char **apass);
static int token();

#define	DEFAULT	1
#define	LOGIN	2
#define	PASSWD	3
#define	NOTIFY	4
#define	WRITE	5
#define	YES	6
#define	NO	7
#define	COMMAND	8
#define	FORCE	9
#define	ID	10
#define	MACHINE	11

#define	MAXTOKEN  11
#define	NTOKENS	(MAXTOKEN - 1 + 2 + 1)	/* two duplicates and null, minus id */

static struct ruserdata {
	char tokval[100];
	struct toktab {
		char *tokstr;
		int tval;
	} toktab[NTOKENS];
	FILE *cfile;
} *ruserdata, *_ruserdata();


static struct ruserdata *
_ruserdata()
{
	struct ruserdata *d = ruserdata;
	struct toktab *t;

	if (d == 0) {
		if ((d = (struct ruserdata *)
			calloc(1, sizeof (struct ruserdata))) == NULL) {
				return (NULL);
		}
		ruserdata = d;
		t = d->toktab;
		t->tokstr = "default";  t++->tval = DEFAULT;
		t->tokstr = "login";    t++->tval = LOGIN;
		t->tokstr = "password"; t++->tval = PASSWD;
		t->tokstr = "notify";   t++->tval = NOTIFY;
		t->tokstr = "write";    t++->tval = WRITE;
		t->tokstr = "yes";	t++->tval = YES;
		t->tokstr = "y";	t++->tval = YES;
		t->tokstr = "no";	t++->tval = NO;
		t->tokstr = "n";	t++->tval = NO;
		t->tokstr = "command";  t++->tval = COMMAND;
		t->tokstr = "force";    t++->tval = FORCE;
		t->tokstr = "machine";  t++->tval = MACHINE;
		t->tokstr = 0;		t->tval = 0;
	}
	return (d);
}


#define	MAXANAME	16

void
_ruserpass(const char *host, char **aname, char **apass)
{

	if (*aname == 0 || *apass == 0)
		rnetrc(host, aname, apass);
	if (*aname == 0) {
		char myname[L_cuserid];

		*aname = malloc(MAXANAME + 1);
		(void) cuserid(myname);
		(void) printf(dgettext(TEXT_DOMAIN, "Name (%s:%s): "),
		    host, myname);
		(void) fflush(stdout);
		if (read(2, *aname, MAXANAME) <= 0)
			exit(1);
		aname[0][MAXANAME] = '\0';
		if ((*aname)[0] == '\n')
			(void) strcpy(*aname, myname);
		else
			if (index(*aname, '\n'))
				*index(*aname, '\n') = 0;
	}
	if (*aname && *apass == 0) {
		(void) printf(dgettext(TEXT_DOMAIN, "Password (%s:%s): "),
		    host, *aname);
		(void) fflush(stdout);
		*apass = getpass("");
	}
}


static void
rnetrc(const char *host, char **aname, char **apass)
{
	struct ruserdata *d = _ruserdata();
	char *hdir, buf[PATH_MAX];
	int t;
	struct stat64 stb;

	if (d == 0)
		return;

	hdir = getenv("HOME");
	if (hdir == NULL)
		hdir = ".";
	t = snprintf(buf, sizeof (buf), "%s/.netrc", hdir);
	if (t < 0 || t >= sizeof (buf)) {
		if (t < 0) {
			perror(buf);
		} else {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "HOME directory name is too long: %s\n"), hdir);
		}
		return;
	}

	d->cfile = fopen(buf, "rF");
	if (d->cfile == NULL) {
		if (errno != ENOENT)
			perror(buf);
		return;
	}
next:
	while ((t = token()))
	switch (t) {

	case DEFAULT:
		(void) token();
		continue;

	case MACHINE:
		if (token() != ID || strcmp(host, d->tokval))
			continue;
		while ((t = token()) != 0 && t != MACHINE)
		switch (t) {

		case LOGIN:
			if (token())
				if (*aname == 0) {
					*aname = malloc(strlen(d->tokval) + 1);
					(void) strcpy(*aname, d->tokval);
				} else {
					if (strcmp(*aname, d->tokval))
						goto next;
				}
			break;
		case PASSWD:
			if (fstat64(fileno(d->cfile), &stb) >= 0 &&
			    (stb.st_mode & 077) != 0) {
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "Error - .netrc file not correct mode.\n"));
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "Remove password or correct mode.\n"));
				exit(1);
			}
			if (token() && *apass == 0) {
				*apass = malloc(strlen(d->tokval) + 1);
				(void) strcpy(*apass, d->tokval);
			}
			break;
		case COMMAND:
		case NOTIFY:
		case WRITE:
		case FORCE:
			(void) token();
			break;
		default:
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Unknown .netrc option %s\n"), d->tokval);
			break;
		}
		goto done;
	}
done:
	(void) fclose(d->cfile);
}

static int
token()
{
	struct ruserdata *d = _ruserdata();
	char *cp;
	int c;
	struct toktab *t;

	if (d == 0)
		return (0);

	if (feof(d->cfile))
		return (0);
	while ((c = getc(d->cfile)) != EOF &&
	    (c == '\n' || c == '\t' || c == ' ' || c == ','))
		continue;
	if (c == EOF)
		return (0);
	cp = d->tokval;
	if (c == '"') {
		while ((c = getc(d->cfile)) != EOF && c != '"') {
			if (c == '\\')
				c = getc(d->cfile);
			*cp++ = (char)c;
		}
	} else {
		*cp++ = (char)c;
		while ((c = getc(d->cfile)) != EOF &&
		    c != '\n' && c != '\t' && c != ' ' && c != ',') {
			if (c == '\\')
				c = getc(d->cfile);
			*cp++ = (char)c;
		}
	}
	*cp = 0;
	if (d->tokval[0] == 0)
		return (0);
	for (t = d->toktab; t->tokstr; t++)
		if ((strcmp(t->tokstr, d->tokval) == 0))
			return (t->tval);
	return (ID);
}
