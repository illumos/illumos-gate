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
 *	Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ftp_var.h"

static	FILE *cfile;

static int rnetrc(char *host, char **aname, char **apass, char **aacct);
static int token(void);

int
ruserpass(char *host, char **aname, char **apass, char **aacct)
{
#if 0
	renv(host, aname, apass, aacct);
	if (*aname == 0 || *apass == 0)
#endif
		return (rnetrc(host, aname, apass, aacct));
}

#define	DEFAULT	1
#define	LOGIN	2
#define	PASSWD	3
#define	ACCOUNT 4
#define	MACDEF	5
#define	SKIPSYST	6
#define	ID	10
#define	MACHINE	11

static char tokval[100];

static struct toktab {
	char *tokstr;
	int tval;
} toktab[] = {
	"default",	DEFAULT,
	"login",	LOGIN,
	"password",	PASSWD,
	"account",	ACCOUNT,
	"machine",	MACHINE,
	"macdef",	MACDEF,
	"skipsyst",	SKIPSYST,
	0,		0
};

static int
rnetrc(char *host, char **aname, char **apass, char **aacct)
{
	char *hdir, buf[PATH_MAX+1], *tmp;
	int t, i, c;
	struct stat stb;
	extern int errno;

	hdir = getenv("HOME");
	if (hdir == NULL)
		hdir = ".";
	if (snprintf(buf, sizeof (buf), "%s/.netrc", hdir) >= sizeof (buf)) {
		fprintf(stderr, ".netrc: %s\n", strerror(ENAMETOOLONG));
		exit(1);
	}

	cfile = fopen(buf, "r");
	if (cfile == NULL) {
		if (errno != ENOENT)
			perror(buf);
		return (0);
	}
next:
	while ((t = token()))
		switch (t) {

	case MACHINE:
		if (token() != ID || strcmp(host, tokval))
			continue;
		/* "machine name" matches host */
		/* FALLTHROUGH */

	case DEFAULT:
		/* "default" matches any host */
		while (((t = token()) != 0) && t != MACHINE && t != DEFAULT)
			switch (t) {

		case LOGIN:
			if (token())
				if (*aname == 0) {
					*aname = malloc((unsigned)
					    strlen(tokval) + 1);
					if (*aname == NULL) {
						fprintf(stderr,
						    "Error - out of VM\n");
						exit(1);
					}
					(void) strcpy(*aname, tokval);
				} else {
					if (strcmp(*aname, tokval))
						goto next;
				}
			break;
		case PASSWD:
			if (fstat(fileno(cfile), &stb) >= 0 &&
			    (stb.st_mode & 077) != 0) {
				fprintf(stderr, "Error - .netrc file not "
				    "correct mode.\n");
				fprintf(stderr, "Remove password or correct "
				    "mode.\n");
				return (-1);
			}
			if (token() && *apass == 0) {
				*apass = malloc((unsigned)strlen(tokval) + 1);
				if (*apass == NULL) {
					fprintf(stderr, "Error - out of VM\n");
					exit(1);
				}
				(void) strcpy(*apass, tokval);
			}
			break;
		case ACCOUNT:
			if (fstat(fileno(cfile), &stb) >= 0 &&
			    (stb.st_mode & 077) != 0) {
				fprintf(stderr, "Error - .netrc file not "
				    "correct mode.\n");
				fprintf(stderr, "Remove account or correct "
				    "mode.\n");
				return (-1);
			}
			if (token() && *aacct == 0) {
				*aacct = malloc((unsigned)strlen(tokval) + 1);
				if (*aacct == NULL) {
					fprintf(stderr, "Error - out of VM\n");
					exit(1);
				}
				(void) strcpy(*aacct, tokval);
			}
			break;
		case MACDEF:
			if (proxy) {
				return (0);
			}
			while ((c = getc(cfile)) != EOF && c == ' ' ||
			    c == '\t');
			if (c == EOF || c == '\n') {
				printf("Missing macdef name argument.\n");
				return (-1);
			}
			if (macnum == 16) {
				printf("Limit of 16 macros have already "
				    "been defined\n");
				return (-1);
			}
			tmp = macros[macnum].mac_name;
			*tmp++ = c;
			for (i = 0; i < 8 && (c = getc(cfile)) != EOF &&
			    !isspace(c); ++i) {
				*tmp++ = c;
			}
			if (c == EOF) {
				printf("Macro definition for `%s` missing "
				    "null line terminator.\n",
				    macros[macnum].mac_name);
				return (-1);
			}
			*tmp = '\0';
			if (c != '\n') {
				while ((c = getc(cfile)) != EOF && c != '\n');
			}
			if (c == EOF) {
				printf("Macro definition for `%s` missing "
				    "null line terminator.\n",
				    macros[macnum].mac_name);
				return (-1);
			}
			if (macnum == 0) {
				macros[macnum].mac_start = macbuf;
			} else {
				macros[macnum].mac_start =
				    macros[macnum-1].mac_end + 1;
			}
			tmp = macros[macnum].mac_start;
			while (tmp != macbuf + 4096) {
				if ((c = getc(cfile)) == EOF) {
				printf("Macro definition for `%s` missing "
				    "null line terminator.\n",
				    macros[macnum].mac_name);
					return (-1);
				}
				*tmp = c;
				if (*tmp == '\n') {
					if (*(tmp-1) == '\0') {
						macros[macnum++].mac_end =
						    tmp - 1;
						break;
					}
					*tmp = '\0';
				}
				tmp++;
			}
			if (tmp == macbuf + 4096) {
				printf("4K macro buffer exceeded\n");
				return (-1);
			}
			if (*macros[macnum - 1].mac_start == '\n') {
				printf("Macro definition for `%s` is empty, "
				    "macro not stored.\n",
					macros[--macnum].mac_name);
			}
			break;
		case SKIPSYST:
			skipsyst = 1;
			break;
		default:
			fprintf(stderr, "Unknown .netrc keyword %s\n", tokval);
			break;
		}
		goto done;
	}
done:
	(void) fclose(cfile);
	return (0);
}

static int
token(void)
{
	char *cp;
	int c;
	struct toktab *t;
	int	len;

	if (feof(cfile))
		return (0);
	while ((c = fgetwc(cfile)) != EOF &&
	    (c == '\n' || c == '\t' || c == ' ' || c == ','))
		continue;
	if (c == EOF)
		return (0);
	cp = tokval;
	if (c == '"') {
		while ((c = fgetwc(cfile)) != EOF && c != '"') {
			if (c == '\\')
				c = fgetwc(cfile);
			if ((len = wctomb(cp, c)) <= 0) {
				len = 1;
				*cp = (unsigned char)c;
			}
			cp += len;
		}
	} else {
		if ((len = wctomb(cp, c)) <= 0) {
			*cp = (unsigned char)c;
			len = 1;
		}
		cp += len;
		while ((c = fgetwc(cfile)) != EOF && c != '\n' && c != '\t' &&
		    c != ' ' && c != ',') {
			if (c == '\\')
				c = fgetwc(cfile);
			if ((len = wctomb(cp, c)) <= 0) {
				len = 1;
				*cp = (unsigned char)c;
			}
			cp += len;
		}
	}
	*cp = 0;
	if (tokval[0] == 0)
		return (0);
	for (t = toktab; t->tokstr; t++)
		if (strcmp(t->tokstr, tokval) == 0)
			return (t->tval);
	return (ID);
}
