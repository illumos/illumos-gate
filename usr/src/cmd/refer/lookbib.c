/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <locale.h>

static void instruct(void);
static void map_lower(char *);

/* look in biblio for record matching keywords */
int
main(int argc, char **argv)
{
	FILE *hfp, *fopen(), *popen();
	char s[BUFSIZ], hunt[64];

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1 || argc > 2) {
		fputs(gettext("Usage:  lookbib database\n\
\tfinds citations specified on standard input\n"), stderr);
		exit(1);
	}
	sprintf(s, "%s.ia", argv[1]);
	if (access(s, 0) == -1) {
		sprintf(s, "%s", argv[1]);
		if (access(s, 0) == -1) {
			perror(s);
			fprintf(stderr, gettext("\tNeither index file %s.ia \
nor reference file %s found\n"), s, s);
			exit(1);
		}
	}
	sprintf(hunt, "/usr/lib/refer/hunt %s", argv[1]);
	if (isatty(fileno(stdin))) {
		fprintf(stderr, gettext("Instructions? "));
		fgets(s, BUFSIZ, stdin);
		if (*s == 'y')
			instruct();
	}
again:
	fprintf(stderr, "> ");
	if (fgets(s, BUFSIZ, stdin)) {
		if (*s == '\n')
			goto again;
		if (strlen(s) <= 3)
			goto again;
		if ((hfp = popen(hunt, "w")) == NULL) {
			perror(gettext("lookbib: /usr/lib/refer/hunt"));
			exit(1);
		}
		map_lower(s);
		fputs(s, hfp);
		pclose(hfp);
		goto again;
	}
	fprintf(stderr, gettext("EOT\n"));
	return (0);
}

static void
map_lower(char *s)		/* map string s to lower case */
{
	for (; *s; ++s)
		if (isupper(*s))
			*s = tolower(*s);
}

static void
instruct(void)
{
	fputs(gettext(
"\nType keywords (such as author and date) after the > prompt.\n\
References with those keywords are printed if they exist;\n\
\tif nothing matches you are given another prompt.\n\
To quit lookbib, press CTRL-d after the > prompt.\n\n"), stderr);

}
