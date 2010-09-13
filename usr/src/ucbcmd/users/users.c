/*
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * users
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <utmpx.h>
#include <string.h>

static char **names;
static char **namp;

static int scmp(const void *p, const void *q);
static void summary(void);

int
main(int argc, char **argv)
{
	int	nusers = 0;
	int	bufflen = BUFSIZ;
	struct utmpx *utmpx;

	if (argc == 2)
		if (!utmpxname(argv[1])) {
			(void) fprintf(stderr, "Filename is too long\n");
			exit(1);
		}

	names = namp = (char **)realloc((void *)NULL, BUFSIZ * sizeof (char *));

	setutxent();

	while ((utmpx = getutxent()) != NULL) {
		if (utmpx->ut_name[0] == '\0')
			continue;
		if (utmpx->ut_type != USER_PROCESS)
			continue;
		if (nonuserx(*utmpx))
			continue;
		if (nusers == bufflen) {
			bufflen *= 2;
			names = (char **)realloc(names,
			    bufflen * sizeof (char *));
			namp = names + nusers;
		}
		*namp++ = strndup(utmpx->ut_name, sizeof (utmpx->ut_name));
		nusers++;
	}

	endutxent();

	summary();
	return (0);
}

static int
scmp(const void *p, const void *q)
{
	return (strcmp((char *)p, (char *)q));
}

static void
summary(void)
{
	register char **p;

	qsort(names, namp - names, sizeof (names[0]), scmp);
	for (p = names; p < namp; p++) {
		if (p != names)
			(void) putchar(' ');
		(void) fputs(*p, stdout);
	}
	if (namp != names)		/* at least one user */
		(void) putchar('\n');
}
