/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * users
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <utmpx.h>

static	char	*strndup(char *p, int n);

struct utmpx *utmpx;
char	**names;
char	**namp;

main(argc, argv)
char **argv;
{
	char	 *tp;
	int	nusers = 0;
	int	bufflen = BUFSIZ;

	if (argc == 2)
		if (!utmpxname(argv[1])) {
			fprintf(stderr, "Filename is too long\n");
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
	exit(0);
}

static	char	*
strndup(char *p, int n)
{

	register char	*x;
	x = malloc(n + 1);
	strncpy(x, p, n);
	*(x + n) = '\0';
	return (x);

}

scmp(const void *p, const void *q)
{
	return (strcmp((char *)p, (char *)q));
}

summary()
{
	register char **p;

	qsort(names, namp - names, sizeof (names[0]), scmp);
	for (p = names; p < namp; p++) {
		if (p != names)
			putchar(' ');
		fputs(*p, stdout);
	}
	if (namp != names)		/* at least one user */
		putchar('\n');
}
