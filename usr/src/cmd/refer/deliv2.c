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
#include <locale.h>

int
hash(char *s)
{
	int c, n;
	for (n = 0; c = *s; s++)
		n += (c*n+ c << (n%4));
	return (n > 0 ? n : -n);
}

void
err(char *s, int a)
{
	fprintf(stderr, gettext("Error: "));
	fprintf(stderr, s, a);
	putc('\n', stderr);
	exit(1);
}

int
prefix(char *t, char *s)
{
	int c;

	while ((c = *t++) == *s++)
		if (c == 0)
			return (1);
	return (c == 0 ? 1 : 0);
}

char *
mindex(char *s, char c)
{
	char *p;
	for (p = s; *p; p++)
		if (*p == c)
			return (p);
	return (0);
}

void *
zalloc(size_t m, size_t n)
{
	char *calloc();
	void *t;
#if D1
	fprintf(stderr, "calling calloc for %d*%d bytes\n", m, n);
#endif
	t = calloc(m, n);
#if D1
	fprintf(stderr, "calloc returned %o\n", t);
#endif
	return (t);
}
