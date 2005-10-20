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

#include "refer..c"

static char ahead[1024];
static int peeked = 0;
static char *noteof = (char *)1;

char *
input(char *s)
{
	if (peeked) {
		peeked = 0;
		if (noteof == 0)
			return (0);
		strcpy(s, ahead);
		return (s);
	}
	return (fgets(s, 1000, in));
}

char *
lookat(void)
{
	if (peeked)
		return (ahead);
	noteof = input(ahead);
	peeked = 1;
	return (noteof);
}

void
addch(char *s, char c)
{
	while (*s)
		s++;
	*s++ = c;
	*s = 0;
}
