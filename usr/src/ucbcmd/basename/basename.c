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
#include <stdlib.h>

int
main(int argc, char **argv)
{
	char *p1, *p2, *p3;

	if (argc < 2) {
		(void) putchar('\n');
		exit(1);
	}
	p1 = argv[1];
	p2 = p1;
	while (*p1) {
		if (*p1++ == '/')
			p2 = p1;
	}
	if (argc > 2) {
		p3 = argv[2];
		while (*p3)
			p3++;

		while (p3 > argv[2])
			if (p1 <= p2 || *--p3 != *--p1)
				goto output;
		*p1 = '\0';
	}
output:

	(void) fputs(p2, stdout);
	(void) putc('\n', stdout);
	return (0);
}
