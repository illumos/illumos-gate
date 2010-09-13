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

/*
 * echo
 */
#include <stdio.h>

int
main(int argc, char *argv[])
{
	int i, nflg;

	nflg = 0;
	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'n' && !argv[1][2]) {
		nflg++;
		argc--;
		argv++;
	}
	for (i = 1; i < argc; i++) {
		(void) fputs(argv[i], stdout);
		if (i < argc-1)
			(void) putchar(' ');
	}

	if (nflg == 0)
		(void) putchar('\n');
	return (0);
}
