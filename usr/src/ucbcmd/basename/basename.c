/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#include	<stdio.h>

main(argc, argv)
char **argv;
{
	register char *p1, *p2, *p3;

	if (argc < 2) {
		(void)putchar('\n');
		exit(1);
	}
	p1 = argv[1];
	p2 = p1;
	while (*p1) {
		if (*p1++ == '/')
			p2 = p1;
	}
	if (argc>2) {
		for(p3=argv[2]; *p3; p3++) 
			;
		while(p3>argv[2])
			if(p1 <= p2 || *--p3 != *--p1)
				goto output;
		*p1 = '\0';
	}
output:
	fputs(p2, stdout);
	putc('\n', stdout);
	exit(0);
	/* NOTREACHED */
}
