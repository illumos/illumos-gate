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
 * Sum bytes in file mod 2^16
 */

#include <stdio.h>

int
main(int argc, char **argv)
{
	unsigned int sum;
	int i, c;
	FILE *f;
	long long nbytes;
	int errflg = 0;

	i = 1;
	do {
		if (i < argc) {
			if ((f = fopen(argv[i], "r")) == NULL) {
				(void) fprintf(stderr,
					"sum: Can't open %s\n", argv[i]);
				errflg += 10;
				continue;
			}
		} else
			f = stdin;
		sum = 0;
		nbytes = 0;
		while ((c = getc(f)) != EOF) {
			nbytes++;
			if (sum&01)
				sum = (sum>>1) + 0x8000;
			else
				sum >>= 1;
			sum += c;
			sum &= 0xFFFF;
		}
		if (ferror(f)) {
			errflg++;
			(void) fprintf(stderr,
				"sum: read error on %s\n",
				argc > 1 ? argv[i] : "-");
		}

		(void) printf("%05u %5lld", sum,
			(nbytes + BUFSIZ - 1) / BUFSIZ);
		if (argc > 2)
			(void) printf(" %s", argv[i]);
		(void) printf("\n");
		(void) fclose(f);
	} while (++i < argc);

	return (errflg);
}
