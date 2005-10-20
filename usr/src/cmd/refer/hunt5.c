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
#include <sys/types.h>
#include <sys/stat.h>

extern char *soutput, *tagout, usedir[];
union ptr {
	unsigned *a;
	long *b;
};

void
result(unsigned *mptr, int nf, FILE *fc)
{
	int i, c;
	char *s;
	long lp;
	extern int iflong;
	char res[100];
	union ptr master;

	if (iflong) {
		master.b = (long *)mptr;
	} else {
		master.a = mptr;
	}

	for (i = 0; i < nf; i++) {
		lp = iflong ? master.b[i] : master.a[i];
		fseek(fc, lp, 0);
		fgets(res, 100, fc);
		for (s = res; c = *s; s++)
			if (c == ';') {
				*s = 0;
				break;
			}
		if (tagout != 0) {
			if (res[0] == '/' || usedir[0] == 0)
				sprintf(tagout, "%s", res);
			else
				sprintf(tagout, "%s/%s", usedir, res);
			while (*tagout) tagout++;
		} else {
			if (res[0] != '/' || usedir[0] == 0)
				printf("%s/", usedir);
			printf("%s\n", res);
		}
	}
}

long
gdate(f)
FILE *f;
{
	struct stat sb;
	fstat(fileno(f), &sb);
	return (sb . st_mtime);
}
