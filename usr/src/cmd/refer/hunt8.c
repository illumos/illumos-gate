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

#include <locale.h>
#include <stdio.h>
#include <assert.h>
#define	unopen(fil) {if (fil != NULL) {fclose(fil); fil = NULL; }}

extern void err();
extern long indexdate, gdate();
extern FILE *iopen();

int ckexist(char *, char *);

static void
runbib(char *s)
{
	/* make a file suitable for fgrep */
	char tmp[200];
	sprintf(tmp, "/usr/lib/refer/mkey '%s' > '%s.ig'", s, s);
	system(tmp);
}

int
makefgrep(char *indexname)
{
	FILE *fa, *fb;
	if (ckexist(indexname, ".ig")) {
		/* existing gfrep -type index */
#if D1
		fprintf(stderr, "found fgrep\n");
#endif
		fa = iopen(indexname, ".ig");
		fb = iopen(indexname, "");
		if (gdate(fb) > gdate(fa)) {
			if (fa != NULL)
				fclose(fa);
			runbib(indexname);
			fa = iopen(indexname, ".ig");
		}
		indexdate = gdate(fa);
		unopen(fa);
		unopen(fb);
	} else
		if (ckexist(indexname, "")) {
			/* make fgrep */
#if D1
			fprintf(stderr, "make fgrep\n");
#endif
			runbib(indexname);
			time(&indexdate);
		} else /* failure */
			return (0);
	return (1); /* success */
}

int
ckexist(char *s, char *t)
{
	char fnam[100];
	strcpy(fnam, s);
	strcat(fnam, t);
	return (access(fnam, 04) != -1);
}

FILE *
iopen(char *s, char *t)
{
	char fnam[100];
	FILE *f;
	strcpy(fnam, s);
	strcat(fnam, t);
	f = fopen(fnam, "r");
	if (f == NULL) {
		err(gettext("Missing expected file %s"), fnam);
		exit(1);
	}
	return (f);
}
