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
#define	COMNUM 500
#define	COMTSIZE 997

char *comname = "/usr/lib/refer/eign";
static int cgate = 0;
extern char *comname;
int comcount = 100;
static char cbuf[COMNUM*9];
static char *cwds[COMTSIZE];
static char *cbp;

extern int hash();
extern char *trimnl();

static void cominit(void);
static int c_look(char *, int);

int
common(char *s)
{
	if (cgate == 0) cominit();
	return (c_look(s, 1));
}

static void
cominit(void)
{
	int i;
	FILE *f;
	cgate = 1;
	f = fopen(comname, "r");
	if (f == NULL)
		return;
	cbp = cbuf;
	for (i = 0; i < comcount; i++) {
		if (fgets(cbp, 15, f) == NULL)
			break;
		trimnl(cbp);
		c_look(cbp, 0);
		while (*cbp++)
			;
	}
	fclose(f);
}

static int
c_look(char *s, int fl)
{
	int h;
	h = hash(s) % (COMTSIZE);
	while (cwds[h] != 0) {
		if (strcmp(s, cwds[h]) == 0)
			return (1);
		h = (h+1) % (COMTSIZE);
	}
	if (fl == 0)
		cwds[h] = s;
	return (0);
}
