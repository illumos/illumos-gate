/*
 * Copyright 2017 Gary Mills
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


#include <stdio.h>
#include <ctype.h>

extern char gfile[];

void
grepcall(char *in, char *out, char *arg)
{
	char line[200], *s, argig[100], *cv[50];
	char *inp, inb[500];
	FILE *qf, *gf;
	int c, alph = 0, nv = 0;
	int sv0, sv1;
	strcpy(argig, arg);
	strcat(argig, ".ig");
	strcpy(inp = inb, in);
	if (gfile[0] == 0)
		sprintf(gfile, "/tmp/rj%dg", getpid());
	for (cv[nv++] = "fgrep"; c = *inp; inp++) {
		if (c == ' ')
			c = *inp = 0;
		else if (isupper(c))
			*inp = tolower(c);
		alph = (c == 0) ? 0 : alph+1;
		if (alph == 1)
			cv[nv++] = inp;
		if (alph > 6)
			*inp = 0;
	}
	{
		sv0 = dup(0);
		close(0);
		if (open(argig, 0) != 0)
			err("Can't read fgrep index %s", argig);
		sv1 = dup(1);
		close(1);
		if (creat(gfile, 0666) != 1)
			err("Can't write fgrep output %s", gfile);
		fgrep(nv, cv);
		close(0);
		dup(sv0);
		close(sv0);
		close(1);
		dup(sv1);
		close(sv1);
	}

	gf = fopen(gfile, "r");
	if (gf == NULL)
		err("can't read fgrep output %s", gfile);
	while (fgets(line, 100, gf) == line) {
		line[100] = 0;
		for (s = line; *s && (*s != '\t'); s++)
			;
		if (*s == '\t') {
			*s++ = '\n';
			*s++ = 0;
		}
		if (line[0])
			strcat(out, line);
		while (*s) s++;
		if (s[-1] != '\n')
			while (!feof(gf) && getc(gf) != '\n')
				;
	}
	fclose(gf);
	unlink(gfile);
}

void
clfgrep(void)
{
	if (gfile[0])
		unlink(gfile);
}
