/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdarg.h>

#define	C		3
#define	RANGE		30
#define	LEN		255
#define	INF		16384

char *text[2][RANGE];
long lineno[2] = {1, 1};	/* no. of 1st stored line in each file */
int ntext[2];		/* number of stored lines in each */
long n0, n1;		/* scan pointer in each */
int bflag;
int debug = 0;
FILE *file[2];
static int diffFound = 0;

static char *getl(int f, long n);
static void clrl(int f, long n);
static void movstr(char *s, char *t);
static int easysynch(void);
static int output(int a, int b);
static void change(long a, int b, long c, int d, char *s);
static void range(long a, int b);
static int cmp(char *s, char *t);
static FILE *dopen(char *f1, char *f2);
static void progerr(char *s);
static void error(char *err, ...);
static int hardsynch(void);

	/* return pointer to line n of file f */
static char *
getl(int f, long n)
{
	char *t;
	int delta, nt;

again:
	delta = n - lineno[f];
	nt = ntext[f];
	if (delta < 0)
		progerr("1");
	if (delta < nt)
		return (text[f][delta]);
	if (delta > nt)
		progerr("2");
	if (nt >= RANGE)
		progerr("3");
	if (feof(file[f]))
		return (NULL);
	t = text[f][nt];
	if (t == 0) {
		t = text[f][nt] = (char *)malloc(LEN+1);
		if (t == NULL)
			if (hardsynch())
				goto again;
			else
				progerr("5");
	}
	t = fgets(t, LEN, file[f]);
	if (t != NULL)
		ntext[f]++;
	return (t);
}

	/* remove thru line n of file f from storage */
static void
clrl(int f, long n)
{
	int i, j;

	j = n-lineno[f]+1;
	for (i = 0; i+j < ntext[f]; i++)
		movstr(text[f][i+j], text[f][i]);
	lineno[f] = n+1;
	ntext[f] -= j;
}

static void
movstr(char *s, char *t)
{
	while (*t++ = *s++)
		continue;
}

int
main(int argc, char **argv)
{
	char *s0, *s1;

	if ((argc > 1) && (*argv[1] == '-')) {
		argc--;
		argv++;
		while (*++argv[0])
			if (*argv[0] == 'b')
				bflag++;
	}

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc != 3)
		error(gettext("must have 2 file arguments"));
	file[0] = dopen(argv[1], argv[2]);
	file[1] = dopen(argv[2], argv[1]);
	for (;;) {
		s0 = getl(0, ++n0);
		s1 = getl(1, ++n1);
		if (s0 == NULL || s1 == NULL)
			break;
		if (cmp(s0, s1) != 0) {
			if (!easysynch() && !hardsynch())
				progerr("5");
		} else {
			clrl(0, n0);
			clrl(1, n1);
		}
	}
	/* diff is expected to return 1 if the files differ */
	if (s0 == NULL && s1 == NULL)
		return (diffFound);
	if (s0 == NULL) {
		(void) output(-1, INF);
		return (1);
	}
	if (s1 == NULL) {
		(void) output(INF, -1);
		return (1);
	}
	/* NOTREACHED */
	return (0);
}

	/* synch on C successive matches */
static int
easysynch()
{
	int i, j;
	int k, m;
	char *s0, *s1;

	for (i = j = 1; i < RANGE && j < RANGE; i++, j++) {
		s0 = getl(0, n0+i);
		if (s0 == NULL)
			return (output(INF, INF));
		for (k = C-1; k < j; k++) {
			for (m = 0; m < C; m++)
				if (cmp(getl(0, n0+i-m),
					getl(1, n1+k-m)) != 0)
					goto cont1;
			return (output(i-C, k-C));
cont1:
			;
		}
		s1 = getl(1, n1+j);
		if (s1 == NULL)
			return (output(INF, INF));
		for (k = C-1; k <= i; k++) {
			for (m = 0; m < C; m++)
				if (cmp(getl(0, n0+k-m),
					getl(1, n1+j-m)) != 0)
					goto cont2;
			return (output(k-C, j-C));
cont2:
			;
		}
	}
	return (0);
}

static int
output(int a, int b)
{
	int i;
	char *s;

	if (a < 0)
		change(n0-1, 0, n1, b, "a");
	else if (b < 0)
		change(n0, a, n1-1, 0, "d");
	else
		change(n0, a, n1, b, "c");
	for (i = 0; i <= a; i++) {
		s = getl(0, n0+i);
		if (s == NULL)
			break;
		(void) printf("< %s", s);
		clrl(0, n0+i);
	}
	n0 += i-1;
	if (a >= 0 && b >= 0)
		(void) printf("---\n");
	for (i = 0; i <= b; i++) {
		s = getl(1, n1+i);
		if (s == NULL)
			break;
		(void) printf("> %s", s);
		clrl(1, n1+i);
	}
	diffFound = 1;
	n1 += i-1;
	return (1);
}

static void
change(long a, int b, long c, int d, char *s)
{
	range(a, b);
	(void) printf("%s", s);
	range(c, d);
	(void) printf("\n");
}

static void
range(long a, int b)
{
	if (b == INF)
		(void) printf("%ld,$", a);
	else if (b == 0)
		(void) printf("%ld", a);
	else
		(void) printf("%ld,%ld", a, a+b);
}

static int
cmp(char *s, char *t)
{
	if (debug)
		(void) printf("%s:%s\n", s, t);
	for (;;) {
		if (bflag && isspace(*s) && isspace(*t)) {
			while (isspace(*++s))
				;
			while (isspace(*++t))
				;
		}
		if (*s != *t || *s == 0)
			break;
		s++;
		t++;
	}
	return (*s-*t);
}

static FILE *
dopen(char *f1, char *f2)
{
	FILE *f;
	char b[PATH_MAX], *bptr, *eptr;
	struct stat statbuf;

	if (cmp(f1, "-") == 0) {
		if (cmp(f2, "-") == 0)
			error(gettext("can't do - -"));
		else {
			if (fstat(fileno(stdin), &statbuf) == -1)
				error(gettext("can't access stdin"));
			else
				return (stdin);
		}
	}
	if (stat(f1, &statbuf) == -1)
		error(gettext("can't access %s"), f1);
	if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
		for (bptr = b; *bptr = *f1++; bptr++)
			;
		*bptr++ = '/';
		for (eptr = f2; *eptr; eptr++)
			if (*eptr == '/' && eptr[1] != 0 && eptr[1] != '/')
				f2 = eptr+1;
		while (*bptr++ = *f2++)
			;
		f1 = b;
	}
	f = fopen(f1, "r");
	if (f == NULL)
		error(gettext("can't open %s"), f1);
	return (f);
}


static void
progerr(char *s)
{
	error(gettext("program error %s"), s);
}

static void
error(char *err, ...)
{
	va_list	ap;

	va_start(ap, err);
	(void) fprintf(stderr, "diffh: ");
	(void) vfprintf(stderr, err, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
	exit(2);
}

	/* stub for resychronization beyond limits of text buf */
static int
hardsynch()
{
	change(n0, INF, n1, INF, "c");
	(void) printf(gettext("---change record omitted\n"));
	error(gettext("can't resynchronize"));
	return (0);
}
