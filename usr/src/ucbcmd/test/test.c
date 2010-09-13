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
 * test expression
 * [ expression ]
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#define	EQ(a, b)	((strcmp(a, b) == 0))

static char *nxtarg(int mt);
static int exp(void);
static int e1(void);
static int e2(void);
static int e3(void);
static int tio(char *a, int f);
static int ftype(char *f, int field);
static int filtyp(char *f, int field);
static int fsizep(char *f);
static void synbad(char *s1, char *s2);

static int	ap;
static int	ac;
static char	**av;

int
main(int argc, char *argv[])
{
	int status;

	ac = argc; av = argv; ap = 1;
	if (EQ(argv[0], "[")) {
		if (!EQ(argv[--ac], "]"))
			synbad("] missing", "");
	}
	argv[ac] = 0;
	if (ac <= 1)
		exit(1);
	status = (exp() ? 0 : 1);
	if (nxtarg(1) != 0)
		synbad("too many arguments", "");
	return (status);
}

static char *
nxtarg(int mt)
{
	if (ap >= ac) {
		if (mt) {
			ap++;
			return (0);
		}
		synbad("argument expected", "");
	}
	return (av[ap++]);
}

static int
exp(void)
{
	int p1;
	char *p2;

	p1 = e1();
	p2 = nxtarg(1);
	if (p2 != 0) {
		if (EQ(p2, "-o"))
			return (p1 | exp());
		if (EQ(p2, "]"))
			synbad("syntax error", "");
	}
	ap--;
	return (p1);
}

static int
e1(void)
{
	int p1;
	char *p2;

	p1 = e2();
	p2 = nxtarg(1);
	if ((p2 != 0) && EQ(p2, "-a"))
		return (p1 & e1());
	ap--;
	return (p1);
}

static int
e2(void)
{
	if (EQ(nxtarg(0), "!"))
		return (!e3());
	ap--;
	return (e3());
}

static int
e3(void)
{
	int p1;
	char *a;
	char *p2;
	int int1, int2;

	a = nxtarg(0);
	if (EQ(a, "(")) {
		p1 = exp();
		if (!EQ(nxtarg(0), ")")) synbad(") expected", "");
		return (p1);
	}
	p2 = nxtarg(1);
	ap--;
	if ((p2 == 0) || (!EQ(p2, "=") && !EQ(p2, "!="))) {
		if (EQ(a, "-r"))
			return (tio(nxtarg(0), 4));

		if (EQ(a, "-w"))
			return (tio(nxtarg(0), 2));

		if (EQ(a, "-x"))
			return (tio(nxtarg(0), 1));

		if (EQ(a, "-d"))
			return (filtyp(nxtarg(0), S_IFDIR));

		if (EQ(a, "-c"))
			return (filtyp(nxtarg(0), S_IFCHR));

		if (EQ(a, "-b"))
			return (filtyp(nxtarg(0), S_IFBLK));

		if (EQ(a, "-f")) {
			struct stat statb;

			return (stat(nxtarg(0), &statb) >= 0 &&
			    (statb.st_mode & S_IFMT) != S_IFDIR);
		}

		if (EQ(a, "-h"))
			return (filtyp(nxtarg(0), S_IFLNK));

		if (EQ(a, "-u"))
			return (ftype(nxtarg(0), S_ISUID));

		if (EQ(a, "-g"))
			return (ftype(nxtarg(0), S_ISGID));

		if (EQ(a, "-k"))
			return (ftype(nxtarg(0), S_ISVTX));

		if (EQ(a, "-p"))
#ifdef S_IFIFO
			return (filtyp(nxtarg(0), S_IFIFO));
#else
			return (nxtarg(0), 0);
#endif

		if (EQ(a, "-s"))
			return (fsizep(nxtarg(0)));

		if (EQ(a, "-t"))
			if (ap >= ac)
				return (isatty(1));
			else if (EQ((a = nxtarg(0)), "-a") || EQ(a, "-o")) {
				ap--;
				return (isatty(1));
			} else
				return (isatty(atoi(a)));

		if (EQ(a, "-n"))
			return (!EQ(nxtarg(0), ""));
		if (EQ(a, "-z"))
			return (EQ(nxtarg(0), ""));
	}

	p2 = nxtarg(1);
	if (p2 == 0)
		return (!EQ(a, ""));
	if (EQ(p2, "-a") || EQ(p2, "-o")) {
		ap--;
		return (!EQ(a, ""));
	}
	if (EQ(p2, "="))
		return (EQ(nxtarg(0), a));

	if (EQ(p2, "!="))
		return (!EQ(nxtarg(0), a));

	int1 = atoi(a);
	int2 = atoi(nxtarg(0));
	if (EQ(p2, "-eq"))
		return (int1 == int2);
	if (EQ(p2, "-ne"))
		return (int1 != int2);
	if (EQ(p2, "-gt"))
		return (int1 > int2);
	if (EQ(p2, "-lt"))
		return (int1 < int2);
	if (EQ(p2, "-ge"))
		return (int1 >= int2);
	if (EQ(p2, "-le"))
		return (int1 <= int2);

	synbad("unknown operator ", p2);
	/* NOTREACHED */
	return (0);
}

static int
tio(char *a, int f)
{
	if (access(a, f) == 0)
		return (1);
	else
		return (0);
}

static int
ftype(char *f, int field)
{
	struct stat statb;

	if (stat(f, &statb) < 0)
		return (0);
	if ((statb.st_mode & field) == field)
		return (1);
	return (0);
}

static int
filtyp(char *f, int field)
{
	struct stat statb;

	if (field == S_IFLNK) {
		if (lstat(f, &statb) < 0)
			return (0);
	} else {
		if (stat(f, &statb) < 0)
			return (0);
	}
	if ((statb.st_mode & S_IFMT) == field)
		return (1);
	else
		return (0);
}

static int
fsizep(char *f)
{
	struct stat statb;

	if (stat(f, &statb) < 0)
		return (0);
	return (statb.st_size > 0);
}

static void
synbad(char *s1, char *s2)
{
	(void) write(2, "test: ", 6);
	(void) write(2, s1, strlen(s1));
	(void) write(2, s2, strlen(s2));
	(void) write(2, "\n", 1);
	exit(255);
}
