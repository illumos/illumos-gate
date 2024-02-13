/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *      test expression
 *      [ expression ]
 */

#include	"defs.h"
#include <sys/types.h>
#include <sys/stat.h>

extern	int lstat();

int	ap, ac;
unsigned char **av;

int
test(int argn, unsigned char *com[])
{
	ac = argn;
	av = com;
	ap = 1;
	if (eq(com[0],"["))
	{
		if (!eq(com[--ac], "]"))
			failed((unsigned char *)"test", nobracket);
	}
	com[ac] = 0;
	if (ac <= 1)
		return(1);
	return(exp() ? 0 : 1);
}

unsigned char *
nxtarg(int mt)
{
	if (ap >= ac)
	{
		if (mt)
		{
			ap++;
			return(0);
		}
		failed((unsigned char *)"test", noarg);
	}
	return(av[ap++]);
}

int
exp(void)
{
	int	p1;
	unsigned char	*p2;

	p1 = e1();
	p2 = nxtarg(1);
	if (p2 != 0)
	{
		if (eq(p2, "-o"))
			return(p1 | exp());

		/* if (!eq(p2, ")"))
			failed((unsigned char *)"test", synmsg); */
	}
	ap--;
	return(p1);
}

int
e1(void)
{
	int	p1;
	unsigned char	*p2;

	p1 = e2();
	p2 = nxtarg(1);

	if ((p2 != 0) && eq(p2, "-a"))
		return(p1 & e1());
	ap--;
	return(p1);
}

int
e2(void)
{
	if (eq(nxtarg(0), "!"))
		return(!e3());
	ap--;
	return(e3());
}

int
e3(void)
{
	int	p1;
	unsigned char	*a;
	unsigned char	*p2;
	longlong_t	ll_1, ll_2;

	a = nxtarg(0);
	if (eq(a, "("))
	{
		p1 = exp();
		if (!eq(nxtarg(0), ")"))
			failed((unsigned char *)"test", noparen);
		return(p1);
	}
	p2 = nxtarg(1);
	ap--;
	if ((p2 == 0) || (!eq(p2, "=") && !eq(p2, "!=")))
	{
		if (eq(a, "-r"))
			return(chk_access(nxtarg(0), S_IREAD, 0) == 0);
		if (eq(a, "-w"))
			return(chk_access(nxtarg(0), S_IWRITE, 0) == 0);
		if (eq(a, "-x"))
			return(chk_access(nxtarg(0), S_IEXEC, 0) == 0);
		if (eq(a, "-d"))
			return(filtyp(nxtarg(0), S_IFDIR));
		if (eq(a, "-c"))
			return(filtyp(nxtarg(0), S_IFCHR));
		if (eq(a, "-b"))
			return(filtyp(nxtarg(0), S_IFBLK));
		if (eq(a, "-f"))
			if (ucb_builtins) {
				struct stat statb;

				return(stat((char *)nxtarg(0), &statb) >= 0 &&
					(statb.st_mode & S_IFMT) != S_IFDIR);
			}
			else
				return(filtyp(nxtarg(0), S_IFREG));
		if (eq(a, "-u"))
			return(ftype(nxtarg(0), S_ISUID));
		if (eq(a, "-g"))
			return(ftype(nxtarg(0), S_ISGID));
		if (eq(a, "-k"))
			return(ftype(nxtarg(0), S_ISVTX));
		if (eq(a, "-p"))
			return(filtyp(nxtarg(0), S_IFIFO));
		if (eq(a, "-h") || eq(a, "-L"))
			return(filtyp(nxtarg(0), S_IFLNK));
   		if (eq(a, "-s"))
			return(fsizep(nxtarg(0)));
		if (eq(a, "-t"))
		{
			if (ap >= ac)		/* no args */
				return(isatty(1));
			else if (eq((a = nxtarg(0)), "-a") || eq(a, "-o"))
			{
				ap--;
				return(isatty(1));
			}
			else
				return(isatty(atoi((char *)a)));
		}
		if (eq(a, "-n"))
			return(!eq(nxtarg(0), ""));
		if (eq(a, "-z"))
			return(eq(nxtarg(0), ""));
	}

	p2 = nxtarg(1);
	if (p2 == 0)
		return(!eq(a, ""));
	if (eq(p2, "-a") || eq(p2, "-o"))
	{
		ap--;
		return(!eq(a, ""));
	}
	if (eq(p2, "="))
		return(eq(nxtarg(0), a));
	if (eq(p2, "!="))
		return(!eq(nxtarg(0), a));
	ll_1 = strtoll((char *)a, NULL, 10);
	ll_2 = strtoll((char *)nxtarg(0), NULL, 10);
	if (eq(p2, "-eq"))
		return (ll_1 == ll_2);
	if (eq(p2, "-ne"))
		return (ll_1 != ll_2);
	if (eq(p2, "-gt"))
		return (ll_1 > ll_2);
	if (eq(p2, "-lt"))
		return (ll_1 < ll_2);
	if (eq(p2, "-ge"))
		return (ll_1 >= ll_2);
	if (eq(p2, "-le"))
		return (ll_1 <= ll_2);

	bfailed((unsigned char *)btest, badop, p2);
/* NOTREACHED */
}

int
ftype(unsigned char *f, int field)
{
	struct stat statb;

	if (stat((char *)f, &statb) < 0)
		return(0);
	if ((statb.st_mode & field) == field)
		return(1);
	return(0);
}

int
filtyp(unsigned char *f, int field)
{
	struct stat statb;
	int (*statf)() = (field == S_IFLNK) ? lstat : stat;

	if ((*statf)(f, &statb) < 0)
		return(0);
	if ((statb.st_mode & S_IFMT) == field)
		return(1);
	else
		return(0);
}


int
fsizep(unsigned char *f)
{
	struct stat statb;

	if (stat((char *)f, &statb) < 0)
		return(0);
	return(statb.st_size > 0);
}
