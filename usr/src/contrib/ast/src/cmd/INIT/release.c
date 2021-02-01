/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1990-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped

/*
 * release -- list recent release changes
 *
 * coded for portability
 */

static char id[] = "\n@(#)$Id: release (AT&T Research) 2000-01-28 $\0\n";

#if _PACKAGE_ast

#include <ast.h>
#include <error.h>

static const char usage[] =
"[-?\n@(#)$Id: release (AT&T Research) 2000-01-28 $\n]"
USAGE_LICENSE
"[+NAME?release - list recent changes]"
"[+DESCRIPTION?\brelease\b lists the changes within the date range specified"
"	by the \b--from\b and \b--to\b options. The input files are assumed to"
"	contain date tag lines of the form [\acc\a]]\ayy-mm-dd\a [ \atext\a ]]"
"	(or \bdate\b(1) default format), where \acc\a is determined by a Y2K"
"	window year of 69 (we can produce an example coding dated 1991 - this"
"	can be patented?, how about 1+1=2?.) The date tag lines are followed by"
"	\areadme\a text in reverse chronological order (newer entries at the"
"	top of the file.) If no selection options are spcified then all"
"	changes are listed. If no \afile\a operands are specified then the"
"	standard input is read.]"
"[+?The entries for each \afile\a are annotated with the file directory name.]"
"[f:from?Entries older than \adate\a are omitted.]:[date]"
"[r:release?List all changes that include the first \acount\a release marks."
"	A release mark has a date tag followed by optional space and at least"
"	three \b-\b characters. Changes from release mark \acount\a+1 are not"
"	listed. If there are no release marks then the date range is used;"
"	if there is at least one release mark then the date range is ignored"
"	and at most \acount\a release marks will be listed.]#[count]"
"[t:to?Entries newer than \adate\a are omitted.]:[date]"
"[V?Print the program version and exit.]"

"\n"
"\n[ file ... ]\n"
"\n"

"[+SEE ALSO?\bpackage\b(1)]"
;

#else

#define elementsof(x)	((int)(sizeof(x)/sizeof(x[0])))

#define NiL		((char*)0)

#endif

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>

#if !_PACKAGE_ast && defined(__STDC__)
#include <stdlib.h>
#include <string.h>
#endif

static char	mon[] = "janfebmaraprmayjunjulaugsepoctnovdec";
static char	day[] = "sunmontuewedthufrisat";

#if !_PACKAGE_ast

static void
usage()
{
	fprintf(stderr, "Usage: release [-V] [-h hi-date] [-l lo-date] [-r count] [ file ...]\n");
	exit(2);
}

#endif

static unsigned long
number(register char* s, char** e)
{
	unsigned long	q = 0;

	while (isspace(*s))
		s++;
	while (isdigit(*s))
		q = q * 10 + *s++ - '0';
	if (e)
		*e = s;
	return q;
}

unsigned long
string(register char* s, char* tab, int num, int siz, char** e)
{
	register int	i;
	register int	j;
	char		buf[16];

	while (isspace(*s))
		s++;
	for (i = 0; i < siz; i++)
		buf[i] = isupper(s[i]) ? tolower(s[i]) : s[i];
	for (i = 0; i < num; i += siz)
		for (j = 0; j < siz && buf[j] == tab[j+i]; j++)
			if (j == (siz - 1))
			{
				*e = s + siz;
				return i / siz + 1;
			}
	return 0;
}

static unsigned long
date(char* s, char** e)
{
	char*		t;
	unsigned long	y;
	unsigned long	m;
	unsigned long	d;

	if (isdigit(*s))
	{
		y = number(s, &t);
		if (*t != '-')
			return 0;
		switch (t - s)
		{
		case 2:
			y += 1900;
			if (y <= 1969)
				y += 100;
			break;
		case 4:
			if (y < 1969)
				return 0;
			break;
		}
		if (!(m = number(++t, &s)))
			return 0;
		if ((s - t) != 2 || *s != '-' || m < 1 || m > 12)
			return 0;
		if (!(d = number(++s, &t)))
			return 0;
		if ((t - s) != 2 || d < 1 || d > 31)
			return 0;
	}
	else
	{
		if (string(s, day, elementsof(day), 3, &t))
			s = t;
		if (!(m = string(s, mon, elementsof(mon), 3, &t)))
			return 0;
		if (!(d = number(t, &s)))
			return 0;
		for (y = 1969; *s; s++)
			if ((y = number(s, &t)) && (t - s) == 4)
			{
				if (y < 1969)
					return 0;
				break;
			}
	}
	if (e)
	{
		while (isspace(*t))
			t++;
		*e = t;
	}
	return ((y - 1969) * 13 + m) * 32 + d;
}

int
main(int argc, char** argv)
{
	register char*		s;
	register char*		u;
	register char*		v;
	char*			p;
	char*			e;
	int			i;
	unsigned long		t;
	unsigned long		lo;
	unsigned long		hi;
	int			mk;
	FILE*			f;
	char			buf[1024];

	mk = 0;
	lo = hi = 0;
#if _PACKAGE_ast
	error_info.id = "release";
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'f':
			if (!(lo = date(opt_info.arg, &e)) || *e)
			{
				error(2, "%s: invalid from date [%s]", opt_info.arg, e);
				return 1;
			}
			continue;
		case 'r':
			mk = opt_info.num + 1;
			continue;
		case 't':
			if (!(hi = date(opt_info.arg, &e)) || *e)
			{
				error(2, "%s: invalid to date [%s]", opt_info.arg, e);
				return 1;
			}
			continue;
		case 'V':
			sfprintf(sfstdout, "%s\n", id + 10);
			return 0;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		}
		break;
	}
	if (error_info.errors)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	argv += opt_info.index;
#else
	while ((s = *++argv) && *s == '-' && *(s + 1))
	{
		if (*(s + 1) == '-')
		{
			if (!*(s + 2))
			{
				argv++;
				break;
			}
			usage();
			break;
		}
		for (;;)
		{
			switch (i = *++s)
			{
			case 0:
				break;
			case 'f':
			case 't':
				if (!*(v = ++s) && !(v = *++argv))
				{
					s = "??";
					continue;
				}
				if (!(t = date(v, &e)) || *e)
				{
					fprintf(stderr, "release: -%c%s: invalid date [%s]\n", i, s, e);
					return 1;
				}
				switch (i)
				{
				case 'f':
					lo = t;
					break;
				case 't':
					hi = t;
					break;
				}
				break;
			case 'r':
				if (!*(v = ++s) && !(v = *++argv))
				{
					s = "??";
					continue;
				}
				mk = number(v, &e) + 1;
				if (*e)
				{
					fprintf(stderr, "release: -%c%s: invalid count\n", i, s);
					return 1;
				}
				break;
			case 'V':
				fprintf(stdout, "%s\n", id + 10);
				return 0;
			default:
				fprintf(stderr, "release: -%c: unknown option\n", i);
				/*FALLTHROUGH*/
			case '?':
				usage();
				break;
			}
			break;
		}
	}
#endif
	do
	{
		if (!(p = *argv++) || !*p || *p == '-' && !*(p + 1))
		{
			argv--;
			p = "";
			f = stdin;
		}
		else if (!(f = fopen(p, "r")))
		{
			fprintf(stderr, "release: %s: cannot read", p);
			return 1;
		}
		while (s = fgets(buf, sizeof(buf), f))
		{
			if (t = date(s, &e))
			{
				if (mk && e[0] == '-' && e[1] == '-' && e[2] == '-' && !--mk)
					break;
				if (t < lo)
					break;
				if (hi && t > hi)
					continue;
				if (p)
				{
					if (*p)
					{
						for (u = v = p; *p; p++)
							if (*p == '/')
							{
								v = u;
								u = p + 1;
							}
						printf("\n:::::::: ");
						while ((i = *v++) && i != '/')
							fputc(i, stdout);
						printf(" ::::::::\n\n");
					}
					p = 0;
				}	
			}
			if (!p)
				fputs(s, stdout);
		}
		if (f == stdin)
			break;
		fclose(f);
	} while (*argv);
	return 0;
}
