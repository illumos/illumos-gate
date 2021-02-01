/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include <ast.h>
#include <ast_getopt.h>

#undef	_BLD_ast	/* enable ast imports since we're user static */

#include <error.h>
#include <option.h>
#include <getopt.h>
#include <ctype.h>

static const char*		lastoptstring;
static const struct option*	lastlongopts;
static char*			usage;
static Sfio_t*			up;

static int			lastoptind;

static int
golly(int argc, char* const* argv, const char* optstring, const struct option* longopts, int* longindex, int flags)
{
	register char*			s;
	register const struct option*	o;
	register int			c;
	char*				t;

	if (!up || optstring != lastoptstring || longopts != lastlongopts)
	{
		if (!up && !(up = sfstropen()) || !(t = strdup(optstring)))
			return -1;
		sfprintf(up, "[-1p%d]", flags);
		for (o = longopts; o->name; o++)
		{
			if (o->flag || o->val <= 0 || o->val > UCHAR_MAX || !isalnum(o->val))
				sfprintf(up, "\n[%d:%s]", UCHAR_MAX + 1 + (o - longopts), o->name);
			else
			{
				sfprintf(up, "\n[%c:%s]", o->val, o->name);
				if (s = strchr(t, o->val))
				{
					*s++ = ' ';
					if (*s == ':')
					{
						*s++ = ' ';
						if (*s == ':')
							*s = ' ';
					}
				}
			}
			if (o->has_arg)
			{
				sfputc(up, ':');
				if (o->has_arg == optional_argument)
					sfputc(up, '?');
				sfprintf(up, "[string]");
			}
		}
		s = t;
		while (c = *s++)
			if (c != ' ')
			{
				sfprintf(up, "\n[%c]", c);
				if (*s == ':')
				{
					sfputc(up, *s);
					if (*++s == ':')
					{
						sfputc(up, '?');
						s++;
					}
					sfputc(up, '[');
					sfputc(up, ']');
				}
			}
		sfputc(up, '\n');
		free(t);
		if (!(usage = sfstruse(up)))
			return -1;
		lastoptstring = optstring;
		lastlongopts = longopts;
	}
	opt_info.index = (optind > 1 || optind == lastoptind) ? optind : 0;
	if (opt_info.index >= argc || !(c = optget((char**)argv, usage)))
	{
		sfstrclose(up);
		up = 0;
		c = -1;
	}
	else
	{
		if (c == ':' || c == '?')
		{
			if (opterr && (!optstring || *optstring != ':'))
			{
				if (!error_info.id)
					error_info.id = argv[0];
				errormsg(NiL, c == '?' ? (ERROR_USAGE|4) : 2, "%s", opt_info.arg);
			}
			optopt = opt_info.option[1];
			c = '?';
		}
		optarg = opt_info.arg;
		if (c < 0)
		{
			o = longopts - c - UCHAR_MAX - 1;
			if (o->flag)
			{
				*o->flag = o->val;
				c = 0;
			}
			else
				c = o->val;
		}
	}
	lastoptind = optind = opt_info.index;
	return c;
}

extern int
getopt_long(int argc, char* const* argv, const char* optstring, const struct option* longopts, int* longindex)
{
	return golly(argc, argv, optstring, longopts, longindex, 2);
}

extern int
getopt_long_only(int argc, char* const* argv, const char* optstring, const struct option* longopts, int* longindex)
{
	return golly(argc, argv, optstring, longopts, longindex, 1);
}
