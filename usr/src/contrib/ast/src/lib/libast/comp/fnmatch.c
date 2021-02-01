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
/*
 * fnmatch implementation
 */

#include <ast_lib.h>

#include <ast.h>
#include <regex.h>
#include <fnmatch.h>

typedef struct
{
	int	fnm;		/* fnmatch flag			*/
	int	reg;		/* regex flag			*/
} Map_t;

static const Map_t	map[] =
{
	FNM_AUGMENTED,	REG_AUGMENTED,
	FNM_ICASE,	REG_ICASE,
	FNM_NOESCAPE,	REG_SHELL_ESCAPED,
	FNM_PATHNAME,	REG_SHELL_PATH,
	FNM_PERIOD,	REG_SHELL_DOT,
};

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int
fnmatch(const char* pattern, const char* subject, register int flags)
{
	register int		reflags = REG_SHELL|REG_LEFT;
	register const Map_t*	mp;
	regex_t			re;
	regmatch_t		match;

	for (mp = map; mp < &map[elementsof(map)]; mp++)
		if (flags & mp->fnm)
			reflags |= mp->reg;
	if (flags & FNM_LEADING_DIR)
	{
		if (!(reflags = regcomp(&re, pattern, reflags)))
		{
			reflags = regexec(&re, subject, 1, &match, 0);
			regfree(&re);
			if (!reflags && (reflags = subject[match.rm_eo]))
				reflags = reflags == '/' ? 0 : FNM_NOMATCH;
		}
	}
	else if (!(reflags = regcomp(&re, pattern, reflags|REG_RIGHT)))
	{
		reflags = regexec(&re, subject, 0, NiL, 0);
		regfree(&re);
	}
	return reflags;
}
