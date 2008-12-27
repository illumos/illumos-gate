/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
 * regcomp() regex_t cache
 * AT&T Research
 */

#include <ast.h>
#include <regex.h>

#define CACHE		8		/* default # cached re's	*/
#define MAXPAT		256		/* max pattern length + 1	*/

#define KEEP		01
#define DROP		02

typedef union Pattern_u
{
	unsigned long	key;
	char		buf[MAXPAT];
} Pattern_t;

typedef struct Cache_s
{
	Pattern_t	pattern;
	regex_t		re;
	unsigned long	serial;
	regflags_t	reflags;
	int		flags;
} Cache_t;

typedef struct State_s
{
	unsigned int	size;
	unsigned long	serial;
	char*		locale;
	Cache_t**	cache;
} State_t;

static State_t	matchstate;

/*
 * flush the cache
 */

static void
flushcache(void)
{
	register int		i;

	for (i = matchstate.size; i--;)
		if (matchstate.cache[i] && matchstate.cache[i]->flags)
		{
			matchstate.cache[i]->flags = 0;
			regfree(&matchstate.cache[i]->re);
		}
}

/*
 * return regcomp() compiled re for pattern and reflags
 */

regex_t*
regcache(const char* pattern, regflags_t reflags, int* status)
{
	register Cache_t*	cp;
	register int		i;
	char*			s;
	int			empty;
	int			unused;
	int			old;
	Pattern_t		head;

	/*
	 * 0 pattern flushes the cache and reflags>0 extends cache
	 */

	if (!pattern)
	{
		flushcache();
		i = 0;
		if (reflags > matchstate.size)
		{
			if (matchstate.cache = newof(matchstate.cache, Cache_t*, reflags, 0))
				matchstate.size = reflags;
			else
			{
				matchstate.size = 0;
				i = 1;
			}
		}
		if (status)
			*status = i;
		return 0;
	}
	if (!matchstate.cache)
	{
		if (!(matchstate.cache = newof(0, Cache_t*, CACHE, 0)))
			return 0;
		matchstate.size = CACHE;
	}

	/*
	 * flush the cache if the locale changed
	 * the ast setlocale() intercept maintains
	 * persistent setlocale() return values
	 */

	if ((s = setlocale(LC_CTYPE, NiL)) != matchstate.locale)
	{
		matchstate.locale = s;
		flushcache();
	}

	/*
	 * check if the pattern is in the cache
	 */

	for (i = 0; i < sizeof(unsigned long) && pattern[i]; i++)
		head.buf[i] = pattern[i];
	for (; i < sizeof(unsigned long); i++)
		head.buf[i] = 0;
	empty = unused = -1;
	old = 0;
	for (i = matchstate.size; i--;)
		if (!matchstate.cache[i])
			empty = i;
		else if (!(matchstate.cache[i]->flags & KEEP))
		{
			if (matchstate.cache[i]->flags)
			{
				matchstate.cache[i]->flags = 0;
				regfree(&matchstate.cache[i]->re);
			}
			unused = i;
		}
		else if (matchstate.cache[i]->pattern.key == head.key && !strcmp(matchstate.cache[i]->pattern.buf, pattern) && matchstate.cache[i]->reflags == reflags)
			break;
		else if (!matchstate.cache[old] || matchstate.cache[old]->serial > matchstate.cache[i]->serial)
			old = i;
	if (i < 0)
	{
		if (unused < 0)
		{
			if (empty < 0)
				unused = old;
			else
				unused = empty;
		}
		if (!(cp = matchstate.cache[unused]) && !(cp = matchstate.cache[unused] = newof(0, Cache_t, 1, 0)))
		{
			if (status)
				*status = REG_ESPACE;
			return 0;
		}
		if (cp->flags)
		{
			cp->flags = 0;
			regfree(&cp->re);
		}
		cp->reflags = reflags;
		if ((i = strlen(pattern)) < sizeof(cp->pattern.buf))
		{
			if (i < sizeof(unsigned long))
				memset(cp->pattern.buf, 0, sizeof(unsigned long));
			strcpy(cp->pattern.buf, pattern);
			pattern = (const char*)cp->pattern.buf;
			cp->flags = KEEP;
		}
		else
			cp->flags = DROP;
		if (i = regcomp(&cp->re, pattern, cp->reflags))
		{
			if (status)
				*status = i;
			cp->flags = 0;
			return 0;
		}
	}
	else
		cp = matchstate.cache[i];
	cp->serial = ++matchstate.serial;
	if (status)
		*status = 0;
	return &cp->re;
}
