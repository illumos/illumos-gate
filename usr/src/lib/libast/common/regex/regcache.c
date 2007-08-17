/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1985-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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

#define CACHE		8		/* # cached re's		*/
#define MAXPAT		256		/* max pattern length + 1	*/

#define KEEP		01
#define DROP		02

typedef struct Cache_s
{
	regex_t		re;
	unsigned long	serial;
	regflags_t	reflags;
	int		flags;
	char		pattern[MAXPAT];
} Cache_t;

static struct State_s
{
	Cache_t*	cache[CACHE];
	unsigned long	serial;
	char*		locale;
} matchstate;

/*
 * flush the cache
 */

static void
flushcache(void)
{
	register int		i;

	for (i = 0; i < elementsof(matchstate.cache); i++)
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

	/*
	 * 0 pattern flushes the cache
	 */

	if (!pattern)
	{
		flushcache();
		if (status)
			*status = 0;
		return 0;
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

	empty = unused = -1;
	old = 0;
	for (i = 0; i < elementsof(matchstate.cache); i++)
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
		else if (streq(matchstate.cache[i]->pattern, pattern) && matchstate.cache[i]->reflags == reflags)
			break;
		else if (!matchstate.cache[old] || matchstate.cache[old]->serial > matchstate.cache[i]->serial)
			old = i;
	if (i >= elementsof(matchstate.cache))
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
		if (strlen(pattern) < sizeof(cp->pattern))
		{
			strcpy(cp->pattern, pattern);
			pattern = (const char*)cp->pattern;
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
