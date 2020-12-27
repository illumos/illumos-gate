/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * D. G. Korn
 * G. S. Fowler
 * AT&T Research
 *
 * match shell file patterns
 * this interface is a wrapper on regex
 *
 *	sh pattern	egrep RE	description
 *	----------	--------	-----------
 *	*		.*		0 or more chars
 *	?		.		any single char
 *	[.]		[.]		char class
 *	[!.]		[^.]		negated char class
 *	[[:.:]]		[[:.:]]		ctype class
 *	[[=.=]]		[[=.=]]		equivalence class
 *	[[...]]		[[...]]		collation element
 *	*(.)		(.)*		0 or more of
 *	+(.)		(.)+		1 or more of
 *	?(.)		(.)?		0 or 1 of
 *	(.)		(.)		1 of
 *	@(.)		(.)		1 of
 *	a|b		a|b		a or b
 *	\#				() subgroup back reference [1-9]
 *	a&b				a and b
 *	!(.)				none of
 *
 * \ used to escape metacharacters
 *
 *	*, ?, (, |, &, ), [, \ must be \'d outside of [...]
 *	only ] must be \'d inside [...]
 *
 */

#include <ast.h>
#include <regex.h>

static struct State_s
{
	regmatch_t*	match;
	int		nmatch;
} matchstate;

#define STR_INT		040000

/*
 * subgroup match
 * 0 returned if no match
 * otherwise number of subgroups matched returned
 * match group begin offsets are even elements of sub
 * match group end offsets are odd elements of sub
 * the matched string is from s+sub[0] up to but not
 * including s+sub[1]
 */

int
strgrpmatch(const char* b, const char* p, ssize_t* sub, int n, register int flags)
{
	register regex_t*	re;
	register ssize_t*	end;
	register int		i;
	register regflags_t	reflags;

	/*
	 * 0 and empty patterns are special
	 */

	if (!p || !b)
	{
		if (!p && !b)
			regcache(NiL, 0, NiL);
		return 0;
	}
	if (!*p)
	{
		if (sub && n > 0)
		{
			if (flags & STR_INT)
			{
				int*	subi = (int*)sub;

				subi[0] = subi[1] = 0;
			}
			else
				sub[0] = sub[1] = 0;
		}
		return *b == 0;
	}

	/*
	 * convert flags
	 */

	if (flags & REG_ADVANCE)
		reflags = flags & ~REG_ADVANCE;
	else
	{
		reflags = REG_SHELL|REG_AUGMENTED;
		if (!(flags & STR_MAXIMAL))
			reflags |= REG_MINIMAL;
		if (flags & STR_GROUP)
			reflags |= REG_SHELL_GROUP;
		if (flags & STR_LEFT)
			reflags |= REG_LEFT;
		if (flags & STR_RIGHT)
			reflags |= REG_RIGHT;
		if (flags & STR_ICASE)
			reflags |= REG_ICASE;
	}
	if (!sub || n <= 0)
		reflags |= REG_NOSUB;
	if (!(re = regcache(p, reflags, NiL)))
		return 0;
	if (n > matchstate.nmatch)
	{
		if (!(matchstate.match = newof(matchstate.match, regmatch_t, n, 0)))
			return 0;
		matchstate.nmatch = n;
	}
	if (regexec(re, b, n, matchstate.match, reflags & ~(REG_MINIMAL|REG_SHELL_GROUP|REG_LEFT|REG_RIGHT|REG_ICASE)))
		return 0;
	if (!sub || n <= 0)
		return 1;
	i = re->re_nsub;
	if (flags & STR_INT)
	{
		int*	subi = (int*)sub;
		int*	endi = subi + n * 2;

		for (n = 0; subi < endi && n <= i; n++)
		{
			*subi++ = matchstate.match[n].rm_so;
			*subi++ = matchstate.match[n].rm_eo;
		}
	}
	else
	{
		end = sub + n * 2;
		for (n = 0; sub < end && n <= i; n++)
		{
			*sub++ = matchstate.match[n].rm_so;
			*sub++ = matchstate.match[n].rm_eo;
		}
	}
	return i + 1;
}

/*
 * compare the string s with the shell pattern p
 * returns 1 for match 0 otherwise
 */

int
strmatch(const char* s, const char* p)
{
	return strgrpmatch(s, p, NiL, 0, STR_MAXIMAL|STR_LEFT|STR_RIGHT);
}

/*
 * leading substring match
 * first char after end of substring returned
 * 0 returned if no match
 *
 * OBSOLETE: use strgrpmatch()
 */

char*
strsubmatch(const char* s, const char* p, int flags)
{
	ssize_t	match[2];

	return strgrpmatch(s, p, match, 1, (flags ? STR_MAXIMAL : 0)|STR_LEFT) ? (char*)s + match[1] : (char*)0;
}

#undef	strgrpmatch
#if _map_libc
#define strgrpmatch	_ast_strgrpmatch
#endif

int
strgrpmatch(const char* b, const char* p, int* sub, int n, int flags)
{
	return strgrpmatch_20120528(b, p, (ssize_t*)sub, n, flags|STR_INT);
}
