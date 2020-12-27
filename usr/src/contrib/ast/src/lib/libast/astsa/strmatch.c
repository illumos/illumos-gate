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
 * match shell file patterns -- derived from Bourne and Korn shell gmatch()
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
 * BUG: unbalanced ) terminates top level pattern
 */

#include <ast.h>
#include <ctype.h>
#include <hashkey.h>

#ifndef	isblank
#define	isblank(x)	((x)==' '||(x)=='\t')
#endif

#ifndef isgraph
#define	isgraph(x)	(isprint(x)&&!isblank(x))
#endif

#define MAXGROUP	10

typedef struct
{
	char*		beg[MAXGROUP];
	char*		end[MAXGROUP];
	char*		next_s;
	short		groups;
} Group_t;

typedef struct
{
	Group_t		current;
	Group_t		best;
	char*		last_s;
	char*		next_p;
} Match_t;

#define mbgetchar(p)	(*p++)

#ifndef isxdigit
#define isxdigit(c)	((c)>='0'&&(c)<='9'||(c)>='a'&&(c)<='f'||(c)>='A'&&(c)<='F')
#endif

#define getsource(s,e)	(((s)>=(e))?0:mbgetchar(s))

#define COLL_MAX	3

/*
 * gobble chars up to <sub> or ) keeping track of (...) and [...]
 * sub must be one of { '|', '&', 0 }
 * 0 returned if s runs out
 */

static char*
gobble(Match_t* mp, register char* s, register int sub, int* g, int clear)
{
	register int	p = 0;
	register char*	b = 0;
	int		c = 0;
	int		n;

	for (;;)
		switch (mbgetchar(s))
		{
		case '\\':
			if (mbgetchar(s))
				break;
			/*FALLTHROUGH*/
		case 0:
			return 0;
		case '[':
			if (!b)
			{
				if (*s == '!' || *s == '^')
					mbgetchar(s);
				b = s;
			}
			else if (*s == '.' || *s == '=' || *s == ':')
				c = *s;
			break;
		case ']':
			if (b)
			{
				if (*(s - 2) == c)
					c = 0;
				else if (b != (s - 1))
					b = 0;
			}
			break;
		case '(':
			if (!b)
			{
				p++;
				n = (*g)++;
				if (clear)
				{
					if (!sub)
						n++;
					if (n < MAXGROUP)
						mp->current.beg[n] = mp->current.end[n] = 0;
				}
			}
			break;
		case ')':
			if (!b && p-- <= 0)
				return sub ? 0 : s;
			break;
		case '|':
			if (!b && !p && sub == '|')
				return s;
			break;
		}
}

static int	grpmatch(Match_t*, int, char*, register char*, char*, int);

/*
 * match a single pattern
 * e is the end (0) of the substring in s
 * r marks the start of a repeated subgroup pattern
 */

static int
onematch(Match_t* mp, int g, char* s, char* p, char* e, char* r, int flags)
{
	register int 	pc;
	register int 	sc;
	register int	n;
	register int	icase;
	char*		olds;
	char*		oldp;

	icase = flags & STR_ICASE;
	do
	{
		olds = s;
		sc = getsource(s, e);
		if (icase && isupper(sc))
			sc = tolower(sc);
		oldp = p;
		switch (pc = mbgetchar(p))
		{
		case '(':
		case '*':
		case '?':
		case '+':
		case '@':
		case '!':
			if (pc == '(' || *p == '(')
			{
				char*	subp;
				int	oldg;

				s = olds;
				subp = p + (pc != '(');
				oldg = g;
				n = ++g;
				if (g < MAXGROUP && (!r || g > mp->current.groups))
					mp->current.beg[g] = mp->current.end[g] = 0;
				if (!(p = gobble(mp, subp, 0, &g, !r)))
					return 0;
				if (pc == '*' || pc == '?' || pc == '+' && oldp == r)
				{
					if (onematch(mp, g, s, p, e, NiL, flags))
						return 1;
					if (!sc || !getsource(s, e))
					{
						mp->current.groups = oldg;
						return 0;
					}
				}
				if (pc == '*' || pc == '+')
				{
					p = oldp;
					sc = n - 1;
				}
				else
					sc = g;
				pc = (pc != '!');
				do
				{
					if (grpmatch(mp, n, olds, subp, s, flags) == pc)
					{
						if (n < MAXGROUP)
						{
							if (!mp->current.beg[n] || mp->current.beg[n] > olds)
								mp->current.beg[n] = olds;
							if (s > mp->current.end[n])
								mp->current.end[n] = s;
						}
						if (onematch(mp, sc, s, p, e, oldp, flags))
						{
							if (p == oldp && n < MAXGROUP)
							{
								if (!mp->current.beg[n] || mp->current.beg[n] > olds)
									mp->current.beg[n] = olds;
								if (s > mp->current.end[n])
									mp->current.end[n] = s;
							}
							return 1;
						}
					}
				} while (s < e && mbgetchar(s));
				mp->current.groups = oldg;
				return 0;
			}
			else if (pc == '*')
			{
				/*
				 * several stars are the same as one
				 */

				while (*p == '*' && *(p + 1) != '(')
					p++;
				oldp = p;
				switch (pc = mbgetchar(p))
				{
				case '@':
				case '!':
				case '+':
					n = *p == '(';
					break;
				case '(':
				case '[':
				case '?':
				case '*':
					n = 1;
					break;
				case 0:
				case '|':
				case '&':
				case ')':
					mp->current.next_s = (flags & STR_MAXIMAL) ? e : olds;
					mp->next_p = oldp;
					mp->current.groups = g;
					if (!pc && (!mp->best.next_s || (flags & STR_MAXIMAL) && mp->current.next_s > mp->best.next_s || !(flags & STR_MAXIMAL) && mp->current.next_s < mp->best.next_s))
						mp->best = mp->current;
					return 1;
				case '\\':
					if (!(pc = mbgetchar(p)))
						return 0;
					if (pc >= '0' && pc <= '9')
					{
						n = pc - '0';
						if (n <= g && mp->current.beg[n])
							pc = *mp->current.beg[n];
					}
					/*FALLTHROUGH*/
				default:
					if (icase && isupper(pc))
						pc = tolower(pc);
					n = 0;
					break;
				}
				p = oldp;
				for (;;)
				{
					if ((n || pc == sc) && onematch(mp, g, olds, p, e, NiL, flags))
						return 1;
					if (!sc)
						return 0;
					olds = s;
					sc = getsource(s, e);
					if ((flags & STR_ICASE) && isupper(sc))
						sc = tolower(sc);
				}
			}
			else if (pc != '?' && pc != sc)
				return 0;
			break;
		case 0:
			if (!(flags & STR_MAXIMAL))
				sc = 0;
			/*FALLTHROUGH*/
		case '|':
		case '&':
		case ')':
			if (!sc)
			{
				mp->current.next_s = olds;
				mp->next_p = oldp;
				mp->current.groups = g;
			}
			if (!pc && (!mp->best.next_s || (flags & STR_MAXIMAL) && olds > mp->best.next_s || !(flags & STR_MAXIMAL) && olds < mp->best.next_s))
			{
				mp->best = mp->current;
				mp->best.next_s = olds;
				mp->best.groups = g;
			}
			return !sc;
		case '[':
			{
				/*UNDENT...*/

	int	invert;
	int	x;
	int	ok = 0;
	char*	range;

	if (!sc)
		return 0;
	range = 0;
	n = 0;
	if (invert = *p == '!' || *p == '^')
		p++;
	for (;;)
	{
		oldp = p;
		if (!(pc = mbgetchar(p)))
			return 0;
		else if (pc == '[' && (*p == ':' || *p == '=' || *p == '.'))
		{
			x = 0;
			n = mbgetchar(p);
			oldp = p;
			for (;;)
			{
				if (!(pc = mbgetchar(p)))
					return 0;
				if (pc == n && *p == ']')
					break;
				x++;
			}
			mbgetchar(p);
			if (ok)
				/*NOP*/;
			else if (n == ':')
			{
				switch (HASHNKEY5(x, oldp[0], oldp[1], oldp[2], oldp[3], oldp[4]))
				{
				case HASHNKEY5(5,'a','l','n','u','m'):
					if (isalnum(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'a','l','p','h','a'):
					if (isalpha(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'b','l','a','n','k'):
					if (isblank(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'c','n','t','r','l'):
					if (iscntrl(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'d','i','g','i','t'):
					if (isdigit(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'g','r','a','p','h'):
					if (isgraph(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'l','o','w','e','r'):
					if (islower(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'p','r','i','n','t'):
					if (isprint(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'p','u','n','c','t'):
					if (ispunct(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'s','p','a','c','e'):
					if (isspace(sc))
						ok = 1;
					break;
				case HASHNKEY5(5,'u','p','p','e','r'):
					if (icase ? islower(sc) : isupper(sc))
						ok = 1;
					break;
				case HASHNKEY5(6,'x','d','i','g','i'):
					if (oldp[5] == 't' && isxdigit(sc))
						ok = 1;
					break;
				}
			}
			else if (range)
				goto getrange;
			else if (*p == '-' && *(p + 1) != ']')
			{
				mbgetchar(p);
				range = oldp;
			}
			else if (isalpha(*oldp) && isalpha(*olds) && tolower(*oldp) == tolower(*olds) || sc == mbgetchar(oldp))
				ok = 1;
			n = 1;
		}
		else if (pc == ']' && n)
		{
			if (ok != invert)
				break;
			return 0;
		}
		else if (pc == '\\' && (oldp = p, !(pc = mbgetchar(p))))
			return 0;
		else if (ok)
			/*NOP*/;
		else if (range)
		{
		getrange:
			if (icase && isupper(pc))
				pc = tolower(pc);
			x = mbgetchar(range);
			if (icase && isupper(x))
				x = tolower(x);
			if (sc == x || sc == pc || sc > x && sc < pc)
				ok = 1;
			if (*p == '-' && *(p + 1) != ']')
			{
				mbgetchar(p);
				range = oldp;
			}
			else
				range = 0;
			n = 1;
		}
		else if (*p == '-' && *(p + 1) != ']')
		{
			mbgetchar(p);
			range = oldp;
			n = 1;
		}
		else
		{
			if (icase && isupper(pc))
				pc = tolower(pc);
			if (sc == pc)
				ok = 1;
			n = pc;
		}
	}

				/*...INDENT*/
			}
			break;
		case '\\':
			if (!(pc = mbgetchar(p)))
				return 0;
			if (pc >= '0' && pc <= '9')
			{
				n = pc - '0';
				if (n <= g && (oldp = mp->current.beg[n]))
				{
					while (oldp < mp->current.end[n])
						if (!*olds || *olds++ != *oldp++)
							return 0;
					s = olds;
					break;
				}
			}
			/*FALLTHROUGH*/
		default:
			if (icase && isupper(pc))
				pc = tolower(pc);
			if (pc != sc)
				return 0;
			break;
		}
	} while (sc);
	return 0;
}

/*
 * match any pattern in a group
 * | and & subgroups are parsed here
 */

static int
grpmatch(Match_t* mp, int g, char* s, register char* p, char* e, int flags)
{
	register char*	a;

	do
	{
		for (a = p; onematch(mp, g, s, a, e, NiL, flags); a++)
			if (*(a = mp->next_p) != '&')
				return 1;
	} while (p = gobble(mp, p, '|', &g, 1));
	return 0;
}

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
strgrpmatch(const char* b, const char* p, ssize_t* sub, int n, int flags)
{
	register int	i;
	register char*	s;
	char*		e;
	Match_t		match;

	s = (char*)b;
	match.last_s = e = s + strlen(s);
	for (;;)
	{
		match.best.next_s = 0;
		match.current.groups = 0;
		if ((i = grpmatch(&match, 0, s, (char*)p, e, flags)) || match.best.next_s)
		{
			if (!i)
				match.current = match.best;
			match.current.groups++;
			match.current.end[0] = match.current.next_s;
			break;
		}
		if ((flags & STR_LEFT) || s >= e)
			return 0;
		s++;
	}
	if ((flags & STR_RIGHT) && match.current.next_s != e)
		return 0;
	if (!sub)
		return 1;
	match.current.beg[0] = s;
	s = (char*)b;
	if (n > match.current.groups)
		n = match.current.groups;
	for (i = 0; i < n; i++)
	{
		sub[i * 2] = match.current.end[i] ? match.current.beg[i] - s : 0;
		sub[i * 2 + 1] = match.current.end[i] ? match.current.end[i] - s : 0;
	}
	return n;
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
