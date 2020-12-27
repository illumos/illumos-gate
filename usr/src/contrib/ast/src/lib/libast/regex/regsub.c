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
 * OBSOLETE Sfio_t buffer interface -- use regsubcomp(),regsubexec()
 */

#include "reglib.h"

/*
 * do a single substitution
 */

static int
subold(register Sfio_t* dp, const char* op, register const char* sp, size_t nmatch, register regmatch_t* match, register regflags_t flags, int sre)
{
	register int	c;
	char*		s;
	char*		e;
	const char*	b;
	regflags_t	f;

	f = flags &= (REG_SUB_LOWER|REG_SUB_UPPER);
	for (;;)
	{
		switch (c = *sp++)
		{
		case 0:
			return 0;
		case '~':
			if (!sre || *sp != '(')
			{
				sfputc(dp, c);
				continue;
			}
			b = sp - 1;
			sp++;
			break;
		case '\\':
			if (sre)
			{
				sfputc(dp, chresc(sp - 1, &s));
				sp = (const char*)s;
				continue;
			}
			if (*sp == '&')
			{
				c = *sp++;
				sfputc(dp, c);
				continue;
			}
			break;
		case '&':
			if (sre)
			{
				sfputc(dp, c);
				continue;
			}
			sp--;
			break;
		default:
			switch (flags)
			{
			case REG_SUB_UPPER:
				if (islower(c))
					c = toupper(c);
				break;
			case REG_SUB_LOWER:
				if (isupper(c))
					c = tolower(c);
				break;
			case REG_SUB_UPPER|REG_SUB_LOWER:
				if (isupper(c))
					c = tolower(c);
				else if (islower(c))
					c = toupper(c);
				break;
			}
			sfputc(dp, c);
			continue;
		}
		switch (c = *sp++)
		{
		case 0:
			sp--;
			continue;
		case '&':
			c = 0;
			break;
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			c -= '0';
			if (sre)
				while (isdigit(*sp))
					c = c * 10 + *sp++ - '0';
			break;
		case 'l':
			if (sre && *sp != ')')
			{
				c = -1;
				break;
			}
			if (c = *sp)
			{
				sp++;
				if (isupper(c))
					c = tolower(c);
				sfputc(dp, c);
			}
			continue;
		case 'u':
			if (sre)
			{
				if (*sp != ')')
				{
					c = -1;
					break;
				}
				sp++;
			}
			if (c = *sp)
			{
				sp++;
				if (islower(c))
					c = toupper(c);
				sfputc(dp, c);
			}
			continue;
		case 'E':
			if (sre)
			{
				if (*sp != ')')
				{
					c = -1;
					break;
				}
				sp++;
			}
			flags = f;
			continue;
		case 'L':
			if (sre)
			{
				if (*sp != ')')
				{
					c = -1;
					break;
				}
				sp++;
			}
			f = flags;
			flags = REG_SUB_LOWER;
			continue;
		case 'U':
			if (sre)
			{
				if (*sp != ')')
				{
					c = -1;
					break;
				}
				sp++;
			}
			f = flags;
			flags = REG_SUB_UPPER;
			continue;
		default:
			if (!sre)
			{
				sfputc(dp, chresc(sp - 2, &s));
				sp = (const char*)s;
				continue;
			}
			sp--;
			c = -1;
			break;
		}
		if (sre)
		{
			if (c < 0 || *sp != ')')
			{
				for (; b < sp; b++)
					sfputc(dp, *b);
				continue;
			}
			sp++;
		}
		if (c >= nmatch)
			return REG_ESUBREG;
		s = (char*)op + match[c].rm_so;
		e = (char*)op + match[c].rm_eo;
		while (s < e)
		{
			c = *s++;
			switch (flags)
			{
			case REG_SUB_UPPER:
				if (islower(c))
					c = toupper(c);
				break;
			case REG_SUB_LOWER:
				if (isupper(c))
					c = tolower(c);
				break;
			case REG_SUB_UPPER|REG_SUB_LOWER:
				if (isupper(c))
					c = tolower(c);
				else if (islower(c))
					c = toupper(c);
				break;
			}
			sfputc(dp, c);
		}
	}
}

/*
 * ed(1) style substitute using matches from last regexec()
 */

int
regsub(const regex_t* p, Sfio_t* dp, const char* op, const char* sp, size_t nmatch, regmatch_t* match, regflags_t flags)
{
	int	m;
	int	r;
	int	sre;

	if ((p->env->flags & REG_NOSUB) || !nmatch)
		return fatal(p->env->disc, REG_BADPAT, NiL);
	m = (flags >> 16) & 0x3fff;
	sre = !!(p->env->flags & REG_SHELL);
	r = 0;
	do
	{
		if (--m > 0)
			sfwrite(dp, op, match->rm_eo);
		else
		{
			sfwrite(dp, op, match->rm_so);
			if (r = subold(dp, op, sp, nmatch, match, flags, sre))
				return fatal(p->env->disc, r, NiL);
		}
		op += match->rm_eo;
	} while ((m > 0 || (flags & REG_SUB_ALL)) && !(r = regexec(p, op, nmatch, match, p->env->flags|(match->rm_so == match->rm_eo ? REG_ADVANCE : 0))));
	if (r && r != REG_NOMATCH)
		return fatal(p->env->disc, r, NiL);
	sfputr(dp, op, -1);
	return 0;
}
