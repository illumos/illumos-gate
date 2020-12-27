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
 * posix regex ed(1) style substitute compile
 */

#include "reglib.h"

static const regflags_t	submap[] =
{
	'g',	REG_SUB_ALL,
	'l',	REG_SUB_LOWER,
	'n',	REG_SUB_NUMBER,
	'p',	REG_SUB_PRINT,
	's',	REG_SUB_STOP,
	'u',	REG_SUB_UPPER,
	'w',	REG_SUB_WRITE|REG_SUB_LAST,
	0,	0
};

int
regsubflags(regex_t* p, register const char* s, char** e, int delim, register const regflags_t* map, int* pm, regflags_t* pf)
{
	register int			c;
	register const regflags_t*	m;
	regflags_t			flags;
	int				minmatch;
	regdisc_t*			disc;

	flags = pf ? *pf : 0;
	minmatch = pm ? *pm : 0;
	if (!map)
		map = submap;
	while (!(flags & REG_SUB_LAST))
	{
		if  (!(c = *s++) || c == delim)
		{
			s--;
			break;
		}
		else if (c >= '0' && c <= '9')
		{
			if (minmatch)
			{
				disc = p->env->disc;
				regfree(p);
				return fatal(disc, REG_EFLAGS, s - 1);
			}
			minmatch = c - '0';
			while (*s >= '0' && *s <= '9')
				minmatch = minmatch * 10 + *s++ - '0';
		}
		else
		{
			for (m = map; *m; m++)
				if (*m++ == c)
				{
					if (flags & *m)
					{
						disc = p->env->disc;
						regfree(p);
						return fatal(disc, REG_EFLAGS, s - 1);
					}
					flags |= *m--;
					break;
				}
			if (!*m)
			{
				s--;
				break;
			}
		}
	}
	if (pf)
		*pf = flags;
	if (pm)
		*pm = minmatch;
	if (e)
		*e = (char*)s;
	return 0;
}

/*
 * compile substitute rhs and optional flags
 */

int
regsubcomp(regex_t* p, register const char* s, const regflags_t* map, int minmatch, regflags_t flags)
{
	register regsub_t*	sub;
	register int		c;
	register int		d;
	register char*		t;
	register regsubop_t*	op;
	char*			e;
	const char*		r;
	int			sre;
	int			f;
	int			g;
	int			n;
	int			nops;
	const char*		o;
	regdisc_t*		disc;

	disc = p->env->disc;
	if (p->env->flags & REG_NOSUB)
	{
		regfree(p);
		return fatal(disc, REG_BADPAT, NiL);
	}
	if (!(sub = (regsub_t*)alloc(p->env->disc, 0, sizeof(regsub_t) + strlen(s))) || !(sub->re_ops = (regsubop_t*)alloc(p->env->disc, 0, (nops = 8) * sizeof(regsubop_t))))
	{
		if (sub)
			alloc(p->env->disc, sub, 0);
		regfree(p);
		return fatal(disc, REG_ESPACE, s);
	}
	sub->re_buf = sub->re_end = 0;
	p->re_sub = sub;
	p->env->sub = 1;
	op = sub->re_ops;
	o = s;
	if (!(p->env->flags & REG_DELIMITED))
		d = 0;
	else
		switch (d = *(s - 1))
		{
		case '\\':
		case '\n':
		case '\r':
			regfree(p);
			return fatal(disc, REG_EDELIM, s);
		}
	sre = p->env->flags & REG_SHELL;
	t = sub->re_rhs;
	if (d)
	{
		r = s;
		for (;;)
		{
			if (!*s)
			{
				if (p->env->flags & REG_MUSTDELIM)
				{
					regfree(p);
					return fatal(disc, REG_EDELIM, r);
				}
				break;
			}
			else if (*s == d)
			{
				flags |= REG_SUB_FULL;
				s++;
				break;
			}
			else if (*s++ == '\\' && !*s++)
			{
				regfree(p);
				return fatal(disc, REG_EESCAPE, r);
			}
		}
		if (*s)
		{
			if (n = regsubflags(p, s, &e, d, map, &minmatch, &flags))
				return n;
			s = (const char*)e;
		}
		p->re_npat = s - o;
		s = r;
	}
	else
		p->re_npat = 0;
	op->op = f = g = flags & (REG_SUB_LOWER|REG_SUB_UPPER);
	op->off = 0;
	while ((c = *s++) != d)
	{
	again:
		if (!c)
		{
			p->re_npat = s - o - 1;
			break;
		}
		else if (c == '\\')
		{
			if (*s == c)
			{
				*t++ = *s++;
				continue;
			}
			if ((c = *s++) == d)
				goto again;
			if (!c)
			{
				regfree(p);
				return fatal(disc, REG_EESCAPE, s - 2);
			}
			if (c == '&')
			{
				*t++ = c;
				continue;
			}
		}
		else if (c == '&')
		{
			if (sre)
			{
				*t++ = c;
				continue;
			}
		}
		else
		{
			switch (op->op)
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
			*t++ = c;
			continue;
		}
		switch (c)
		{
		case 0:
			s--;
			continue;
		case '&':
			c = 0;
			break;
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			c -= '0';
			if (isdigit(*s) && (p->env->flags & REG_MULTIREF))
				c = c * 10 + *s++ - '0';
			break;
		case 'l':
			if (c = *s)
			{
				s++;
				if (isupper(c))
					c = tolower(c);
				*t++ = c;
			}
			continue;
		case 'u':
			if (c = *s)
			{
				s++;
				if (islower(c))
					c = toupper(c);
				*t++ = c;
			}
			continue;
		case 'E':
			f = g;
		set:
			if ((op->len = (t - sub->re_rhs) - op->off) && (n = ++op - sub->re_ops) >= nops)
			{
				if (!(sub->re_ops = (regsubop_t*)alloc(p->env->disc, sub->re_ops, (nops *= 2) * sizeof(regsubop_t))))
				{
					regfree(p);
					return fatal(disc, REG_ESPACE, NiL);
				}
				op = sub->re_ops + n;
			}
			op->op = f;
			op->off = t - sub->re_rhs;
			continue;
		case 'L':
			g = f;
			f = REG_SUB_LOWER;
			goto set;
		case 'U':
			g = f;
			f = REG_SUB_UPPER;
			goto set;
		default:
			if (!sre)
			{
				*t++ = chresc(s - 2, &e);
				s = (const char*)e;
				continue;
			}
			s--;
			c = -1;
			break;
		}
		if (c > p->re_nsub)
		{
			regfree(p);
			return fatal(disc, REG_ESUBREG, s - 1);
		}
		if ((n = op - sub->re_ops) >= (nops - 2))
		{
			if (!(sub->re_ops = (regsubop_t*)alloc(p->env->disc, sub->re_ops, (nops *= 2) * sizeof(regsubop_t))))
			{
				regfree(p);
				return fatal(disc, REG_ESPACE, NiL);
			}
			op = sub->re_ops + n;
		}
		if (op->len = (t - sub->re_rhs) - op->off)
			op++;
		op->op = f;
		op->off = c;
		op->len = 0;
		op++;
		op->op = f;
		op->off = t - sub->re_rhs;
	}
	if ((op->len = (t - sub->re_rhs) - op->off) && (n = ++op - sub->re_ops) >= nops)
	{
		if (!(sub->re_ops = (regsubop_t*)alloc(p->env->disc, sub->re_ops, (nops *= 2) * sizeof(regsubop_t))))
		{
			regfree(p);
			return fatal(disc, REG_ESPACE, NiL);
		}
		op = sub->re_ops + n;
	}
	op->len = -1;
	sub->re_flags = flags;
	sub->re_min = minmatch;
	return 0;
}

void
regsubfree(regex_t* p)
{
	Env_t*		env;
	regsub_t*	sub;

	if (p && (env = p->env) && env->sub && (sub = p->re_sub))
	{
		env->sub = 0;
		p->re_sub = 0;
		if (!(env->disc->re_flags & REG_NOFREE))
		{
			if (sub->re_buf)
				alloc(env->disc, sub->re_buf, 0);
			if (sub->re_ops)
				alloc(env->disc, sub->re_ops, 0);
			alloc(env->disc, sub, 0);
		}
	}
}
