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
 * posix regex ed(1) style substitute execute
 */

#include "reglib.h"

#define NEED(p,b,n,r)	\
	do \
	{ \
		if (((b)->re_end - (b)->re_cur) < (n)) \
		{ \
			size_t	o = (b)->re_cur - (b)->re_buf; \
			size_t	a = ((b)->re_end - (b)->re_buf); \
			if (a < n) \
				a = roundof(n, 128); \
			a *= 2; \
			if (!((b)->re_buf = alloc(p->env->disc, (b)->re_buf, a))) \
			{ \
				(b)->re_buf = (b)->re_cur = (b)->re_end = 0; \
				c = REG_ESPACE; \
				r; \
			} \
			(b)->re_cur = (b)->re_buf + o; \
			(b)->re_end = (b)->re_buf + a; \
		} \
	} while (0)

#define PUTC(p,b,x,r)	\
	do \
	{ \
		NEED(p, b, 1, r); \
		*(b)->re_cur++ = (x); \
	} while (0)

#define PUTS(p,b,x,z,r)	\
	do if (z) \
	{ \
		NEED(p, b, z, r); \
		memcpy((b)->re_cur, x, z); \
		(b)->re_cur += (z); \
	} while (0)

/*
 * do a single substitution
 */

static int
sub(const regex_t* p, register regsub_t* b, const char* ss, register regsubop_t* op, size_t nmatch, register regmatch_t* match)
{
	register char*	s;
	register char*	e;
	register int	c;

	for (;; op++)
	{
		switch (op->len)
		{
		case -1:
			break;
		case 0:
			if (op->off >= nmatch)
				return REG_ESUBREG;
			if ((c = match[op->off].rm_so) < 0)
				continue;
			s = (char*)ss + c;
			if ((c = match[op->off].rm_eo) < 0)
				continue;
			e = (char*)ss + c;
			NEED(p, b, e - s, return c);
			switch (op->op)
			{
			case REG_SUB_UPPER:
				while (s < e)
				{
					c = *s++;
					if (islower(c))
						c = toupper(c);
					*b->re_cur++ = c;
				}
				break;
			case REG_SUB_LOWER:
				while (s < e)
				{
					c = *s++;
					if (isupper(c))
						c = tolower(c);
					*b->re_cur++ = c;
				}
				break;
			case REG_SUB_UPPER|REG_SUB_LOWER:
				while (s < e)
				{
					c = *s++;
					if (isupper(c))
						c = tolower(c);
					else if (islower(c))
						c = toupper(c);
					*b->re_cur++ = c;
				}
				break;
			default:
				while (s < e)
					*b->re_cur++ = *s++;
				break;
			}
			continue;
		default:
			NEED(p, b, op->len, return c);
			s = b->re_rhs + op->off;
			e = s + op->len;
			while (s < e)
				*b->re_cur++ = *s++;
			continue;
		}
		break;
	}
	return 0;
}

/*
 * ed(1) style substitute using matches from last regexec()
 */

int
regsubexec(const regex_t* p, const char* s, size_t nmatch, regmatch_t* match)
{
	register int		c;
	register regsub_t*	b;
	const char*		e;
	int			m;

	if (!p->env->sub || (p->env->flags & REG_NOSUB) || !nmatch)
		return fatal(p->env->disc, REG_BADPAT, NiL);
	b = p->re_sub;
	m = b->re_min;
	b->re_cur = b->re_buf;
	e = (const char*)p->env->end;
	c = 0;
	for (;;)
	{
		if (--m > 0)
			PUTS(p, b, s, match->rm_eo, return fatal(p->env->disc, c, NiL));
		else
		{
			PUTS(p, b, s, match->rm_so, return fatal(p->env->disc, c, NiL));
			if (!c && (c = sub(p, b, s, b->re_ops, nmatch, match)))
				return fatal(p->env->disc, c, NiL);
		}
		s += match->rm_eo;
		if (m <= 0 && !(b->re_flags & REG_SUB_ALL) || !*s)
			break;
		if (c = regnexec(p, s, e - s, nmatch, match, p->env->flags|(match->rm_so == match->rm_eo ? REG_ADVANCE : 0)))
		{
			if (c != REG_NOMATCH)
				return fatal(p->env->disc, c, NiL);
			break;
		}
		if (!match->rm_so && !match->rm_eo && *s && m <= 1)
		{
			match->rm_so = match->rm_eo = 1;
			c = 1;
		}
	}
	while (s < e)
	{
		c = *s++;
		PUTC(p, b, c, return fatal(p->env->disc, c, NiL));
	}
	NEED(p, b, 1, return fatal(p->env->disc, c, NiL));
	*b->re_cur = 0;
	b->re_len = b->re_cur - b->re_buf;
	return 0;
}

/*
 * 20120528: regoff_t changed from int to ssize_t
 */

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#undef	regsubexec
#if _map_libc
#define regsubexec	_ast_regsubexec
#endif

extern int
regsubexec(const regex_t* p, const char* s, size_t nmatch, oldregmatch_t* oldmatch)
{
	if (oldmatch)
	{
		regmatch_t*	match;
		ssize_t		i;
		int		r;

		if (!(match = oldof(0, regmatch_t, nmatch, 0)))
			return -1;
		for (i = 0; i < nmatch; i++)
		{
			match[i].rm_so = oldmatch[i].rm_so;
			match[i].rm_eo = oldmatch[i].rm_eo;
		}
		if (!(r = regsubexec_20120528(p, s, nmatch, match)))
			for (i = 0; i < nmatch; i++)
			{
				oldmatch[i].rm_so = match[i].rm_so;
				oldmatch[i].rm_eo = match[i].rm_eo;
			}
		free(match);
		return r;
	}
	return regsubexec_20120528(p, s, 0, NiL);
}
