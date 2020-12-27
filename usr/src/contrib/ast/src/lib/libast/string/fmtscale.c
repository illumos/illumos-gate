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
 * Glenn Fowler
 * AT&T Research
 *
 * return number n scaled to metric multiples of k { 1000 1024 }
 * return string length is at most 5 chars + terminating nul
 */

#include <ast.h>
#include <lclib.h>

char*
fmtscale(register Sfulong_t n, int k)
{
	register Sfulong_t	m;
	int			r;
	int			z;
	const char*		u;
	char			suf[3];
	char*			s;
	char*			buf;
	Lc_numeric_t*		p = (Lc_numeric_t*)LCINFO(AST_LC_NUMERIC)->data;

	static const char	scale[] = "bkMGTPE";

	u = scale;
	if (n < 1000)
		r = 0;
	else
	{
		m = 0;
		while (n >= k && *(u + 1))
		{
			m = n;
			n /= k;
			u++;
		}
		if ((r = (10 * (m % k) + (k / 2)) / k) > 9)
		{
			r = 0;
			n++;
		}
		if (k == 1024 && n >= 1000)
		{
			n = 1;
			r = 0;
			u++;
		}
	}
	buf = fmtbuf(z = 8);
	s = suf;
	if (u > scale)
	{
		if (k == 1024)
		{
			*s++ = *u == 'k' ? 'K' : *u;
			*s++ = 'i';
		}
		else
			*s++ = *u;
	}
	*s = 0;
	if (n > 0 && n < 10)
		sfsprintf(buf, z, "%I*u%c%d%s", sizeof(n), n, p->decimal >= 0 ? p->decimal : '.', r, suf);
	else
	{
		if (r >= 5)
			n++;
		sfsprintf(buf, z, "%I*u%s", sizeof(n), n, suf);
	}
	return buf;
}
