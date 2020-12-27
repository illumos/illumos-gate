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
 * AT&T Bell Laboratories
 *
 * parse elapsed time in 1/n secs from s
 * compatible with fmtelapsed()
 * also handles ps [day-][hour:]min:sec
 * also handles coshell % for 'infinity'
 * if e!=0 then it is set to first unrecognized char
 */

#include <ast.h>
#include <ctype.h>

unsigned long
strelapsed(register const char* s, char** e, int n)
{
	register int		c;
	register unsigned long	v;
	unsigned long		t = 0;
	int			f = 0;
	int			p = 0;
	int			z = 1;
	int			m;
	const char*		last;

	for (;;)
	{
		while (isspace(*s) || *s == '_')
			s++;
		if (!*(last = s))
			break;
		if (z)
		{
			z = 0;
			if (*s == '0' && (!(c = *(s + 1)) || isspace(c) || c == '_'))
			{
				last = s + 1;
				break;
			}
		}
		v = 0;
		while ((c = *s++) >= '0' && c <= '9')
			v = v * 10 + c - '0';
		v *= n;
		if (c == '.')
			for (m = n; (c = *s++) >= '0' && c <= '9';)
				f += (m /= 10) * (c - '0');
		if (c == '%')
		{
			t = ~t;
			last = s;
			break;
		}
		if (s == last + 1)
			break;
		if (!p)
			while (isspace(c) || c == '_')
				c = *s++;
		switch (c)
		{
		case 'S':
			if (*s == 'E' || *s == 'e')
			{
				v += f;
				f = 0;
			}
			else
				v *= 20 * 12 * 4 * 7 * 24 * 60 * 60;
			break;
		case 'y':
		case 'Y':
			v *= 12 * 4 * 7 * 24 * 60 * 60;
			break;
		case 'M':
			if (*s == 'I' || *s == 'i')
				v *= 60;
			else
				v *= 4 * 7 * 24 * 60 * 60;
			break;
		case 'w':
			v *= 7 * 24 * 60 * 60;
			break;
		case '-':
			p = 1;
			/*FALLTHROUGH*/
		case 'd':
			v *= 24 * 60 * 60;
			break;
		case 'h':
			v *= 60 * 60;
			break;
		case ':':
			p = 1;
			v *= strchr(s, ':') ? (60 * 60) : 60;
			break;
		case 'm':
			if (*s == 'o')
				v *= 4 * 7 * 24 * 60 * 60;
			else
				v *= 60;
			break;
		case 's':
			if (*s == 'c')
			{
				v *= 20 * 12 * 4 * 7 * 24 * 60 * 60;
				break;
			}
			v += f;
			f = 0;
			break;
		case 0:
			s--;
			v += f;
			break;
		default:
			if (p)
			{
				last = s - 1;
				t += v + f;
			}
			goto done;
		}
		t += v;
		while (isalpha(*s))
			s++;
	}
 done:
	if (e)
		*e = (char*)last;
	return t;
}
