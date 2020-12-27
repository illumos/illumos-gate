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
 * return printf(3) format signature given format string
 * the format signature contains one char per format optionally preceded
 * by the number of `*' args
 *	c	char
 *	d	double
 *	D	long double
 *	f	float
 *	h	short
 *	i	int
 *	j	long long
 *	l	long
 *	p	void*
 *	s	string
 *	t	ptrdiff_t
 *	z	size_t
 *	?	unknown
 */

#include <ast.h>
#include <ctype.h>

char*
fmtfmt(const char* as)
{
	register char*	s = (char*)as;
	char*		buf;
	int		i;
	int		c;
	int		a;
	int		q;
	int		x;
	int		t;
	int		m;
	int		n;
	int		z;
	char		formats[256];
	unsigned int	extra[elementsof(formats)];

	z = 1;
	i = m = 0;
	for (;;)
	{
		switch (*s++)
		{
		case 0:
			break;
		case '%':
			if (*s == '%')
				continue;
			n = 0;
			a = 0;
			q = 0;
			t = '?';
			x = 0;
			for (;;)
			{
				switch (c = *s++)
				{
				case 0:
					s--;
					break;
				case '(':
					q++;
					continue;
				case ')':
					if (--q <= 0)
						n = 0;
					continue;
				case '0': case '1': case '2': case '3':
				case '4': case '5': case '6': case '7':
				case '8': case '9':
					n = n * 10 + (c - '0');
					continue;
				case '$':
					a = n;
					n = 0;
					continue;
				case '*':
					x++;
					n = 0;
					continue;
				case 'h':
					if (!q)
						t = t == 'h' ? 'c' : 'h';
					continue;
				case 'l':
					if (!q)
						t = t == 'l' ? 'j' : 'l';
					continue;
				case 'j':
				case 't':
				case 'z':
					if (!q)
						t = c;
					continue;
				case 'c':
				case 'p':
				case 's':
					if (!q)
					{
						t = c;
						break;
					}
					continue;
				case 'e':
				case 'g':
					if (!q)
					{
						switch (t)
						{
						case 'j':
							t = 'D';
							break;
						default:
							t = 'd';
							break;
						}
						break;
					}
					continue;
				case 'f':
					if (!q)
					{
						switch (t)
						{
						case 'j':
							t = 'D';
							break;
						case 'l':
							t = 'd';
							break;
						default:
							t = c;
							break;
						}
						break;
					}
					continue;
				default:
					if (!q && isalpha(c))
					{
						if (t == '?')
							t = 'i';
						break;
					}
					n = 0;
					continue;
				}
				break;
			}
			if (a)
				i = a;
			else
				i++;
			if (i < elementsof(formats))
			{
				formats[i] = t;
				if (extra[i] = x)
					do z++; while (x /= 10);
				if (m < i)
					m = i;
			}
			continue;
		default:
			continue;
		}
		break;
	}
	s = buf = fmtbuf(m + z);
	for (i = 1; i <= m; i++)
	{
		if (extra[i])
			s += sfsprintf(s, 10, "%d", extra[m]);
		*s++ = formats[i];
	}
	*s = 0;
	return buf;
}
