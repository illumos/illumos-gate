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

#include <ast.h>
#include <ctype.h>

#define IDENT	01
#define USAGE	02

/*
 * format what(1) and/or ident(1) string a
 */

char*
fmtident(const char* a)
{
	register char*	s = (char*)a;
	register char*	t;
	char*		buf;
	int		i;

	i = 0;
	for (;;)
	{
		while (isspace(*s))
			s++;
		if (s[0] == '[')
		{
			while (*++s && *s != '\n');
			i |= USAGE;
		}
		else if (s[0] == '@' && s[1] == '(' && s[2] == '#' && s[3] == ')')
			s += 4;
		else if (s[0] == '$' && s[1] == 'I' && s[2] == 'd' && s[3] == ':' && isspace(s[4]))
		{
			s += 5;
			i |= IDENT;
		}
		else
			break;
	}
	if (i)
	{
		i &= IDENT;
		for (t = s; isprint(*t) && *t != '\n'; t++)
			if (i && t[0] == ' ' && t[1] == '$')
				break;
		while (t > s && isspace(t[-1]))
			t--;
		i = t - s;
		buf = fmtbuf(i + 1);
		memcpy(buf, s, i);
		s = buf;
		s[i] = 0;
	}
	return s;
}
