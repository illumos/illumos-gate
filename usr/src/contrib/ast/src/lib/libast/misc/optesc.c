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
 * escape optget() special chars in s and write to sp
 * esc == '?' or ':' also escaped
 */

#include <optlib.h>
#include <ctype.h>

int
optesc(Sfio_t* sp, register const char* s, int esc)
{
	register const char*	m;
	register int		c;

	if (*s == '[' && *(s + 1) == '+' && *(s + 2) == '?')
	{
		c = strlen(s);
		if (s[c - 1] == ']')
		{
			sfprintf(sp, "%-.*s", c - 4, s + 3);
			return 0;
		}
	}
	if (esc != '?' && esc != ':')
		esc = 0;
	while (c = *s++)
	{
		if (isalnum(c))
		{
			for (m = s - 1; isalnum(*s); s++);
			if (isalpha(c) && *s == '(' && isdigit(*(s + 1)) && *(s + 2) == ')')
			{
				sfputc(sp, '\b');
				sfwrite(sp, m, s - m);
				sfputc(sp, '\b');
				sfwrite(sp, s, 3);
				s += 3;
			}
			else
				sfwrite(sp, m, s - m);
		}
		else if (c == '-' && *s == '-' || c == '<')
		{
			m = s - 1;
			if (c == '-')
				s++;
			else if (*s == '/')
				s++;
			while (isalnum(*s))
				s++;
			if (c == '<' && *s == '>' || isspace(*s) || *s == 0 || *s == '=' || *s == ':' || *s == ';' || *s == '.' || *s == ',')
			{
				sfputc(sp, '\b');
				sfwrite(sp, m, s - m);
				sfputc(sp, '\b');
			}
			else
				sfwrite(sp, m, s - m);
		}
		else
		{
			if (c == ']' || c == esc)
				sfputc(sp, c);
			sfputc(sp, c);
		}
	}
	return 0;
}
