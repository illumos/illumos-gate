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
 * time conversion support
 */

#include <ast.h>
#include <tm.h>
#include <ctype.h>

/*
 * match s against t ignoring case and .'s
 *
 * suf is an n element table of suffixes that may trail s
 * if all isalpha() chars in s match then 1 is returned
 * and if e is non-null it will point to the first unmatched
 * char in s, otherwise 0 is returned
 */

int
tmword(register const char* s, char** e, register const char* t, char** suf, int n)
{
	register int	c;
	const char*	b;

	if (*s && *t)
	{
		b = s;
		while (c = *s++)
		{
			if (c != '.')
			{
				if (!isalpha(c) || c != *t && (islower(c) ? toupper(c) : tolower(c)) != *t)
					break;
				t++;
			}
		}
		s--;
		if (!isalpha(c))
		{
			if (c == '_')
				s++;
			if (e)
				*e = (char*)s;
			return s > b;
		}
		if (!*t && s > (b + 1))
		{
			b = s;
			while (n-- && (t = *suf++))
			{
				s = b;
				while (isalpha(c = *s++) && (c == *t || (islower(c) ? toupper(c) : tolower(c)) == *t)) t++;
				if (!*t && !isalpha(c))
				{
					if (c != '_')
						s--;
					if (e)
						*e = (char*)s;
					return 1;
				}
			}
		}
	}
	return 0;
}
