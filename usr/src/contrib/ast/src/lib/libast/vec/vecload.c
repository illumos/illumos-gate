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
 * string vector load support
 */

#include <ast.h>
#include <vecargs.h>

/*
 * load a string vector from lines in buf
 * buf may be modified on return
 *
 * each line in buf is treated as a new vector element
 * lines with # as first char are comments
 * \ as the last char joins consecutive lines
 *
 * the vector ends with a 0 sentinel
 *
 * the string array pointer is returned
 */

char**
vecload(char* buf)
{
	register char*	s;
	register int	n;
	register char**	p;
	char**		vec;

	vec = 0;
	n = (*buf == '#') ? -1 : 0;
	for (s = buf;; s++)
	{
		if (*s == '\n')
		{
			if (s > buf && *(s - 1) == '\\') *(s - 1) = *s = ' ';
			else
			{
				*s = 0;
				if (*(s + 1) != '#')
				{
					n++;
					if (!*(s + 1)) break;
				}
			}
		}
		else if (!*s)
		{
			n++;
			break;
		}
	}
	if (n < 0) n = 0;
	if (p = newof(0, char*, n + 3, 0))
	{
		*p++ = s = buf;
		vec = ++p;
		if (n > 0) for (;;)
		{
			if (*s != '#')
			{
				*p++ = s;
				if (--n <= 0) break;
			}
			while (*s) s++;
			s++;
		}
		*p = 0;
		*(vec - 1) = (char*)p;
	}
	return(vec);
}
