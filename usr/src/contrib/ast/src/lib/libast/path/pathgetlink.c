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
*/

#include "univlib.h"

#ifdef UNIV_MAX

#include <ctype.h>

#endif

/*
 * return external representation for symbolic link text of name in buf
 * the link text string length is returned
 */

int
pathgetlink(const char* name, char* buf, int siz)
{
	int	n;

	if ((n = readlink(name, buf, siz)) < 0) return(-1);
	if (n >= siz)
	{
		errno = EINVAL;
		return(-1);
	}
	buf[n] = 0;
#ifdef UNIV_MAX
	if (isspace(*buf))
	{
		register char*	s;
		register char*	t;
		register char*	u;
		register char*	v;
		int		match = 0;
		char		tmp[PATH_MAX];

		s = buf;
		t = tmp;
		while (isalnum(*++s) || *s == '_' || *s == '.');
		if (*s++)
		{
			for (;;)
			{
				if (!*s || isspace(*s))
				{
					if (match)
					{
						*t = 0;
						n = t - tmp;
						strcpy(buf, tmp);
					}
					break;
				}
				if (t >= &tmp[sizeof(tmp)]) break;
				*t++ = *s++;
				if (!match && t < &tmp[sizeof(tmp) - univ_size + 1]) for (n = 0; n < UNIV_MAX; n++)
				{
					if (*(v = s - 1) == *(u = univ_name[n]))
					{
						while (*u && *v++ == *u) u++;
						if (!*u)
						{
							match = 1;
							strcpy(t - 1, univ_cond);
							t += univ_size - 1;
							s = v;
							break;
						}
					}
				}
			}
		}
	}
#endif
	return(n);
}
