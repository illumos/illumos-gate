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
 * strlcat implementation
 */

#define strlcat		______strlcat

#include <ast.h>

#undef	strlcat

#undef	_def_map_ast
#include <ast_map.h>

#if _lib_strlcat

NoN(strlcat)

#else

/*
 * append t onto s limiting total size of s to n
 * s 0 terminated if n>0
 * min(n,strlen(s))+strlen(t) returned
 */

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern size_t
strlcat(register char* s, register const char* t, register size_t n)
{
	register size_t	m;
	const char*	o = t;

	if (m = n)
	{
		while (n && *s)
		{
			n--;
			s++;
		}
		m -= n;
		if (n)
			do
			{
				if (!--n)
				{
					*s = 0;
					break;
				}
			} while (*s++ = *t++);
		else
			*s = 0;
	}
	if (!n)
		while (*t++);
	return (t - o) + m - 1;
}

#endif
