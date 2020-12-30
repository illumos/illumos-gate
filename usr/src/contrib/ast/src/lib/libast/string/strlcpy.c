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
 * strlcpy implementation
 */

#define strlcpy		______strlcpy

#include <ast.h>

#undef	strlcpy

#undef	_def_map_ast
#include <ast_map.h>

#if _lib_strlcpy

NoN(strlcpy)

#else

/*
 * copy at most n chars from t into s
 * result 0 terminated if n>0
 * strlen(t) returned
 */

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern size_t
strlcpy(register char* s, register const char* t, register size_t n)
{
	const char*	o = t;

	if (n)
		do
		{
			if (!--n)
			{
				*s = 0;
				break;
			}
		} while (*s++ = *t++);
	if (!n)
		while (*t++);
	return t - o - 1;
}

#endif
