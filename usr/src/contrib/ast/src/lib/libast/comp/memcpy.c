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

#if _lib_memcpy

NoN(memcpy)

#else

#undef	memcpy

#if _lib_bcopy

extern void	bcopy(void*, void*, size_t);

void*
memcpy(void* s1, void* s2, size_t n)
{
	bcopy(s2, s1, n);
	return(s1);
}

#else

void*
memcpy(void* as1, const void* as2, register size_t n)
{
	register char*		s1 = (char*)as1;
	register const char*	s2 = (const char*)as2;

	while (n-- > 0)
		*s1++ = *s2++;
	return(as1);
}

#endif

#endif
