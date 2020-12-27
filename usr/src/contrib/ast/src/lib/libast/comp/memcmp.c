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

#if _lib_memcmp

NoN(memcmp)

#else

int
memcmp(const void* ab1, const void* ab2, size_t n)
{
	register const unsigned char*	b1 = (const unsigned char*)ab1;
	register const unsigned char*	b2 = (const unsigned char*)ab2;
	register const unsigned char*	e = b1 + n;

	while (b1 < e)
		if (*b1++ != *b2++)
			return(*--b1 - *--b2);
	return(0);
}

#endif
