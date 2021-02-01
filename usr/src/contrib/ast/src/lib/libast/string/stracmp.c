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
 * ccmapchr(ccmap(CC_NATIVE,CC_ASCII),c) and strcmp
 */

#include <ast.h>
#include <ccode.h>

#if _lib_stracmp

NoN(stracmp)

#else

#include <ctype.h>

int
stracmp(const char* aa, const char* ab)
{
	register unsigned char*	a;
	register unsigned char*	b;
	register unsigned char*	m;
	register int		c;
	register int		d;

	if (!(m = ccmap(CC_NATIVE, CC_ASCII)))
		return strcmp(aa, ab);
	a = (unsigned char*)aa;
	b = (unsigned char*)ab;
	for (;;)
	{
		c = m[*a++];
		if (d = c - m[*b++])
			return d;
		if (!c)
			return 0;
	}
}

#endif
