/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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

#if _lib_strncasecmp

NoN(strncasecmp)

#else

#include <ctype.h>

#undef	strncasecmp

int
strncasecmp(register const char* a, register const char* b, size_t n)
{
	register const char*	e;
	register int		ac;
	register int		bc;
	register int		d;

	e = a + n;
	for (;;)
	{
		if (a >= e)
			return 0;
		ac = *a++;
		if (isupper(ac))
			ac = tolower(ac);
		bc = *b++;
		if (isupper(bc))
			bc = tolower(bc);
		if (d = ac - bc)
			return d;
		if (!ac)
			return 0;
	}
}

#endif
