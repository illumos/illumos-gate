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

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide strstr
#else
#define strstr		______strstr
#endif

#include <ast.h>

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide strstr
#else
#undef	strstr
#endif

#if _lib_strstr

NoN(strstr)

#else

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern char*
strstr(register const char* s1, register const char* s2)
{
	register int		c1;
	register int		c2;
	register const char*	t1;
	register const char*	t2;
	
	if (s2)
	{
		if (!*s2)
			return (char*)s1;
		c2 = *s2++;
		while (c1 = *s1++)
			if (c1 == c2)
			{
				t1 = s1;
				t2 = s2;
				do
				{
					if (!*t2)
						return (char*)s1 - 1;
				} while (*t1++ == *t2++);
			}
	}
	return 0;
}

#endif
