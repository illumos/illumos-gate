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

#if _lib_strrchr

NoN(strrchr)

#else

#undef	strrchr

#if _lib_rindex

#undef	rindex

extern char*	rindex(const char*, int);

char*
strrchr(const char* s, int c)
{
	return(rindex(s, c));
}

#else

char*
strrchr(register const char* s, register int c)
{
	register const char*	r;

	r = 0;
	do if (*s == c) r = s; while(*s++);
	return((char*)r);
}

#endif

#endif
