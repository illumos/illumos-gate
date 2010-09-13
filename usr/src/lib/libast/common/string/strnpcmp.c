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

/*
 * path prefix strncmp(3) -- longest first!
 */

int
strnpcmp(register const char* a, register const char* b, size_t n)
{
	register const char*	e;

	e = a + n;
	for (;;)
	{
		if (a >= e)
			return 0;
		if (*a != *b)
			break;
		if (!*a++)
			return 0;
		b++;
	}
	if (*a == 0 && *b == '/')
		return 1;
	if (*a == '/' && *b == 0)
		return -1;
	return (a < b) ? -1 : 1;
}
