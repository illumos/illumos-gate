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
/*
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * single dir support for pathaccess()
 */

#include <ast.h>

char*
pathcat(char* path, register const char* dirs, int sep, const char* a, register const char* b)
{
	register char*	s;

	s = path;
	while (*dirs && *dirs != sep)
		*s++ = *dirs++;
	if (s != path)
		*s++ = '/';
	if (a)
	{
		while (*s = *a++)
			s++;
		if (b)
			*s++ = '/';
	}
	else if (!b)
		b = ".";
	if (b)
		while (*s++ = *b++);
	return *dirs ? (char*)++dirs : 0;
}
