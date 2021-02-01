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
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * single dir support for pathaccess()
 */

#define _AST_API_H	1

#include <ast.h>

/*
 * building 3d flirts with the dark side
 */

#if _BLD_3d

#undef	pathcat
#define pathcat_20100601	_3d_pathcat

#else

char*
pathcat(char* path, const char* dirs, int sep, const char* a, const char* b)
{
	return pathcat_20100601(dirs, sep, a, b, path, PATH_MAX);
}

#endif

#undef	_AST_API

#include <ast_api.h>

char*
pathcat_20100601(register const char* dirs, int sep, const char* a, register const char* b, char* path, size_t size)
{
	register char*	s;
	register char*	e;

	s = path;
	e = path + size;
	while (*dirs && *dirs != sep)
	{
		if (s >= e)
			return 0;
		*s++ = *dirs++;
	}
	if (s != path)
	{
		if (s >= e)
			return 0;
		*s++ = '/';
	}
	if (a)
	{
		while (*s = *a++)
			if (++s >= e)
				return 0;
		if (b)
		{
			if (s >= e)
				return 0;
			*s++ = '/';
		}
	}
	else if (!b)
		b = ".";
	if (b)
		do
		{
			if (s >= e)
				return 0;
		} while (*s++ = *b++);
	return *dirs ? (char*)++dirs : 0;
}
