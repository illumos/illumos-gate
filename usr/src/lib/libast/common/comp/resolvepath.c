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
 * resolvepath implementation
 */

#define resolvepath	______resolvepath

#include <ast.h>
#include <error.h>

#undef	resolvepath

#undef	_def_map_ast
#include <ast_map.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int
resolvepath(const char* file, char* path, size_t size)
{
	register char*	s;
	register int	n;
	register int	r;

	r = *file != '/';
	n = strlen(file) + r + 1;
	if (n >= size)
	{
#ifdef ENAMETOOLONG
		errno = ENAMETOOLONG;
#else
		errno = ENOMEM;
#endif
		return 0;
	}
	if (!r)
		s = path;
	else if (!getcwd(path, size - n))
		return 0;
	else
	{
		s = path + strlen(path);
		*s++ = '/';
	}
	strcpy(s, file);
	return pathcanon(path, PATH_PHYSICAL|PATH_DOTDOT|PATH_EXISTS) ? strlen(path) : -1;
}
