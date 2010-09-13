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

#define setenv		______setenv

#include <ast.h>

#undef	setenv
#undef	_lib_setenv	/* procopen() calls setenv() */

#if _lib_setenv

NoN(setenv)

#else

#undef	_def_map_ast
#include <ast_map.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int
setenv(const char* name, const char* value, int overwrite)
{
	char*	s;

	if (overwrite || !getenv(name))
	{
		if (!(s = sfprints("%s=%s", name, value)) || !(s = strdup(s)))
			return -1;
		return setenviron(s) ? 0 : -1;
	}
	return 0;
}

#endif
