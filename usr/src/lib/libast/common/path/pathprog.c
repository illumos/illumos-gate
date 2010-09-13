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
 * AT&T Research
 *
 * return the full path of the current program in path
 * command!=0 is used as a default
 */

#include <ast.h>

#if _WINIX
#include <ast_windows.h>
#include <ctype.h>
#endif

#include "FEATURE/prog"

static size_t
prog(const char* command, char* path, size_t size)
{
	ssize_t		n;
#if _WINIX || _lib_getexecname
	char*		s;
#endif
#if _WINIX
	char*		t;
	char*		e;
	int		c;
	int		q;
#endif

#ifdef _PROC_PROG
	if ((n = readlink(_PROC_PROG, path, size)) > 0)
	{
		if (n < size)
			path[n] = 0;
		return n;
	}
#endif
#if _lib_getexecname
	if (s = (char*)getexecname())
	{
		n = strlen(s);
		if (n < size)
			strcpy(path, s);
		return n;
	}
#endif
#if _WINIX
	if (s = GetCommandLine())
	{
		n = 0;
		q = 0;
		t = path;
		e = path + size - 1;
		while (c = *s++)
		{
			if (c == q)
				q = 0;
			else if (!q && c == '"')
				q = c;
			else if (!q && isspace(c))
				break;
			else if (t < e)
				*t++ = c == '\\' ? '/' : c;
			else
				n++;
		}
		if (t < e)
			*t = 0;
		return (t - path) + n;
	}
#endif
	if (command)
	{
		if ((n = strlen(command) + 1) <= size)
			memcpy(path, command, n);
		return n;
	}
	return 0;
}

size_t
pathprog(const char* command, char* path, size_t size)
{
	ssize_t		n;
	char		buf[PATH_MAX];

	if ((n = prog(command, path, size)) > 0 && n <= size && *path != '/')
	{
		if (!pathpath(buf, path, NiL, PATH_REGULAR|PATH_EXECUTE))
			n = 0;
		else if ((n = strlen(buf) + 1) <= size)
			memcpy(path, buf, n);
	}
	return n;
}
