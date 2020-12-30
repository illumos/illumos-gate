/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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

#if _hdr_macho_o_dyld && _lib__NSGetExecutablePath
#include <mach-o/dyld.h>
#else
#undef	_lib__NSGetExecutablePath
#endif

static size_t
prog(const char* command, char* path, size_t size)
{
	ssize_t		n;
	char*		s;
#if _WINIX
	char*		t;
	char*		e;
	int		c;
	int		q;
#endif
#if _lib__NSGetExecutablePath
	uint32_t	z;
#endif

#ifdef _PROC_PROG
	if ((n = readlink(_PROC_PROG, path, size)) > 0 && *path == '/')
	{
		if (n < size)
			path[n] = 0;
		return n;
	}
#endif
#if _lib_getexecname
	if ((s = (char*)getexecname()) && *s == '/')
		goto found;
#endif
#if _lib__NSGetExecutablePath
	z = size;
	if (!_NSGetExecutablePath(path, &z) && *path == '/')
		return strlen(path);
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
		s = (char*)command;
		goto found;
	}
	return 0;
 found:
	n = strlen(s);
	if (n < size)
		memcpy(path, s, n + 1);
	return n;
}

size_t
pathprog(const char* command, char* path, size_t size)
{
	char*		rel;
	ssize_t		n;

	if ((n = prog(command, path, size)) > 0 && n < size && *path != '/' && (rel = strdup(path)))
	{
		n = pathpath(rel, NiL, PATH_REGULAR|PATH_EXECUTE, path, size) ? strlen(path) : 0;
		free(rel);
	}
	return n;
}
