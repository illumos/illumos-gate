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
 * return path to file a/b with access mode using : separated dirs
 * both a and b may be 0
 * if a==".." then relative paths in dirs are ignored
 * if (mode&PATH_REGULAR) then path must not be a directory
 * if (mode&PATH_ABSOLUTE) then path must be rooted
 * path returned in path buffer
 */

#define _AST_API_H	1

#include <ast.h>

char*
pathaccess(char* path, const char* dirs, const char* a, const char* b, int mode)
{
	return pathaccess_20100601(dirs, a, b, mode, path, PATH_MAX);
}

#undef	_AST_API_H

#include <ast_api.h>

char*
pathaccess_20100601(register const char* dirs, const char* a, const char* b, register int mode, register char* path, size_t size)
{
	int		sib = a && a[0] == '.' && a[1] == '.' && a[2] == 0;
	int		sep = ':';
	char		cwd[PATH_MAX];

	do
	{
		dirs = pathcat(dirs, sep, a, b, path, size);
		pathcanon(path, size, 0);
		if ((!sib || *path == '/') && pathexists(path, mode))
		{
			if (*path == '/' || !(mode & PATH_ABSOLUTE))
				return path;
			dirs = getcwd(cwd, sizeof(cwd));
			sep = 0;
		}
	} while (dirs);
	return 0;
}
