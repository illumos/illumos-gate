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
 * return full path to p with mode access using $PATH
 * a!=0 enables related root search
 * a!=0 && a!="" searches a dir first
 * the related root must have a bin subdir
 * p==0 sets the cached relative dir to a
 * full path returned in path buffer
 * if path==0 then the space is malloc'd
 */

#define _AST_API_H	1

#include <ast.h>

char*
pathpath(char* path, const char* p, const char* a, int mode)
{
	return pathpath_20100601(p, a, mode, path, PATH_MAX);
}

#undef	_AST_API_H

#include <ast_api.h>

char*
pathpath_20100601(const char* p, const char* a, int mode, register char* path, size_t size)
{
	register char*	s;
	char*		x;
	char		buf[PATH_MAX];

	static char*	cmd;

	if (!path)
	{
		path = buf;
		if (!size || size > sizeof(buf))
			size = sizeof(buf);
	}
	if (!p)
	{
		if (cmd)
			free(cmd);
		cmd = a ? strdup(a) : (char*)0;
		return 0;
	}
	if (strlen(p) < size)
	{
		strcpy(path, p);
		if (pathexists(path, mode))
		{
			if (*p != '/' && (mode & PATH_ABSOLUTE))
			{
				getcwd(buf, sizeof(buf));
				s = buf + strlen(buf);
				sfsprintf(s, sizeof(buf) - (s - buf), "/%s", p);
				if (path != buf)
					strcpy(path, buf);
			}
			return (path == buf) ? strdup(path) : path;
		}
	}
	if (*p == '/')
		a = 0;
	else if (s = (char*)a)
	{
		x = s;
		if (strchr(p, '/'))
		{
			a = p;
			p = "..";
		}
		else
			a = 0;
		if ((!cmd || *cmd) && (strchr(s, '/') || (s = cmd)))
		{
			if (!cmd && *s == '/')
				cmd = strdup(s);
			if (strlen(s) < (sizeof(buf) - 6))
			{
				s = strcopy(path, s);
				for (;;)
				{
					do if (s <= path) goto normal; while (*--s == '/');
					do if (s <= path) goto normal; while (*--s != '/');
					strcpy(s + 1, "bin");
					if (pathexists(path, PATH_EXECUTE))
					{
						if (s = pathaccess(path, p, a, mode, path, size))
							return path == buf ? strdup(s) : s;
						goto normal;
					}
				}
			normal: ;
			}
		}
	}
	x = !a && strchr(p, '/') ? "" : pathbin();
	if (!(s = pathaccess(x, p, a, mode, path, size)) && !*x && (x = getenv("FPATH")))
		s = pathaccess(x, p, a, mode, path, size);
	return (s && path == buf) ? strdup(s) : s;
}
