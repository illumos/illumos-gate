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
 * return full path to p with mode access using $PATH
 * a!=0 enables related root search
 * a!=0 && a!="" searches a dir first
 * the related root must have a bin subdir
 * p==0 sets the cached relative dir to a
 * full path returned in path buffer
 * if path==0 then the space is malloc'd
 */

#include <ast.h>

char*
pathpath(register char* path, const char* p, const char* a, int mode)
{
	register char*	s;
	char*		x;
	char		buf[PATH_MAX];

	static char*	cmd;

	if (!path)
		path = buf;
	if (!p)
	{
		if (cmd)
			free(cmd);
		cmd = a ? strdup(a) : (char*)0;
		return 0;
	}
	if (strlen(p) < PATH_MAX)
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
						if (s = pathaccess(path, path, p, a, mode))
							return path == buf ? strdup(s) : s;
						goto normal;
					}
				}
			normal: ;
			}
		}
	}
	x = !a && strchr(p, '/') ? "" : pathbin();
	if (!(s = pathaccess(path, x, p, a, mode)) && !*x && (x = getenv("FPATH")))
		s = pathaccess(path, x, p, a, mode);
	return (s && path == buf) ? strdup(s) : s;
}
