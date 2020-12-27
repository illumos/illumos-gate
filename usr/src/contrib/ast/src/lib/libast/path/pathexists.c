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
 * AT&T Research
 *
 * return 1 if path exisis
 * maintains a cache to minimize stat(2) calls
 * path is modified in-place but restored on return
 * path components checked in pairs to cut stat()'s
 * in half by checking ENOTDIR vs. ENOENT
 * case ignorance infection unavoidable here
 */

#include "lclib.h"

#include <ls.h>
#include <error.h>

typedef struct Tree_s
{
	struct Tree_s*	next;
	struct Tree_s*	tree;
	int		mode;
	char		name[1];
} Tree_t;

int
pathexists(char* path, int mode)
{
	register char*		s;
	register char*		e;
	register Tree_t*	p;
	register Tree_t*	t;
	register int		c;
	char*			ee;
	int			cc;
	int			x;
	struct stat		st;
	int			(*cmp)(const char*, const char*);

	static Tree_t		tree;

	t = &tree;
	e = (c = *path) == '/' ? path + 1 : path;
	cmp = strchr(astconf("PATH_ATTRIBUTES", path, NiL), 'c') ? strcasecmp : strcmp;
	if ((ast.locale.set & (AST_LC_debug|AST_LC_find)) == (AST_LC_debug|AST_LC_find))
		sfprintf(sfstderr, "locale test %s\n", path);
	while (c)
	{
		p = t;
		for (s = e; *e && *e != '/'; e++);
		c = *e;
		*e = 0;
		for (t = p->tree; t && (*cmp)(s, t->name); t = t->next);
		if (!t)
		{
			if (!(t = newof(0, Tree_t, 1, strlen(s))))
			{
				*e = c;
				return 0;
			}
			strcpy(t->name, s);
			t->next = p->tree;
			p->tree = t;
			if (c)
			{
				*e = c;
				for (s = ee = e + 1; *ee && *ee != '/'; ee++);
				cc = *ee;
				*ee = 0;
			}
			else
				ee = 0;
			if ((ast.locale.set & (AST_LC_debug|AST_LC_find)) == (AST_LC_debug|AST_LC_find))
				sfprintf(sfstderr, "locale stat %s\n", path);
			x = stat(path, &st);
			if (ee)
			{
				e = ee;
				c = cc;
				if (!x || errno == ENOENT)
					t->mode = PATH_READ|PATH_EXECUTE;
				if (!(p = newof(0, Tree_t, 1, strlen(s))))
				{
					*e = c;
					return 0;
				}
				strcpy(p->name, s);
				p->next = t->tree;
				t->tree = p;
				t = p;
			}
			if (x)
			{
				*e = c;
				return 0;
			}
			if (st.st_mode & (S_IRUSR|S_IRGRP|S_IROTH))
				t->mode |= PATH_READ;
			if (st.st_mode & (S_IWUSR|S_IWGRP|S_IWOTH))
				t->mode |= PATH_WRITE;
			if (st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))
				t->mode |= PATH_EXECUTE;
			if (!S_ISDIR(st.st_mode))
				t->mode |= PATH_REGULAR;
		}
		*e++ = c;
		if (!t->mode || c && (t->mode & PATH_REGULAR))
			return 0;
	}
	mode &= (PATH_READ|PATH_WRITE|PATH_EXECUTE|PATH_REGULAR);
	return (t->mode & mode) == mode;
}
