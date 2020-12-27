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
 * ftw implementation
 */

#include <ast.h>
#include <ftw.h>

static int	(*ftw_userf)(const char*, const struct stat*, int);

static int
ftw_user(Ftw_t* ftw)
{
	register int	n = ftw->info;

	if (n & (FTW_C|FTW_NX))
		n = FTW_DNR;
	else if (n & FTW_SL)
		n = FTW_NS;
	return (*ftw_userf)(ftw->path, &ftw->statb, n);
}

int
ftw(const char* path, int(*userf)(const char*, const struct stat*, int), int depth)
{
	NoP(depth);
	ftw_userf = userf;
	return ftwalk(path, ftw_user, FTW_DOT, NiL);
}
