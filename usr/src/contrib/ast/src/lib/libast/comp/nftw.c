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
 * nftw implementation
 */

#include <ast.h>
#include <ftw.h>

static int	nftw_flags;
static int	(*nftw_userf)(const char*, const struct stat*, int, struct FTW*);

static int
nftw_user(Ftw_t* ftw)
{
	register int	n = ftw->info;
	struct FTW	nftw;
	struct stat	st;

	if (n & (FTW_C|FTW_NX))
		n = FTW_DNR;
	else if ((n & FTW_SL) && (!(nftw_flags & FTW_PHYSICAL) || stat(ftw->path, &st)))
		n = FTW_SLN;
	nftw.base = ftw->pathlen - ftw->namelen;
	nftw.level = ftw->level;
	nftw.quit = 0;
	n = (*nftw_userf)(ftw->path, &ftw->statb, n, &nftw);
	ftw->status = nftw.quit;
	return n;
}

int
nftw(const char* path, int(*userf)(const char*, const struct stat*, int, struct FTW*), int depth, int flags)
{
	NoP(depth);
	nftw_userf = userf;
	if (flags & FTW_CHDIR) flags &= ~FTW_DOT;
	else flags |= FTW_DOT;
	nftw_flags = flags;
	return ftwalk(path, nftw_user, flags, NiL);
}
