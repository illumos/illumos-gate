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
 * AT&T Bell Laboratories
 * return 1 if dir [any dir] is the preroot
 */

#include <ast.h>
#include <preroot.h>

#if FS_PREROOT

#include <ls.h>

/*
 * return 1 if files a and b are the same under preroot
 *
 * NOTE: the kernel disables preroot for set-uid processes
 */

static int
same(const char* a, const char* b)
{
	int		i;
	int		euid;
	int		ruid;

	struct stat	ast;
	struct stat	bst;

	if ((ruid = getuid()) != (euid = geteuid())) setuid(ruid);
	i = !stat(a, &ast) && !stat(b, &bst) && ast.st_dev == bst.st_dev && ast.st_ino == bst.st_ino;
	if (ruid != euid) setuid(euid);
	return(i);
}

int
ispreroot(const char* dir)
{
	static int	prerooted = -1;

	if (dir) return(same("/", dir));
	if (prerooted < 0) prerooted = !same("/", PR_REAL);
	return(prerooted);
}

#else

NoN(ispreroot)

#endif
