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
 * AT&T Bell Laboratories
 * disable preroot and open path relative to the real root
 */

#include <ast.h>
#include <preroot.h>

#if FS_PREROOT

int
realopen(const char* path, int mode, int perm)
{
	char		buf[PATH_MAX + 8];

	if (*path != '/' || !ispreroot(NiL)) return(-1);
	strcopy(strcopy(buf, PR_REAL), path);
	return(open(buf, mode, perm));
}

#else

NoN(realopen)

#endif
