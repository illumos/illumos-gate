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

#include <ast.h>
#include <ls.h>

#if _lib_mknod

NoN(mknod)

#else

#include <error.h>

#ifndef ENOSYS
#define ENOSYS	EINVAL
#endif

int
mknod(const char* path, mode_t mode, dev_t dev)
{
	if (S_ISFIFO(mode))
		return mkfifo(path, mode);
	if (S_ISDIR(mode))
		return mkdir(path, mode);
	errno = ENOSYS;
	return -1;
}

#endif
