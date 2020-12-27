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

#include <ast.h>

#if _lib_setpgid

NoN(setpgid)

#else

#include <error.h>

#ifndef ENOSYS
#define ENOSYS		EINVAL
#endif

#if _lib_setpgrp2
#define setpgrp		setpgrp2
#else
#if _lib_BSDsetpgrp
#define _lib_setpgrp2	1
#define setpgrp		BSDsetpgrp
#else
#if _lib_wait3
#define	_lib_setpgrp2	1
#endif
#endif
#endif

#if _lib_setpgrp2
extern int		setpgrp(int, int);
#else
extern int		setpgrp(void);
#endif

/*
 * set process group id
 */

int
setpgid(pid_t pid, pid_t pgid)
{
#if _lib_setpgrp2
	return(setpgrp(pid, pgid));
#else
#if _lib_setpgrp
	int	caller = getpid();

	if ((pid == 0 || pid == caller) && (pgid == 0 || pgid == caller))
		return(setpgrp());
	errno = EINVAL;
#else
	errno = ENOSYS;
#endif
	return(-1);
#endif
}

#endif
