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

#if _lib_setsid

NoN(setsid)

#else

#include <ast_tty.h>
#include <error.h>

/*
 * become new process group leader and drop control tty
 */

pid_t
setsid(void)
{
	int	pg;
#ifdef TIOCNOTTY
	int	fd;
#endif

	/*
	 * become a new process group leader
	 */

	if ((pg = getpid()) == getpgrp())
	{
		errno = EPERM;
		return(-1);
	}
	setpgid(pg, pg);
#ifdef TIOCNOTTY

	/*
	 * drop the control tty
	 */

	if ((fd = open("/dev/tty", O_RDONLY)) >= 0)
	{
		ioctl(fd, TIOCNOTTY, 0);
		close(fd);
	}
#else

	/*
	 * second child in s5 to avoid reacquiring the control tty
	 */

#if _lib_fork && HUH920711 /* some s5's botch this */
	switch (fork())
	{
	case -1:
		exit(1);
	case 0:
		break;
	default:
		exit(0);
	}
#endif

#endif
	return(pg);
}

#endif
