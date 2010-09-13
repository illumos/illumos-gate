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

#if _lib_execve

NoN(execve)

#else

#include <sig.h>
#include <wait.h>
#include <error.h>

static pid_t		childpid;

static void
execsig(int sig)
{
	kill(childpid, sig);
	signal(sig, execsig);
}

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int
execve(const char* path, char* const argv[], char* const arge[])
{
	int	status;

	if ((childpid = spawnve(path, argv, arge)) < 0)
		return(-1);
	for (status = 0; status < 64; status++)
		signal(status, execsig);
	while (waitpid(childpid, &status, 0) == -1)
		if (errno != EINTR) return(-1);
	if (WIFSIGNALED(status))
	{
		signal(WTERMSIG(status), SIG_DFL);
		kill(getpid(), WTERMSIG(status));
		pause();
	}
	else status = WEXITSTATUS(status);
	exit(status);
}

#endif
