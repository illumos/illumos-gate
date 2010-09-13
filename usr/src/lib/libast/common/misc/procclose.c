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
 * close a proc opened by procopen()
 * otherwise exit() status of process is returned
 */

#include "proclib.h"

#include <wait.h>

int
procclose(register Proc_t* p)
{
	int	pid;
	int	flags = 0;
	int	status = -1;

	if (p)
	{
		if (p->rfd >= 0)
			close(p->rfd);
		if (p->wfd >= 0 && p->wfd != p->rfd)
			close(p->wfd);
		if (p->flags & PROC_ZOMBIE)
		{
			/*
			 * process may leave a zombie behind
			 * give it a chance to do that but
			 * don't hang waiting for it
			 */

			flags |= WNOHANG;
			sleep(1);
		}
		if (!(p->flags & PROC_FOREGROUND))
			sigcritical(SIG_REG_EXEC|SIG_REG_PROC);
		while ((pid = waitpid(p->pid, &status, flags)) == -1 && errno == EINTR);
		if (pid != p->pid && (flags & WNOHANG))
			status = 0;
		if (!(p->flags & PROC_FOREGROUND))
			sigcritical(0);
		else
		{
			if (p->sigint != SIG_IGN)
				signal(SIGINT, p->sigint);
			if (p->sigquit != SIG_IGN)
				signal(SIGQUIT, p->sigquit);
#if defined(SIGCHLD)
#if _lib_sigprocmask
			sigprocmask(SIG_SETMASK, &p->mask, NiL);
#else
#if _lib_sigsetmask
			sigsetmask(p->mask);
#else
			if (p->sigchld != SIG_DFL)
				signal(SIGCHLD, p->sigchld);
#endif
#endif
#endif
		}
		status = status == -1 ?
			 EXIT_QUIT :
			 WIFSIGNALED(status) ?
			 EXIT_TERM(WTERMSIG(status)) :
			 EXIT_CODE(WEXITSTATUS(status));
		procfree(p);
	}
	else
		status = errno == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC;
	return status;
}
