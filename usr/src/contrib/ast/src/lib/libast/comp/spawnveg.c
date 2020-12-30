/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * spawnveg -- spawnve with process group or session control
 *
 *	pgid	<0	setsid()	[session group leader]
 *		 0	nothing		[retain session and process group]
 *		 1	setpgid(0,0)	[process group leader]
 *		>1	setpgid(0,pgid)	[join process group]
 */

#include <ast.h>

#if _lib_spawnveg

NoN(spawnveg)

#else

#if _lib_posix_spawn > 1	/* reports underlying exec() errors */

#include <spawn.h>
#include <error.h>
#include <wait.h>

pid_t
spawnveg(const char* path, char* const argv[], char* const envv[], pid_t pgid)
{
	int			err;
	pid_t			pid;
	posix_spawnattr_t	attr;

	if (err = posix_spawnattr_init(&attr))
		goto nope;
	if (pgid)
	{
		if (pgid <= 1)
			pgid = 0;
		if (err = posix_spawnattr_setpgroup(&attr, pgid))
			goto bad;
		if (err = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP))
			goto bad;
	}
	if (err = posix_spawn(&pid, path, NiL, &attr, argv, envv ? envv : environ))
		goto bad;
	posix_spawnattr_destroy(&attr);
#if _lib_posix_spawn < 2
	if (waitpid(pid, &err, WNOHANG|WNOWAIT) == pid && EXIT_STATUS(err) == 127)
	{
		while (waitpid(pid, NiL, 0) == -1 && errno == EINTR);
		if (!access(path, X_OK))
			errno = ENOEXEC;
		pid = -1;
	}
#endif
	return pid;
 bad:
	posix_spawnattr_destroy(&attr);
 nope:
	errno = err;
	return -1;
}

#else

#if _lib_spawn_mode

#include <process.h>

#ifndef P_NOWAIT
#define P_NOWAIT	_P_NOWAIT
#endif
#ifndef P_DETACH
#define P_DETACH	_P_DETACH
#endif

pid_t
spawnveg(const char* path, char* const argv[], char* const envv[], pid_t pgid)
{
	return spawnve(pgid ? P_DETACH : P_NOWAIT, path, argv, envv ? envv : environ);
}

#else

#if _lib_spawn && _hdr_spawn && _mem_pgroup_inheritance

#include <spawn.h>

/*
 * open-edition/mvs/zos fork+exec+(setpgid)
 */

pid_t
spawnveg(const char* path, char* const argv[], char* const envv[], pid_t pgid)
{
	struct inheritance	inherit;

	inherit.flags = 0;
	if (pgid)
	{
		inherit.flags |= SPAWN_SETGROUP;
		inherit.pgroup = (pgid > 1) ? pgid : SPAWN_NEWPGROUP;
	}
	return spawn(path, 0, (int*)0, &inherit, (const char**)argv, (const char**)envv);
}

#else

#include <error.h>
#include <wait.h>
#include <sig.h>
#include <ast_tty.h>
#include <ast_vfork.h>

#ifndef ENOSYS
#define ENOSYS	EINVAL
#endif

#if _lib_spawnve && _hdr_process
#include <process.h>
#if defined(P_NOWAIT) || defined(_P_NOWAIT)
#undef	_lib_spawnve
#endif
#endif

#if !_lib_vfork
#undef	_real_vfork
#endif

/*
 * fork+exec+(setsid|setpgid)
 */

pid_t
spawnveg(const char* path, char* const argv[], char* const envv[], pid_t pgid)
{
#if _lib_fork || _lib_vfork
	int			n;
	int			m;
	pid_t			pid;
	pid_t			rid;
#if _real_vfork
	volatile int		exec_errno;
	volatile int* volatile	exec_errno_ptr;
#else
	int			err[2];
#endif
#endif

#if 0
	if (access(path, X_OK))
		return -1;
#endif
	if (!envv)
		envv = environ;
#if _lib_spawnve
#if _lib_fork || _lib_vfork
	if (!pgid)
#endif
		return spawnve(path, argv, envv);
#endif
#if _lib_fork || _lib_vfork
	n = errno;
#if _real_vfork
	exec_errno = 0;
	exec_errno_ptr = &exec_errno;
#else
	if (pipe(err) < 0)
		err[0] = -1;
	else
	{
		fcntl(err[0], F_SETFD, FD_CLOEXEC);
		fcntl(err[1], F_SETFD, FD_CLOEXEC);
	}
#endif
	sigcritical(SIG_REG_EXEC|SIG_REG_PROC);
#if _lib_vfork
	pid = vfork();
#else
	pid = fork();
#endif
	if (pid == -1)
		n = errno;
	else if (!pid)
	{
		sigcritical(0);
		if (pgid == -1)
			setsid();
		else if (pgid)
		{
			m = 0;
			if (pgid == 1 || pgid == -2 && (m = 1))
				pgid = getpid();
			if (setpgid(0, pgid) < 0 && errno == EPERM)
				setpgid(pgid, 0);
#if _lib_tcgetpgrp
			if (m)
				tcsetpgrp(2, pgid);
#else
#ifdef TIOCSPGRP
			if (m)
				ioctl(2, TIOCSPGRP, &pgid);
#endif
#endif
		}
		execve(path, argv, envv);
#if _real_vfork
		*exec_errno_ptr = errno;
#else
		if (err[0] != -1)
		{
			m = errno;
			write(err[1], &m, sizeof(m));
		}
#endif
		_exit(errno == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC);
	}
	rid = pid;
#if _real_vfork
	if (pid != -1 && (m = *exec_errno_ptr))
	{
		while (waitpid(pid, NiL, 0) == -1 && errno == EINTR);
		rid = pid = -1;
		n = m;
	}
#else
	if (err[0] != -1)
	{
		close(err[1]);
		if (pid != -1)
		{
			m = 0;
			while (read(err[0], &m, sizeof(m)) == -1)
				if (errno != EINTR)
				{
					m = errno;
					break;
				}
			if (m)
			{
				while (waitpid(pid, &n, 0) && errno == EINTR);
				rid = pid = -1;
				n = m;
			}
		}
		close(err[0]);
	}
#endif
	sigcritical(0);
	if (pid != -1 && pgid > 0)
	{
		/*
		 * parent and child are in a race here
		 */

		if (pgid == 1)
			pgid = pid;
		if (setpgid(pid, pgid) < 0 && pid != pgid && errno == EPERM)
			setpgid(pid, pid);
	}
	errno = n;
	return rid;
#else
	errno = ENOSYS;
	return -1;
#endif
}

#endif

#endif

#endif

#endif
