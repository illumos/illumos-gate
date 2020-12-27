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
 * Glenn Fowler
 * AT&T Research
 *
 * common process execution support with
 * proper sfio, signal and wait() syncronization
 *
 * _ contains the process path name and is
 * placed at the top of the environment
 */

#include "proclib.h"

#include <ls.h>
#include <ast_tty.h>

/*
 * not quite ready for _use_spawnveg 
 */

#if _use_spawnveg
#if _lib_fork
#undef	_use_spawnveg
#else
#if _WINIX
#define _lib_fork	1
#endif
#endif
#endif

#ifndef DEBUG_PROC
#define DEBUG_PROC	1
#endif

#if _lib_socketpair
#if _sys_socket
#include <sys/types.h>
#include <sys/socket.h>
#else
#undef	_lib_socketpair
#endif
#endif

Proc_t			proc_default = { -1 };

#if DEBUG_PROC

#include <namval.h>

#define PROC_ENV_OPTIONS	"PROC_OPTIONS"

#define PROC_OPT_ENVIRONMENT	(1<<0)
#define PROC_OPT_EXEC		(1<<1)
#define PROC_OPT_TRACE		(1<<2)
#define PROC_OPT_VERBOSE	(1<<3)

static const Namval_t		options[] =
{
	"debug",	PROC_OPT_VERBOSE,
	"environment",	PROC_OPT_ENVIRONMENT,
	"exec",		PROC_OPT_EXEC,
	"trace",	PROC_OPT_TRACE,
	"verbose",	PROC_OPT_VERBOSE,
	0,		0
};

/*
 * called by stropt() to set options
 */

static int
setopt(register void* a, register const void* p, register int n, const char* v)
{
	NoP(v);
	if (p)
	{
		if (n)
			*((int*)a) |= ((Namval_t*)p)->value;
		else
			*((int*)a) &= ~((Namval_t*)p)->value;
	}
	return 0;
}

#endif

#if _use_spawnveg

typedef struct Fd_s
{
	short		fd;
	short		flag;
} Fd_t;

typedef struct Mod_s
{
	struct Mod_s*	next;
	short		op;
	short		save;

	union
	{

	struct
	{
	Fd_t		parent;
	Fd_t		child;
	}		fd;

	Handler_t	handler;

	}		arg;

} Modify_t;

#endif

#ifdef SIGPIPE

/*
 * catch but ignore sig
 * avoids SIG_IGN being passed to children
 */

static void
ignoresig(int sig)
{
	signal(sig, ignoresig);
}

#endif

/*
 * do modification op and save previous state for restore()
 */

static int
modify(Proc_t* proc, int forked, int op, long arg1, long arg2)
{
#if _lib_fork
	if (forked)
	{
		int	i;
#ifndef TIOCSCTTY
		char*	s;
#endif

		switch (op)
		{
		case PROC_fd_dup:
		case PROC_fd_dup|PROC_FD_PARENT:
		case PROC_fd_dup|PROC_FD_CHILD:
		case PROC_fd_dup|PROC_FD_PARENT|PROC_FD_CHILD:
			if (arg1 != arg2)
			{
				if (arg2 != PROC_ARG_NULL)
				{
					close(arg2);
					if (fcntl(arg1, F_DUPFD, arg2) != arg2)
						return -1;
				}
				if (op & PROC_FD_CHILD)
					close(arg1);
			}
			break;
		case PROC_fd_ctty:
			setsid();
			for (i = 0; i <= 2; i++)
				if (arg1 != i)
					close(i);
			arg2 = -1;
#ifdef TIOCSCTTY
			if (ioctl(arg1, TIOCSCTTY, NiL) < 0)
				return -1;
#else
			if (!(s = ttyname(arg1)))
				return -1;
			if ((arg2 = open(s, O_RDWR)) < 0)
				return -1;
#endif
			for (i = 0; i <= 2; i++)
				if (arg1 != i && arg2 != i && fcntl(arg1, F_DUPFD, i) != i)
					return -1;
			if (arg1 > 2)
				close(arg1);
			if (arg2 > 2)
				close(arg2);
			break;
		case PROC_sig_dfl:
			signal(arg1, SIG_DFL);
			break;
		case PROC_sig_ign:
			signal(arg1, SIG_IGN);
			break;
		case PROC_sys_pgrp:
			if (arg1 < 0)
				setsid();
			else if (arg1 > 0)
			{
				if (arg1 == 1)
					arg1 = 0;
				if (setpgid(0, arg1) < 0 && arg1 && errno == EPERM)
					setpgid(0, 0);
			}
			break;
		case PROC_sys_umask:
			umask(arg1);
			break;
		default:
			return -1;
		}
	}
#if _use_spawnveg
	else
#endif
#else
	NoP(forked);
#endif
#if _use_spawnveg
	{
		register Modify_t*	m;

		if (!(m = newof(NiL, Modify_t, 1, 0)))
			return -1;
		m->next = proc->mods;
		proc->mods = m;
		switch (m->op = op)
		{
		case PROC_fd_dup:
		case PROC_fd_dup|PROC_FD_PARENT:
		case PROC_fd_dup|PROC_FD_CHILD:
		case PROC_fd_dup|PROC_FD_PARENT|PROC_FD_CHILD:
			m->arg.fd.parent.fd = (short)arg1;
			m->arg.fd.parent.flag = fcntl(arg1, F_GETFD, 0);
			if ((m->arg.fd.child.fd = (short)arg2) != arg1)
			{
				if (arg2 != PROC_ARG_NULL)
				{
					m->arg.fd.child.flag = fcntl(arg2, F_GETFD, 0);
					if ((m->save = fcntl(arg2, F_dupfd_cloexec, 3)) < 0)
					{
						m->op = 0;
						return -1;
					}
#if F_dupfd_cloexec == F_DUPFD
					fcntl(m->save, F_SETFD, FD_CLOEXEC);
#endif
					close(arg2);
					if (fcntl(arg1, F_DUPFD, arg2) != arg2)
						return -1;
					if (op & PROC_FD_CHILD)
						close(arg1);
				}
				else if (op & PROC_FD_CHILD)
				{
					if (m->arg.fd.parent.flag)
						break;
					fcntl(arg1, F_SETFD, FD_CLOEXEC);
				}
				else if (!m->arg.fd.parent.flag)
					break;
				else
					fcntl(arg1, F_SETFD, 0);
				return 0;
			}
			break;
		case PROC_sig_dfl:
			if ((m->arg.handler = signal(arg1, SIG_DFL)) == SIG_DFL)
				break;
			m->save = (short)arg1;
			return 0;
		case PROC_sig_ign:
			if ((m->arg.handler = signal(arg1, SIG_IGN)) == SIG_IGN)
				break;
			m->save = (short)arg1;
			return 0;
		case PROC_sys_pgrp:
			proc->pgrp = arg1;
			break;
		case PROC_sys_umask:
			if ((m->save = (short)umask(arg1)) == arg1)
				break;
			return 0;
		default:
			proc->mods = m->next;
			free(m);
			return -1;
		}
		proc->mods = m->next;
		free(m);
	}
#else
	NoP(proc);
#endif
	return 0;
}

#if _use_spawnveg

/*
 * restore modifications
 */

static void
restore(Proc_t* proc)
{
	register Modify_t*	m;
	register Modify_t*	p;
	int			oerrno;

	NoP(proc);
	oerrno = errno;
	m = proc->mods;
	proc->mods = 0;
	while (m)
	{
		switch (m->op)
		{
		case PROC_fd_dup:
		case PROC_fd_dup|PROC_FD_PARENT:
		case PROC_fd_dup|PROC_FD_CHILD:
		case PROC_fd_dup|PROC_FD_PARENT|PROC_FD_CHILD:
			if (m->op & PROC_FD_PARENT)
				close(m->arg.fd.parent.fd);
			if (m->arg.fd.child.fd != m->arg.fd.parent.fd && m->arg.fd.child.fd != PROC_ARG_NULL)
			{
				if (!(m->op & PROC_FD_PARENT))
				{
					if (m->op & PROC_FD_CHILD)
					{
						close(m->arg.fd.parent.fd);
						fcntl(m->arg.fd.child.fd, F_DUPFD, m->arg.fd.parent.fd);
					}
					fcntl(m->arg.fd.parent.fd, F_SETFD, m->arg.fd.parent.flag);
				}
				close(m->arg.fd.child.fd);
				fcntl(m->save, F_DUPFD, m->arg.fd.child.fd);
				close(m->save);
				if (m->arg.fd.child.flag)
					fcntl(m->arg.fd.child.fd, F_SETFD, FD_CLOEXEC);
			}
			else if ((m->op & (PROC_FD_PARENT|PROC_FD_CHILD)) == PROC_FD_CHILD)
				fcntl(m->arg.fd.parent.fd, F_SETFD, 0);
			break;
		case PROC_sig_dfl:
		case PROC_sig_ign:
			signal(m->save, m->arg.handler);
			break;
		case PROC_sys_umask:
			umask(m->save);
			break;
		}
		p = m;
		m = m->next;
		free(p);
	}
	errno = oerrno;
}

#else

#define restore(p)

#endif

/*
 * fork and exec or spawn proc(argv) and return a Proc_t handle
 *
 * pipe not used when PROC_READ|PROC_WRITE omitted
 * argv==0 duplicates current process if possible
 * cmd==0 names the current shell
 * cmd=="" does error cleanup
 * envv is the child environment
 * modv is the child modification vector of PROC_*() ops
 */

Proc_t*
procopen(const char* cmd, char** argv, char** envv, long* modv, int flags)
{
	register Proc_t*	proc = 0;
	register int		procfd;
	register char**		p;
	char**			v;
	int			i;
	int			forked = 0;
	int			signalled = 0;
	long			n;
	char			path[PATH_MAX];
	char			env[PATH_MAX + 2];
	int			pio[2];
#if _lib_fork
	int			pop[2];
#endif
#if !_pipe_rw && !_lib_socketpair
	int			poi[2];
#endif
#if defined(SIGCHLD) && ( _lib_sigprocmask || _lib_sigsetmask )
	Sig_mask_t		mask;
#endif
#if _use_spawnveg
	int			newenv = 0;
#endif
#if DEBUG_PROC
	int			debug = PROC_OPT_EXEC;
#endif

#if _lib_fork
	if (!argv && (flags & (PROC_ORPHAN|PROC_OVERLAY)))
#else
	if (!argv || (flags & PROC_ORPHAN))
#endif
	{
		errno = ENOEXEC;
		return 0;
	}
	pio[0] = pio[1] = -1;
#if _lib_fork
	pop[0] = pop[1] = -1;
#endif
#if !_pipe_rw && !_lib_socketpair
	poi[0] = poi[1] = -1;
#endif
	if (cmd && (!*cmd || !pathpath(cmd, NiL, PATH_REGULAR|PATH_EXECUTE, path, sizeof(path))))
		goto bad;
	switch (flags & (PROC_READ|PROC_WRITE))
	{
	case 0:
		procfd = -1;
		break;
	case PROC_READ:
		procfd = 1;
		break;
	case PROC_WRITE:
		procfd = 0;
		break;
	case PROC_READ|PROC_WRITE:
		procfd = 2;
		break;
	}
	if (proc_default.pid == -1)
		proc = &proc_default;
	else if (!(proc = newof(0, Proc_t, 1, 0)))
		goto bad;
	proc->pid = -1;
	proc->pgrp = 0;
	proc->rfd = -1;
	proc->wfd = -1;
	proc->flags = flags;
	sfsync(NiL);
	if (environ && envv != (char**)environ && (envv || (flags & PROC_PARANOID) || argv && (environ[0][0] != '_' || environ[0][1] != '=')))
	{
		if (!setenviron(NiL))
			goto bad;
#if _use_spawnveg
		if (!(flags & PROC_ORPHAN))
			newenv = 1;
#endif
	}
	if (procfd >= 0)
	{
#if _pipe_rw
		if (pipe(pio))
			goto bad;
#else
		if (procfd > 1)
		{
#if _lib_socketpair
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, pio))
				goto bad;
#else
			if (pipe(pio) || pipe(poi))
				goto bad;
#endif
		}
		else if (pipe(pio))
			goto bad;
#endif
	}
	if (flags & PROC_OVERLAY)
	{
		proc->pid = 0;
		forked = 1;
	}
#if _use_spawnveg
	else if (argv && !(flags & PROC_ORPHAN))
		proc->pid = 0;
#endif
#if _lib_fork
	else
	{
		if (!(flags & PROC_FOREGROUND))
			sigcritical(SIG_REG_EXEC|SIG_REG_PROC);
		else
		{
			signalled = 1;
			proc->sigint = signal(SIGINT, SIG_IGN);
			proc->sigquit = signal(SIGQUIT, SIG_IGN);
#if defined(SIGCHLD)
#if _lib_sigprocmask
			sigemptyset(&mask);
			sigaddset(&mask, SIGCHLD);
			sigprocmask(SIG_BLOCK, &mask, &proc->mask);
#else
#if _lib_sigsetmask
			mask = sigmask(SIGCHLD);
			proc->mask = sigblock(mask);
#else
			proc->sigchld = signal(SIGCHLD, SIG_DFL);
#endif
#endif
#endif
		}
		if ((flags & PROC_ORPHAN) && pipe(pop))
			goto bad;
		proc->pid = fork();
		if (!(flags & PROC_FOREGROUND))
			sigcritical(0);
		else if (!proc->pid)
		{
			if (proc->sigint != SIG_IGN)
			{
				proc->sigint = SIG_DFL;
				signal(SIGINT, proc->sigint);
			}
			if (proc->sigquit != SIG_IGN)
			{
				proc->sigquit = SIG_DFL;
				signal(SIGQUIT, proc->sigquit);
			}
#if defined(SIGCHLD)
#if _lib_sigprocmask
			sigprocmask(SIG_SETMASK, &proc->mask, NiL);
#else
#if _lib_sigsetmask
			sigsetmask(proc->mask);
#else
			if (proc->sigchld != SIG_IGN)
				signal(SIGCHLD, SIG_DFL);
#endif
#endif
#endif
		}
		else if (proc->pid == -1)
			goto bad;
		forked = 1;
	}
#endif
	if (!proc->pid)
	{
#if _use_spawnveg
		char**		oenviron = 0;
		char*		oenviron0 = 0;

		v = 0;
#endif
#if _lib_fork
		if (flags & PROC_ORPHAN)
		{
			if (!(proc->pid = fork()))
			{
				close(pop[0]);
				close(pop[1]);
			}
			else
			{
				if (proc->pid > 0)
					write(pop[1], &proc->pid, sizeof(proc->pid));
				_exit(EXIT_NOEXEC);
			}
		}
#endif
#if DEBUG_PROC
		stropt(getenv(PROC_ENV_OPTIONS), options, sizeof(*options), setopt, &debug);
#if _lib_fork
		if (debug & PROC_OPT_TRACE)
		{
			if (!fork())
			{
				sfsprintf(path, sizeof(path), "%d", getppid());
				execlp("trace", "trace", "-p", path, NiL);
				_exit(EXIT_NOTFOUND);
			}
			sleep(2);
		}
#endif
#endif
		if (flags & PROC_DAEMON)
		{
#ifdef SIGHUP
			modify(proc, forked, PROC_sig_ign, SIGHUP, 0);
#endif
			modify(proc, forked, PROC_sig_dfl, SIGTERM, 0);
#ifdef SIGTSTP
			modify(proc, forked, PROC_sig_ign, SIGTSTP, 0);
#endif
#ifdef SIGTTIN
			modify(proc, forked, PROC_sig_ign, SIGTTIN, 0);
#endif
#ifdef SIGTTOU
			modify(proc, forked, PROC_sig_ign, SIGTTOU, 0);
#endif
		}
		if (flags & (PROC_BACKGROUND|PROC_DAEMON))
		{
			modify(proc, forked, PROC_sig_ign, SIGINT, 0);
#ifdef SIGQUIT
			modify(proc, forked, PROC_sig_ign, SIGQUIT, 0);
#endif
		}
		if (flags & (PROC_DAEMON|PROC_SESSION))
			modify(proc, forked, PROC_sys_pgrp, -1, 0);
		if (forked || (flags & PROC_OVERLAY))
		{
			if ((flags & PROC_PRIVELEGED) && !geteuid())
			{
				setuid(geteuid());
				setgid(getegid());
			}
			if (flags & (PROC_PARANOID|PROC_GID))
				setgid(getgid());
			if (flags & (PROC_PARANOID|PROC_UID))
				setuid(getuid());
		}
		if (procfd > 1)
		{
			if (modify(proc, forked, PROC_fd_dup|PROC_FD_CHILD, pio[0], PROC_ARG_NULL))
				goto cleanup;
			if (modify(proc, forked, PROC_fd_dup|PROC_FD_CHILD, pio[1], 1))
				goto cleanup;
#if _pipe_rw || _lib_socketpair
			if (modify(proc, forked, PROC_fd_dup, 1, 0))
				goto cleanup;
#else
			if (modify(proc, forked, PROC_fd_dup|PROC_FD_CHILD, poi[0], 0))
				goto cleanup;
			if (poi[1] != 0 && modify(proc, forked, PROC_fd_dup|PROC_FD_CHILD, poi[1], PROC_ARG_NULL))
				goto cleanup;
#endif
		}
		else if (procfd >= 0)
		{
			if (modify(proc, forked, PROC_fd_dup|PROC_FD_CHILD, pio[!!procfd], !!procfd))
				goto cleanup;
			if (pio[!procfd] != !!procfd && modify(proc, forked, PROC_fd_dup|PROC_FD_CHILD, pio[!procfd], PROC_ARG_NULL))
				goto cleanup;
		}
		if (modv)
			for (i = 0; n = modv[i]; i++)
				switch (PROC_OP(n))
				{
				case PROC_fd_dup:
				case PROC_fd_dup|PROC_FD_PARENT:
				case PROC_fd_dup|PROC_FD_CHILD:
				case PROC_fd_dup|PROC_FD_PARENT|PROC_FD_CHILD:
					if (modify(proc, forked, PROC_OP(n), PROC_ARG(n, 1), PROC_ARG(n, 2)))
						goto cleanup;
					break;
				default:
					if (modify(proc, forked, PROC_OP(n), PROC_ARG(n, 1), 0))
						goto cleanup;
					break;
				}
#if _lib_fork
		if (forked && (flags & PROC_ENVCLEAR))
			environ = 0;
#if _use_spawnveg
		else
#endif
#endif
#if _use_spawnveg
		if (newenv)
		{
			p = environ;
			while (*p++);
			if (!(oenviron = (char**)memdup(environ, (p - environ) * sizeof(char*))))
				goto cleanup;
		}
#endif
		if (argv && envv != (char**)environ)
		{
#if _use_spawnveg
			if (!newenv && environ[0][0] == '_' && environ[0][1] == '=')
				oenviron0 = environ[0];
#endif
			env[0] = '_';
			env[1] = '=';
			env[2] = 0;
			if (!setenviron(env))
				goto cleanup;
		}
		if ((flags & PROC_PARANOID) && setenv("PATH", astconf("PATH", NiL, NiL), 1))
			goto cleanup;
		if ((p = envv) && p != (char**)environ)
			while (*p)
				if (!setenviron(*p++))
					goto cleanup;
		p = argv;
#if _lib_fork
		if (forked && !p)
			return proc;
#endif
#if DEBUG_PROC
		if (!(debug & PROC_OPT_EXEC) || (debug & PROC_OPT_VERBOSE))
		{
			if ((debug & PROC_OPT_ENVIRONMENT) && (p = environ))
				while (*p)
					sfprintf(sfstderr, "%s\n", *p++);
			sfprintf(sfstderr, "+ %s", cmd ? path : "sh");
			if ((p = argv) && *p)
				while (*++p)
					sfprintf(sfstderr, " %s", *p);
			sfprintf(sfstderr, "\n");
sfsync(sfstderr);
			if (!(debug & PROC_OPT_EXEC))
				_exit(0);
			p = argv;
		}
#endif
		if (cmd)
		{
			strcpy(env + 2, path);
			if (forked || (flags & PROC_OVERLAY))
				execve(path, p, environ);
#if _use_spawnveg
			else if ((proc->pid = spawnveg(path, p, environ, proc->pgrp)) != -1)
				goto cleanup;
#endif
			if (errno != ENOEXEC)
				goto cleanup;

			/*
			 * try cmd as a shell script
			 */

			if (!(flags & PROC_ARGMOD))
			{
				while (*p++);
				if (!(v = newof(0, char*, p - argv + 2, 0)))
					goto cleanup;
				p = v + 2;
				if (*argv)
					argv++;
				while (*p++ = *argv++);
				p = v + 1;
			}
			*p = path;
			*--p = "sh";
		}
		strcpy(env + 2, (flags & PROC_PARANOID) ? astconf("SH", NiL, NiL) : pathshell());
		if (forked || (flags & PROC_OVERLAY))
			execve(env + 2, p, environ);
#if _use_spawnveg
		else
			proc->pid = spawnveg(env + 2, p, environ, proc->pgrp);
#endif
	cleanup:
		if (forked)
		{
			if (!(flags & PROC_OVERLAY))
				_exit(errno == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC);
			goto bad;
		}
#if _use_spawnveg
		if (v)
			free(v);
		if (p = oenviron)
		{
			environ = 0;
			while (*p)
				if (!setenviron(*p++))
					goto bad;
			free(oenviron);
		}
		else if (oenviron0)
			environ[0] = oenviron0;
		restore(proc);
		if (flags & PROC_OVERLAY)
			exit(0);
#endif
	}
	if (proc->pid != -1)
	{
		if (!forked)
		{
			if (flags & PROC_FOREGROUND)
			{
				signalled = 1;
				proc->sigint = signal(SIGINT, SIG_IGN);
				proc->sigquit = signal(SIGQUIT, SIG_IGN);
#if defined(SIGCHLD)
#if _lib_sigprocmask
				sigemptyset(&mask);
				sigaddset(&mask, SIGCHLD);
				sigprocmask(SIG_BLOCK, &mask, &proc->mask);
#else
#if _lib_sigsetmask
				mask = sigmask(SIGCHLD);
				proc->mask = sigblock(mask);
#else
				proc->sigchld = signal(SIGCHLD, SIG_DFL);
#endif
#endif
#endif
			}
		}
		else if (modv)
			for (i = 0; n = modv[i]; i++)
				switch (PROC_OP(n))
				{
				case PROC_fd_dup|PROC_FD_PARENT:
				case PROC_fd_dup|PROC_FD_PARENT|PROC_FD_CHILD:
					close(PROC_ARG(n, 1));
					break;
				case PROC_sys_pgrp:
					if (proc->pgrp < 0)
						proc->pgrp = proc->pid;
					else if (proc->pgrp > 0)
					{
						if (proc->pgrp == 1)
							proc->pgrp = proc->pid;
						if (setpgid(proc->pid, proc->pgrp) < 0 && proc->pid != proc->pgrp && errno == EPERM)
							setpgid(proc->pid, proc->pid);
					}
					break;
				}
		if (procfd >= 0)
		{
#ifdef SIGPIPE
			if ((flags & (PROC_WRITE|PROC_IGNORE)) == (PROC_WRITE|PROC_IGNORE))
			{
				Handler_t	handler;

				if ((handler = signal(SIGPIPE, ignoresig)) != SIG_DFL && handler != ignoresig)
					signal(SIGPIPE, handler);
			}
#endif
			switch (procfd)
			{
			case 0:
				proc->wfd = pio[1];
				close(pio[0]);
				break;
			default:
#if _pipe_rw || _lib_socketpair
				proc->wfd = pio[0];
#else
				proc->wfd = poi[1];
				close(poi[0]);
#endif
				/*FALLTHROUGH*/
			case 1:
				proc->rfd = pio[0];
				close(pio[1]);
				break;
			}
			if (proc->rfd > 2)
				fcntl(proc->rfd, F_SETFD, FD_CLOEXEC);
			if (proc->wfd > 2)
				fcntl(proc->wfd, F_SETFD, FD_CLOEXEC);
		}
		if (!proc->pid)
			proc->pid = getpid();
		else if (flags & PROC_ORPHAN)
		{
			while (waitpid(proc->pid, &i, 0) == -1 && errno == EINTR);
			if (read(pop[0], &proc->pid, sizeof(proc->pid)) != sizeof(proc->pid))
				goto bad;
			close(pop[0]);
		}
		return proc;
	}
 bad:
	if (signalled)
	{
		if (proc->sigint != SIG_IGN)
			signal(SIGINT, proc->sigint);
		if (proc->sigquit != SIG_IGN)
			signal(SIGQUIT, proc->sigquit);
#if defined(SIGCHLD)
#if _lib_sigprocmask
		sigprocmask(SIG_SETMASK, &proc->mask, NiL);
#else
#if _lib_sigsetmask
		sigsetmask(proc->mask);
#else
		if (proc->sigchld != SIG_DFL)
			signal(SIGCHLD, proc->sigchld);
#endif
#endif
#endif
	}
	if ((flags & PROC_CLEANUP) && modv)
		for (i = 0; n = modv[i]; i++)
			switch (PROC_OP(n))
			{
			case PROC_fd_dup:
			case PROC_fd_dup|PROC_FD_PARENT:
			case PROC_fd_dup|PROC_FD_CHILD:
			case PROC_fd_dup|PROC_FD_PARENT|PROC_FD_CHILD:
				if (PROC_ARG(n, 2) != PROC_ARG_NULL)
					close(PROC_ARG(n, 1));
				break;
			}
	if (pio[0] >= 0)
		close(pio[0]);
	if (pio[1] >= 0)
		close(pio[1]);
	if (pop[0] >= 0)
		close(pop[0]);
	if (pop[1] >= 0)
		close(pop[1]);
#if !_pipe_rw && !_lib_socketpair
	if (poi[0] >= 0)
		close(poi[0]);
	if (poi[1] >= 0)
		close(poi[1]);
#endif
	procfree(proc);
	return 0;
}
