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
 * -last fcntl
 */

#include <ast.h>

#ifndef fcntl

NoN(fcntl)

#else

#include <ls.h>
#include <ast_tty.h>
#include <error.h>

#if F_SETFD >= _ast_F_LOCAL
#if _sys_filio
#include <sys/filio.h>
#endif
#endif

#if _lib_fcntl
#undef	fcntl
extern int	fcntl(int, int, ...);
#endif

int
_ast_fcntl(int fd, int op, ...)
{
	int		n;
	int		save_errno;
	struct stat	st;
	va_list		ap;

	save_errno = errno;
	va_start(ap, op);
	if (op >= _ast_F_LOCAL) switch (op)
	{
#if F_DUPFD >= _ast_F_LOCAL
	case F_DUPFD:
		n = va_arg(ap, int);
		op = dup2(fd, n);
		break;
#endif
#if F_GETFL >= _ast_F_LOCAL
	case F_GETFL:
		op = fstat(fd, &st);
		break;
#endif
#if F_SETFD >= _ast_F_LOCAL && defined(FIOCLEX)
	case F_SETFD:
		n = va_arg(ap, int);
		op = ioctl(fd, n == FD_CLOEXEC ? FIOCLEX : FIONCLEX, 0);
		break;
#endif
	default:
		errno = EINVAL;
		op = -1;
		break;
	}
	else
#if _lib_fcntl
	op = fcntl(fd, op, va_arg(ap, int));
#else
	{
		errno = EINVAL;
		op = -1;
	}
#endif
	va_end(ap);
	return(op);
}

#endif
