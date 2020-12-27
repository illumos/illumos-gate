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

#if _lib_sigflag

NoN(sigflag)

#else

#include <sig.h>

int
sigflag(int sig, int flags, int set)
{
#if _lib_sigaction
	struct sigaction	sa;

	if (sigaction(sig, NiL, &sa))
		return -1;
	if (set)
		sa.sa_flags |= flags;
	else
		sa.sa_flags &= ~flags;
	return sigaction(sig, &sa, NiL);
#else
	return -1;
#endif
}

#endif
