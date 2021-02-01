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

#include <tv.h>
#include <tm.h>

/*
 * Tv_t fmttime()
 */

char*
fmttv(const char* fmt, Tv_t* tv)
{
	char*	s;
	char*	t;
	int	n;

	s = fmttime(fmt, (time_t)tv->tv_sec);
	if (!tv->tv_nsec || tv->tv_nsec == TV_NSEC_IGNORE)
		return s;
	t = fmtbuf(n = strlen(s) + 11);
	sfsprintf(t, n, "%s.%09lu", s, (unsigned long)tv->tv_nsec);
	return t;
}
