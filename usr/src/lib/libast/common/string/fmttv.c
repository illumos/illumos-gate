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
