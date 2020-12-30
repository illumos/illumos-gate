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
#include <errno.h>

#include "FEATURE/tvlib"

int
tvsettime(const Tv_t* tv)
{

#if _lib_clock_settime && defined(CLOCK_REALTIME)

	struct timespec			s;

	s.tv_sec = tv->tv_sec;
	s.tv_nsec = tv->tv_nsec;
	return clock_settime(CLOCK_REALTIME, &s);

#else

#if defined(tmsettimeofday)

	struct timeval			v;

	v.tv_sec = tv->tv_sec;
	v.tv_usec = tv->tv_nsec / 1000;
	return tmsettimeofday(&v);

#else

#if _lib_stime

	static time_t			s;

	s = tv->tv_sec + (tv->tv_nsec != 0);
	return stime(s);

#else

	errno = EPERM;
	return -1;

#endif

#endif

#endif

}
