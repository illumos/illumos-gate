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

#include "asohdr.h"

#if defined(_UWIN) && defined(_BLD_ast)

NoN(asorelax)

#else

#if _PACKAGE_ast
#include <tv.h>
#else
#include <time.h>
#endif

int
asorelax(long nsec)
{
#if _PACKAGE_ast
	Tv_t		tv;

	tv.tv_sec = 0;
	tv.tv_nsec = nsec;
	return tvsleep(&tv, 0);
#else
	struct timespec	ts;

	ts.tv_sec = 0;
	ts.tv_nsec = nsec;
	return nanosleep(&ts, 0);
#endif
}

#endif
