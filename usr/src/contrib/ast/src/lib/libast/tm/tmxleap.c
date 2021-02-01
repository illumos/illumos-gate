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
 * Glenn Fowler
 * AT&T Research
 *
 * Time_t conversion support
 */

#include <tmx.h>

/*
 * return t with leap seconds adjusted
 * for direct localtime() access
 */

Time_t
tmxleap(Time_t t)
{
	register Tm_leap_t*	lp;
	uint32_t		sec;

	tmset(tm_info.zone);
	if (tm_info.flags & TM_ADJUST)
	{
		sec = tmxsec(t);
		for (lp = &tm_data.leap[0]; sec < (lp->time - lp->total); lp++);
		t = tmxsns(sec + lp->total, tmxnsec(t));
	}
	return t;
}
