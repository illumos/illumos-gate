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
