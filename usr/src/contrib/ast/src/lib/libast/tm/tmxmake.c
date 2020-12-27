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

#include "FEATURE/tmlib"

/*
 * return Tm_t for t
 * time zone and leap seconds accounted for in return value
 */

Tm_t*
tmxtm(register Tm_t* tm, Time_t t, Tm_zone_t* zone)
{
	register struct tm*	tp;
	register Tm_leap_t*	lp;
	Time_t			x;
	time_t			now;
	int			leapsec;
	int			y;
	uint32_t		n;
	int32_t			o;
#if TMX_FLOAT
	Time_t			z;
	uint32_t		i;
#endif

	tmset(tm_info.zone);
	leapsec = 0;
	if ((tm_info.flags & (TM_ADJUST|TM_LEAP)) == (TM_ADJUST|TM_LEAP) && (n = tmxsec(t)))
	{
		for (lp = &tm_data.leap[0]; n < lp->time; lp++);
		if (lp->total)
		{
			if (n == lp->time && (leapsec = (lp->total - (lp+1)->total)) < 0)
				leapsec = 0;
			t = tmxsns(n - lp->total, tmxnsec(t));
		}
	}
	x = tmxsec(t);
	if (!(tm->tm_zone = zone))
	{
		if (tm_info.flags & TM_UTC)
			tm->tm_zone = &tm_data.zone[2];
		else
			tm->tm_zone = tm_info.zone;
	}
	if ((o = 60 * tm->tm_zone->west) && x > o)
	{
		x -= o;
		o = 0;
	}
#if TMX_FLOAT
	i = x / (24 * 60 * 60);
	z = i;
	n = x - z * (24 * 60 * 60);
	tm->tm_sec = n % 60 + leapsec;
	n /= 60;
	tm->tm_min = n % 60;
	n /= 60;
	tm->tm_hour = n % 24;
#define x	i
#else
	tm->tm_sec = x % 60 + leapsec;
	x /= 60;
	tm->tm_min = x % 60;
	x /= 60;
	tm->tm_hour = x % 24;
	x /= 24;
#endif
	tm->tm_wday = (x + 4) % 7;
	tm->tm_year = (400 * (x + 25202)) / 146097 + 1;
	n = tm->tm_year - 1;
	x -= n * 365 + n / 4 - n / 100 + (n + (1900 - 1600)) / 400 - (1970 - 1901) * 365 - (1970 - 1901) / 4;
	tm->tm_mon = 0;
	tm->tm_mday = x + 1;
	tm->tm_nsec = tmxnsec(t);
	tmfix(tm);
	n += 1900;
	tm->tm_isdst = 0;
	if (tm->tm_zone->daylight)
	{
		if ((y = tmequiv(tm) - 1900) == tm->tm_year)
			now = tmxsec(t);
		else
		{
			Tm_t	te;

			te = *tm;
			te.tm_year = y;
			now = tmxsec(tmxtime(&te, tm->tm_zone->west));
		}
		if ((tp = tmlocaltime(&now)) && ((tm->tm_isdst = tp->tm_isdst) || o))
		{
			tm->tm_min -= o / 60 + (tm->tm_isdst ? tm->tm_zone->dst : 0);
			tmfix(tm);
		}
	}
	return tm;
}

/*
 * return Tm_t for t
 * time zone and leap seconds accounted for in return value
 */

Tm_t*
tmxmake(Time_t t)
{
	static Tm_t		ts;

	return tmxtm(&ts, t, NiL);
}
