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
 * time conversion support
 */

#include <ast.h>
#include <tmx.h>

#define DAYS(p)	(tm_data.days[(p)->tm_mon]+((p)->tm_mon==1&&LEAP(p)))
#define LEAP(p)	(tmisleapyear((p)->tm_year))

/*
 * correct out of bounds fields in tm
 *
 * tm_isdst is not changed -- call tmxtm() to get that
 *
 * tm is the return value
 */

Tm_t*
tmfix(register Tm_t* tm)
{
	register int	n;
	register int	w;
	Tm_t*		p;
	time_t		t;

	/*
	 * check for special case that adjusts tm_wday at the end
	 * this happens during
	 *	nl_langinfo() => strftime() => tmfmt()
	 */

	if (w = !tm->tm_sec && !tm->tm_min && !tm->tm_mday && !tm->tm_year && !tm->tm_yday && !tm->tm_isdst)
	{
		tm->tm_year = 99;
		tm->tm_mday = 2;
	}

	/*
	 * adjust from shortest to longest units
	 */

	if ((n = tm->tm_nsec) < 0)
	{
		tm->tm_sec -= (TMX_RESOLUTION - n) / TMX_RESOLUTION;
		tm->tm_nsec = TMX_RESOLUTION - (-n) % TMX_RESOLUTION;
	}
	else if (n >= TMX_RESOLUTION)
	{
		tm->tm_sec += n / TMX_RESOLUTION;
		tm->tm_nsec %= TMX_RESOLUTION;
	}
	if ((n = tm->tm_sec) < 0)
	{
		tm->tm_min -= (60 - n) / 60;
		tm->tm_sec = 60 - (-n) % 60;
	}
	else if (n > (59 + TM_MAXLEAP))
	{
		tm->tm_min += n / 60;
		tm->tm_sec %= 60;
	}
	if ((n = tm->tm_min) < 0)
	{
		tm->tm_hour -= (60 - n) / 60;
		n = tm->tm_min = 60 - (-n) % 60;
	}
	if (n > 59)
	{
		tm->tm_hour += n / 60;
		tm->tm_min %= 60;
	}
	if ((n = tm->tm_hour) < 0)
	{
		tm->tm_mday -= (23 - n) / 24;
		tm->tm_hour = 24 - (-n) % 24;
	}
	else if (n >= 24)
	{
		tm->tm_mday += n / 24;
		tm->tm_hour %= 24;
	}
	if (tm->tm_mon >= 12)
	{
		tm->tm_year += tm->tm_mon / 12;
		tm->tm_mon %= 12;
	}
	else if (tm->tm_mon < 0)
	{
		tm->tm_year--;
		if ((tm->tm_mon += 12) < 0)
		{
			tm->tm_year += tm->tm_mon / 12;
			tm->tm_mon = (-tm->tm_mon) % 12;
		}
	}
	while (tm->tm_mday < -365)
	{
		tm->tm_year--;
		tm->tm_mday += 365 + LEAP(tm);
	}
	while (tm->tm_mday > 365)
	{
		tm->tm_mday -= 365 + LEAP(tm);
		tm->tm_year++;
	}
	while (tm->tm_mday < 1)
	{
		if (--tm->tm_mon < 0)
		{
			tm->tm_mon = 11;
			tm->tm_year--;
		}
		tm->tm_mday += DAYS(tm);
	}
	while (tm->tm_mday > (n = DAYS(tm)))
	{
		tm->tm_mday -= n;
		if (++tm->tm_mon > 11)
		{
			tm->tm_mon = 0;
			tm->tm_year++;
		}
	}
	if (w)
	{
		w = tm->tm_wday;
		t = tmtime(tm, TM_LOCALZONE);
		p = tmmake(&t);
		if (w = (w - p->tm_wday))
		{
			if (w < 0)
				w += 7;
			tm->tm_wday += w;
			if ((tm->tm_mday += w) > DAYS(tm))
				tm->tm_mday -= 7;
		}
	}
	tm->tm_yday = tm_data.sum[tm->tm_mon] + (tm->tm_mon > 1 && LEAP(tm)) + tm->tm_mday - 1;
	n = tm->tm_year + 1900 - 1;
	tm->tm_wday = (n + n / 4 - n / 100 + n / 400 + tm->tm_yday + 1) % 7;

	/*
	 * tm_isdst is adjusted by tmtime()
	 */

	return tm;
}
