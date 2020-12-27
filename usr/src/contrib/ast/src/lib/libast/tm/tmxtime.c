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
 * convert Tm_t to Time_t
 *
 * if west==TM_LOCALZONE then the local timezone is used
 * otherwise west is the number of minutes west
 * of GMT with DST taken into account
 *
 * this routine works with a copy of Tm_t to avoid clashes
 * with other tm*() that may return static Tm_t*
 */

Time_t
tmxtime(register Tm_t* tm, int west)
{
	register Time_t		t;
	register Tm_leap_t*	lp;
	register int32_t	y;
	int			n;
	int			sec;
	time_t			now;
	struct tm*		tl;
	Tm_t*			to;
	Tm_t			ts;

	ts = *tm;
	to = tm;
	tm = &ts;
	tmset(tm_info.zone);
	tmfix(tm);
	y = tm->tm_year;
	if (y < 69 || y > (TMX_MAXYEAR - 1900))
		return TMX_NOTIME;
	y--;
	t = y * 365 + y / 4 - y / 100 + (y + (1900 - 1600)) / 400 - (1970 - 1901) * 365 - (1970 - 1901) / 4;
	if ((n = tm->tm_mon) > 11)
		n = 11;
	y += 1901;
	if (n > 1 && tmisleapyear(y))
		t++;
	t += tm_data.sum[n] + tm->tm_mday - 1;
	t *= 24;
	t += tm->tm_hour;
	t *= 60;
	t += tm->tm_min;
	t *= 60;
	t += sec = tm->tm_sec;
	if (west != TM_UTCZONE && !(tm_info.flags & TM_UTC))
	{
		/*
		 * time zone adjustments
		 */

		if (west == TM_LOCALZONE)
		{
			t += tm_info.zone->west * 60;
			if (!tm_info.zone->daylight)
				tm->tm_isdst = 0;
			else
			{
				y = tm->tm_year;
				tm->tm_year = tmequiv(tm) - 1900;
				now = tmxsec(tmxtime(tm, tm_info.zone->west));
				tm->tm_year = y;
				if (!(tl = tmlocaltime(&now)))
					return TMX_NOTIME;
				if (tm->tm_isdst = tl->tm_isdst)
					t += tm_info.zone->dst * 60;
			}
		}
		else
		{
			t += west * 60;
			if (!tm_info.zone->daylight)
				tm->tm_isdst = 0;
			else if (tm->tm_isdst < 0)
			{
				y = tm->tm_year;
				tm->tm_year = tmequiv(tm) - 1900;
				tm->tm_isdst = 0;
				now = tmxsec(tmxtime(tm, tm_info.zone->west));
				tm->tm_year = y;
				if (!(tl = tmlocaltime(&now)))
					return TMX_NOTIME;
				tm->tm_isdst = tl->tm_isdst;
			}
		}
	}
	else if (tm->tm_isdst)
		tm->tm_isdst = 0;
	*to = *tm;
	if (tm_info.flags & TM_LEAP)
	{
		/*
		 * leap second adjustments
		 */

		for (lp = &tm_data.leap[0]; t < lp->time - (lp+1)->total; lp++);
		t += lp->total;
		n = lp->total - (lp+1)->total;
		if (t <= (lp->time + n) && (n > 0 && sec > 59 || n < 0 && sec > (59 + n) && sec <= 59))
			t -= n;
	}
	return tmxsns(t, tm->tm_nsec);
}
