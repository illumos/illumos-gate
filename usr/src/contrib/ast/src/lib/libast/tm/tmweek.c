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

static unsigned char	offset[7][3] =
{
	{ 7, 6, 6 },
	{ 1, 7, 7 },
	{ 2, 1, 8 },
	{ 3, 2, 9 },
	{ 4, 3, 10},
	{ 5, 4, 4 },
	{ 6, 5, 5 },
};

/*
 * type is week type
 *	0 sunday first day of week
 *	1 monday first day of week
 *	2 monday first day of iso week
 * if week<0 then return week for tm
 * if day<0 then set tm to first day of week
 * otherwise set tm to day in week
 * and return tm->tm_yday
 */

int
tmweek(Tm_t* tm, int type, int week, int day)
{
	int	d;

	if (week < 0)
	{
		if ((day = tm->tm_wday - tm->tm_yday % 7) < 0)
			day += 7;
		week = (tm->tm_yday + offset[day][type]) / 7;
		if (type == 2)
		{
			if (!week)
				week = (day > 0 && day < 6 || tmisleapyear(tm->tm_year - 1)) ? 53 : 52;
			else if (week == 53 && (tm->tm_wday + (31 - tm->tm_mday)) < 4)
				week = 1;
		}
		return week;
	}
	if (day < 0)
		day = type != 0;
	tm->tm_mon = 0;
	tm->tm_mday = 1;
	tmfix(tm);
	d = tm->tm_wday;
	tm->tm_mday = week * 7 - offset[d][type] + ((day || type != 2) ? day : 7);
	tmfix(tm);
	if (d = tm->tm_wday - day)
	{
		tm->tm_mday -= d;
		tmfix(tm);
	}
	return tm->tm_yday;
}
