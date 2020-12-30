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
 * strftime implementation
 */

#define strftime	______strftime

#include <ast.h>
#include <tm.h>

#undef	strftime

#undef	_def_map_ast
#include <ast_map.h>

#undef	_lib_strftime	/* we can pass X/Open */

#if _lib_strftime

NoN(strftime)

#else

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern size_t
strftime(char* buf, size_t len, const char* format, const struct tm* tm)
{
	register char*	s;
	time_t		t;
	Tm_t		tl;

	memset(&tl, 0, sizeof(tl));

	/*
	 * nl_langinfo() may call strftime() with bogus tm except for
	 * one value -- what a way to go
	 */

	if (tm->tm_sec < 0 || tm->tm_sec > 60 ||
	    tm->tm_min < 0 || tm->tm_min > 59 ||
	    tm->tm_hour < 0 || tm->tm_hour > 23 ||
	    tm->tm_wday < 0 || tm->tm_wday > 6 ||
	    tm->tm_mday < 1 || tm->tm_mday > 31 ||
	    tm->tm_mon < 0 || tm->tm_mon > 11 ||
	    tm->tm_year < 0 || tm->tm_year > (2138 - 1900))
	{
		if (tm->tm_sec >= 0 && tm->tm_sec <= 60)
			tl.tm_sec = tm->tm_sec;
		if (tm->tm_min >= 0 && tm->tm_min <= 59)
			tl.tm_min = tm->tm_min;
		if (tm->tm_hour >= 0 && tm->tm_hour <= 23)
			tl.tm_hour = tm->tm_hour;
		if (tm->tm_wday >= 0 && tm->tm_wday <= 6)
			tl.tm_wday = tm->tm_wday;
		if (tm->tm_mday >= 0 && tm->tm_mday <= 31)
			tl.tm_mday = tm->tm_mday;
		if (tm->tm_mon >= 0 && tm->tm_mon <= 11)
			tl.tm_mon = tm->tm_mon;
		if (tm->tm_year >= 0 && tm->tm_year <= (2138 - 1900))
			tl.tm_year = tm->tm_year;
	}
	else
	{
		tl.tm_sec = tm->tm_sec;
		tl.tm_min = tm->tm_min;
		tl.tm_hour = tm->tm_hour;
		tl.tm_mday = tm->tm_mday;
		tl.tm_mon = tm->tm_mon;
		tl.tm_year = tm->tm_year;
		tl.tm_wday = tm->tm_wday;
		tl.tm_yday = tm->tm_yday;
		tl.tm_isdst = tm->tm_isdst;
	}
	t = tmtime(&tl, TM_LOCALZONE);
	if (!(s = tmfmt(buf, len, format, &t)))
		return 0;
	return s - buf;
}

#endif
