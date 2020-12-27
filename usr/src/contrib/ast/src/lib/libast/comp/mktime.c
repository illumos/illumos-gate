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
 * mktime implementation
 */

#define mktime		______mktime

#include <ast.h>
#include <tm.h>

#undef	mktime

#undef	_def_map_ast
#include <ast_map.h>

#undef	_lib_mktime	/* we can pass X/Open */

#if _lib_mktime

NoN(mktime)

#else

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern time_t
mktime(struct tm* ts)
{
	time_t	t;
	Tm_t	tm;

	tm.tm_sec = ts->tm_sec;
	tm.tm_min = ts->tm_min;
	tm.tm_hour = ts->tm_hour;
	tm.tm_mday = ts->tm_mday;
	tm.tm_mon = ts->tm_mon;
	tm.tm_year = ts->tm_year;
	tm.tm_wday = ts->tm_wday;
	tm.tm_yday = ts->tm_yday;
	tm.tm_isdst = ts->tm_isdst;
	t = tmtime(&tm, TM_LOCALZONE);
	ts->tm_sec = tm.tm_sec;
	ts->tm_min = tm.tm_min;
	ts->tm_hour = tm.tm_hour;
	ts->tm_mday = tm.tm_mday;
	ts->tm_mon = tm.tm_mon;
	ts->tm_year = tm.tm_year;
	ts->tm_wday = tm.tm_wday;
	ts->tm_yday = tm.tm_yday;
	ts->tm_isdst = tm.tm_isdst;
	return t;
}

#endif
