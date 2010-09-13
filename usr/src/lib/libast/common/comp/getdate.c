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
 * getdate implementation
 */

#define getdate	______getdate

#include <ast.h>
#include <tm.h>

#undef	getdate

#undef	_def_map_ast
#include <ast_map.h>

#undef	_lib_getdate	/* we can pass X/Open */

#if _lib_getdate

NoN(getdate)

#else

#ifndef getdate_err
__DEFINE__(int, getdate_err, 0);
#endif

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern struct tm*
getdate(const char* s)
{
	char*			e;
	char*			f;
	time_t			t;
	Tm_t*			tm;

	static struct tm	ts;

	t = tmscan(s, &e, NiL, &f, NiL, TM_PEDANTIC);
	if (*e || *f)
	{
		/* of course we all know what 7 means */
		getdate_err = 7;
		return 0;
	}
	tm = tmmake(&t);
	ts.tm_sec = tm->tm_sec;
	ts.tm_min = tm->tm_min;
	ts.tm_hour = tm->tm_hour;
	ts.tm_mday = tm->tm_mday;
	ts.tm_mon = tm->tm_mon;
	ts.tm_year = tm->tm_year;
	ts.tm_wday = tm->tm_wday;
	ts.tm_yday = tm->tm_yday;
	ts.tm_isdst = tm->tm_isdst;
	return &ts;
}

#endif
