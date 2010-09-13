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
 * touch file access and modify times of file
 * if flags&PATH_TOUCH_CREATE then file will be created if it doesn't exist
 * if flags&PATH_TOUCH_VERBATIM then times are taken verbatim
 * times have one second granularity
 *
 *	(time_t)(-1)	retain old time
 *	0		use current time
 *
 * the old interface flag values were:
 *	 1	PATH_TOUCH_CREATE
 *	-1	PATH_TOUCH_CREATE|PATH_TOUCH_VERBATIM
 *		PATH_TOUCH_VERBATIM -- not supported
 */

#include <ast.h>
#include <times.h>
#include <tv.h>

int
touch(const char* path, time_t at, time_t mt, int flags)
{
	Tv_t	av;
	Tv_t	mv;
	Tv_t*	ap;
	Tv_t*	mp;

	if (at == (time_t)(-1) && !(flags & PATH_TOUCH_VERBATIM))
		ap = TV_TOUCH_RETAIN;
	else if (!at && !(flags & PATH_TOUCH_VERBATIM))
		ap = 0;
	else
	{
		av.tv_sec = at;
		av.tv_nsec = 0;
		ap = &av;
	}
	if (mt == (time_t)(-1) && !(flags & PATH_TOUCH_VERBATIM))
		mp = TV_TOUCH_RETAIN;
	else if (!mt && !(flags & PATH_TOUCH_VERBATIM))
		mp = 0;
	else
	{
		mv.tv_sec = mt;
		mv.tv_nsec = 0;
		mp = &mv;
	}
	return tvtouch(path, ap, mp, NiL, flags & 1);
}
