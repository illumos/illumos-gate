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

#include <tv.h>

/*
 * compare a with b
 * strcmp semantics
 */

int
tvcmp(register const Tv_t* a, register const Tv_t* b)
{
	if (a->tv_sec < b->tv_sec)
		return 1;
	if (a->tv_sec > b->tv_sec)
		return -1;
	if (a->tv_nsec != TV_NSEC_IGNORE && b->tv_nsec != TV_NSEC_IGNORE)
	{
		if (a->tv_nsec < b->tv_nsec)
			return 1;
		if (a->tv_nsec > b->tv_nsec)
			return -1;
	}
	return 0;
}
