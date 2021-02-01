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
 * AT&T Bell Laboratories
 *
 * time conversion support
 */

#include <ast.h>
#include <tm.h>

/*
 * return the tm_data.zone[] time zone entry for type s
 *
 * if e is non-null then it will point to the first
 * unmatched char in s
 *
 * 0 returned for no match
 */

Tm_zone_t*
tmtype(register const char* s, char** e)
{
	register Tm_zone_t*	zp;
	register char*		t;

	tmset(tm_info.zone);
	zp = tm_info.local;
	do
	{
		if ((t = zp->type) && tmword(s, e, t, NiL, 0)) return(zp);
		if (zp == tm_info.local) zp = tm_data.zone;
		else zp++;
	} while (zp->standard);
	return(0);
}
