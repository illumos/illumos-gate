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
#include <tm.h>

/*
 * return timezone pointer given name and type
 *
 * if type==0 then all time zone types match
 * otherwise type must be one of tm_info.zone[].type
 *
 * if end is non-null then it will point to the next
 * unmatched char in name
 *
 * if dst!=0 then it will point to 0 for standard zones
 * and the offset for daylight zones
 *
 * 0 returned for no match
 */

Tm_zone_t*
tmzone(register const char* name, char** end, const char* type, int* dst)
{
	register Tm_zone_t*	zp;
	register char*		prev;
	char*			e;

	static Tm_zone_t	fixed;
	static char		off[16];

	tmset(tm_info.zone);
	if ((*name == '+' || *name == '-') && (fixed.west = tmgoff(name, &e, TM_LOCALZONE)) != TM_LOCALZONE && !*e)
	{
		strlcpy(fixed.standard = fixed.daylight = off, name, sizeof(off));
		if (end)
			*end = e;
		if (dst)
			*dst = 0;
		return &fixed;
	}
	zp = tm_info.local;
	prev = 0;
	do
	{
		if (zp->type)
			prev = zp->type;
		if (!type || type == prev || !prev)
		{
			if (tmword(name, end, zp->standard, NiL, 0))
			{
				if (dst)
					*dst = 0;
				return zp;
			}
			if (zp->dst && zp->daylight && tmword(name, end, zp->daylight, NiL, 0))
			{
				if (dst)
					*dst = zp->dst;
				return zp;
			}
		}
		if (zp == tm_info.local)
			zp = tm_data.zone;
		else
			zp++;
	} while (zp->standard);
	return 0;
}
