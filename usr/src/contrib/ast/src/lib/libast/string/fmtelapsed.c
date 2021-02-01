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
 * return pointer to formatted elapsed time for u 1/n secs
 * compatible with strelapsed()
 * return value length is at most 7
 */

#include <ast.h>

char*
fmtelapsed(register unsigned long u, register int n)
{
	register unsigned long	t;
	char*			buf;
	int			z;

	if (u == 0L)
		return "0";
	if (u == ~0L)
		return "%";
	buf = fmtbuf(z = 8);
	t = u / n;
	if (t < 60)
		sfsprintf(buf, z, "%lu.%02lus", t, (u * 100 / n) % 100);
	else if (t < 60*60)
		sfsprintf(buf, z, "%lum%02lus", t / 60, t - (t / 60) * 60);
	else if (t < 24*60*60)
		sfsprintf(buf, z, "%luh%02lum", t / (60*60), (t - (t / (60*60)) * (60*60)) / 60);
	else if (t < 7*24*60*60)
		sfsprintf(buf, z, "%lud%02luh", t / (24*60*60), (t - (t / (24*60*60)) * (24*60*60)) / (60*60));
	else if (t < 31*24*60*60)
		sfsprintf(buf, z, "%luw%02lud", t / (7*24*60*60), (t - (t / (7*24*60*60)) * (7*24*60*60)) / (24*60*60));
	else if (t < 365*24*60*60)
		sfsprintf(buf, z, "%luM%02lud", (t * 12) / (365*24*60*60), ((t * 12) - ((t * 12) / (365*24*60*60)) * (365*24*60*60)) / (12*24*60*60));
	else if (t < (365UL*4UL+1UL)*24UL*60UL*60UL)
		sfsprintf(buf, z, "%luY%02luM", t / (365*24*60*60), ((t - (t / (365*24*60*60)) * (365*24*60*60)) * 5) / (152 * 24 * 60 * 60));
	else
		sfsprintf(buf, z, "%luY%02luM", (t * 4) / ((365UL*4UL+1UL)*24UL*60UL*60UL), (((t * 4) - ((t * 4) / ((365UL*4UL+1UL)*24UL*60UL*60UL)) * ((365UL*4UL+1UL)*24UL*60UL*60UL)) * 5) / ((4 * 152 + 1) * 24 * 60 * 60));
	return buf;
}
