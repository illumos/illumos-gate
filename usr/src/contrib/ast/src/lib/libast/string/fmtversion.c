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
 * return formatted <magicid.h> version string
 */

#include <ast.h>

char*
fmtversion(register unsigned long v)
{
	register char*	cur;
	register char*	end;
	char*		buf;
	int		n;

	buf = cur = fmtbuf(n = 18);
	end = cur + n;
	if (v >= 19700101L && v <= 29991231L)
		sfsprintf(cur, end - cur, "%04lu-%02lu-%02lu", (v / 10000) % 10000, (v / 100) % 100, v % 100);
	else
	{
		if (n = (v >> 24) & 0xff)
			cur += sfsprintf(cur, end - cur, "%d.", n);
		if (n = (v >> 16) & 0xff)
			cur += sfsprintf(cur, end - cur, "%d.", n);
		sfsprintf(cur, end - cur, "%ld.%ld", (v >> 8) & 0xff, v & 0xff);
	}
	return buf;
}
