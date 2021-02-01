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
 * n is minutes west of UTC
 *
 * append p and SHHMM part of n to s
 * where S is + or -
 *
 * n ignored if n==d
 * end of s is returned
 */

char*
tmpoff(register char* s, size_t z, register const char* p, register int n, int d)
{
	register char*	e = s + z;

	while (s < e && (*s = *p++))
		s++;
	if (n != d && s < e)
	{
		if (n < 0)
		{
			n = -n;
			*s++ = '+';
		}
		else
			*s++ = '-';
		s += sfsprintf(s, e - s, "%02d%s%02d", n / 60, d == -24*60 ? ":" : "", n % 60);
	}
	return s;
}
