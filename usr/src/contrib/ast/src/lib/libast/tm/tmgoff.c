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
#include <ctype.h>

/*
 * return minutes offset from absolute timezone expression
 *
 *	[[-+]hh[:mm[:ss]]]
 *	[-+]hhmm
 *
 * if e is non-null then it points to the first unrecognized char in s
 * d returned if no offset in s
 */

int
tmgoff(register const char* s, char** e, int d)
{
	register int	n = d;
	int		east;
	const char*	t = s;

	if ((east = *s == '+') || *s == '-')
	{
		s++;
		if (isdigit(*s) && isdigit(*(s + 1)))
		{
			n = ((*s - '0') * 10 + (*(s + 1) - '0')) * 60;
			s += 2;
			if (*s == ':')
				s++;
			if (isdigit(*s) && isdigit(*(s + 1)))
			{
				n += ((*s - '0') * 10 + (*(s + 1) - '0'));
				s += 2;
				if (*s == ':')
					s++;
				if (isdigit(*s) && isdigit(*(s + 1)))
					s += 2;
			}
			if (east)
				n = -n;
			t = s;
		}
	}
	if (e)
		*e = (char*)t;
	return n;
}
