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

#include <ast.h>
#include <ctype.h>

/*
 * version strncmp(3)
 */

int
strnvcmp(register const char* a, register const char* b, size_t n)
{
	register const char*	ae;
	register const char*	be;
	register unsigned long	na;
	register unsigned long	nb;

	ae = a + n;
	be = b + n;
	for (;;)
	{
		if (a >= ae)
		{
			if (b >= be)
				return 0;
			return 1;
		}
		else if (b >= be)
			return -1;
		if (isdigit(*a) && isdigit(*b))
		{
			na = nb = 0;
			while (a < ae && isdigit(*a))
				na = na * 10 + *a++ - '0';
			while (b < be && isdigit(*b))
				nb = nb * 10 + *b++ - '0';
			if (na < nb)
				return -1;
			if (na > nb)
				return 1;
		}
		else if (*a != *b)
			break;
		else if (!*a)
			return 0;
		else
		{
			a++;
			b++;
		}
	}
	if (*a == 0)
		return -1;
	if (*b == 0)
		return 1;
	if (*a == '.')
		return -1;
	if (*b == '.')
		return 1;
	if (*a == '-')
		return -1;
	if (*b == '-')
		return 1;
	return *a < *b ? -1 : 1;
}
