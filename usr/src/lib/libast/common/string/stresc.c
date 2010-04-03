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
 * convert \X character constants in s in place
 * the length of the converted s is returned (may have embedded \0's)
 */

#include <ast.h>

int
stresc(register char* s)
{
	register char*		t;
	register unsigned int	c;
	char*			b;
	char*			e;

	b = t = s;
	while (c = *s++)
	{
		if (c == '\\')
		{
			c = chresc(s - 1, &e);
			s = e;
			if (c > UCHAR_MAX)
			{
				t += mbconv(t, c);
				continue;
			}
		}
		*t++ = c;
	}
	*t = 0;
	return t - b;
}
