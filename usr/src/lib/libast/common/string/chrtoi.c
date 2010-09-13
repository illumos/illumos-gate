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
 * AT&T Bell Laboratories
 *
 * convert a 0 terminated character constant string to an int
 */

#include <ast.h>

int
chrtoi(register const char* s)
{
	register int	c;
	register int	n;
	register int	x;
	char*		p;

	c = 0;
	for (n = 0; n < sizeof(int) * CHAR_BIT; n += CHAR_BIT)
	{
		switch (x = *((unsigned char*)s++))
		{
		case '\\':
			x = chresc(s - 1, &p);
			s = (const char*)p;
			break;
		case 0:
			return(c);
		}
		c = (c << CHAR_BIT) | x;
	}
	return(c);
}
