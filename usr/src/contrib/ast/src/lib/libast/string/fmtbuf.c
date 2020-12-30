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

/*
 * return small format buffer chunk of size n
 * spin lock for thread access
 * format buffers are short lived
 * only one concurrent buffer with size > sizeof(buf)
 */

static char		buf[16 * 1024];
static char*		nxt = buf;
static int		lck = -1;

static char*		big;
static size_t		bigsiz;

char*
fmtbuf(size_t n)
{
	register char*	cur;

	while (++lck)
		lck--;
	if (n > (&buf[elementsof(buf)] - nxt))
	{
		if (n > elementsof(buf))
		{
			if (n > bigsiz)
			{
				bigsiz = roundof(n, 8 * 1024);
				if (!(big = newof(big, char, bigsiz, 0)))
				{
					lck--;
					return 0;
				}
			}
			lck--;
			return big;
		}
		nxt = buf;
	}
	cur = nxt;
	nxt += n;
	lck--;
	return cur;
}
