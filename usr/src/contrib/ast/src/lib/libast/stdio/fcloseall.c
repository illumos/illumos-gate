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

#include "stdhdr.h"

#define MAXLOOP		3

int
fcloseall(void)
{
	Sfpool_t*	p;
	Sfpool_t*	next;
	int		n;
	int		nclose;
	int		count;
	int		loop;

	STDIO_INT(0, "fcloseall", int, (void), ())

	for(loop = 0; loop < MAXLOOP; ++loop)
	{	nclose = count = 0;
		for(p = &_Sfpool; p; p = next)
		{	/* find the next legitimate pool */
			for(next = p->next; next; next = next->next)
				if(next->n_sf > 0)
					break;
			for(n = 0; n < ((p == &_Sfpool) ? p->n_sf : 1); ++n)
			{	count += 1;
				if(sfclose(p->sf[n]) >= 0)
					nclose += 1;
			}
		}
		if(nclose == count)
			break;
	}
	return 0; /* always return 0 per GNU */
}
