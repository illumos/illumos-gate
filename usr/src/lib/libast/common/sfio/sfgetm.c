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
#include	"sfhdr.h"

/*	Read an unsigned long value coded portably for a given range.
**
**	Written by Kiem-Phong Vo
*/

#if __STD_C
Sfulong_t sfgetm(Sfio_t* f, Sfulong_t m)
#else
Sfulong_t sfgetm(f, m)
Sfio_t*		f;
Sfulong_t	m;
#endif
{
	Sfulong_t	v;
	reg uchar	*s, *ends, c;
	reg int		p;
	SFMTXDECL(f);

	SFMTXENTER(f, (Sfulong_t)(-1));

	if(f->mode != SF_READ && _sfmode(f,SF_READ,0) < 0)
		SFMTXRETURN(f, (Sfulong_t)(-1));

	SFLOCK(f,0);

	for(v = 0;; )
	{	if(SFRPEEK(f,s,p) <= 0)
		{	f->flags |= SF_ERROR;
			v = (Sfulong_t)(-1);
			goto done;
		}
		for(ends = s+p; s < ends;)
		{	c = *s++;
			v = (v << SF_BBITS) | SFBVALUE(c);
			if((m >>= SF_BBITS) <= 0)
			{	f->next = s;
				goto done;
			}
		}
		f->next = s;
	}
done:
	SFOPEN(f,0);
	SFMTXRETURN(f, v);
}
