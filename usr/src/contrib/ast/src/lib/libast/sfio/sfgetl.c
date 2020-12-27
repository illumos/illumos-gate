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
#include	"sfhdr.h"

/*	Read a long value coded in a portable format.
**
**	Written by Kiem-Phong Vo
*/

#if __STD_C
Sflong_t sfgetl(Sfio_t* f)
#else
Sflong_t sfgetl(f)
Sfio_t*	f;
#endif
{
	Sflong_t	v;
	uchar		*s, *ends, c;
	int		p;
	SFMTXDECL(f); /* declare a local stream variable for multithreading */

	SFMTXENTER(f,(Sflong_t)(-1));

	if(f->mode != SF_READ && _sfmode(f,SF_READ,0) < 0)
		SFMTXRETURN(f, (Sflong_t)(-1));
	SFLOCK(f,0);

	for(v = 0;;)
	{	if(SFRPEEK(f,s,p) <= 0)
		{	f->flags |= SF_ERROR;
			v = (Sflong_t)(-1);
			goto done;
		}
		for(ends = s+p; s < ends;)
		{	c = *s++;
			if(c&SF_MORE)
				v = ((Sfulong_t)v << SF_UBITS) | SFUVALUE(c);
			else
			{	/* special translation for this byte */
				v = ((Sfulong_t)v << SF_SBITS) | SFSVALUE(c);
				f->next = s;
				v = (c&SF_SIGN) ? -v-1 : v;
				goto done;
			}
		}
		f->next = s;
	}
done :
	SFOPEN(f,0);
	SFMTXRETURN(f, v);
}
