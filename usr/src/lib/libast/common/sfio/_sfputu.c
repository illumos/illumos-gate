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

/*	Write out an unsigned long value in a portable format.
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
int _sfputu(Sfio_t* f, Sfulong_t v)
#else
int _sfputu(f,v)
Sfio_t*		f;	/* write a portable ulong to this stream */
Sfulong_t	v;	/* the unsigned value to be written */
#endif
{
#define N_ARRAY		(2*sizeof(Sfulong_t))
	reg uchar	*s, *ps;
	reg ssize_t	n, p;
	uchar		c[N_ARRAY];
	SFMTXDECL(f);

	SFMTXENTER(f, -1);

	if(f->mode != SF_WRITE && _sfmode(f,SF_WRITE,0) < 0)
		SFMTXRETURN(f, -1);
	SFLOCK(f,0);

	/* code v as integers in base SF_UBASE */
	s = ps = &(c[N_ARRAY-1]);
	*s = (uchar)SFUVALUE(v);
	while((v >>= SF_UBITS) )
		*--s = (uchar)(SFUVALUE(v) | SF_MORE);
	n = (ps-s)+1;

	if(n > 8 || SFWPEEK(f,ps,p) < n)
		n = SFWRITE(f,(Void_t*)s,n); /* write the hard way */
	else
	{	switch(n)
		{
		case 8 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 7 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 6 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 5 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 4 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 3 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 2 : *ps++ = *s++;
		/* FALLTHROUGH */
		case 1 : *ps++ = *s++;
		}
		f->next = ps;
	}

	SFOPEN(f,0);
	SFMTXRETURN(f, (int)n);
}
