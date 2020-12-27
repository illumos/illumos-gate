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

/*	Tell the current location in a given stream
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
Sfoff_t sftell(Sfio_t* f)
#else
Sfoff_t sftell(f)
Sfio_t	*f;
#endif
{	
	reg int	mode;
	Sfoff_t	p;
	SFMTXDECL(f);

	SFMTXENTER(f, (Sfoff_t)(-1));

	/* set the stream to the right mode */
	if((mode = f->mode&SF_RDWR) != (int)f->mode && _sfmode(f,mode,0) < 0)
		SFMTXRETURN(f, (Sfoff_t)(-1));

	/* throw away ungetc data */
	if(f->disc == _Sfudisc)
		(void)sfclose((*_Sfstack)(f,NIL(Sfio_t*)));

	if(f->flags&SF_STRING)
		SFMTXRETURN(f, (Sfoff_t)(f->next-f->data));

	/* let sfseek() handle the hard case */
	if(f->extent >= 0 && (f->flags&(SF_SHARE|SF_APPENDWR)) )
		p = sfseek(f,(Sfoff_t)0,SEEK_CUR);
	else	p = f->here + ((f->mode&SF_WRITE) ? f->next-f->data : f->next-f->endb);

	SFMTXRETURN(f,p);
}
