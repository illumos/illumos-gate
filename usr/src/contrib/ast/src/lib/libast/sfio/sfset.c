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

/*	Set some control flags or file descript for the stream
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
int sfset(Sfio_t* f, int flags, int set)
#else
int sfset(f,flags,set)
Sfio_t*		f;
int		flags;
int		set;
#endif
{
	reg int	oflags, tflags, rv;
	SFMTXDECL(f);

	SFMTXENTER(f,0);

	if(flags == 0 && set == 0)
		SFMTXRETURN(f, (f->flags&SF_FLAGS));

	if((oflags = (f->mode&SF_RDWR)) != (int)f->mode)
	{	/* avoid sfsetbuf() isatty() call if user sets (SF_LINE|SF_WCWIDTH) */
		if(set && (flags & (SF_LINE|SF_WCWIDTH)) && !(f->flags & (SF_LINE|SF_WCWIDTH)))
		{	tflags = (SF_LINE|SF_WCWIDTH);
			f->flags |= tflags;
		}
		else	tflags = 0;
		rv = _sfmode(f,oflags,0);
		if(tflags)
			f->flags &= ~tflags;
		if(rv < 0)
			SFMTXRETURN(f, 0);
	}
	if(flags == 0)
		SFMTXRETURN(f, (f->flags&SF_FLAGS));

	SFLOCK(f,0);

	/* preserve at least one rd/wr flag */
	oflags = f->flags;
	if(!(f->bits&SF_BOTH) || (flags&SF_RDWR) == SF_RDWR )
		flags &= ~SF_RDWR;

	/* set the flag */
	if(set)
		f->flags |=  (flags&SF_SETS);
	else	f->flags &= ~(flags&SF_SETS);

	/* must have at least one of read/write */
	if(!(f->flags&SF_RDWR))
		f->flags |= (oflags&SF_RDWR);

	if(f->extent < 0)
		f->flags &= ~SF_APPENDWR;

	/* turn to appropriate mode as necessary */
	if((flags &= SF_RDWR) )
	{	if(!set)
		{	if(flags == SF_READ)
				flags = SF_WRITE;
			else	flags = SF_READ;
		}
		if((flags == SF_WRITE && !(f->mode&SF_WRITE)) ||
		   (flags == SF_READ && !(f->mode&(SF_READ|SF_SYNCED))) )
			(void)_sfmode(f,flags,1);
	}

	/* if not shared or unseekable, public means nothing */
	if(!(f->flags&SF_SHARE) || f->extent < 0)
		f->flags &= ~SF_PUBLIC;

	SFOPEN(f,0);
	SFMTXRETURN(f, (oflags&SF_FLAGS));
}
