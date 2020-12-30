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

/*	Write out a character n times
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
ssize_t sfnputc(Sfio_t* f, int c, size_t n)
#else
ssize_t sfnputc(f,c,n)
Sfio_t*		f;	/* file to write */
int		c;	/* char to be written */
size_t		n;	/* number of time to repeat */
#endif
{
	reg uchar*	ps;
	reg ssize_t	p, w;
	uchar		buf[128];
	reg int		local;
	SFMTXDECL(f); /* declare a local stream variable for multithreading */

	SFMTXENTER(f,-1);

	GETLOCAL(f,local);
	if(SFMODE(f,local) != SF_WRITE && _sfmode(f,SF_WRITE,local) < 0)
		SFMTXRETURN(f, -1);

	SFLOCK(f,local);

	/* write into a suitable buffer */
	if((size_t)(p = (f->endb-(ps = f->next))) < n)
		{ ps = buf; p = sizeof(buf); }
	if((size_t)p > n)
		p = n;
	MEMSET(ps,c,p);
	ps -= p;

	w = n;
	if(ps == f->next)
	{	/* simple sfwrite */
		f->next += p;
		if(c == '\n')
			(void)SFFLSBUF(f,-1);
		goto done;
	}

	for(;;)
	{	/* hard write of data */
		if((p = SFWRITE(f,(Void_t*)ps,p)) <= 0 || (n -= p) <= 0)
		{	w -= n;
			goto done;
		}
		if((size_t)p > n)
			p = n;
	}
done :
	SFOPEN(f,local);
	SFMTXRETURN(f, w);
}
