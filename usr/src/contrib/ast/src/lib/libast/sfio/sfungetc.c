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

/*	Push back one byte to a given SF_READ stream
**
**	Written by Kiem-Phong Vo.
*/
#if __STD_C
static int _uexcept(Sfio_t* f, int type, Void_t* val, Sfdisc_t* disc)
#else
static int _uexcept(f,type,val,disc)
Sfio_t		*f;
int		type;
Void_t*		val;
Sfdisc_t	*disc;
#endif
{	
	NOTUSED(val);

	/* hmm! This should never happen */
	if(disc != _Sfudisc)
		return -1;

	/* close the unget stream */
	if(type != SF_CLOSING)
		(void)sfclose((*_Sfstack)(f,NIL(Sfio_t*)));

	return 1;
}

#if __STD_C
int sfungetc(Sfio_t* f, int c)
#else
int sfungetc(f,c)
Sfio_t*		f;	/* push back one byte to this stream */
int		c;	/* the value to be pushed back */
#endif
{
	reg Sfio_t*	uf;
	SFMTXDECL(f);

	SFMTXENTER(f, -1);

	if(c < 0 || (f->mode != SF_READ && _sfmode(f,SF_READ,0) < 0))
		SFMTXRETURN(f, -1);
	SFLOCK(f,0);

	/* fast handling of the typical unget */
	if(f->next > f->data && f->next[-1] == (uchar)c)
	{	f->next -= 1;
		goto done;
	}

	/* make a string stream for unget characters */
	if(f->disc != _Sfudisc)
	{	if(!(uf = sfnew(NIL(Sfio_t*),NIL(char*),(size_t)SF_UNBOUND,
				-1,SF_STRING|SF_READ)))
		{	c = -1;
			goto done;
		}
		_Sfudisc->exceptf = _uexcept;
		sfdisc(uf,_Sfudisc);
		SFOPEN(f,0); (void)sfstack(f,uf); SFLOCK(f,0);
	}

	/* space for data */
	if(f->next == f->data)
	{	reg uchar*	data;
		if(f->size < 0)
			f->size = 0;
		if(!(data = (uchar*)malloc(f->size+16)))
		{	c = -1;
			goto done;
		}
		f->flags |= SF_MALLOC;
		if(f->data)
			memcpy((char*)(data+16),(char*)f->data,f->size);
		f->size += 16;
		f->data  = data;
		f->next  = data+16;
		f->endb  = data+f->size;
	}

	*--f->next = (uchar)c;
done:
	SFOPEN(f,0);
	SFMTXRETURN(f, c);
}
