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

/*	Invoke event handlers for a stream
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
static int _sfraiseall(int type, Void_t* data)
#else
static int _sfraiseall(type, data)
int	type;	/* type of event	*/
Void_t*	data;	/* associated data	*/
#endif
{
	Sfio_t		*f;
	Sfpool_t	*p, *next;
	int		n, rv;

	rv = 0;
	for(p = &_Sfpool; p; p = next)
	{
		for(next = p->next; next; next = next->next)
			if(next->n_sf > 0)
				break;
		for(n = 0; n < p->n_sf; ++n)
		{	f = p->sf[n];
			if(sfraise(f, type, data) < 0)
				rv -= 1;
		}
	}
	return rv;
}

#if __STD_C
int sfraise(Sfio_t* f, int type, Void_t* data)
#else
int sfraise(f, type, data)
Sfio_t*	f;	/* stream		*/
int	type;	/* type of event	*/
Void_t*	data;	/* associated data	*/
#endif
{
	reg Sfdisc_t	*disc, *next, *d;
	reg int		local, rv;
	SFMTXDECL(f);

	if(!f)
		return _sfraiseall(type,data);

	SFMTXENTER(f, -1);

	GETLOCAL(f,local);
	if(!SFKILLED(f) &&
	   !(local &&
	     (type == SF_NEW || type == SF_CLOSING ||
	      type == SF_FINAL || type == SF_ATEXIT)) &&
	   SFMODE(f,local) != (f->mode&SF_RDWR) && _sfmode(f,0,local) < 0)
		SFMTXRETURN(f, -1);
	SFLOCK(f,local);

	for(disc = f->disc; disc; )
	{	next = disc->disc;
		if(type == SF_FINAL)
			f->disc = next;

		if(disc->exceptf)
		{	SFOPEN(f,0);
			if((rv = (*disc->exceptf)(f,type,data,disc)) != 0 )
				SFMTXRETURN(f, rv);
			SFLOCK(f,0);
		}

		if((disc = next) )
		{	/* make sure that "next" hasn't been popped */
			for(d = f->disc; d; d = d->disc)
				if(d == disc)
					break;
			if(!d)
				disc = f->disc;
		}
	}

	SFOPEN(f,local);
	SFMTXRETURN(f, 0);
}
