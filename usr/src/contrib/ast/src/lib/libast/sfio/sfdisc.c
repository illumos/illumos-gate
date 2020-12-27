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

/*	Add a new discipline to the discipline stack. Each discipline
**	provides alternative I/O functions that are analogues of the
**	system calls.
**
**	When the application fills or flushes the stream buffer, data
**	will be processed through discipline functions. A case deserving
**	consideration is stacking a discipline onto a read stream. Each
**	discipline operation implies buffer synchronization so the stream
**	buffer should be empty. However, a read stream representing an
**	unseekable device (eg, a pipe) may not be synchronizable. In that
**	case, any buffered data must then be fed to the new discipline
**	to preserve data processing semantics. This is done by creating
**	a temporary discipline to cache such buffered data and feed
**	them to the new discipline when its readf() asks for new data.
**	Care must then be taken to remove this temporary discipline
**	when it runs out of cached data.
**
**	Written by Kiem-Phong Vo
*/

typedef struct _dccache_s
{	Sfdisc_t	disc;
	uchar*		data;
	uchar*		endb;
} Dccache_t;

#if __STD_C
static int _dccaexcept(Sfio_t* f, int type, Void_t* val, Sfdisc_t* disc)
#else
static int _dccaexcept(f,type,val,disc)
Sfio_t*		f;
int		type;
Void_t*		val;
Sfdisc_t*	disc;
#endif
{
	if(disc && type == SF_FINAL)
		free(disc);
	return 0;
}

#if __STD_C
static ssize_t _dccaread(Sfio_t* f, Void_t* buf, size_t size, Sfdisc_t* disc)
#else
static ssize_t _dccaread(f, buf, size, disc)
Sfio_t*		f;
Void_t*		buf;
size_t		size;
Sfdisc_t*	disc;
#endif
{
	ssize_t		sz;
	Sfdisc_t	*prev;
	Dccache_t	*dcca;

	if(!f) /* bad stream */
		return -1;

	/* make sure that this is on the discipline stack */
	for(prev = f->disc; prev; prev = prev->disc)
		if(prev->disc == disc)
			break;
	if(!prev)
		return -1;

	if(size <= 0) /* nothing to do */
		return size;

	/* read from available data */
	dcca = (Dccache_t*)disc;
	if((sz = dcca->endb - dcca->data) > (ssize_t)size)
		sz = (ssize_t)size;
	memcpy(buf, dcca->data, sz);

	if((dcca->data += sz) >= dcca->endb) /* free empty cache */
	{	prev->disc = disc->disc;
		free(disc);
	}

	return sz;
}

#if __STD_C
Sfdisc_t* sfdisc(Sfio_t* f, Sfdisc_t* disc)
#else
Sfdisc_t* sfdisc(f,disc)
Sfio_t*		f;
Sfdisc_t*	disc;
#endif
{
	Sfdisc_t	*d, *rdisc;
	Sfread_f	oreadf;
	Sfwrite_f	owritef;
	Sfseek_f	oseekf;
	ssize_t		n;
	Dccache_t	*dcca = NIL(Dccache_t*);
	SFMTXDECL(f); /* declare a local stream variable for multithreading */

	SFMTXENTER(f, NIL(Sfdisc_t*));

	if((Sfio_t*)disc == f) /* special case to get the top discipline */
		SFMTXRETURN(f,f->disc);

	if((f->flags&SF_READ) && f->proc && (f->mode&SF_WRITE) )
	{	/* make sure in read mode to check for read-ahead data */
		if(_sfmode(f,SF_READ,0) < 0)
			SFMTXRETURN(f, NIL(Sfdisc_t*));
	}
	else
	{	if((f->mode&SF_RDWR) != f->mode && _sfmode(f,0,0) < 0)
			SFMTXRETURN(f, NIL(Sfdisc_t*));
	}

	SFLOCK(f,0);
	rdisc = NIL(Sfdisc_t*);

	/* disallow popping while there is cached data */
	if(!disc && f->disc && f->disc->disc && f->disc->disc->readf == _dccaread )
		goto done;

	/* synchronize before switching to a new discipline */
	if(!(f->flags&SF_STRING))
	{	(void)SFSYNC(f); /* do a silent buffer synch */
		if((f->mode&SF_READ) && (f->mode&SF_SYNCED) )
		{	f->mode &= ~SF_SYNCED;
			f->endb = f->next = f->endr = f->endw = f->data;
		}

		/* if there is buffered data, ask app before proceeding */
		if(((f->mode&SF_WRITE) && (n = f->next-f->data) > 0) ||
		   ((f->mode&SF_READ) && (n = f->endb-f->next) > 0) )
		{	int	rv = 0;
			if(rv == 0 && f->disc && f->disc->exceptf) /* ask current discipline */
			{	SFOPEN(f,0);
				rv = (*f->disc->exceptf)(f, SF_DBUFFER, &n, f->disc);
				SFLOCK(f,0);
			}
			if(rv == 0 && disc && disc->exceptf) /* ask discipline being pushed */
			{	SFOPEN(f,0);
				rv = (*disc->exceptf)(f, SF_DBUFFER, &n, disc);
				SFLOCK(f,0);
			}
			if(rv < 0)
				goto done;
		}

		/* trick the new discipline into processing already buffered data */
		if((f->mode&SF_READ) && n > 0 && disc && disc->readf )
		{	if(!(dcca = (Dccache_t*)malloc(sizeof(Dccache_t)+n)) )
				goto done;
			memclear(dcca, sizeof(Dccache_t));

			dcca->disc.readf = _dccaread;
			dcca->disc.exceptf = _dccaexcept;

			/* move buffered data into the temp discipline */
			dcca->data = ((uchar*)dcca) + sizeof(Dccache_t);
			dcca->endb = dcca->data + n;
			memcpy(dcca->data, f->next, n);
			f->endb = f->next = f->endr = f->endw = f->data;
		}
	}

	/* save old readf, writef, and seekf to see if stream need reinit */
#define GETDISCF(func,iof,type) \
	{ for(d = f->disc; d && !d->iof; d = d->disc) ; \
	  func = d ? d->iof : NIL(type); \
	}
	GETDISCF(oreadf,readf,Sfread_f);
	GETDISCF(owritef,writef,Sfwrite_f);
	GETDISCF(oseekf,seekf,Sfseek_f);

	if(disc == SF_POPDISC)
	{	/* popping, warn the being popped discipline */
		if(!(d = f->disc) )
			goto done;
		disc = d->disc;
		if(d->exceptf)
		{	SFOPEN(f,0);
			if((*(d->exceptf))(f,SF_DPOP,(Void_t*)disc,d) < 0 )
				goto done;
			SFLOCK(f,0);
		}
		f->disc = disc;
		rdisc = d;
	}
	else
	{	/* pushing, warn being pushed discipline */
		do
		{	/* loop to handle the case where d may pop itself */
			d = f->disc;
			if(d && d->exceptf)
			{	SFOPEN(f,0);
				if( (*(d->exceptf))(f,SF_DPUSH,(Void_t*)disc,d) < 0 )
					goto done;
				SFLOCK(f,0);
			}
		} while(d != f->disc);

		/* make sure we are not creating an infinite loop */
		for(; d; d = d->disc)
			if(d == disc)
				goto done;

		/* set new disc */
		if(dcca) /* insert the discipline with cached data */
		{	dcca->disc.disc = f->disc;
			disc->disc = &dcca->disc;
		}
		else	disc->disc = f->disc;
		f->disc = disc;
		rdisc = disc;
	}

	if(!(f->flags&SF_STRING) )
	{	/* this stream may have to be reinitialized */
		reg int	reinit = 0;
#define DISCF(dst,iof,type)	(dst ? dst->iof : NIL(type)) 
#define REINIT(oiof,iof,type) \
		if(!reinit) \
		{	for(d = f->disc; d && !d->iof; d = d->disc) ; \
			if(DISCF(d,iof,type) != oiof) \
				reinit = 1; \
		}

		REINIT(oreadf,readf,Sfread_f);
		REINIT(owritef,writef,Sfwrite_f);
		REINIT(oseekf,seekf,Sfseek_f);

		if(reinit)
		{	SETLOCAL(f);
			f->bits &= ~SF_NULL;	/* turn off /dev/null handling */
			if((f->bits&SF_MMAP) || (f->mode&SF_INIT))
				sfsetbuf(f,NIL(Void_t*),(size_t)SF_UNBOUND);
			else if(f->data == f->tiny)
				sfsetbuf(f,NIL(Void_t*),0);
			else
			{	int	flags = f->flags;
				sfsetbuf(f,(Void_t*)f->data,f->size);
				f->flags |= (flags&SF_MALLOC);
			}
		}
	}

done :
	SFOPEN(f,0);
	SFMTXRETURN(f, rdisc);
}
