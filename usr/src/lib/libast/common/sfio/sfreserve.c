/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1985-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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

/*	Reserve a segment of data or buffer.
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
Void_t* sfreserve(reg Sfio_t* f, ssize_t size, int type)
#else
Void_t* sfreserve(f,size,type)
reg Sfio_t*	f;	/* file to peek */
ssize_t		size;	/* size of peek */
int		type;	/* LOCKR: lock stream, LASTR: last record */
#endif
{
	reg ssize_t	n, now, sz, iosz;
	reg Sfrsrv_t*	rsrv;
	reg Void_t*	data;
	reg int		mode, local;

	SFMTXSTART(f,NIL(Void_t*));

	sz = size < 0 ? -size : size;

	/* see if we need to bias toward SF_WRITE instead of the default SF_READ */
	if(type < 0)
		mode = 0;
	else if((mode = type&SF_WRITE) )
		type &= ~SF_WRITE;

	/* return the last record */
	if(type == SF_LASTR )
	{	if((n = f->endb - f->next) > 0 && n == f->val )
		{	data = (Void_t*)f->next;
			f->next += n;
		}
		else if((rsrv = f->rsrv) && (n = -rsrv->slen) > 0)
		{	rsrv->slen = 0;
			_Sfi = f->val = n;
			data = (Void_t*)rsrv->data;
		}
		else
		{	_Sfi = f->val = -1;
			data = NIL(Void_t*);
		}

		SFMTXRETURN(f, data);
	}

	if(type > 0)
	{	if(type == 1 ) /* upward compatibility mode */
			type = SF_LOCKR;
		else if(type != SF_LOCKR)
			SFMTXRETURN(f, NIL(Void_t*));
	}

	if(size == 0 && (type < 0 || type == SF_LOCKR) )
	{	if((f->mode&SF_RDWR) != f->mode && _sfmode(f,0,0) < 0)
			SFMTXRETURN(f, NIL(Void_t*));

		SFLOCK(f,0);
		if((n = f->endb - f->next) < 0)
			n = 0;

		goto done;
	}

	/* iterate until get to a stream that has data or buffer space */
	for(local = 0;; local = SF_LOCAL)
	{	_Sfi = f->val = -1;

		if(!mode && !(mode = f->flags&SF_READ) )
			mode = SF_WRITE;
		if((int)f->mode != mode && _sfmode(f,mode,local) < 0)
		{	SFOPEN(f,0);
			SFMTXRETURN(f, NIL(Void_t*));
		}

		SFLOCK(f,local);

		if((n = now = f->endb - f->next) < 0)
			n = 0;
		if(n > 0 && n >= sz) /* all done */
			break;

		/* amount to perform IO */
		if(size == 0 || (f->mode&SF_WRITE) )
			iosz = -1;
		else
		{	iosz = sz - n;
			if(type != SF_LOCKR && size < 0 && iosz < (f->size - n) )
				iosz = f->size - n;
			if(iosz <= 0)
				break;
		}

		/* do a buffer refill or flush */
		now = n;
		if(f->mode&SF_WRITE)
			(void)SFFLSBUF(f, iosz);
		else if(type == SF_LOCKR && f->extent < 0 && (f->flags&SF_SHARE) )
		{	if(n == 0) /* peek-read only if there is no buffered data */
			{	f->mode |= SF_RV;
				(void)SFFILBUF(f, iosz );
			}
			if((n = f->endb - f->next) < sz)
			{	if(f->mode&SF_PKRD)
				{	f->endb = f->endr = f->next;
					f->mode &= ~SF_PKRD;
				}
				break;
			}
		}
		else	(void)SFFILBUF(f, iosz );

		if((n = f->endb - f->next) <= 0)
			n = 0;

		if(n >= sz) /* got it */
			break;

		if(n == now || sferror(f) || sfeof(f)) /* no progress */
			break;

		/* request was only to assess data availability */
		if(type == SF_LOCKR && size > 0 && n > 0 )
			break;
	}

done:	/* compute the buffer to be returned */
	data = NIL(Void_t*);
	if(size == 0 || n == 0)
	{	if(n > 0) /* got data */
			data = (Void_t*)f->next;
		else if(type == SF_LOCKR && size == 0 && (rsrv = _sfrsrv(f,0)) )
			data = (Void_t*)rsrv->data;
	}
	else if(n >= sz) /* got data */
		data = (Void_t*)f->next;
	else if(f->flags&SF_STRING) /* try extending string buffer */
	{	if((f->mode&SF_WRITE) && (f->flags&SF_MALLOC) )
		{	(void)SFWR(f,f->next,sz,f->disc);
			if((n = f->endb - f->next) >= sz )
				data = (Void_t*)f->next;
		}
	}
	else if(f->mode&SF_WRITE) /* allocate side buffer */
	{	if(type == SF_LOCKR && (rsrv = _sfrsrv(f, sz)) )
			data = (Void_t*)rsrv->data;
	}
	else if(type != SF_LOCKR && sz > f->size && (rsrv = _sfrsrv(f,sz)) )
	{	if((n = SFREAD(f,(Void_t*)rsrv->data,sz)) >= sz) /* read side buffer */
			data = (Void_t*)rsrv->data;
		else	rsrv->slen = -n;
	}

	SFOPEN(f,0);

	if(data)
	{	if(type == SF_LOCKR)
		{	f->mode |= SF_PEEK;
			if((f->mode & SF_READ) && size == 0 && data != f->next)
				f->mode |= SF_GETR; /* so sfread() will unlock */
			f->endr = f->endw = f->data;
		}
		else
		{	if(data == (Void_t*)f->next)
				f->next += (size >= 0 ? size : n);
		}
	}

	_Sfi = f->val = n; /* return true buffer size */

	SFMTXRETURN(f, data);
}
