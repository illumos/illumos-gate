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

/*	Move data from one stream to another.
**	This code is written so that it'll work even in the presence
**	of stacking streams, pool, and discipline.
**	If you must change it, be gentle.
**
**	Written by Kiem-Phong Vo.
*/
#define MAX_SSIZE	((ssize_t)((~((size_t)0)) >> 1))

#if __STD_C
Sfoff_t sfmove(Sfio_t* fr, Sfio_t* fw, Sfoff_t n, reg int rc)
#else
Sfoff_t sfmove(fr,fw,n,rc)
Sfio_t*	fr;	/* moving data from this stream */
Sfio_t*	fw;	/* moving data to this stream */
Sfoff_t		n;	/* number of bytes/records to move. <0 for unbounded move */
reg int		rc;	/* record separator */
#endif
{
	reg uchar	*cp, *next;
	reg ssize_t	r, w;
	reg uchar	*endb;
	reg int		direct;
	Sfoff_t		n_move, sk, cur;
	uchar		*rbuf = NIL(uchar*);
	ssize_t		rsize = 0;
	SFMTXDECL(fr);	/* declare a shadow stream variable for from stream */
	SFMTXDECL2(fw);	/* declare a shadow stream variable for to stream */

	SFMTXENTER(fr, (Sfoff_t)0);
	if(fw)
		SFMTXBEGIN2(fw, (Sfoff_t)0);

	for(n_move = 0; n != 0; )
	{
		if(rc >= 0) /* moving records, let sfgetr() deal with record reading */
		{	if(!(cp = (uchar*)sfgetr(fr,rc,0)) )
				n = 0;
			else
			{	r = sfvalue(fr);
				if(fw && (w = SFWRITE(fw, cp, r)) != r)
				{	if(fr->extent >= 0 )
						(void)SFSEEK(fr,(Sfoff_t)(-r),SEEK_CUR);
					if(fw->extent >= 0 && w > 0)
						(void)SFSEEK(fw,(Sfoff_t)(-w),SEEK_CUR);
					n = 0;
				}
				else
				{	n_move += 1;
					if(n > 0)
						n -= 1;
				}
			}
			continue;
		}

		/* get the streams into the right mode */
		if(fr->mode != SF_READ && _sfmode(fr,SF_READ,0) < 0)
			break;

		SFLOCK(fr,0);

		/* flush the write buffer as necessary to make room */
		if(fw)
		{	if(fw->mode != SF_WRITE && _sfmode(fw,SF_WRITE,0) < 0 )
				break;
			SFLOCK(fw,0);
			if(fw->next >= fw->endb ||
			   (fw->next > fw->data && fr->extent < 0 &&
			    (fw->extent < 0 || (fw->flags&SF_SHARE)) ) )
				if(SFFLSBUF(fw,-1) < 0 )
					break;
		}
		else if((cur = SFSEEK(fr, (Sfoff_t)0, SEEK_CUR)) >= 0 )
		{	sk = n > 0 ? SFSEEK(fr, n, SEEK_CUR) : SFSEEK(fr, 0, SEEK_END);
			if(sk > cur) /* safe to skip over data in current stream */
			{	n_move += sk - cur;
				if(n > 0)
					n -= sk - cur;
				continue;
			}
			/* else: stream unstacking may happen below */
		}

		/* about to move all, set map to a large amount */
		if(n < 0 && (fr->bits&SF_MMAP) && !(fr->bits&SF_MVSIZE) )
		{	SFMVSET(fr);
			fr->bits |= SF_SEQUENTIAL; /* sequentially access data */
		}

		/* try reading a block of data */
		direct = 0;
		if((r = fr->endb - (next = fr->next)) <= 0)
		{	/* amount of data remained to be read */
			if((w = n > MAX_SSIZE ? MAX_SSIZE : (ssize_t)n) < 0)
			{	if(fr->extent < 0)
					w = fr->data == fr->tiny ? SF_GRAIN : fr->size;
				else if((fr->extent-fr->here) > SF_NMAP*SF_PAGE)
					w = SF_NMAP*SF_PAGE;
				else	w = (ssize_t)(fr->extent-fr->here);
			}

			/* use a decent buffer for data transfer but make sure
			   that if we overread, the left over can be retrieved
			*/
			if(!(fr->flags&SF_STRING) && !(fr->bits&SF_MMAP) &&
			   (n < 0 || fr->extent >= 0) )
			{	reg ssize_t maxw = 4*(_Sfpage > 0 ? _Sfpage : SF_PAGE);

				/* direct transfer to a seekable write stream */
				if(fw && fw->extent >= 0 && w <= (fw->endb-fw->next) )
				{	w = fw->endb - (next = fw->next);
					direct = SF_WRITE;
				}
				else if(w > fr->size && maxw > fr->size)
				{	/* making our own buffer */
					if(w >= maxw)
						w = maxw;
					else	w = ((w+fr->size-1)/fr->size)*fr->size;
					if(rsize <= 0 && (rbuf = (uchar*)malloc(w)) )
						rsize = w;
					if(rbuf)
					{	next = rbuf;
						w = rsize;
						direct = SF_STRING;
					}
				}
			}

			if(!direct)
			{	/* make sure we don't read too far ahead */
				if(n > 0 && fr->extent < 0 && (fr->flags&SF_SHARE) )
				{	if((Sfoff_t)(r = fr->size) > n)
						r = (ssize_t)n;
				}
				else	r = -1;
				if((r = SFFILBUF(fr,r)) <= 0)
					break;
				next = fr->next;
			}
			else
			{	/* actual amount to be read */
				if(n > 0 && n < w)
					w = (ssize_t)n;

				if((r = SFRD(fr,next,w,fr->disc)) > 0)
					fr->next = fr->endb = fr->endr = fr->data;
				else if(r == 0)
					break;		/* eof */
				else	goto again;	/* popped stack */
			}
		}

		/* compute the extent of data to be moved */
		endb = next+r;
		if(n > 0)
		{	if(r > n)
				r = (ssize_t)n;
			n -= r;
		}
		n_move += r;
		cp = next+r;

		if(!direct)
			fr->next += r;
		else if((w = endb-cp) > 0)
		{	/* move left-over to read stream */
			if(w > fr->size)
				w = fr->size;
			memcpy((Void_t*)fr->data,(Void_t*)cp,w);
			fr->endb = fr->data+w;
			if((w = endb - (cp+w)) > 0)
				(void)SFSK(fr,(Sfoff_t)(-w),SEEK_CUR,fr->disc);
		}

		if(fw)
		{	if(direct == SF_WRITE)
				fw->next += r;
			else if(r <= (fw->endb-fw->next) )
			{	memcpy((Void_t*)fw->next,(Void_t*)next,r);
				fw->next += r;
			}
			else if((w = SFWRITE(fw,(Void_t*)next,r)) != r)
			{	/* a write error happened */
				if(w > 0)
				{	r -= w;
					n_move -= r;
				}
				if(fr->extent >= 0)
					(void)SFSEEK(fr,(Sfoff_t)(-r),SEEK_CUR);
				break;
			}
		}

	again:
		SFOPEN(fr,0);
		if(fw)
			SFOPEN(fw,0);
	}

	if(n < 0 && (fr->bits&SF_MMAP) && (fr->bits&SF_MVSIZE))
	{	/* back to normal access mode */
		SFMVUNSET(fr);
		if((fr->bits&SF_SEQUENTIAL) && (fr->data))
			SFMMSEQOFF(fr,fr->data,fr->endb-fr->data);
		fr->bits &= ~SF_SEQUENTIAL;
	}

	if(rbuf)
		free(rbuf);

	if(fw)
	{	SFOPEN(fw,0);
		SFMTXEND2(fw);
	}

	SFOPEN(fr,0);
	SFMTXRETURN(fr, n_move);
}
