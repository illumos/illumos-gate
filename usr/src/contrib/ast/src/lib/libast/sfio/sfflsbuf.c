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

/*	Write a buffer out to a file descriptor or
**	extending a buffer for a SF_STRING stream.
**
**	Written by Kiem-Phong Vo
*/

#if __STD_C
int _sfflsbuf(Sfio_t* f, int c)
#else
int _sfflsbuf(f,c)
Sfio_t*	f;	/* write out the buffered content of this stream */
int	c;	/* if c>=0, c is also written out */ 
#endif
{
	ssize_t		n, w, written;
	uchar*		data;
	uchar		outc;
	int		local, isall;
	int		inpc = c;
	SFMTXDECL(f); /* declare a local stream variable for multithreading */

	SFMTXENTER(f,-1);

	GETLOCAL(f,local);

	for(written = 0;; f->mode &= ~SF_LOCK)
	{	/* check stream mode */
		if(SFMODE(f,local) != SF_WRITE && _sfmode(f,SF_WRITE,local) < 0)
			SFMTXRETURN(f, -1);
		SFLOCK(f,local);

		/* current data extent */
		n = f->next - (data = f->data);

		if(n == (f->endb-data) && (f->flags&SF_STRING))
		{	/* call sfwr() to extend string buffer and process events */
			w = ((f->bits&SF_PUTR) && f->val > 0) ? f->val : 1;
			(void)SFWR(f, data, w, f->disc);

			/* !(f->flags&SF_STRING) is required because exception
			   handlers may turn a string stream to a file stream */
			if(f->next < f->endb || !(f->flags&SF_STRING) )
				n = f->next - (data = f->data);
			else
			{	SFOPEN(f,local);
				SFMTXRETURN(f, -1);
			}
		}

		if(c >= 0)
		{	/* write into buffer */
			if(n < (f->endb - (data = f->data)))
			{	*f->next++ = c;
				if(c == '\n' &&
				   (f->flags&SF_LINE) && !(f->flags&SF_STRING))
				{	c = -1;
					n += 1;
				}
				else	break;
			}
			else if(n == 0)
			{	/* unbuffered io */
				outc = (uchar)c;
				data = &outc;
				c = -1;
				n = 1;
			}
		}

		if(n == 0 || (f->flags&SF_STRING))
			break;

		isall = SFISALL(f,isall);
		if((w = SFWR(f,data,n,f->disc)) > 0)
		{	if((n -= w) > 0) /* save unwritten data, then resume */
				memcpy((char*)f->data,(char*)data+w,n);
			written += w;
			f->next = f->data+n;
			if(c < 0 && (!isall || n == 0))
				break;
		}
		else if(w == 0)
		{	if(written > 0) /* some buffer was cleared */
				break; /* do normal exit below */
			else /* nothing was done, returning failure */
			{	SFOPEN(f,local);
				SFMTXRETURN(f, -1);
			}
		}
		else /* w < 0 means SF_EDISC or SF_ESTACK in sfwr() */
		{	if(c < 0) /* back to the calling write operation */
				break;
			else	continue; /* try again to write out c */
		}
	}

	SFOPEN(f,local);

	if(inpc < 0)
		inpc = f->endb-f->next;

	SFMTXRETURN(f,inpc);
}
