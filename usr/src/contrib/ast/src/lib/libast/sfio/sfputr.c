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

/*	Put out a null-terminated string
**
**	Written by Kiem-Phong Vo.
*/
#if __STD_C
ssize_t sfputr(Sfio_t* f, const char* s, int rc)
#else
ssize_t sfputr(f,s,rc)
Sfio_t*		f;	/* write to this stream	*/
char*		s;	/* string to write	*/
int		rc;	/* record separator.	*/
#endif
{
	ssize_t		p, n, w, sn;
	uchar		*ps;
	char		*ss;
	SFMTXDECL(f);

	SFMTXENTER(f,-1);

	if(f->mode != SF_WRITE && _sfmode(f,SF_WRITE,0) < 0)
		SFMTXRETURN(f, -1);

	SFLOCK(f,0);

	f->val = sn = -1; ss = (char*)s; 
	for(w = 0; (*s || rc >= 0); )
	{	/* need to communicate string size to exception handler */
		if((f->flags&SF_STRING) && f->next >= f->endb )
		{	sn = sn < 0 ? strlen(s) : (sn - (s-ss));
			ss = (char*)s; /* save current checkpoint */
			f->val = sn + (rc >= 0 ? 1 : 0); /* space requirement */
			f->bits |= SF_PUTR; /* tell sfflsbuf to use f->val */
		}

		SFWPEEK(f,ps,p);
		f->bits &= ~SF_PUTR; /* remove any trace of this */

		if(p < 0 ) /* something not right about buffering */
			break;

		if(p == 0 || (f->flags&SF_WHOLE) )
		{	n = sn < 0 ? strlen(s) : sn - (s-ss);
			if(p >= (n + (rc < 0 ? 0 : 1)) )
			{	/* buffer can hold everything */
				if(n > 0)
				{	memcpy(ps, s, n);
					ps += n;
					w += n;
				}
				if(rc >= 0)
				{	*ps++ = rc;
					w += 1;
				}
				f->next = ps;
			}
			else
			{	/* create a reserve buffer to hold data */
				Sfrsrv_t*	rsrv;

				p = n + (rc >= 0 ? 1 : 0);
				if(!(rsrv = _sfrsrv(f, p)) )
					n = 0;
				else
				{	if(n > 0)
						memcpy(rsrv->data, s, n);
					if(rc >= 0)
						rsrv->data[n] = rc;
					if((n = SFWRITE(f,rsrv->data,p)) < 0 )
						n = 0;
				}

				w += n;
			}
			break;
		}

		if(*s == 0)
		{	*ps++ = rc;
			f->next = ps;
			w += 1;
			break;
		}

#if _lib_memccpy && !__ia64 /* these guys may never get it right */
		if((ps = (uchar*)memccpy(ps,s,'\0',p)) != NIL(uchar*))
			ps -= 1;
		else	ps  = f->next+p;
		s += ps - f->next;
#else
		for(; p > 0; --p, ++ps, ++s)
			if((*ps = *s) == 0)
				break;
#endif
		w += ps - f->next;
		f->next = ps;
	}

	/* sync unseekable shared streams */
	if(f->extent < 0 && (f->flags&SF_SHARE) )
		(void)SFFLSBUF(f,-1);

	/* check for line buffering */
	else if((f->flags&SF_LINE) && !(f->flags&SF_STRING) && (n = f->next-f->data) > 0)
	{	if(n > w)
			n = w;
		f->next -= n;
		(void)SFWRITE(f,(Void_t*)f->next,n);
	}

	SFOPEN(f,0);
	SFMTXRETURN(f, w);
}
