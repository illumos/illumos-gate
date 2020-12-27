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
#pragma prototyped

#include "stdhdr.h"

ssize_t
getdelim(char** sp, size_t* np, int delim, Sfio_t* f)
{
	ssize_t		m;
	ssize_t		n;
	ssize_t		k;
	ssize_t		p;
	uchar*		s;
	uchar*		ps;
	SFMTXDECL(f);

	STDIO_INT(f, "getdelim", ssize_t, (char**, size_t*, int, Sfio_t*), (sp, np, delim, f))

	SFMTXENTER(f, -1);

	if(delim < 0 || delim > 255 || !sp || !np) /* bad parameters */
		SFMTXRETURN(f, -1);

	if(f->mode != SF_READ && _sfmode(f,SF_READ,0) < 0)
		SFMTXRETURN(f, -1);

	SFLOCK(f,0);

	if(!(s = (uchar*)(*sp)) || (n = *np) < 0)
		{ s = NIL(uchar*); n = 0; }
	for(m = 0;; )
	{	/* read new data */
		if((p = f->endb - (ps = f->next)) <= 0 )
		{	f->getr = delim;
			f->mode |= SF_RC;
			if(SFRPEEK(f,ps,p) <= 0)
			{	m = -1;
				break;
			}
		}

		for(k = 0; k < p; ++k) /* find the delimiter */
		{	if(ps[k] == delim)
			{	k += 1; /* include delim in copying */
				break;
			}
		}

		if((m+k+1) >= n ) /* make sure there is space */
		{	n = ((m+k+15)/8)*8;
			if(!(s = (uchar*)realloc(s, n)) )
			{	*sp = 0; *np = 0;
				m = -1;
				break;
			}
			*sp = (char*)s; *np = n;
		}

		memcpy(s+m, ps, k); m += k;
		f->next = ps+k; /* skip copied data in buffer */

		if(s[m-1] == delim)
		{	s[m] = 0; /* 0-terminated */
			break;
		}
	}

	SFOPEN(f,0);
	SFMTXRETURN(f,m);
}

ssize_t
__getdelim(char** sp, size_t* np, int delim, Sfio_t* f)
{
	return getdelim(sp, np, delim, f);
}
