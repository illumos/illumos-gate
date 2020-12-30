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

extern char*
_stdgets(Sfio_t* f, char* us, int n, int isgets)
{
	int		p;
	unsigned char*	is;
	unsigned char*	ps;

	if(n <= 0 || !us || (f->mode != SF_READ && _sfmode(f,SF_READ,0) < 0))
		return NIL(char*);

	SFLOCK(f,0);

	n -= 1;
	is = (uchar*)us;
	
	while(n)
	{	/* peek the read buffer for data */
		if((p = f->endb - (ps = f->next)) <= 0 )
		{	f->getr = '\n';
			f->mode |= SF_RC;
			if(SFRPEEK(f,ps,p) <= 0)
				break;
		}

		if(p > n)
			p = n;

#if _lib_memccpy
		if((ps = (uchar*)memccpy((char*)is,(char*)ps,'\n',p)) != NIL(uchar*))
			p = ps-is;
		is += p;
		ps  = f->next+p;
#else
		if(!(f->flags&(SF_BOTH|SF_MALLOC)))
		{	while(p-- && (*is++ = *ps++) != '\n')
				;
			p = ps-f->next;
		}
		else
		{	reg int	c = ps[p-1];
			if(c != '\n')
				ps[p-1] = '\n';
			while((*is++ = *ps++) != '\n')
				;
			if(c != '\n')
			{	f->next[p-1] = c;
				if((ps-f->next) >= p)
					is[-1] = c;
			}
		}
#endif

		/* gobble up read data and continue */
		f->next = ps;
		if(is[-1] == '\n')
			break;
		else if(n > 0)
			n -= p;
	}

	if((_Sfi = is - ((uchar*)us)) <= 0)
		us = NIL(char*);
	else if(isgets && is[-1] == '\n')
	{	is[-1] = '\0';
		_Sfi -= 1;
	}
	else	*is = '\0';

	SFOPEN(f,0);
	return us;
}

char*
fgets(char* s, int n, Sfio_t* f)
{
	STDIO_PTR(f, "fgets", char*, (char*, int, Sfio_t*), (s, n, f))

	return _stdgets(f, s, n, 0);
}

char*
gets(char* s)
{
	return _stdgets(sfstdin, s, BUFSIZ, 1);
}
