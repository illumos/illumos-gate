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

int
vsnprintf(char* s, int n, const char* form, va_list args)
{
	Sfio_t*	f;
	ssize_t	rv;

	/* make a temp stream */
	if(!(f = sfnew(NIL(Sfio_t*),NIL(char*),(size_t)SF_UNBOUND,
                        -1,SF_WRITE|SF_STRING)) )
		return -1;

	if((rv = sfvprintf(f,form,args)) >= 0 )
	{	if(s && n > 0)
		{	if((rv+1) >= n)
				n--;
			else
				n = rv;
			memcpy(s, f->data, n);
			s[n] = 0;
		}
		_Sfi = rv;
	}

	sfclose(f);

	return rv;
}
