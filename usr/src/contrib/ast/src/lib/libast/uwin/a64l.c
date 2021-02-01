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
#include "FEATURE/uwin"

#if !_UWIN || _lib_a64l

void _STUB_a64l(){}

#else

#define a64l	______a64l
#define l64a	______l64a

#include	<stdlib.h>
#include	<string.h>

#undef	a64l
#undef	l64a

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

static char letter[65] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

extern long a64l(const char *str)
{
	register unsigned long ul = 0;
	register int n = 6;
	register int c;
	register char *cp;
	for(n=0; n <6; n++)
	{
		if((c= *str++)==0)
			break;
		if(!(cp=strchr(letter,c)))
			break;
		ul |= (cp-letter)<< (6*n);
	}
	return((long)ul);
}

extern char *l64a(long l)
{
	static char buff[7];
	unsigned ul = ((unsigned long)l & 0xffffffff);
	register char *cp = buff;
	while(ul>0)
	{
		*cp++ = letter[ul&077];
		ul >>= 6;
	}
	*cp = 0;
	return(buff);
}

#endif
