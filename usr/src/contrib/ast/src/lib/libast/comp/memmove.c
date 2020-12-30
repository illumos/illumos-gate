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

#include <ast.h>

#if _lib_memmove

NoN(memmove)

#else

void*
memmove(void* to, const void* from, register size_t n)
{
	register char*	out = (char*)to;
	register char*	in = (char*)from;

	if (n <= 0)	/* works if size_t is signed or not */
		;
	else if (in + n <= out || out + n <= in)
		return(memcpy(to, from, n));	/* hope it's fast*/
	else if (out < in)
		do *out++ = *in++; while (--n > 0);
	else
	{
		out += n;
		in += n;
		do *--out = *--in; while(--n > 0);
	}
	return(to);
}

#endif
