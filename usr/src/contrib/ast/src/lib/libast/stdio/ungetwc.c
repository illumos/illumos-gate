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

wint_t
ungetwc(wint_t c, Sfio_t* f)
{
	register unsigned char*	s = (unsigned char*)&c;
	register unsigned char*	e = s + sizeof(c);

	STDIO_INT(f, "ungetwc", wint_t, (wint_t, Sfio_t*), (c, f))

	FWIDE(f, WEOF);
	while (s < e)
		if (sfungetc(f, *s++) == EOF)
			return WEOF;
	return c;
}
