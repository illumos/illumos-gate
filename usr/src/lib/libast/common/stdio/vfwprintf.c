/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
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
#pragma prototyped

#include "stdhdr.h"

int
vfwprintf(Sfio_t* f, const wchar_t* fmt, va_list args)
{
	char*	m;
	char*	x;
	wchar_t*w;
	size_t	n;
	int	v;
	Sfio_t*	t;

	STDIO_INT(f, "vfwprintf", int, (Sfio_t*, const wchar_t*, va_list), (f, fmt, args))

	FWIDE(f, WEOF);
	n = wcstombs(NiL, fmt, 0);
	if (m = malloc(n + 1))
	{
		if (t = sfstropen())
		{
			wcstombs(m, fmt, n + 1);
			sfvprintf(t, m, args);
			free(m);
			if (!(x = sfstruse(t)))
				v = -1;
			else
			{
				n = mbstowcs(NiL, x, 0);
				if (w = (wchar_t*)sfreserve(f, n * sizeof(wchar_t) + 1, 0))
					v = mbstowcs(w, x, n + 1);
				else
					v = -1;
			}
			sfstrclose(t);
		}
		else
			v = -1;
	}
	else
		v = -1;
	return v;
}
