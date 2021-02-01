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

/*
 * NOTE: mbs* and wcs* are provided to avoid link errors only
 */

#include <ast.h>
#include <wchar.h>

#define STUB	1

#if !_lib_mbtowc
#undef	STUB
size_t
mbtowc(wchar_t* t, const char* s, size_t n)
{
	if (t && n > 0)
		*t = *s;
	return 1;
}
#endif

#if !_lib_mbrtowc
#undef	STUB
size_t
mbrtowc(wchar_t* t, const char* s, size_t n, mbstate_t* q)
{
#if _lib_mbtowc
#undef	STUB
	memset(q, 0, sizeof(*q));
	return mbtowc(t, s, n);
#else
	*q = 0;
	if (t && n > 0)
		*t = *s;
	return 1;
#endif
}
#endif

#if !_lib_mbstowcs
#undef	STUB
size_t
mbstowcs(wchar_t* t, const char* s, size_t n)
{
	register wchar_t*	p = t;
	register wchar_t*	e = t + n;
	register unsigned char*	u = (unsigned char*)s;

	if (t)
		while (p < e && (*p++ = *u++));
	else
		while (p++, *u++);
	return p - t;
}
#endif

#if !_lib_wctomb
#undef	STUB
int
wctomb(char* s, wchar_t c)
{
	if (s)
		*s = c;
	return 1;
}
#endif

#if !_lib_wcrtomb
#undef	STUB
size_t
wcrtomb(char* s, wchar_t c, mbstate_t* q)
{
#if _lib_wctomb
#undef	STUB
	memset(q, 0, sizeof(*q));
	return wctomb(s, c);
#else
	if (s)
		*s = c;
	*q = 0;
	return 1;
#endif
}
#endif

#if !_lib_wcslen
#undef	STUB
size_t
wcslen(const wchar_t* s)
{
	register const wchar_t*	p = s;

	while (*p)
		p++;
	return p - s;
}
#endif

#if !_lib_wcstombs
#undef	STUB
size_t
wcstombs(char* t, register const wchar_t* s, size_t n)
{
	register char*		p = t;
	register char*		e = t + n;

	if (t)
		while (p < e && (*p++ = *s++));
	else
		while (p++, *s++);
	return p - t;
}
#endif

#if STUB
NoN(wc)
#endif
