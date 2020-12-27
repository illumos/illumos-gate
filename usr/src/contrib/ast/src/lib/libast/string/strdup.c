/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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

#undef	VMDEBUG
#define	VMDEBUG		0

#if defined(_MSVCRT_H)
#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide strdup
#else
#define strdup		______strdup
#endif
#endif

#include <ast.h>

#if defined(_MSVCRT_H)
#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide strdup
#else
#undef	strdup
#endif
#endif

/*
 * return a copy of s using malloc
 */

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern char*
strdup(register const char* s)
{
	register char*	t;
	register int	n;

	return (s && (t = oldof(0, char, n = strlen(s) + 1, 0))) ? (char*)memcpy(t, s, n) : (char*)0;
}
