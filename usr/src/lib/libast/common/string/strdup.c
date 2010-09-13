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

#undef	VMDEBUG
#define	VMDEBUG		0

#include <ast.h>

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

	return (s && (t = newof(0, char, n = strlen(s) + 1, 0))) ? (char*)memcpy(t, s, n) : (char*)0;
}
