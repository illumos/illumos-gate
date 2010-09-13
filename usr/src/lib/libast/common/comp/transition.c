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

/*
 * transient code to aid transition between releases
 */

#include <ast.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

#define STUB		1

/*
 * 2006-09-28
 *
 *	on some systems the _std_strtol iffe changed (due to a faulty
 *	test prototype) and the cause programs dynamically linked to
 *	an updated -last to fail at runtime with missing _ast_strtol etc.
 */

#if !_std_strtol

#ifndef strtol
#undef	STUB
extern long
_ast_strtol(const char* a, char** b, int c)
{
	return strtol(a, b, c);
}
#endif

#ifndef strtoul
#undef	STUB
extern unsigned long
_ast_strtoul(const char* a, char** b, int c)
{
	return strtoul(a, b, c);
}
#endif

#ifndef strtoll
#undef	STUB
extern intmax_t
_ast_strtoll(const char* a, char** b, int c)
{
	return strtoll(a, b, c);
}
#endif

#ifndef strtoull
#undef	STUB
extern uintmax_t
_ast_strtoull(const char* a, char** b, int c)
{
	return strtoull(a, b, c);
}
#endif

#endif

#if STUB
NoN(transition)
#endif
