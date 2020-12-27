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
 * tempnam implementation
 */

#include <ast_std.h>

#ifdef tempnam
#define _def_tempnam	1
#else
#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide tempnam
#else
#define tempnam		______tempnam
#endif
#endif

#include <ast.h>
#include <stdio.h>

#if !_def_tempnam
#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide tempnam
#else
#undef	tempnam
#endif
#endif

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern char*
tempnam(const char* dir, const char* pfx)
{
	return pathtmp(NiL, dir, pfx, NiL);
}
