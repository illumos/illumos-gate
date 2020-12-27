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

#include <ast_lib.h>

#if _lib_execlp

#include <ast.h>

NoN(execlp)

#else

#if defined(__EXPORT__)
__EXPORT__ int execlp(const char*, const char*, ...);
#endif

#include <ast.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int
execlp(const char* name, const char* arg, ...)
{
	return execvp(name, (char *const*)&arg);
}

#endif
