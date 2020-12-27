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
 * obsolete streval() interface to strexpr()
 */

#include <ast.h>

typedef long (*Old_convert_t)(const char*, char**);

typedef long (*Convert_t)(const char*, char**, void*);

typedef struct
{
	Old_convert_t	convert;
} Handle_t;

static long
userconv(const char* s, char** end, void* handle)
{
	return((*((Handle_t*)handle)->convert)(s, end));
}

long
streval(const char* s, char** end, Old_convert_t convert)
{
	Handle_t	handle;

	return((handle.convert = convert) ? strexpr(s, end, userconv, &handle) : strexpr(s, end, (Convert_t)0, NiL));
}
