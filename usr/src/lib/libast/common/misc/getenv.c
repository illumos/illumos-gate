/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2008 AT&T Intellectual Property          *
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

#include "intercepts.h"

/*
 * NOTE: the "intercepts" definition is here instead of astintercept.c because some
 *	 static linkers miss lone references to "intercepts" without "astintercept()"
 * ALSO: { 0 } definition required by some dynamic linkers avers to common symbols
 */

Intercepts_t	intercepts = { 0 };

/*
 * get name from the environment
 */

char*
getenv(const char* name)
{
#undef	getenv
	return intercepts.intercept_getenv ? (*intercepts.intercept_getenv)(name) : getenv(name);
}
