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

#include "intercepts.h"

/*
 * NOTE: the "intercepts" definition is in getenv.c because some static linkers
 *	 miss lone references to "intercepts" without "astintercept()"
 */

/*
 * set/clear ast intercept callouts
 */

int
astintercept(Shbltin_t* call, int set)
{
	if (call->shgetenv)
	{
		if (set)
			intercepts.intercept_getenv = call->shgetenv;
		else
			intercepts.intercept_getenv = 0;
	}
	if (call->shsetenv)
	{
		if (set)
			intercepts.intercept_setenviron = call->shsetenv;
		else
			intercepts.intercept_setenviron = 0;
	}
	return 0;
}
