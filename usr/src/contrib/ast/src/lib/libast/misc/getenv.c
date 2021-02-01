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

#if _UWIN && __STDPP__
__STDPP__directive pragma pp:hide getenv
#endif

#include "intercepts.h"

#if _UWIN && __STDPP__
__STDPP__directive pragma pp:nohide getenv
#endif

/*
 * NOTE: the "intercepts" definition is here instead of astintercept.c because some
 *	 static linkers miss lone references to "intercepts" without "astintercept()"
 * ALSO: { 0 } definition required by some dynamic linkers averse to common symbols
 * UWIN: no _ast_getenv macro map to maintain ast54 compatibility
 */

Intercepts_t	intercepts
#if _BLD_3d
		;
#else
		= { 0 };
#endif

#if _UWIN && !defined(getenv)

#include <windows.h>

extern char**	environ;

static char*
default_getenv(const char* name)
{
	register char**		av;
	register const char*	cp;
	register const char*	sp;
	register char		c0;
	register char		c1;

	av = environ;
	if (!av || !name || !(c0 = *name))
		return 0;
	if (!(c1 = *++name))
		c1 = '=';
	while (cp = *av++)
	{
		if (cp[0] != c0 || cp[1] != c1)
			continue;
		sp = name;
		cp++;
		while (*sp && *sp++ == *cp++);
		if (*(sp-1) != *(cp-1))
			continue;
		if (*sp == 0 && *cp == '=')
			return (char*)(cp+1);
	}
	return 0;
}

#endif

/*
 * get name from the environment
 */

#if defined(__EXPORT__) && defined(getenv)
#define extern	__EXPORT__
#endif

extern char*
getenv(const char* name)
{
#if _UWIN && !defined(getenv) /* for ast54 compatibility */
	HANDLE		dll;

	static char*	(*posix_getenv)(const char*);

	if (!posix_getenv)
	{
		if (dll = GetModuleHandle("posix.dll"))
			posix_getenv = (char*(*)(const char*))GetProcAddress(dll, "getenv");
		if (!posix_getenv)
			posix_getenv = default_getenv;
	}
	return intercepts.intercept_getenv ? (*intercepts.intercept_getenv)(name) : (*posix_getenv)(name);
#else
#undef	getenv
	return intercepts.intercept_getenv ? (*intercepts.intercept_getenv)(name) : getenv(name);
#endif
}
