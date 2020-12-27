/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1997-2011 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * at&t research
 */

#include "dlllib.h"

#if 0

/*
 * dlopen() wrapper that properly initializes LIBPATH
 * with the path of the dll to be opened
 *
 * 2009-04-15 -- if ld.so re-checked the env this would work ...
 */

void*
dllopen(const char* name, int mode)
{
	void*		dll;
	Dllinfo_t*	info;
	char*		olibpath;
	char*		path;
	char*		oenv;
	char*		nenv[2];
	char*		dir;
	char*		base;
	int		len;

	if (!environ)
	{
		nenv[0] = nenv[1] = 0;
		environ = nenv;
	}
	info = dllinfo();
	oenv = environ[0];
	olibpath = getenv(info->env);
	if (base = strrchr(name, '/'))
	{
		dir = (char*)name;
		len = ++base - dir;
	}
	else
	{
		dir = "./";
		len = 2;
		base = (char*)name;
	}
	path = sfprints("%-.*s%s%c%s=%-.*s%s%s", len, dir, base, 0, info->env, len, dir, olibpath ? ":" : "", olibpath ? olibpath : "");
	environ[0] = path + strlen(path) + 1;
	state.error = 0;
	dll = dlopen(path, mode);
	if (environ == nenv)
		environ = 0;
	else
		environ[0] = oenv;
	return dll;
}

#else

/*
 * dlopen() wrapper -- waiting for prestidigitaions
 */

void*
dllopen(const char* name, int mode)
{
	state.error = 0;
	return dlopen(name, mode);
}

#endif
