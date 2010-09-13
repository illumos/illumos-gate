/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1997-2010 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * at&t research
 */

#include <ast.h>
#include <dlldefs.h>
#include <error.h>

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
	return dlopen(name, mode);
}

#endif
