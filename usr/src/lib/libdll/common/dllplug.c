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
 * AT&T Research
 */

#include <ast.h>
#include <dlldefs.h>
#include <error.h>

/*
 * find and load lib plugin/module library name with optional version ver and dlopen() flags
 * at least one dlopen() is called to initialize dlerror()
 * if path!=0 then library path up to size chars copied to path with trailing 0
 * if name contains a directory prefix then library search is limited to the dir and siblings
 */

extern void*
dllplug(const char* lib, const char* name, const char* ver, int flags, char* path, size_t size)
{
	void*		dll;
	int		hit;
	Dllscan_t*	dls;
	Dllent_t*	dle;

	hit = 0;
	for (;;)
	{
		if (dls = dllsopen(lib, name, ver))
		{
			while (dle = dllsread(dls))
			{
				hit = 1;
				if (dll = dllopen(dle->path, flags|RTLD_GLOBAL|RTLD_PARENT))
				{
					if (path && size)
						strncopy(path, dle->path, size);
					break;
				}
				else
					errorf("dll", NiL, 1, "%s: dlopen failed: %s", dle->path, dlerror());
			}
			dllsclose(dls);
		}
		if (hit)
			return dll;
		if (!lib)
			break;
		lib = 0;
	}
	if ((dll = dllopen(name, flags)) && dll && path && size)
		strncopy(path, name, size);
	return dll;
}
