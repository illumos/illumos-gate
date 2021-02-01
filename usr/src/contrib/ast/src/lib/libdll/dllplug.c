/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1997-2012 AT&T Intellectual Property          *
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
 * AT&T Research
 */

#include "dlllib.h"

/*
 * find and load lib plugin/module library name with optional version ver and dlopen() flags
 * at least one dlopen() is called to initialize dlerror()
 * if path!=0 then library path up to size chars copied to path with trailing 0
 * if name contains a directory prefix then library search is limited to the dir and siblings
 */

extern void*
dllplugin(const char* lib, const char* name, const char* ver, unsigned long rel, unsigned long* cur, int flags, char* path, size_t size)
{
	void*		dll;
	int		err;
	int		hit;
	Dllscan_t*	dls;
	Dllent_t*	dle;

	err = hit = 0;
	for (;;)
	{
		if (dls = dllsopen(lib, name, ver))
		{
			while (dle = dllsread(dls))
			{
				hit = 1;
#if 0
			again:
#endif
				if (dll = dllopen(dle->path, flags|RTLD_GLOBAL|RTLD_PARENT))
				{
					if (!dllcheck(dll, dle->path, rel, cur))
					{
						err = state.error;
						dlclose(dll);
						dll = 0;
						continue;
					}
					if (path && size)
						strlcpy(path, dle->path, size);
					break;
				}
				else
				{
#if 0
					/*
					 * dlopen() should load implicit libraries
					 * this code does that
					 * but it doesn't help on galadriel
					 */

					char*	s;
					char*	e;

					if ((s = dllerror(1)) && (e = strchr(s, ':')))
					{
						*e = 0;
						error(1, "AHA %s implicit", s);
						dll = dllplugin(lib, s, 0, 0, 0, flags, path, size);
						*e = ':';
						if (dll)
						{
							error(1, "AHA implicit %s => %s", s, path);
							goto again;
						}
					}
#endif
					errorf("dll", NiL, 1, "dllplugin: %s dlopen failed: %s", dle->path, dllerror(1));
					err = state.error;
				}
			}
			dllsclose(dls);
		}
		if (hit)
		{
			if (!dll)
				state.error = err;
			return dll;
		}
		if (!lib)
			break;
		lib = 0;
	}
	if (dll = dllopen(name, flags))
	{
		if (!dllcheck(dll, name, rel, cur))
		{
			dlclose(dll);
			dll = 0;
		}
		else if (path && size)
			strlcpy(path, name, size);
	}
	return dll;
}

extern void*
dllplug(const char* lib, const char* name, const char* ver, int flags, char* path, size_t size)
{
	return dllplugin(lib, name, ver, 0, NiL, flags, path, size);
}
