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
 * AT&T Research
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE	1
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__	1
#endif

#include <ast.h>
#include <dlldefs.h>

#if _hdr_rld_interface
#include <rld_interface.h>
#endif

/*
 * return a handle for the next layer down,
 * i.e., the next layer that has symbols covered
 * by the main prog and dll's loaded so far
 *
 * intentionally light on external lib calls
 * so this routine can be used early in process
 * startup
 */

#ifdef	_DLL_RLD_SYM

#define DEBUG		1

#if DEBUG

typedef ssize_t (*Write_f)(int, const void*, size_t);

#endif

#undef	dllnext

void*
_dll_next(int flags, _DLL_RLD_SYM_TYPE* here)
{
	register char*	vp;
	register void*	lp;
	register int	found = 0;
	char*		s;
	char*		b;
	char*		e;
	char		dummy[256];
#if DEBUG
	Write_f		wr = 0;
	Write_f		xr;
	char		buf[1024];
#endif

#if DEBUG
	if (getenv("DLL_DEBUG") && (vp = (char*)_rld_new_interface(_RLD_FIRST_PATHNAME)))
	{
		do
		{
			if (strcmp(vp, "MAIN") && (lp = dllopen(vp, flags)))
			{
				if (xr = (Write_f)dlsym(lp, "write"))
					wr = xr;
			}
		} while (vp = (char*)_rld_new_interface(_RLD_NEXT_PATHNAME));
	}
#endif
	if (vp = (char*)_rld_new_interface(_RLD_FIRST_PATHNAME))
	{
		do
		{
			if (lp = dllopen(strcmp(vp, "MAIN") ? vp : (char*)0, flags))
			{
				if (found)
				{
					b = e = 0;
					s = vp;
					for (;;)
					{
						switch (*s++)
						{
						case 0:
							break;
						case '/':
							b = s;
							e = 0;
							continue;
						case '.':
							if (!e)
								e = s - 1;
							continue;
						default:
							continue;
						}
						break;
					}
					if (b && e)
					{
						s = dummy;
						*s++ = '_';
						*s++ = '_';
						while (b < e)
							*s++ = *b++;
						b = "_dummy";
						while (*s++ = *b++);
						if (dlsym(lp, dummy))
						{
							dlclose(lp);
							lp = 0;
						}
					}
					if (lp)
					{
#if DEBUG
						if (wr)
							(*wr)(2, buf, sfsprintf(buf, sizeof(buf), "dll: next %s\n", vp));
#endif
						return lp;
					}
#if DEBUG
					else if (wr)
						(*wr)(2, buf, sfsprintf(buf, sizeof(buf), "dll: skip %s\n", vp));
#endif
				}
				else if ((_DLL_RLD_SYM_TYPE*)dlsym(lp, _DLL_RLD_SYM_STR) == here)
				{
#if DEBUG
					if (wr)
						(*wr)(2, buf, sfsprintf(buf, sizeof(buf), "dll: this %s\n", vp));
#endif
					found = 1;
				}
			}
		} while (vp = (char*)_rld_new_interface(_RLD_NEXT_PATHNAME));
	}
	return dllnext(flags);
}

#endif

#ifndef RTLD_NEXT
#if _dll_DYNAMIC

#include <link.h>

extern struct link_dynamic	_DYNAMIC;

#endif
#endif

void*
dllnext(int flags)
{
	register void*			dll;
#ifndef RTLD_NEXT
#if _dll_DYNAMIC
	register struct link_map*	map;
	register char*			s;
	register char*			b;
#endif
	register char*			ver;
	char*				path;

	static char			next[] = { _DLL_NEXT_PATH };
#endif

#ifdef RTLD_NEXT
	dll = RTLD_NEXT;
#else
	path = next;
#if _dll_DYNAMIC
	for (map = _DYNAMIC.ld_un.ld_1->ld_loaded; map; map = map->lm_next)
	{
		b = 0;
		s = map->lm_name;
		while (*s)
			if (*s++ == '/')
				b = s;
		if (b && b[0] == 'l' && b[1] == 'i' && b[2] == 'b' && b[3] == 'c' && b[4] == '.')
		{
			path = map->lm_name;
			break;
		}
	}
#endif
	ver = path + strlen(path);
	while (!(dll = dllopen(path, flags)))
	{
		do
		{
			if (ver <= path)
				return 0;
		} while (*--ver != '.');
		if (*(ver + 1) <= '0' || *(ver + 1) >= '9')
			return 0;
		*ver = 0;
	}
#endif
	return dll;
}
