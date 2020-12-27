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

#include <ast.h>
#include <error.h>
#include <dlldefs.h>

/*
 * dlsym() with `_' weak fallback
 */

void*
dlllook(void* dll, const char* name)
{
	register void*	addr;
	char		buf[256];

	if (!(addr = dlsym(dll, name)) && strlen(name) < (sizeof(buf) - 2))
	{
		buf[0] = '_';
		strcpy(buf + 1, name);
		name = (const char*)buf;
		addr = dlsym(dll, name);
	}
	errorf("dll", NiL, -1, "dlllook: %s addr %p", name, addr);
	return addr;
}
