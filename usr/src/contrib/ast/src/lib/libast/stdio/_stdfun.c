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

#include <ast.h>

#if !_UWIN

void _STUB_stdfun(){}

#else

#include <ast_windows.h>
#include <uwin.h>
#include <dlfcn.h>
#include "FEATURE/uwin"

#if _lib___iob_func
#define IOB		((char*)__iob_func())
#elif _lib___p__iob
#define IOB		((char*)__p__iob())
#elif _dat__iob
#define IOB		((char*)_iob)
#else
#define IOB		((char*)_p__iob())
#endif

#define IOBMAX		(512*32)

#include "stdhdr.h"

int
_stdfun(Sfio_t* f, Funvec_t* vp)
{
	static char*	iob;
	static int	init;
	static void*	bp;
	static void*	np;

	if (!iob && !(iob = IOB))
		return 0;
	if (f && ((char*)f < iob || (char*)f > iob+IOBMAX))
		return 0;
	if (!vp->vec[1])
	{
		if (!init)
		{
			init = 1;
			bp = dlopen("/usr/bin/stdio.dll", 0);
		}
		if (bp && (vp->vec[1] = (Fun_f)dlsym(bp, vp->name)))
			return 1;
		if (!np && !(np = dlopen("/sys/msvcrt.dll", 0)))
			return -1;
		if (!(vp->vec[1] = (Fun_f)dlsym(np, vp->name)))
			return -1;
	}
	return 1;
}

#endif
