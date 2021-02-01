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

#ifndef _USE_GNU
#define _USE_GNU
#endif

#include "stdhdr.h"

int
fflush(Sfio_t* f)
{
	if (!f)
		return fcloseall();

	STDIO_INT(f, "fflush", int, (Sfio_t*), (f))

	if (f->extent > 0)
		sfseek(f, (Sfoff_t)0, SEEK_CUR|SF_PUBLIC);
	return (sfsync(f) < 0 || sfpurge(f) < 0) ? -1 : 0;
}
