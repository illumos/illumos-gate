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

#ifndef _NO_LARGEFILE64_SOURCE
#define _NO_LARGEFILE64_SOURCE	1
#endif

#include "stdhdr.h"

off_t
ftello(Sfio_t* f)
{
	STDIO_INT(f, "ftello", off_t, (Sfio_t*), (f))

	return sfseek(f, (Sfoff_t)0, SEEK_CUR);
}

#ifdef _typ_int64_t

int64_t
ftello64(Sfio_t* f)
{
	STDIO_INT(f, "ftello64", int64_t, (Sfio_t*), (f))

	return sfseek(f, (Sfoff_t)0, SEEK_CUR) >= 0 ? 0 : -1;
}

#endif
