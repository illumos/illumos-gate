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

int
fseek(Sfio_t* f, long off, int op)
{
	STDIO_INT(f, "fseek", int, (Sfio_t*, long, int), (f, off, op))

	return sfseek(f, (Sfoff_t)off, op|SF_SHARE) >= 0 ? 0 : -1;
}

#ifdef _typ_int64_t

int
fseek64(Sfio_t* f, int64_t off, int op)
{
	STDIO_INT(f, "fseek64", int, (Sfio_t*, int64_t, int), (f, off, op))

	return sfseek(f, (Sfoff_t)off, op|SF_SHARE) >= 0 ? 0 : -1;
}

#endif
