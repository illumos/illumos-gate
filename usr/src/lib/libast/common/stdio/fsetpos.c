/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
fsetpos(Sfio_t* f, const fpos_t* pos)
{
	STDIO_INT(f, "fsetpos", int, (Sfio_t*, const fpos_t*), (f, pos))

	return sfseek(f, (Sfoff_t)pos->_sf_offset, SF_PUBLIC) == (Sfoff_t)pos->_sf_offset ? 0 : -1;
}

#ifdef _typ_int64_t

int
fsetpos64(Sfio_t* f, const fpos64_t* pos)
{
	STDIO_INT(f, "fsetpos64", int, (Sfio_t*, const fpos64_t*), (f, pos))

	return sfseek(f, (Sfoff_t)pos->_sf_offset, SF_PUBLIC) == (Sfoff_t)pos->_sf_offset ? 0 : -1;
}

#endif
