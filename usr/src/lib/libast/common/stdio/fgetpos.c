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
fgetpos(Sfio_t* f, fpos_t* pos)
{
	STDIO_INT(f, "fgetpos", int, (Sfio_t*, fpos_t*), (f, pos))

	return (pos->_sf_offset = sfseek(f, (Sfoff_t)0, SEEK_CUR)) >= 0 ? 0 : -1;
}

#ifdef _typ_int64_t

int
fgetpos64(Sfio_t* f, fpos64_t* pos)
{
	STDIO_INT(f, "fgetpos64", int, (Sfio_t*, fpos64_t*), (f, pos))

	return (pos->_sf_offset = sfseek(f, (Sfoff_t)0, SEEK_CUR)) >= 0 ? 0 : -1;
}

#endif
