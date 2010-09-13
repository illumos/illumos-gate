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

#include "stdhdr.h"

int
vswscanf(const wchar_t* s, const wchar_t* fmt, va_list args)
{
	Sfio_t	f;

	if (!s)
		return -1;

	/*
	 * make a fake stream
	 */

	SFCLEAR(&f, NiL);
	f.flags = SF_STRING|SF_READ;
	f.bits = SF_PRIVATE;
	f.mode = SF_READ;
	f.size = wcslen(s) * sizeof(wchar_t);
	f.data = f.next = f.endw = (uchar*)s;
	f.endb = f.endr = f.data + f.size;

	/*
	 * sfio does the rest
	 */

	return vfwscanf(&f, fmt, args);
}
