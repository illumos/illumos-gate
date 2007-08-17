/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1985-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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

/*
 * gnu stdio extensions
 */

#include "stdhdr.h"

int
fcloseall(void)
{
	return sfsync(NiL) < 0 ? -1 : 0;
}

Sfio_t*
fmemopen(void* buf, size_t size, const char* mode)
{
	return sfnew(NiL, buf, size, -1, SF_STRING|_sftype(mode, NiL, NiL));
}

ssize_t
__getdelim(char** pbuf, size_t* psize, int del, Sfio_t* sp)
{
	char*	s;
	size_t	n;
	size_t	m;

	if (!(s = sfgetr(sp, del, 1)))
		return -1;
	n = sfsize(sp);
	m = n + 1;
	if (!*pbuf || m > *psize)
	{
		m = roundof(m, 1024);
		if (!(*pbuf = newof(*pbuf, char, m, 0)))
			return -1;
		*psize = m;
	}
	memcpy(*pbuf, s, n);
	return n;
}

ssize_t
getdelim(char** pbuf, size_t* psize, int del, Sfio_t* sp)
{
	return __getdelim(pbuf, psize, del, sp);
}

ssize_t
getline(char** pbuf, size_t* psize, Sfio_t* sp)
{
	return __getdelim(pbuf, psize, '\n', sp);
}
