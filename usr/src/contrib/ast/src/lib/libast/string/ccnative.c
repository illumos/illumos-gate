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

/*
 * Glenn Fowler
 * AT&T Research
 *
 * copy table with element size n
 * indexed by CC_ASCII to table
 * indexed by CC_NATIVE
 */

#include <ast.h>
#include <ccode.h>

void*
ccnative(void* b, const void* a, size_t n)
{
#if CC_ASCII == CC_NATIVE
	return memcpy(b, a, n * (UCHAR_MAX + 1));
#else
	register int			c;
	register const unsigned char*	m;
	register unsigned char*		cb = (unsigned char*)b;
	register unsigned char*		ca = (unsigned char*)a;

	m = CCMAP(CC_ASCII, CC_NATIVE);
	if (n == sizeof(char))
		for (c = 0; c <= UCHAR_MAX; c++)
			cb[c] = ca[m[c]];
	else
		for (c = 0; c <= UCHAR_MAX; c++)
			memcpy(cb + n * c, ca + n * m[c], n);
	return b;
#endif
}
