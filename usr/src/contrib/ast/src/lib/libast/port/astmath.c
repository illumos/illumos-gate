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
/*
 * used to test if -last requires -lm
 *
 *	arch		-last			-lm
 *	----		-----			---
 *	linux.sparc	sfdlen,sfputd		frexp,ldexp	
 */

#if N >= 8
#define _ISOC99_SOURCE	1
#endif

#include <math.h>

int
main()
{
#if N & 1
	long double	value = 0;
#else
	double		value = 0;
#endif
#if N < 5
	int		exp = 0;
#endif

#if N == 1
	return ldexpl(value, exp) != 0;
#endif
#if N == 2
	return ldexp(value, exp) != 0;
#endif
#if N == 3
	return frexpl(value, &exp) != 0;
#endif
#if N == 4
	return frexp(value, &exp) != 0;
#endif
#if N == 5
	return isnan(value);
#endif
#if N == 6
	return isnan(value);
#endif
#if N == 7
	return copysign(1.0, value) < 0;
#endif
#if N == 8
	return signbit(value);
#endif
}
