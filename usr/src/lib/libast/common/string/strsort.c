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
/*
 *  strsort - sort an array pointers using fn
 *
 *	fn follows strcmp(3) conventions
 *
 *   David Korn
 *   AT&T Bell Laboratories
 *
 *  derived from Bourne Shell
 */

#include <ast.h>

void
strsort(char** argv, int n, int(*fn)(const char*, const char*))
{
	register int 	i;
	register int 	j;
	register int 	m;
	register char**	ap;
	char*		s;
	int 		k;

	for (j = 1; j <= n; j *= 2);
	for (m = 2 * j - 1; m /= 2;)
		for (j = 0, k = n - m; j < k; j++)
			for (i = j; i >= 0; i -= m)
			{
				ap = &argv[i];
				if ((*fn)(ap[m], ap[0]) >= 0) break;
				s = ap[m];
				ap[m] = ap[0];
				ap[0] = s;
			}
}
