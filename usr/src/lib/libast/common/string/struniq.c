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
 * struniq - uniq a sorted argv
 * 0 sentinel is neither expected nor restored
 *
 * Glenn Fowler
 * David Korn
 * AT&T Research
 */

#include <ast.h>

int
struniq(char** argv, int n)
{
	register char**	ao;
	register char**	an;
	register char**	ae;

	ao = an = argv;
	ae = ao + n;
	while (++an < ae)
	{
		while (streq(*ao, *an))
			if (++an >= ae)
				return ao - argv + 1;
		*++ao = *an;
	}
	return ao - argv + 1;
}
