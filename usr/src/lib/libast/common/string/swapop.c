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
 * Glenn Fowler
 * AT&T Research
 *
 * internal representation conversion support
 */

#include <ast.h>
#include <swap.h>

/*
 * return the swap operation for external to internal conversion
 * if size<0 then (-size) used and (-size==4)&&(op==3) => op=7
 * this is a workaround for 4 byte magic predicting 8 byte swap
 */

int
swapop(const void* internal, const void* external, int size)
{
	register int	op;
	register int	z;
	char		tmp[sizeof(intmax_t)];

	if ((z = size) < 0)
		z = -z;
	if (z <= 1)
		return 0;
	if (z <= sizeof(intmax_t))
		for (op = 0; op < z; op++)
			if (!memcmp(internal, swapmem(op, external, tmp, z), z))
			{
				if (size < 0 && z == 4 && op == 3)
					op = 7;
				return op;
			}
	return -1;
}
