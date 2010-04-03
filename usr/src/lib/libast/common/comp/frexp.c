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
 * frexp/ldexp implementation
 */

#include <ast.h>

#include "FEATURE/float"

#if _lib_frexp && _lib_ldexp

NoN(frexp)

#else

#if defined(_ast_dbl_exp_index) && defined(_ast_dbl_exp_shift)

#define INIT()		_ast_dbl_exp_t _pow_
#define pow2(i)		(_pow_.f=1,_pow_.e[_ast_dbl_exp_index]+=((i)<<_ast_dbl_exp_shift),_pow_.f)

#else

static double		pow2tab[DBL_MAX_EXP + 1];

static int
init(void)
{
	register int	x;
	double		g;

	g = 1;
	for (x = 0; x < elementsof(pow2tab); x++)
	{
		pow2tab[x] = g;
		g *= 2;
	}
	return 0;
}

#define INIT()		(pow2tab[0]?0:init())

#define pow2(i)		pow2tab[i]

#endif

#if !_lib_frexp

extern double
frexp(double f, int* p)
{
	register int	k;
	register int	x;
	double		g;

	INIT();

	/*
	 * normalize
	 */

	x = k = DBL_MAX_EXP / 2;
	if (f < 1)
	{
		g = 1.0L / f;
		for (;;)
		{
			k = (k + 1) / 2;
			if (g < pow2(x))
				x -= k;
			else if (k == 1 && g < pow2(x+1))
				break;
			else
				x += k;
		}
		if (g == pow2(x))
			x--;
		x = -x;
	}
	else if (f > 1)
	{
		for (;;)
		{
			k = (k + 1) / 2;
			if (f > pow2(x))
				x += k;
			else if (k == 1 && f > pow2(x-1))
				break;
			else
				x -= k;
		}
		if (f == pow2(x))
			x++;
	}
	else
		x = 1;
	*p = x;

	/*
	 * shift
	 */

	x = -x;
	if (x < 0)
		f /= pow2(-x);
	else if (x < DBL_MAX_EXP)
		f *= pow2(x);
	else
		f = (f * pow2(DBL_MAX_EXP - 1)) * pow2(x - (DBL_MAX_EXP - 1));
	return f;
}

#endif

#if !_lib_ldexp

extern double
ldexp(double f, register int x)
{
	INIT();
	if (x < 0)
		f /= pow2(-x);
	else if (x < DBL_MAX_EXP)
		f *= pow2(x);
	else
		f = (f * pow2(DBL_MAX_EXP - 1)) * pow2(x - (DBL_MAX_EXP - 1));
	return f;
}

#endif

#endif
