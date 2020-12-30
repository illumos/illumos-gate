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
#include	"sfhdr.h"

/*	Return the length of a double value if coded in a portable format
**
**	Written by Kiem-Phong Vo
*/

#if __STD_C
int _sfdlen(Sfdouble_t v)
#else
int _sfdlen(v)
Sfdouble_t	v;
#endif
{
#define N_ARRAY		(16*sizeof(Sfdouble_t))
	reg int		n, w;
	Sfdouble_t	x;
	int		exp;

	if(v < 0)
		v = -v;

	/* make the magnitude of v < 1 */
	if(v != 0.)
		v = frexpl(v,&exp);
	else	exp = 0;

	for(w = 1; w <= N_ARRAY; ++w)
	{	/* get 2^SF_PRECIS precision at a time */
		n = (int)(x = ldexpl(v,SF_PRECIS));
		v = x-n;
		if(v <= 0.)
			break;
	}

	return 1 + sfulen(exp) + w;
}
