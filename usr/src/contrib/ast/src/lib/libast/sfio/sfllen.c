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

/*	Get size of a long value coded in a portable format
**
**	Written by Kiem-Phong Vo
*/
#if __STD_C
int _sfllen(Sflong_t v)
#else
int _sfllen(v)
Sflong_t	v;
#endif
{
	if(v < 0)
		v = -(v+1);
	v = (Sfulong_t)v >> SF_SBITS;
	return 1 + (v > 0 ? sfulen(v) : 0);
}
