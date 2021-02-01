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
 * AT&T Bell Laboratories
 *
 * mode_t representation support
 */

#include "modelib.h"

/*
 * convert external mode to internal
 *
 * NOTE: X_IFMT ignored
 */

#undef	modei

int
modei(register int x)
{
#if _S_IDPERM
	return(x & X_IPERM);
#else
	register int	i;
	register int	c;

	i = 0;
	for (c = 0; c < PERMLEN; c += 2)
		if (x & permmap[c + 1])
			i |= permmap[c];
	return(i);
#endif
}
