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
 * AT&T Bell Laboratories
 *
 * mode_t representation support
 */

#include "modelib.h"

/*
 * convert internal mode to external
 */

#undef	modex

int
modex(register int i)
{
#if _S_IDPERM && _S_IDTYPE
	return(i);
#else
	register int	x;
	register int	c;

	x = 0;
#if _S_IDPERM
	x |= (i & 07777);
#else
	for (c = 0; c < PERMLEN; c++)
		if (i & permmap[c++])
			x |= permmap[c];
#endif
#if _S_IDTYPE
	x |= (i & X_IFMT);
#else
	if (S_ISREG(i)) x |= X_IFREG;
	else if (S_ISDIR(i)) x |= X_IFDIR;
#ifdef S_ISLNK
	else if (S_ISLNK(i)) x |= X_IFLNK;
#endif
	else if (S_ISBLK(i)) x |= X_IFBLK;
	else if (S_ISCHR(i)) x |= X_IFCHR;
#ifdef S_ISCTG
	else if (S_ISCTG(i)) x |= X_IFCTG;
#endif
	else if (S_ISFIFO(i)) x |= X_IFIFO;
#ifdef S_ISSOCK
	else if (S_ISSOCK(i)) x |= X_IFSOCK;
#endif
#endif
	return(x);
#endif
}
