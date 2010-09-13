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
 * seekdir
 *
 * seek on directory stream
 * this is not optimal because there aren't portable
 * semantics for directory seeks
 */

#include "dirlib.h"

#if _dir_ok

NoN(seekdir)

#else

void
seekdir(register DIR* dirp, long loc)
{
	off_t	base;		/* file location of block */
	off_t	offset; 	/* offset within block */

	if (telldir(dirp) != loc)
	{
		lseek(dirp->dd_fd, 0L, SEEK_SET);
		dirp->dd_loc = dirp->dd_size = 0;
		while (telldir(dirp) != loc)
			if (!readdir(dirp))
				break; 	/* "can't happen" */
	}
}

#endif
