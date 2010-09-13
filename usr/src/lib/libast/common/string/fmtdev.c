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
 * idevice() formatter
 */

#include <ast.h>
#include <ctype.h>
#include <ls.h>

char*
fmtdev(struct stat* st)
{
	char*		buf;
	int		z;

	unsigned int	ma = major(idevice(st));
	unsigned int	mi = minor(idevice(st));

	buf = fmtbuf(z = 17);
	if (ma == '#' && isalnum(mi))
	{
		/*
		 * Plan? Nein!
		 */

		buf[0] = ma;
		buf[1] = mi;
		buf[2] = 0;
	}
	else
		sfsprintf(buf, z, "%03d,%03d", ma, mi);
	return buf;
}
