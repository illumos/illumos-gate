/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * AT&T Research
 *
 * string vector load support
 */

#include <ast.h>
#include <ls.h>
#include <vecargs.h>

/*
 * load a string vector from lines in file
 */

char**
vecfile(const char* file)
{
	register int	n;
	register char*	buf;
	register char**	vec;
	int		fd;
	struct stat	st;

	vec = 0;
	if ((fd = open(file, O_RDONLY|O_cloexec)) >= 0)
	{
		if (!fstat(fd, &st) && S_ISREG(st.st_mode) && (n = st.st_size) > 0 && (buf = newof(0, char, n + 1, 0)))
		{
			if (read(fd, buf, n) == n)
			{
				buf[n] = 0;
				vec = vecload(buf);
			}
			if (!vec) free(buf);
		}
		close(fd);
	}
	return(vec);
}
