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

#include <ast.h>

#if _lib_mkdir

NoN(mkdir)

#else

#include <ls.h>
#include <wait.h>
#include <error.h>

int
mkdir(const char* path, mode_t mode)
{
	register int	n;
	char*		av[3];

	static char*	cmd[] = { "/bin/mkdir", 0 };


	n = errno;
	if (!access(path, F_OK))
	{
		errno = EEXIST;
		return(-1);
	}
	if (errno != ENOENT) return(-1);
	errno = n;
	av[0] = "mkdir";
	av[1] = path;
	av[2] = 0;
	for (n = 0; n < elementsof(cmd); n++)
		if (procclose(procopen(cmd[n], av, NiL, NiL, 0)) != -1)
			break;
	return(chmod(path, mode));
}

#endif
