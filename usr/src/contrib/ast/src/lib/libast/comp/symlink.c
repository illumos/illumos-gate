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

#include <ast.h>

#if _lib_symlink

NoN(symlink)

#else

#include "fakelink.h"

#include <error.h>

#ifndef ENOSYS
#define ENOSYS	EINVAL
#endif

int
symlink(const char* a, char* b)
{
	if (*a == '/' && (*(a + 1) == 'd' || *(a + 1) == 'p' || *(a + 1) == 'n') && (!strncmp(a, "/dev/tcp/", 9) || !strncmp(a, "/dev/udp/", 9) || !strncmp(a, "/proc/", 6) || !strncmp(a, "/n/", 3)))
	{
		int	n;
		int	fd;

		if ((fd = open(b, O_CREAT|O_TRUNC|O_WRONLY|O_cloexec, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) < 0)
			return -1;
		n = strlen(a) + 1;
		n = (write(fd, FAKELINK_MAGIC, sizeof(FAKELINK_MAGIC)) != sizeof(FAKELINK_MAGIC) || write(fd, a, n) != n) ? -1 : 0;
		close(fd);
		return n;
	}
	errno = ENOSYS;
	return -1;
}

#endif
