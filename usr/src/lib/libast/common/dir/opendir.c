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
 * opendir, closedir
 *
 * open|close directory stream
 *
 * POSIX compatible directory stream access routines:
 *
 *	#include <sys/types.h>
 *	#include <dirent.h>
 *
 * NOTE: readdir() returns a pointer to struct dirent
 */

#include "dirlib.h"

#if _dir_ok

NoN(opendir)

#else

static const char id_dir[] = "\n@(#)$Id: directory (AT&T Research) 1993-04-01 $\0\n";

static DIR*	freedirp;		/* always keep one dirp */

DIR*
opendir(register const char* path)
{
	register DIR*	dirp = 0;
	register int	fd;
	struct stat	st;

	if ((fd = open(path, O_RDONLY)) < 0) return(0);
	if (fstat(fd, &st) < 0 ||
	   !S_ISDIR(st.st_mode) && (errno = ENOTDIR) ||
	   fcntl(fd, F_SETFD, FD_CLOEXEC) ||
	   !(dirp = freedirp ? freedirp :
#if defined(_DIR_PRIVATE_) || _ptr_dd_buf
	   newof(0, DIR, 1, DIRBLKSIZ)
#else
	   newof(0, DIR, 1, 0)
#endif
		))
	{
		close(fd);
		if (dirp)
		{
			if (!freedirp) freedirp = dirp;
			else free(dirp);
		}
		return(0);
	}
	freedirp = 0;
	dirp->dd_fd = fd;
	dirp->dd_loc = dirp->dd_size = 0;	/* refill needed */
#if defined(_DIR_PRIVATE_) || _ptr_dd_buf
	dirp->dd_buf = (void*)((char*)dirp + sizeof(DIR));
#endif
	return(dirp);
}

void
closedir(register DIR* dirp)
{
	if (dirp)
	{
		close(dirp->dd_fd);
		if (!freedirp) freedirp = dirp;
		else free(dirp);
	}
}

#endif
