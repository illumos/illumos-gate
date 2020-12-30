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

#include "dirlib.h"

#if _dir_ok || _lib_getdents

NoN(getdents)

#else

/*
 * getdents
 *
 * read directory entries into directory block
 *
 * NOTE: directory entries must fit within DIRBLKSIZ boundaries
 */

#ifndef MAXNAMLEN
#define MAXNAMLEN	255
#endif

#if _lib_dirread
extern int		dirread(int, char*, int);
#endif
#if _lib_getdirentries
extern int		getdirentries(int, char*, int, long*);
#endif

ssize_t
getdents(int fd, void* buf, size_t siz)
{
	struct stat		st;

	if (siz < DIRBLKSIZ)
	{
		errno = EINVAL;
		return(-1);
	}
	if (fstat(fd, &st)) return(-1);
	if (!S_ISDIR(st.st_mode))
	{
#ifdef ENOTDIR
		errno = ENOTDIR;
#else
		errno = EBADF;
#endif
		return(-1);
	}
#if _lib_getdirentries
	{
		long		off;
		return(getdirentries(fd, buf, siz, &off));
	}
#else
#if _lib_dirread
	{
		register char*		sp;	/* system */
		register struct dirent*	up;	/* user */
		char*			u;
		int			n;
		int			m;
		int			i;

		m = (siz * 6) / 10;
		m = roundof(m, 8);
		sp = (char*)buf + siz - m - 1;
		if (!(n = dirread(fd, sp, m))) return(0);
		if (n > 0)
		{
			up = (struct dirent*)buf;
			sp[n] = 0;
			while (sp < (char*)buf + siz - m + n)
			{
				i = 0;
				while (*sp >= '0' && *sp <= '9')
					i = 10 * i + *sp++ - '0';
				while (*sp && *sp != '\t') sp++;
				if (*sp++)
				{
					up->d_fileno = i;
					u = up->d_name;
					while ((*u = *sp++) && u < up->d_name + MAXNAMLEN) u++;
					*u = 0;
					up->d_reclen = sizeof(struct dirent) - sizeof(up->d_name) + (up->d_namlen = u - up->d_name) + 1;
					up->d_reclen = roundof(up->d_reclen, 8);
					up = (struct dirent*)((char*)up + up->d_reclen);
				}
			}
			return((char*)up - (char*)buf);
		}
	}
#else
#if _mem_d_reclen_direct
	return(read(fd, buf, siz));
#else
	{

#define MAXREC	roundof(sizeof(*up)-sizeof(up->d_name)+sizeof(sp->d_name)+1,8)

		register struct direct*	sp;	/* system */
		register struct dirent*	up;	/* user */
		register char*		s;
		register char*		u;
		int			n;
		int			m;
		char			tmp[sizeof(sp->d_name) + 1];

		/*
		 * we assume sizeof(struct dirent) > sizeof(struct direct)
		 */

		up = (struct dirent*)buf;
		n = (siz / MAXREC) * sizeof(struct direct);
		if ((!(m = n & ~511) || m < MAXREC) && (!(m = n & ~255) || m < MAXREC)) m = n;
		do
		{
			if ((n = read(fd, (char*)buf + siz - m, m)) <= 0) break;
			sp = (struct direct*)((char*)buf + siz - m);
			while (sp < (struct direct*)((char*)buf + siz - m + n))
			{
				if (sp->d_ino)
				{
					up->d_fileno = sp->d_ino;
					s = sp->d_name;
					u = tmp;
					while (s < sp->d_name + sizeof(sp->d_name) && *s)
						*u++ = *s++;
					*u = 0;
					strcpy(up->d_name, tmp);
					up->d_reclen = sizeof(struct dirent) - sizeof(up->d_name) + (up->d_namlen = u - tmp) + 1;
					up->d_reclen = roundof(up->d_reclen, 8);
					up = (struct dirent*)((char*)up + up->d_reclen);
				}
				sp++;
			}
		} while (up == (struct dirent*)buf);
		return((char*)up - (char*)buf);
	}
#endif
#endif
#endif
}

#endif
