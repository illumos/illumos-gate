/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.14	*/
/* LINTLIBRARY */

#include "unistd.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "errno.h"
#include "fcntl.h"
#include "stdlib.h"
#include "string.h"

/**
 ** Auto-restarting system calls:
 **/

int
#if	defined(__STDC__)
_Access (
	char *			s,
	int			i
)
#else
_Access (s, i)
	char *			s;
	int			i;
#endif
{
	register int		n;

	while ((n = access(s, i)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Chdir (
	char *			s
)
#else
_Chdir (s)
	char *			s;
#endif
{
	register int		n;

	while ((n = chdir(s)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Chmod (
	char *			s,
	int			i
)
#else
_Chmod (s, i)
	char *			s;
	int			i;
#endif
{
	register int		n;

	while ((n = chmod(s, i)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Chown (
	char *			s,
	int			i,
	int			j
)
#else
_Chown (s, i, j)
	char *			s;
	int			i;
	int			j;
#endif
{
	register int		n;

	while ((n = chown(s, i, j)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Close (
	int			i
)
#else
_Close (i)
	int			i;
#endif
{
	register int		n;

	while ((n = close(i)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Creat (
	char *			s,
	int			i
)
#else
_Creat (s, i)
	char *			s;
	int			i;
#endif
{
	register int		n;

	while ((n = creat(s, i)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Fcntl (
	int			i,
	int			j,
	struct flock *		k
)
#else
_Fcntl (i, j, k)
	int			i;
	int			j;
	struct flock *		k;
#endif
{
	register int		n;

	while ((n = fcntl(i, j, k)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Fstat (
	int			i,
	struct stat *		st
)
#else
_Fstat (i, st)
	int			i;
	struct stat *		st;
#endif
{
	register int		n;

	while ((n = fstat(i, st)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Link (
	char *			s1,
	char *			s2
)
#else
_Link (s1, s2)
	char *			s1;
	char *			s2;
#endif
{
	register int		n;

	while ((n = link(s1, s2)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Lstat (
	char *			s,
	struct stat *		st
)
#else
_Lstat (s, st)
	char *			s;
	struct stat *		st;
#endif
{
	register int		n;

	while ((n = lstat(s, st)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Mknod (
	char *			s,
	int			i,
	int			j
)
#else
_Mknod (s, i, j)
	char *			s;
	int			i;
	int			j;
#endif
{
	register int		n;

	while ((n = mknod(s, i, j)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Open (
	char *			s,
	int			i,
	int			j
)
#else
_Open (s, i, j)
	char *			s;
	int			i;
	int			j;
#endif
{
	register int		n;

	while ((n = open(s, i, j)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Read (
	int			i,
	char *			s,
	unsigned int		j
)
#else
_Read (i, s, j)
	int			i;
	char *			s;
	unsigned int		j;
#endif
{
	register int		n;

	while ((n = read(i, s, j)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Readlink (
	char *			s1,
	char *			s2,
	unsigned int		j
)
#else
_Readlink (s1, s2, j)
	char *			s1;
	char *			s2;
	unsigned int		j;
#endif
{
	register int		n;

	while ((n = readlink(s1, s2, j)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Rename (
	char *			s1,
	char *			s2
)
#else
_Rename (s1, s2)
	char *			s1;
	char *			s2;
#endif
{
	register int		n;

	while  ((n = rename(s1, s2)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Stat (
	char *			s,
	struct stat *		st
)
#else
_Stat (s, st)
	char *			s;
	struct stat *		st;
#endif
{
	register int		n;

	while ((n = stat(s, st)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Symlink (
	char *			s1,
	char *			s2
)
#else
_Symlink (s1, s2)
	char *			s1;
	char *			s2;
#endif
{
	register int		n;

	while ((n = symlink(s1, s2)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Unlink (
	char *			s
)
#else
_Unlink (s)
	char *			s;
#endif
{
	register int		n;

	while ((n = unlink(s)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Wait (
	int *			i
)
#else
_Wait (i)
	int *			i;
#endif
{
	register int		n;

	while ((n = wait(i)) == -1 && errno == EINTR)
		;
	return (n);
}

int
#if	defined(__STDC__)
_Write (
	int			i,
	char *			s,
	unsigned int		j
)
#else
_Write (i, s, j)
	int			i;
	char *			s;
	unsigned int		j;
#endif
{
	register int		n;

	while ((n = write(i, s, j)) == -1 && errno == EINTR)
		;
	return (n);
}
