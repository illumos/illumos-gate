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
/*
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Filesystem-independent directory information.
 */

#ifndef	__dirent_h
#define	__dirent_h

#include <sys/types.h>

#ifndef	_POSIX_SOURCE
#define	d_ino	d_fileno	/* compatability */
#ifndef	NULL
#define	NULL	0
#endif
#endif	/* !_POSIX_SOURCE */

/*
 * Definitions for library routines operating on directories.
 */
typedef	struct __dirdesc {
	int	dd_fd;		/* file descriptor */
	long	dd_loc;		/* buf offset of entry from last readddir() */
	long	dd_size;	/* amount of valid data in buffer */
	long	dd_bsize;	/* amount of entries read at a time */
	long	dd_off;		/* Current offset in dir (for telldir) */
	char	*dd_buf;	/* directory data buffer */
} DIR;

extern	DIR *opendir(/* char *dirname */);
extern	struct dirent *readdir(/* DIR *dirp */);
extern	int closedir(/* DIR *dirp */);
#ifndef	_POSIX_SOURCE
extern	void seekdir(/* DIR *dirp, int loc */);
extern	long telldir(/* DIR *dirp */);
#endif	/* POSIX_SOURCE */
extern	void rewinddir(/* DIR *dirp */);

#ifndef	lint
#define	rewinddir(dirp)	seekdir((dirp), (long)0)
#endif

#include <sys/dirent.h>

#endif	/* !__dirent_h */
