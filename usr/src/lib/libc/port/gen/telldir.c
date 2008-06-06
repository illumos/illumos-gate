/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * telldir -- C library extension routine
 */

#include <sys/isa_defs.h>

#if !defined(_LP64)
#pragma weak _telldir64 = telldir64
#endif
#pragma weak _telldir = telldir

#include "lint.h"
#include "libc.h"
#include <mtlib.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef _LP64

long
telldir(DIR *dirp)
{
	private_DIR	*pdirp = (private_DIR *)dirp;
	dirent_t	*dp;
	off_t		off = 0;

	lmutex_lock(&pdirp->dd_lock);
	/* if at beginning of dir, return 0 */
	if (lseek(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp = (dirent_t *)(uintptr_t)(&dirp->dd_buf[dirp->dd_loc]);
		off = dp->d_off;
	}
	lmutex_unlock(&pdirp->dd_lock);
	return (off);
}

#else

/*
 * Note: Instead of making this function static, we reduce it to local
 * scope in the mapfile. That allows the linker to prevent it from
 * appearing in the .SUNW_dynsymsort section.
 */
off64_t
telldir64(DIR *dirp)
{
	private_DIR	*pdirp = (private_DIR *)(uintptr_t)dirp;
	dirent64_t	*dp64;
	off64_t		off = 0;

	lmutex_lock(&pdirp->dd_lock);
	/* if at beginning of dir, return 0 */
	if (lseek64(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp64 = (dirent64_t *)(uintptr_t)(&dirp->dd_buf[dirp->dd_loc]);
		/* was converted by readdir and needs to be reversed */
		if (dp64->d_ino == (ino64_t)-1) {
			dirent_t *dp32;

			dp32 = (dirent_t *)((uintptr_t)dp64 + sizeof (ino64_t));
			dp64->d_ino = (ino64_t)dp32->d_ino;
			dp64->d_off = (off64_t)dp32->d_off;
			dp64->d_reclen = (unsigned short)(dp32->d_reclen +
			    ((char *)&dp64->d_off - (char *)dp64));
		}
		off = dp64->d_off;
	}
	lmutex_unlock(&pdirp->dd_lock);
	return (off);
}

long
telldir(DIR *dirp)
{
	off64_t off;

	off = telldir64(dirp);

	/*
	 * Make sure that the offset fits in 32 bits.
	 */
	if ((long)off != off && (uint64_t)off > (uint64_t)UINT32_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	return ((long)off);
}

#endif	/* _LP64 */
