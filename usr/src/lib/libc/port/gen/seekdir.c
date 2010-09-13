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
 * seekdir -- C library extension routine
 */

#include	<sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak _seekdir64 = seekdir64
#endif
#pragma weak _seekdir = seekdir

#include "lint.h"
#include "libc.h"
#include <mtlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef _LP64

void
seekdir(DIR *dirp, long loc)
{
	private_DIR	*pdirp = (private_DIR *)dirp;
	dirent_t	*dp;
	off_t		off = 0;

	lmutex_lock(&pdirp->dd_lock);
	if (lseek(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp = (dirent_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		off = dp->d_off;
	}
	if (off != loc) {
		dirp->dd_loc = 0;
		(void) lseek(dirp->dd_fd, loc, SEEK_SET);
		dirp->dd_size = 0;

		/*
		 * Save seek offset in d_off field, in case telldir
		 * follows seekdir with no intervening call to readdir
		 */
		((dirent_t *)(uintptr_t)&dirp->dd_buf[0])->d_off = loc;
	}
	lmutex_unlock(&pdirp->dd_lock);
}

#else	/* _LP64 */

/*
 * Note: Instead of making this function static, we reduce it to local
 * scope in the mapfile. That allows the linker to prevent it from
 * appearing in the .SUNW_dynsymsort section.
 */
void
seekdir64(DIR *dirp, off64_t loc)
{
	private_DIR	*pdirp = (private_DIR *)(uintptr_t)dirp;
	dirent64_t	*dp64;
	off64_t		off = 0;

	lmutex_lock(&pdirp->dd_lock);
	if (lseek64(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp64 = (dirent64_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
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
	if (off != loc) {
		dirp->dd_loc = 0;
		(void) lseek64(dirp->dd_fd, loc, SEEK_SET);
		dirp->dd_size = 0;

		/*
		 * Save seek offset in d_off field, in case telldir
		 * follows seekdir with no intervening call to readdir
		 */
		((dirent64_t *)(uintptr_t)&dirp->dd_buf[0])->d_off = loc;
	}
	lmutex_unlock(&pdirp->dd_lock);
}

void
seekdir(DIR *dirp, long loc)
{
	seekdir64(dirp, (off64_t)(uint32_t)loc);
}

#endif	/* _LP64 */
