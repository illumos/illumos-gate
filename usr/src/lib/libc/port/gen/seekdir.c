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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * seekdir -- C library extension routine
 */

#include	<sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak seekdir64 = _seekdir64
#endif
#pragma weak seekdir = _seekdir

#include	"synonyms.h"
#include	<mtlib.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<dirent.h>
#include	<thread.h>
#include	<synch.h>


extern mutex_t	_dirent_lock;

#ifdef _LP64

void
seekdir(DIR *dirp, long loc)
{
	struct dirent	*dp;
	off_t		off = 0;

	lmutex_lock(&_dirent_lock);
	if (lseek(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp = (struct dirent *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
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
		((struct dirent *)(uintptr_t)&dirp->dd_buf[0])->d_off = loc;
	}
	lmutex_unlock(&_dirent_lock);
}

#else	/* _LP64 */

static void
seekdir64(DIR *dirp, off64_t loc)
{
	struct dirent64	*dp64;
	off64_t		off = 0;

	lmutex_lock(&_dirent_lock);
	if (lseek64(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp64 = (struct dirent64 *)
			(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		/* was converted by readdir and needs to be reversed */
		if (dp64->d_ino == (ino64_t)-1) {
			struct dirent	*dp32;

			dp32 = (struct dirent *)
			    ((uintptr_t)dp64 + sizeof (ino64_t));
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
		((struct dirent64 *)(uintptr_t)&dirp->dd_buf[0])->d_off = loc;
	}
	lmutex_unlock(&_dirent_lock);
}

void
seekdir(DIR *dirp, long loc)
{
	seekdir64(dirp, (off64_t)loc);
}

#endif	/* _LP64 */
