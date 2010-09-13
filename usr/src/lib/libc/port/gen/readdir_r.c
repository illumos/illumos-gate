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
 * readdir_r -- C library extension routine
 */

#include	<sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak _readdir64_r = readdir64_r
#endif

#include "lint.h"
#include "libc.h"
#include <mtlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef _LP64

/*
 * POSIX.1c standard version of the thread function readdir_r.
 */

int
readdir_r(DIR *dirp, dirent_t *entry, dirent_t **result)
{
	private_DIR *pdirp = (private_DIR *)dirp;
	dirent_t *dp;		/* -> directory data */
	int saveloc = 0;

	lmutex_lock(&pdirp->dd_lock);
	if (dirp->dd_size != 0) {
		dp = (dirent_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		saveloc = dirp->dd_loc;		/* save for possible EOF */
		dirp->dd_loc += (int)dp->d_reclen;
	}

	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if (dirp->dd_size == 0 &&	/* refill buffer */
	    (dirp->dd_size = getdents(dirp->dd_fd,
	    (dirent_t *)(uintptr_t)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0) {	/* This means EOF */
			dirp->dd_loc = saveloc;	/* so save for telldir */
			lmutex_unlock(&pdirp->dd_lock);
			*result = NULL;
			return (0);
		}
		lmutex_unlock(&pdirp->dd_lock);
		*result = NULL;
		return (errno);		/* error */
	}

	dp = (dirent_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
	(void) memcpy(entry, dp, (size_t)dp->d_reclen);
	lmutex_unlock(&pdirp->dd_lock);
	*result = entry;
	return (0);
}

#else	/* _LP64 */

/*
 * POSIX.1c standard version of the thr function readdir_r.
 * Large file version.
 */

int
readdir64_r(DIR *dirp, dirent64_t *entry, dirent64_t **result)
{
	private_DIR *pdirp = (private_DIR *)(uintptr_t)dirp;
	dirent64_t *dp64;	/* -> directory data */
	int saveloc = 0;

	lmutex_lock(&pdirp->dd_lock);
	if (dirp->dd_size != 0) {
		dp64 = (dirent64_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		/* was converted by readdir and needs to be reversed */
		if (dp64->d_ino == (ino64_t)-1) {
			dirent_t *dp32;	/* -> 32 bit directory data */

			dp32 = (dirent_t *)(&dp64->d_off);
			dp64->d_ino = (ino64_t)dp32->d_ino;
			dp64->d_off = (off64_t)dp32->d_off;
			dp64->d_reclen = (unsigned short)(dp32->d_reclen +
			    ((char *)&dp64->d_off - (char *)dp64));
		}
		saveloc = dirp->dd_loc;		/* save for possible EOF */
		dirp->dd_loc += (int)dp64->d_reclen;
	}

	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if (dirp->dd_size == 0 &&	/* refill buffer */
	    (dirp->dd_size = getdents64(dirp->dd_fd,
	    (dirent64_t *)(uintptr_t)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0) {	/* This means EOF */
			dirp->dd_loc = saveloc;	/* so save for telldir */
			lmutex_unlock(&pdirp->dd_lock);
			*result = NULL;
			return (0);
		}
		lmutex_unlock(&pdirp->dd_lock);
		*result = NULL;
		return (errno);		/* error */
	}

	dp64 = (dirent64_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
	(void) memcpy(entry, dp64, (size_t)dp64->d_reclen);
	*result = entry;
	lmutex_unlock(&pdirp->dd_lock);
	return (0);
}

/*
 * POSIX.1c standard version of the function readdir_r.
 * User gets it via static readdir_r from header file.
 */

int
__posix_readdir_r(DIR *dirp, dirent_t *entry, dirent_t **result)
{
	int error;
	dirent64_t *dp64;
	struct {
		dirent64_t dirent64;
		char chars[MAXNAMLEN];
	} buf;

	error = readdir64_r(dirp, (dirent64_t *)&buf, &dp64);
	if (error != 0 || dp64 == NULL) {
		*result = NULL;
		return (error);
	}

	if (dp64->d_ino > SIZE_MAX ||
	    (uint64_t)dp64->d_off > (uint64_t)UINT32_MAX) {
		*result = NULL;
		return (EOVERFLOW);
	}

	entry->d_ino = (ino_t)dp64->d_ino;
	entry->d_off = (off_t)dp64->d_off;
	entry->d_reclen = (unsigned short)((((char *)entry->d_name -
	    (char *)entry) + strlen(dp64->d_name) + 1 + 3) & ~3);
	(void) strcpy(entry->d_name, dp64->d_name);
	*result = entry;
	return (0);
}

/*
 * POSIX.1c Draft-6 version of the function readdir_r.
 * It was implemented by Solaris 2.3.
 */

dirent_t *
readdir_r(DIR *dirp, dirent_t *entry)
{
	int error;
	dirent_t *result;

	if ((error = __posix_readdir_r(dirp, entry, &result)) != 0)
		errno = error;
	return (result);
}

#endif	/* _LP64 */
