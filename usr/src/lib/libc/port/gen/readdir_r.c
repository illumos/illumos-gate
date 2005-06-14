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
 * readdir_r -- C library extension routine
 */

#include	<sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak readdir64_r = _readdir64_r
#endif
#pragma weak readdir_r = _readdir_r

#include	"synonyms.h"
#include	<mtlib.h>
#include	<sys/types.h>
#include	<sys/dirent.h>
#include	<dirent.h>
#include	<thread.h>
#include	<string.h>
#include	<synch.h>
#include	<stdio.h>
#include	<limits.h>
#include	<errno.h>
#include	"libc.h"

extern mutex_t	_dirent_lock;

#define	LBUFSIZE	(sizeof (struct dirent64) + _POSIX_PATH_MAX + 1)

#ifdef _LP64

/*
 * POSIX.1c standard version of the thread function readdir_r.
 */

int
readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
	struct dirent	*dp;	/* -> directory data */
	int saveloc = 0;

	lmutex_lock(&_dirent_lock);
	if (dirp->dd_size != 0) {
		dp = (struct dirent *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		saveloc = dirp->dd_loc;   /* save for possible EOF */
		dirp->dd_loc += (int)dp->d_reclen;
	}

	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if (dirp->dd_size == 0 &&	/* refill buffer */
	    (dirp->dd_size = getdents(dirp->dd_fd,
	    (struct dirent *)(uintptr_t)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0) { /* This means EOF */
			dirp->dd_loc = saveloc;  /* EOF so save for telldir */
			lmutex_unlock(&_dirent_lock);
			*result = NULL;
			return (0); /* EOF */
		}
		lmutex_unlock(&_dirent_lock);
		*result = NULL;
		return (errno);	/* error */
	}

	dp = (struct dirent *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
	(void) memcpy(entry, dp, (size_t)dp->d_reclen);
	lmutex_unlock(&_dirent_lock);
	*result = entry;
	return (0);
}

#else	/* _LP64 */

/*
 * POSIX.1c standard version of the thr function readdir_r.
 * Large file version.
 */

int
readdir64_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result)
{
	struct dirent64	*dp64;	/* -> directory data */
	int saveloc = 0;

	lmutex_lock(&_dirent_lock);
	if (dirp->dd_size != 0) {
		dp64 = (struct dirent64 *)
			(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		/* was converted by readdir and needs to be reversed */
		if (dp64->d_ino == (ino64_t)-1) {
			struct dirent	*dp32;	/* -> 32 bit directory data */

			dp32 = (struct dirent *)(&dp64->d_off);
			dp64->d_ino = (ino64_t)dp32->d_ino;
			dp64->d_off = (off64_t)dp32->d_off;
			dp64->d_reclen = (unsigned short)(dp32->d_reclen +
				((char *)&dp64->d_off - (char *)dp64));
		}
		saveloc = dirp->dd_loc;   /* save for possible EOF */
		dirp->dd_loc += (int)dp64->d_reclen;
	}

	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if (dirp->dd_size == 0 &&	/* refill buffer */
	    (dirp->dd_size = getdents64(dirp->dd_fd,
	    (struct dirent64 *)(uintptr_t)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0) { /* This means EOF */
			dirp->dd_loc = saveloc;  /* EOF so save for telldir */
			lmutex_unlock(&_dirent_lock);
			*result = NULL;
			return (0); /* EOF */
		}
		lmutex_unlock(&_dirent_lock);
		*result = NULL;
		return (errno);	/* error */
	}

	dp64 = (struct dirent64 *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
	(void) memcpy(entry, dp64, (size_t)dp64->d_reclen);
	*result = entry;
	lmutex_unlock(&_dirent_lock);
	return (0);
}

/*
 * POSIX.1c Draft-6 version of the function readdir_r.
 * It was implemented by Solaris 2.3.
 */

struct dirent *
readdir_r(DIR *dirp, struct dirent *entry)
{
	long buf[LBUFSIZE / sizeof (long) + 1];
	struct dirent64	*dp64;

	if (readdir64_r(dirp, (struct dirent64 *)(uintptr_t)buf, &dp64) != 0 ||
	    dp64 == NULL)
		return (NULL);

	if ((dp64->d_ino > SIZE_MAX) || ((uint64_t)dp64->d_off >
	    (uint64_t)UINT32_MAX)) {
		errno = EOVERFLOW;
		return (NULL);
	}

	entry->d_ino = (ino_t)dp64->d_ino;
	entry->d_off = (off_t)dp64->d_off;
	entry->d_reclen = (unsigned short)((((char *)entry->d_name -
	    (char *)entry) + strlen(dp64->d_name) + 1 + 3) & ~3);
	(void) strcpy(entry->d_name, dp64->d_name);

	return (entry);
}

/*
 * POSIX.1c standard version of the thr function readdir_r.
 * User gets it via static readdir_r from header file.
 */

int
__posix_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
	long buf[LBUFSIZE / sizeof (long) + 1];
	struct dirent64 *dp64;
	int ret;

	ret = readdir64_r(dirp, (struct dirent64 *)(uintptr_t)buf, &dp64);
	if (ret != 0 || dp64 == NULL) {
		*result = NULL;
		return (ret);
	}

	if ((dp64->d_ino > SIZE_MAX) || ((uint64_t)dp64->d_off >
		(uint64_t)UINT32_MAX)) {
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

#endif	/* _LP64 */
