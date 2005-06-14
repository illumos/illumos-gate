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
 * telldir -- C library extension routine
 */

#include <sys/isa_defs.h>

#if !defined(_LP64)
#pragma weak telldir64 = _telldir64
#endif
#pragma weak telldir = _telldir

#include "synonyms.h"
#include <mtlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <thread.h>
#include <errno.h>
#include <limits.h>
#include <synch.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

extern mutex_t	_dirent_lock;

#ifdef _LP64

long
telldir(DIR *dirp)
{
	struct dirent	*dp;
	off_t off = 0;

	lmutex_lock(&_dirent_lock);
	/* if at beginning of dir, return 0 */
	if (lseek(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp = (struct dirent *)(uintptr_t)(&dirp->dd_buf[dirp->dd_loc]);
		off = dp->d_off;
	}
	lmutex_unlock(&_dirent_lock);
	return (off);
}

#else

static off64_t
telldir64(DIR *dirp)
{
	struct dirent64	*dp64;
	off64_t		off = 0;

	lmutex_lock(&_dirent_lock);
	/* if at beginning of dir, return 0 */
	if (lseek64(dirp->dd_fd, 0, SEEK_CUR) != 0) {
		dp64 = (struct dirent64 *)
			(uintptr_t)(&dirp->dd_buf[dirp->dd_loc]);
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
	lmutex_unlock(&_dirent_lock);
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
	if ((long)off != off &&
		(uint64_t)off > (uint64_t)UINT32_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	return ((long)off);
}

#endif	/* _LP64 */
