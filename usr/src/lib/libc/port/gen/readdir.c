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

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * readdir -- C library extension routine
 */

#include	<sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak _readdir64 = readdir64
#endif
#pragma weak _readdir = readdir

#include "lint.h"
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include "libc.h"

#ifdef _LP64

dirent_t *
readdir(DIR *dirp)
{
	dirent_t *dp;	/* -> directory data */
	int saveloc = 0;

	if (dirp->dd_size != 0) {
		dp = (dirent_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		saveloc = dirp->dd_loc;		/* save for possible EOF */
		dirp->dd_loc += (int)dp->d_reclen;
	}
	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if (dirp->dd_size == 0 && 	/* refill buffer */
	    (dirp->dd_size = getdents(dirp->dd_fd,
	    (dirent_t *)(uintptr_t)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0)		/* This means EOF */
			dirp->dd_loc = saveloc;	/* so save for telldir */
		return (NULL);		/* error or EOF */
	}

	return ((dirent_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc]);
}

#else	/* _LP64 */

/*
 * Welcome to the complicated world of large files on a small system.
 */

dirent64_t *
readdir64(DIR *dirp)
{
	dirent64_t *dp64;	/* -> directory data */
	int saveloc = 0;

	if (dirp->dd_size != 0) {
		dp64 = (dirent64_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
		/* was converted by readdir and needs to be reversed */
		if (dp64->d_ino == (ino64_t)-1) {
			dirent_t *dp32;

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

	if (dirp->dd_size == 0 && 	/* refill buffer */
	    (dirp->dd_size = getdents64(dirp->dd_fd,
	    (dirent64_t *)(uintptr_t)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0)		/* This means EOF */
			dirp->dd_loc = saveloc;	/* so save for telldir */
		return (NULL);		/* error or EOF */
	}

	dp64 = (dirent64_t *)(uintptr_t)&dirp->dd_buf[dirp->dd_loc];
	return (dp64);
}

/*
 * readdir now does translation of dirent64 entries into dirent entries.
 * We rely on the fact that dirents are smaller than dirent64s and we
 * reuse the space accordingly.
 */
dirent_t *
readdir(DIR *dirp)
{
	dirent64_t *dp64;	/* -> directory data */
	dirent_t *dp32;		/* -> directory data */

	if ((dp64 = readdir64(dirp)) == NULL)
		return (NULL);

	/*
	 * Make sure that the offset fits in 32 bits.
	 */
	if (((off_t)dp64->d_off != dp64->d_off &&
	    (uint64_t)dp64->d_off > (uint64_t)UINT32_MAX) ||
	    dp64->d_ino > SIZE_MAX) {
		errno = EOVERFLOW;
		return (NULL);
	}

	dp32 = (dirent_t *)(&dp64->d_off);
	dp32->d_off = (off_t)dp64->d_off;
	dp32->d_ino = (ino_t)dp64->d_ino;
	dp32->d_reclen = (unsigned short)(dp64->d_reclen -
	    ((char *)&dp64->d_off - (char *)dp64));
	dp64->d_ino = (ino64_t)-1;	/* flag as converted for readdir64 */
	/* d_name d_reclen should not move */
	return (dp32);
}
#endif	/* _LP64 */
