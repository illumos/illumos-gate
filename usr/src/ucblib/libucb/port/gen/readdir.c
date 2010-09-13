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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

/*LINTLIBRARY*/

/*
 * readdir -- C library extension routine
 */

#include	<sys/types.h>
#include	<sys/dir.h>
#include 	<sys/dirent.h>
#include 	<limits.h>
#include 	<string.h>
#include 	<errno.h>
#include 	"libc.h"

static struct direct	dc;
static struct direct64	dc64;

static struct direct64 *
internal_readdir(DIR *dirp)
{
	struct dirent64	*dp;	/* -> directory data */
	int saveloc = 0;

	if (dirp->dd_size != 0) {
		dp = (struct dirent64 *)&dirp->dd_buf[dirp->dd_loc];
		saveloc = dirp->dd_loc;   /* save for possible EOF */
		dirp->dd_loc += dp->d_reclen;
	}
	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if (dirp->dd_size == 0 && 	/* refill buffer */
	    (dirp->dd_size = getdents64(dirp->dd_fd,
	    (struct dirent64 *)dirp->dd_buf, DIRBUF)) <= 0) {
		if (dirp->dd_size == 0)	/* This means EOF */
			dirp->dd_loc = saveloc;  /* EOF so save for telldir */
		return (NULL);	/* error or EOF */
	}

	dp = (struct dirent64 *)&dirp->dd_buf[dirp->dd_loc];

	/* Copy dirent into direct */
	dc64.d_ino = dp->d_ino;
	dc64.d_reclen = dp->d_reclen;
	dc64.d_namlen = (ushort_t)strlen(dp->d_name);
	if (dc64.d_namlen > MAXNAMLEN) {
		errno = ENAMETOOLONG;
		return (NULL);
	}
	(void) strcpy(dc64.d_name, dp->d_name);

	return (&dc64);
}

struct direct *
readdir(DIR *dirp)
{
	if (internal_readdir(dirp) == NULL)
		return (NULL);

	/* Check for overflows */
	if (dc64.d_ino > SIZE_MAX) {
		errno = EOVERFLOW;
		return (NULL);
	}

	/* Copy dirent into direct */
	dc.d_ino = dc64.d_ino;
	dc.d_reclen = dc64.d_reclen - 4;
	dc.d_namlen = dc64.d_namlen;
	(void) strcpy(dc.d_name, dc64.d_name);

	return (&dc);
}

#if !defined(_LP64)
struct direct64 *
readdir64(DIR *dirp)
{
	return (internal_readdir(dirp));
}
#endif
