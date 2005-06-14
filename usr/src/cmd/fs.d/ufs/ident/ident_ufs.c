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

#ifndef lint
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#endif

#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<rpc/types.h>
#include	<sys/types.h>
#include	<sys/fs/ufs_fs.h>

#include	<rmmount.h>

/*
 * We call it a ufs file system iff:
 *	The magic number for the superblock is correct.
 *
 */

/*ARGSUSED*/
int
ident_fs(int fd, char *rawpath, int *clean, int verbose)
{
	struct fs *fs;

	/*
	 * Read an entire superblock's worth of data, as we know
	 * that that'll be properly sized for both raw and cooked
	 * devices.  Also, if we can't read an entire superblock,
	 * then we know this isn't UFS, even if it has a valid-
	 * looking struct fs.
	 */
	fs = (struct fs *)malloc(SBSIZE);
	if (fs == NULL) {
		return (FALSE);
	}

	if (lseek(fd, SBOFF, SEEK_SET) < 0) {
		free(fs);
		return (FALSE);
	}

	if (read(fd, fs, SBSIZE) < 0) {
		free(fs);
		return (FALSE);
	}

	if ((fs->fs_state + (long)fs->fs_time == FSOKAY) &&
	    (fs->fs_clean == FSCLEAN || fs->fs_clean == FSSTABLE ||
	    (fs->fs_clean == FSLOG))) {
		*clean = TRUE;
	} else {
		*clean = FALSE;
	}

	if ((fs->fs_magic == FS_MAGIC) ||
	    (fs->fs_magic == MTB_UFS_MAGIC &&
	    (fs->fs_version <= MTB_UFS_VERSION_1 &&
	    fs->fs_version >= MTB_UFS_VERSION_MIN))) {
		free(fs);
		return (TRUE);
	}
	free(fs);
	return (FALSE);
}
