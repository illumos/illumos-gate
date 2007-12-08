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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOOTSTAT_H
#define	_SYS_BOOTSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * 32/64-bit neutral stat and time structure to allow booters to be shared
 *	among ILP32 and LP64 kernels.
 */
typedef struct boottime {
	int64_t	tv_sec;
	int64_t	tv_nsec;
} boottime_t;

/*
 * Current booters only support mode and size, with the exception of
 *	nfs booter also uses ino.
 */
struct bootstat {
	uint64_t	st_dev;
	uint64_t	st_ino;
	uint32_t	st_mode;
	uint32_t	st_nlink;
	int32_t		st_uid;
	int32_t		st_gid;
	uint64_t	st_rdev;
	uint64_t	st_size;
	boottime_t	st_atim;
	boottime_t	st_mtim;
	boottime_t	st_ctim;
	int32_t		st_blksize;
	int64_t		st_blocks;
	char		st_fstype[_ST_FSTYPSZ];
};

/*
 * Special struct for compressed files.
 * Only used by kobj to decompress files before
 * root is mounted. Afterwards, dcfs will take
 * over decompression.
 */
struct compinfo {
	int	iscmp;
	size_t	fsize;
	size_t	blksize;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BOOTSTAT_H */
