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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LX_STAT_H
#define	_SYS_LX_STAT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/lx_types.h>
#include <sys/stat.h>

#define	LX_MAJORSHIFT		8
#define	LX_MINORMASK		((1 << LX_MAJORSHIFT) - 1)
#define	LX_MAKEDEVICE(lx_maj, lx_min)	\
	((lx_dev_t)((lx_maj) << LX_MAJORSHIFT | ((lx_min) & LX_MINORMASK)))

#define	LX_GETMAJOR(lx_dev)	((lx_dev) >> LX_MAJORSHIFT)
#define	LX_GETMINOR(lx_dev)	((lx_dev) & LX_MINORMASK)

#undef st_atime
#undef st_mtime
#undef st_ctime

struct lx_stat {
	lx_dev16_t		st_dev;
	uint16_t		st_pad1;
	lx_ino_t		st_ino;
	lx_mode16_t		st_mode;
	uint16_t		st_nlink;
	lx_uid16_t		st_uid;
	lx_gid16_t		st_gid;
	lx_dev16_t		st_rdev;
	uint16_t 		st_pad2;
	lx_off_t		st_size;
	lx_blksize_t		st_blksize;
	lx_blkcnt_t		st_blocks;
	struct lx_timespec	st_atime;
	struct lx_timespec	st_mtime;
	struct lx_timespec	st_ctime;
	uint32_t		st_pad3;
	uint32_t		st_pad4;
};

#if defined(_LP64)
struct lx_stat64 {
	ulong_t			st_dev;
	ulong_t			st_ino;
	ulong_t			st_nlink;	/* yes, the order really is */
	uint_t			st_mode;	/* different for these two */
	uint_t			st_uid;
	uint_t			st_gid;
	uint_t			st_pad0;
	ulong_t			st_rdev;
	long			st_size;
	long			st_blksize;
	long			st_blocks;
	struct lx_timespec	st_atime;
	struct lx_timespec	st_mtime;
	struct lx_timespec	st_ctime;
	long			st_unused[3];
};

#else /* is 32-bit */

struct lx_stat64 {
	lx_dev_t		st_dev;
	uint32_t		st_pad1;
	lx_ino_t		st_small_ino;
	lx_mode_t		st_mode;
	uint_t			st_nlink;
	lx_uid_t		st_uid;
	lx_gid_t		st_gid;
	lx_dev_t		st_rdev;
	uint32_t		st_pad2;
	lx_off64_t		st_size;
	lx_blksize_t		st_blksize;
	lx_blkcnt64_t		st_blocks;
	struct lx_timespec	st_atime;
	struct lx_timespec	st_mtime;
	struct lx_timespec	st_ctime;
	lx_ino64_t		st_ino;
};
#endif

extern int lx_stat_init(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_STAT_H */
