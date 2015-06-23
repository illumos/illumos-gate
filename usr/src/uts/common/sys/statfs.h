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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_STATFS_H
#define	_SYS_STATFS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structure returned by statfs(2) and fstatfs(2).
 * This structure and associated system calls have been replaced
 * by statvfs(2) and fstatvfs(2) and will be removed from the system
 * in a near-future release.
 */

struct	statfs {
	short	f_fstyp;	/* File system type */
	long	f_bsize;	/* Block size */
	long	f_frsize;	/* Fragment size (if supported) */
	long	f_blocks;	/* Total number of blocks on file system */
	long	f_bfree;	/* Total number of free blocks */
	ino_t	f_files;	/* Total number of file nodes (inodes) */
	ino_t	f_ffree;	/* Total number of free file nodes */
	char	f_fname[6];	/* Volume name */
	char	f_fpack[6];	/* Pack name */
};

#ifdef _SYSCALL32

struct statfs32 {
	int16_t	f_fstyp;
	int32_t	f_bsize;
	int32_t f_frsize;
	int32_t	f_blocks;
	int32_t	f_bfree;
	ino32_t	f_files;
	ino32_t	f_ffree;
	char	f_fname[6];
	char	f_fpack[6];
};

#endif	/* _SYSCALL32 */

#if !defined(_KERNEL)
int statfs(const char *, struct statfs *, int, int);
int fstatfs(int, struct statfs *, int, int);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STATFS_H */
